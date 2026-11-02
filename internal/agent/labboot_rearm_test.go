package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// rearmSystem is a Sim whose arming fails from its nth call on, as arming
// does once limine-snapper-sync has rewritten limine.conf and the block
// can't be written back.
type rearmSystem struct {
	*Sim
	mu      sync.Mutex
	arms    int
	failAt  int // the first BootOnce call that fails; 0: none
	reboots int
	cancels int
}

func (s *rearmSystem) CancelBootOnce() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancels++
	return nil
}

func (s *rearmSystem) BootOnce(entry string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arms++
	if s.failAt > 0 && s.arms >= s.failAt {
		return errors.New("limine.conf has no /" + entry + " entry")
	}
	return nil
}

func (s *rearmSystem) Reboot() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reboots++
	return nil
}

// A Lab boot is armed again just before its result goes to labd and again
// just before the reboot. A re-arm that fails before the report fails the
// boot_once command, so labd records infra_error rather than boot_failed;
// one that fails after it leaves the Mac up rather than boot the default.
func TestLabBootRearmBeforeReboot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failAt  int // 1: the re-arm before the report, 2: the one before the reboot
		ok      bool
		reboots int
	}{
		{"armed", 0, true, 1},
		{"dropped before the report", 1, false, 0},
		{"dropped before the reboot", 2, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu      sync.Mutex
				results []api.CommandResult
			)
			hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var rep api.Report
				json.NewDecoder(r.Body).Decode(&rep)
				mu.Lock()
				results = append(results, rep.Results...)
				mu.Unlock()
				w.Write([]byte("ok"))
			}))
			t.Cleanup(hs.Close)
			sys := &rearmSystem{Sim: NewSim(t.TempDir()), failAt: tc.failAt}
			var logged bytes.Buffer
			a := New(&Config{Server: hs.URL, Secret: "test"}, sys, log.New(&logged, "", 0))

			after := a.labBootAfterAck(entryPrefix + "j1")
			after.id = "c1"
			a.results = []api.CommandResult{{ID: "c1", OK: true}}
			a.after = []afterAck{*after}
			if err := a.report(context.Background()); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			sys.mu.Lock()
			defer sys.mu.Unlock()
			if len(results) != 1 || results[0].OK != tc.ok || sys.reboots != tc.reboots || len(a.after) != 0 {
				t.Fatalf("labd got %+v; %d reboots; %d left to run\n%s", results, sys.reboots, len(a.after), logged.String())
			}
			if !tc.ok && !strings.Contains(results[0].Error, "re-arming the Lab boot before the reboot: limine.conf has no /maclab-j1 entry") {
				t.Errorf("error: %q", results[0].Error)
			}
			// a failed re-arm cancels the one-shot it may have left set
			if wantCancels := map[bool]int{true: 1, false: 0}[tc.failAt > 0]; sys.cancels != wantCancels {
				t.Errorf("%d cancels, want %d", sys.cancels, wantCancels)
			}
		})
	}
}

// While labd can't be reached, lab-agent retries its report every few
// seconds, for hours if need be: the Lab boot is re-armed once before the
// report, not on every retry, as each arm can write NVRAM and the ESP.
func TestLabBootRearmsOnceWhileLabdIsDown(t *testing.T) {
	var (
		mu    sync.Mutex
		tries int
	)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if tries++; tries <= 10 {
			http.Error(w, "down", 502)
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(hs.Close)
	sys := &rearmSystem{Sim: NewSim(t.TempDir())}
	a := New(&Config{Server: hs.URL, Secret: "test"}, sys, log.New(io.Discard, "", 0))
	after := a.labBootAfterAck(entryPrefix + "j1")
	after.id = "c1"
	a.results = []api.CommandResult{{ID: "c1", OK: true}}
	a.after = []afterAck{*after}
	for range 10 {
		if err := a.report(context.Background()); err == nil {
			t.Fatal("labd is down, yet the report went")
		}
	}
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	sys.mu.Lock()
	defer sys.mu.Unlock()
	// once before the report, once before the reboot
	if sys.arms != 2 || sys.reboots != 1 {
		t.Errorf("%d arms and %d reboots over 11 tries, want 2 and 1", sys.arms, sys.reboots)
	}
}

// A boot_once labd gave up on (its arm timeout) whose result reaches it late
// is answered forgotten: the agent cancels the one-shot instead of rebooting
// into a Lab boot for a job labd has already ended.
func TestLabBootForgottenByLabdIsCancelledNotBooted(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.ReportReply{Forgotten: []string{"c1"}})
	}))
	t.Cleanup(hs.Close)
	sys := &rearmSystem{Sim: NewSim(t.TempDir())}
	a := New(&Config{Server: hs.URL, Secret: "test"}, sys, log.New(io.Discard, "", 0))
	after := a.labBootAfterAck(entryPrefix + "j1")
	after.id = "c1"
	a.results = []api.CommandResult{{ID: "c1", OK: true}}
	a.after = []afterAck{*after}
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	sys.mu.Lock()
	defer sys.mu.Unlock()
	if sys.reboots != 0 || sys.cancels != 1 || len(a.after) != 0 {
		t.Fatalf("%d reboots, %d cancels, %d left to run; want 0, 1, 0", sys.reboots, sys.cancels, len(a.after))
	}
}

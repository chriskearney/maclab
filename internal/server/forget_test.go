package server

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

func (l *lab) adminDo(method, path string) int {
	l.t.Helper()
	req, _ := http.NewRequest(method, l.url+path, nil)
	req.Header.Set("Authorization", "Bearer admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// After lab-agent uninstall a Mac is forgotten, and can then enroll again
// under the same name; a Mac with a job is refused.
func TestForgetDevice(t *testing.T) {
	l := newLab(t, false)
	v := l.s.dev(l.name)

	v.mu.Lock()
	v.d.State = api.StateBusy
	v.mu.Unlock()
	if code := l.adminDo("DELETE", "/api/devices/"+l.name); code != http.StatusConflict {
		t.Fatalf("forgetting a busy Mac: %d", code)
	}
	v.mu.Lock()
	v.d.State = api.StateReady
	v.mu.Unlock()

	// A job left unfinished in the store (queued while the Mac was offline).
	open := &api.Job{ID: "j-open", Spec: api.JobSpec{Device: l.name}, State: api.JobQueued}
	if err := l.s.store.saveJob(open); err != nil {
		t.Fatal(err)
	}
	if code := l.adminDo("DELETE", "/api/devices/"+l.name); code != http.StatusConflict {
		t.Fatalf("forgetting a Mac with an unfinished job: %d", code)
	}
	open.State = api.JobDone
	l.s.store.saveJob(open)

	if code := l.adminDo("DELETE", "/api/devices/"+l.name); code != http.StatusOK {
		t.Fatalf("forget: %d", code)
	}
	if code := l.adminDo("GET", "/api/devices/"+l.name); code != http.StatusNotFound {
		t.Fatalf("a forgotten Mac is still listed: %d", code)
	}
	select {
	case <-v.gone:
	default:
		t.Fatal("deviceLoop was not told to stop")
	}
	rows, _ := l.s.store.devices()
	if len(rows) != 0 {
		t.Fatalf("store still has %d devices", len(rows))
	}

	tok, _ := l.s.store.addTokenForTest(l.name)
	resp, err := agent.Enroll(context.Background(), l.url, tok, l.sim.Facts())
	if err != nil || resp.Name != l.name {
		t.Fatalf("enroll again under the same name: %v %+v", err, resp)
	}
}

// Forgetting one Mac twice at once: one forget wins, the other finds no
// device, and neither panics.
func TestForgetDeviceTwiceAtOnce(t *testing.T) {
	l := newLab(t, true)
	codes := make(chan int, 4)
	var wg sync.WaitGroup
	for range cap(codes) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("DELETE", l.url+"/api/devices/"+l.name, nil)
			req.Header.Set("Authorization", "Bearer admin")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				codes <- 0
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	n := map[int]int{}
	for c := range codes {
		n[c]++
	}
	if n[http.StatusOK] != 1 || n[http.StatusNotFound] != cap(codes)-1 {
		t.Fatalf("status codes: %v", n)
	}
}

// A check-in, the monitor or a promotion that still holds a forgotten Mac
// must not write its row back: the Mac enrolled again under the same name
// would then fail to save, and vanish when labd restarts.
func TestForgetThenLateSave(t *testing.T) {
	l := newLab(t, false)
	v := l.s.dev(l.name)
	if code := l.adminDo("DELETE", "/api/devices/"+l.name); code != http.StatusOK {
		t.Fatalf("forget: %d", code)
	}
	late := func() {
		v.heartbeat(api.Checkin{BootID: "late-" + randHex(4), Kernel: "7.1-late"}) // a new boot: saved
		v.setState(api.StateOffline, "no heartbeat")                               // the monitor
		v.mu.Lock()
		err := v.storeLocked() // a promotion
		v.mu.Unlock()
		if !errors.Is(err, errForgotten) {
			t.Errorf("a promotion saved a forgotten Mac: %v", err)
		}
	}
	late()
	if rows, _ := l.s.store.devices(); len(rows) != 0 {
		t.Fatalf("a late save brought back %d rows", len(rows))
	}

	tok, _ := l.s.store.addTokenForTest(l.name)
	resp, err := agent.Enroll(context.Background(), l.url, tok, l.sim.Facts())
	if err != nil {
		t.Fatal(err)
	}
	late()
	rows, _ := l.s.store.devices()
	if len(rows) != 1 || rows[0].d.ID != resp.DeviceID {
		t.Fatalf("rows after enrolling again: %+v", rows)
	}

	// What labd loads when it starts again.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s2, err := New(ctx, Config{DataDir: l.s.cfg.DataDir, AdminToken: "admin"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if v2 := s2.dev(l.name); v2 == nil || v2.snapshot().ID != resp.DeviceID || v2.secretHash != hashSecret(resp.Secret) {
		t.Fatalf("after a restart %s is not the Mac enrolled again", l.name)
	}
}

// Submit looks the Mac up before it saves the job. If lab forget ran in
// between, the job is canceled, not queued where nothing runs it.
func TestSubmitToForgottenMac(t *testing.T) {
	l := newLab(t, false)
	v := l.s.dev(l.name)
	if code, err := l.s.forget(v); err != nil {
		t.Fatalf("forget: %d %v", code, err)
	}
	// as if Submit had looked v up just before the forget
	l.s.mu.Lock()
	l.s.devs[l.name] = v
	l.s.mu.Unlock()
	_, code, err := l.s.Submit(api.JobSpec{Device: l.name, Baseline: true})
	l.s.mu.Lock()
	delete(l.s.devs, l.name)
	l.s.mu.Unlock()
	if code != http.StatusNotFound || err == nil {
		t.Fatalf("submit: %d %v", code, err)
	}
	if len(v.queue) > 0 {
		t.Error("queued on a forgotten Mac")
	}
	jobs, _ := l.s.store.jobs(l.name, 10, false)
	if len(jobs) != 1 || jobs[0].State != api.JobDone || jobs[0].Outcome != api.OutcomeCanceled {
		t.Fatalf("jobs: %+v", jobs)
	}
}

// A forgotten Mac's jobs stay, its known-good kernel doesn't: `lab publish`
// of one of its omarchy-m-test reports is refused, not a crashed handler.
func TestPublishForgottenMacsReport(t *testing.T) {
	var posts atomic.Int32
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer site.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "admin", OMTSite: site.URL}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()
	tok, _ := s.store.addTokenForTest("m1air")
	if _, err := agent.Enroll(ctx, hs.URL, tok, agent.NewSim(t.TempDir()).Facts()); err != nil {
		t.Fatal(err)
	}
	j := &api.Job{ID: "j-omt", Spec: api.JobSpec{Device: "m1air"}, State: api.JobDone, Result: api.JobResult{BootKernel: agent.SimKnownGood,
		OMT: &api.OMTResult{Report: "omt-report.json", Kernel: agent.SimKnownGood, KnownGood: true}}}
	if err := s.store.saveJob(j); err != nil {
		t.Fatal(err)
	}
	admin := func(method, path string) (int, string) {
		req, _ := http.NewRequest(method, hs.URL+path, nil)
		req.Header.Set("Authorization", "Bearer admin")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err) // the handler panicked
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := admin("DELETE", "/api/devices/m1air"); code != http.StatusOK {
		t.Fatalf("forget: %d %s", code, body)
	}
	if code, body := admin("POST", "/api/jobs/j-omt/publish"); code != http.StatusConflict || !strings.Contains(body, "m1air was forgotten") {
		t.Fatalf("publish: %d %s", code, body)
	}
	if posts.Load() != 0 {
		t.Error("the report was uploaded")
	}
	if j, _ := s.store.job("j-omt"); j.Result.OMT.PublishNote == "" {
		t.Error("the job doesn't say why it wasn't published")
	}
}

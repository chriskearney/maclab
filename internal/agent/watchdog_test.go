package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// wdClock is the time a labWatchdog sees; tests move it by hand.
type wdClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *wdClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *wdClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// wdDevice stands in for /dev/watchdog0 and counts the feeds.
type wdDevice struct{ feeds atomic.Int32 }

func (w *wdDevice) Write(p []byte) (int, error) {
	w.feeds.Add(1)
	return len(p), nil
}

// answers has PID 1 answer d's question now, or not.
func answers(d *labWatchdog, ok bool) {
	d.askPID1(context.Background(), func(context.Context) error {
		if ok {
			return nil
		}
		return errors.New("no answer")
	})
}

func TestLabWatchdogBudgets(t *testing.T) {
	clock := &wdClock{t: time.Unix(1_000_000, 0)}
	var dev wdDevice
	d := newLabWatchdog(&dev, clock.now)
	fed := func(want bool, when string) {
		t.Helper()
		answers(d, true)
		if got := d.tick(); got != want {
			t.Fatalf("%s: fed %v, want %v", when, got, want)
		}
	}

	fed(true, "fresh")
	clock.add(9 * time.Minute)
	answers(d, true)
	d.idle() // a check-in
	clock.add(9 * time.Minute)
	fed(true, "9 minutes after a check-in")
	clock.add(2 * time.Minute)
	fed(false, "11 minutes after the last check-in")

	d.idle()
	done := d.test(2 * time.Minute) // the test's budget replaces the idle one
	clock.add(time.Minute)
	fed(true, "a minute into a 2-minute test")
	d.idle() // check-ins carry on while the test hangs
	second := d.test(time.Hour)
	clock.add(90 * time.Second)
	fed(false, "past the test's budget, after a check-in and another test started")
	second()
	fed(false, "another test ended while the hung one runs")
	done()
	fed(true, "after the test ended")
	clock.add(watchdogIdle + time.Second)
	fed(false, "idle too long after the test")
	if n := dev.feeds.Load(); n != 4 {
		t.Fatalf("fed %d times, want 4", n)
	}
}

// Without an answer from PID 1 for pid1Silence nothing feeds the watchdog,
// test or not, and nothing extends the idle budget.
func TestLabWatchdogPID1(t *testing.T) {
	clock := &wdClock{t: time.Unix(1_000_000, 0)}
	d := newLabWatchdog(&wdDevice{}, clock.now)
	fed := func(want bool, when string) {
		t.Helper()
		if got := d.tick(); got != want {
			t.Fatalf("%s: fed %v, want %v", when, got, want)
		}
	}

	clock.add(9*time.Minute + 40*time.Second)
	d.idle() // a check-in, with PID 1 silent since the start
	answers(d, true)
	clock.add(40 * time.Second)
	answers(d, true)
	fed(false, "past the idle budget a silent check-in would have extended")

	d.idle()
	clock.add(20 * time.Second)
	answers(d, false)
	fed(true, "PID 1 silent for 20 s")
	clock.add(15 * time.Second)
	answers(d, false)
	fed(false, "PID 1 silent for 35 s, inside the idle budget")
	done := d.test(time.Hour)
	fed(false, "PID 1 silent, inside a test's budget")
	answers(d, true)
	fed(true, "PID 1 answers again")
	done()
}

// The agent says once when PID 1's silence stops the feeding, and again
// after it has answered and gone quiet once more.
func TestLabWatchdogLogsPID1Silence(t *testing.T) {
	clock := &wdClock{t: time.Unix(1_000_000, 0)}
	d := newLabWatchdog(&wdDevice{}, clock.now)
	var logged int
	d.logf = func(string, ...any) { logged++ }
	clock.add(35 * time.Second)
	d.tick()
	d.tick()
	if logged != 1 {
		t.Fatalf("logged %d times for one silence, want 1", logged)
	}
	answers(d, true)
	d.tick()
	clock.add(35 * time.Second)
	d.tick()
	if logged != 2 {
		t.Fatalf("logged %d times for two silences, want 2", logged)
	}
}

func TestTestBudget(t *testing.T) {
	for _, c := range []struct {
		test api.TestSpec
		want time.Duration
	}{
		{api.TestSpec{Name: "default"}, 5*time.Minute + 20*time.Second},
		{api.TestSpec{Name: "short", TimeoutSec: 60}, 80 * time.Second},
		{api.TestSpec{Name: "gui", TimeoutSec: 900, GUI: true}, 17*time.Minute + 20*time.Second},
	} {
		if got := testBudget(c.test); got != c.want {
			t.Errorf("%s: budget %s, want %s", c.test.Name, got, c.want)
		}
	}
}

func TestLabWatchdogNil(t *testing.T) {
	var d *labWatchdog // a boot without the watchdog: no-ops, no panic
	d.idle()
	d.test(time.Minute)()
}

// wdSystem is a Sim whose watchdog the test sees, whose tests and execs run
// until the test lets them finish, and whose script tests fetch the script
// first, as on a real Mac.
type wdSystem struct {
	*Sim
	dev      wdDevice
	openErrs []error // what OpenWatchdog fails with, in turn
	opened   atomic.Int32
	pinged   atomic.Int32
	running  chan struct{} // a test started
	finish   chan struct{} // let it end
	execing  chan struct{} // an exec started
	execDone chan struct{} // let it end
}

func (s *wdSystem) OpenWatchdog() (io.Writer, error) {
	if n := int(s.opened.Add(1)); n <= len(s.openErrs) {
		return nil, s.openErrs[n-1]
	}
	return &s.dev, nil
}

func (s *wdSystem) PingInit(ctx context.Context) error {
	s.pinged.Add(1)
	return nil
}

// Facts says what systemd says on a test boot: it doesn't hold the watchdog.
func (s *wdSystem) Facts() api.Facts {
	f := s.Sim.Facts()
	f.WatchdogArmed = false
	return f
}

func (s *wdSystem) RunTest(ctx context.Context, job string, t api.TestSpec, fetch Fetcher, outDir string) api.TestResult {
	if t.Script != "" {
		if err := fetch(ctx, t.Script, filepath.Join(s.Sim.WorkDir, t.Name+".sh")); err != nil {
			return api.TestResult{Name: t.Name, ExitCode: -1, Error: err.Error()}
		}
	}
	s.running <- struct{}{}
	<-s.finish
	os.WriteFile(filepath.Join(outDir, "log.txt"), []byte("ok\n"), 0o644)
	return api.TestResult{Name: t.Name, Passed: true}
}

func (s *wdSystem) Exec(ctx context.Context, a api.ExecArgs) api.ExecResult {
	s.execing <- struct{}{}
	<-s.execDone
	return api.ExecResult{Via: "agent"}
}

// wdLabd stands in for labd: it answers check-ins, serves one artifact and
// takes uploads.
type wdLabd struct {
	down     atomic.Bool      // check-ins fail
	checkins chan api.Checkin // gets each check-in, if set
	hold     time.Duration    // how long a check-in is held
	art      []byte
	onFetch  func() // runs while the artifact downloads
	onUpload func() // runs while a file uploads
}

func (l *wdLabd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/agent/checkin":
		var ci api.Checkin
		json.NewDecoder(r.Body).Decode(&ci)
		if l.checkins != nil {
			select {
			case l.checkins <- ci:
			default:
			}
		}
		time.Sleep(l.hold)
		if l.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "{}")
	case strings.HasPrefix(r.URL.Path, "/api/agent/artifacts/"):
		if l.onFetch != nil {
			l.onFetch()
		}
		w.Write(l.art)
	case r.URL.Path == "/api/agent/upload":
		if l.onUpload != nil {
			l.onUpload()
		}
		io.WriteString(w, "ok")
	default:
		io.WriteString(w, "ok")
	}
}

const testBoot = "root=UUID=sim rw maclab.job=j1"

func wdAgent(t *testing.T, cmdline string, lab *wdLabd) (*Agent, *wdSystem) {
	t.Helper()
	hs := httptest.NewServer(lab)
	t.Cleanup(hs.Close)
	sys := &wdSystem{Sim: NewSim(t.TempDir()), running: make(chan struct{}), finish: make(chan struct{}),
		execing: make(chan struct{}), execDone: make(chan struct{})}
	sys.Sim.cmdline = cmdline
	a := New(&Config{Server: hs.URL, Secret: "test", WorkDir: t.TempDir()}, sys, log.New(io.Discard, "", 0))
	return a, sys
}

func TestRunHoldsWatchdogOnTestBoot(t *testing.T) {
	busy := errors.New("device or resource busy")
	for _, c := range []struct {
		name, cmdline string
		openErrs      []error
		opened        int32
		held          bool
	}{
		{"test boot", testBoot, nil, 1, true},
		{"known-good boot", "root=UUID=sim rw", nil, 0, false},
		{"busy for a moment", testBoot, []error{busy}, 2, true},
		{"systemd holds it", testBoot, []error{busy, busy}, 2, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			lab := &wdLabd{checkins: make(chan api.Checkin, 100), hold: 10 * time.Millisecond}
			a, sys := wdAgent(t, c.cmdline, lab)
			sys.openErrs = c.openErrs
			ctx, cancel := context.WithCancel(context.Background())
			ran := make(chan error, 1)
			go func() { ran <- a.Run(ctx) }()

			select {
			case ci := <-lab.checkins:
				if ci.Facts == nil || ci.Facts.WatchdogArmed != c.held {
					t.Errorf("first check-in's facts: %+v, want watchdog_armed %v", ci.Facts, c.held)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no check-in")
			}
			if c.held {
				for start := time.Now(); sys.dev.feeds.Load() == 0 || sys.pinged.Load() == 0; time.Sleep(time.Millisecond) {
					if time.Since(start) > 5*time.Second {
						t.Fatalf("fed %d times, asked PID 1 %d times", sys.dev.feeds.Load(), sys.pinged.Load())
					}
				}
			}
			cancel()
			<-ran
			if n := sys.opened.Load(); n != c.opened {
				t.Errorf("opened the watchdog %d times, want %d", n, c.opened)
			}
			if (a.wd != nil) != c.held || !c.held && sys.dev.feeds.Load() != 0 {
				t.Errorf("holding %v with %d feeds, want holding %v", a.wd != nil, sys.dev.feeds.Load(), c.held)
			}
		})
	}
}

// wdHarness drives an agent's commands and check-ins by hand, on a test boot,
// with the watchdog on a clock the test moves.
type wdHarness struct {
	t     *testing.T
	a     *Agent
	sys   *wdSystem
	lab   *wdLabd
	clock *wdClock
	n     int
}

func newWDHarness(t *testing.T) *wdHarness {
	lab := &wdLabd{}
	a, sys := wdAgent(t, testBoot, lab)
	h := &wdHarness{t: t, a: a, sys: sys, lab: lab, clock: &wdClock{t: time.Unix(1_000_000, 0)}}
	a.wd = newLabWatchdog(&sys.dev, h.clock.now)
	return h
}

// at moves the clock on by d, with PID 1 answering then.
func (h *wdHarness) at(d time.Duration) {
	h.clock.add(d)
	answers(h.a.wd, true)
}

func (h *wdHarness) fed(want bool, when string) {
	h.t.Helper()
	if got := h.a.wd.tick(); got != want {
		h.t.Fatalf("%s: fed %v, want %v", when, got, want)
	}
}

func (h *wdHarness) checkin() {
	h.t.Helper()
	if err := h.a.poll(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

func (h *wdHarness) command(kind string, args any) string {
	h.n++
	c := api.Command{ID: fmt.Sprintf("c%d", h.n), Kind: kind, JobID: "j1"}
	c.Args, _ = json.Marshal(args)
	h.a.start(context.Background(), c)
	return c.ID
}

func (h *wdHarness) finished(id string) {
	h.t.Helper()
	for start := time.Now(); ; time.Sleep(time.Millisecond) {
		h.a.mu.Lock()
		running := h.a.running[id]
		h.a.mu.Unlock()
		if !running {
			return
		}
		if time.Since(start) > 5*time.Second {
			h.t.Fatalf("command %s did not finish", id)
		}
	}
}

// Outside a test, every check-in that reaches labd while PID 1 answers, and
// every command as it starts and as it ends, keeps the watchdog fed; a test's
// budget is moved by nothing else, in either direction, until the test ends.
func TestWatchdogFollowsCheckinsCommandsAndTests(t *testing.T) {
	h := newWDHarness(t)

	h.at(9 * time.Minute)
	h.checkin()
	h.at(9 * time.Minute)
	h.fed(true, "9 minutes after a check-in, 18 after the start")

	h.lab.down.Store(true)
	if err := h.a.poll(context.Background()); err == nil {
		t.Fatal("check-in to a down labd succeeded")
	}
	h.lab.down.Store(false)
	h.at(2 * time.Minute)
	h.fed(false, "11 minutes after the last check-in that reached labd")

	h.clock.add(40 * time.Second) // PID 1 silent
	h.checkin()
	h.at(0)
	h.fed(false, "after a check-in while PID 1 was silent")
	h.checkin()
	h.fed(true, "after a check-in while PID 1 answers")

	// a command keeps it fed from when it starts, and again from when it ends
	h.at(5 * time.Minute)
	exec := h.command(api.CmdExec, api.ExecArgs{Command: "sleep"})
	<-h.sys.execing
	h.at(9*time.Minute + 30*time.Second)
	h.fed(true, "9.5 minutes into a command, 14.5 after the last check-in")
	h.sys.execDone <- struct{}{}
	h.finished(exec)
	h.at(9*time.Minute + 30*time.Second)
	h.fed(true, "9.5 minutes after a command ended")

	// A test with an hour's timeout: its budget is the timeout plus the margin.
	test := h.command(api.CmdRunTest, api.TestSpec{Name: "long", Builtin: "x", TimeoutSec: 3600})
	<-h.sys.running
	h.at(time.Minute)
	h.checkin()
	h.finished(h.command(api.CmdConfig, nil))
	h.at(58 * time.Minute)
	h.fed(true, "59 minutes into the test, after a check-in and a command")
	h.checkin()
	h.finished(h.command(api.CmdConfig, nil))
	h.at(2 * time.Minute)
	h.fed(false, "past the test's budget, after a check-in and a command")
	h.sys.finish <- struct{}{}
	h.finished(test)
	h.fed(true, "after the test ended")
	h.at(watchdogIdle - time.Second)
	h.fed(true, "just inside the idle budget after the test")
}

// A test's budget ends when the test does, so uploading its output (over a
// slow link, say) runs on the idle budget.
func TestWatchdogIdleWhileUploading(t *testing.T) {
	h := newWDHarness(t)
	var uploading atomic.Bool
	h.lab.onUpload = func() {
		h.at(5 * time.Minute)
		uploading.Store(h.a.wd.tick())
	}
	test := h.command(api.CmdRunTest, api.TestSpec{Name: "short", Builtin: "x", TimeoutSec: 60})
	<-h.sys.running
	h.at(10 * time.Second)
	h.sys.finish <- struct{}{}
	h.finished(test)
	if !uploading.Load() {
		t.Fatal("not fed 5 minutes into uploading the output of a test with an 80 s budget")
	}
}

// PingInit asks PID 1 over systemctl.
func TestPingInit(t *testing.T) {
	old := systemctl
	t.Cleanup(func() { systemctl = old })
	for _, c := range []struct {
		name       string
		run        func(*Linux) error
		fail, hang string // systemctl commands that fail, or never answer
		calls      string
		err        string
	}{
		{"ping", func(l *Linux) error { return l.PingInit(context.Background()) }, "", "", "show -p Version --value", ""},
		{"ping, no answer", func(l *Linux) error { return l.PingInit(context.Background()) }, "show -p Version --value", "",
			"show -p Version --value", "systemctl show: exit status 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls []string
			systemctl = func(ctx context.Context, args ...string) ([]byte, error) {
				cmd := strings.Join(args, " ")
				calls = append(calls, cmd)
				switch cmd {
				case c.hang:
					<-ctx.Done()
					return nil, ctx.Err()
				case c.fail:
					return []byte("failed\n"), errors.New("exit status 1")
				}
				return []byte("262\n"), nil
			}
			err := c.run(&Linux{})
			if got := strings.Join(calls, "; "); got != c.calls {
				t.Errorf("ran systemctl %q, want %q", got, c.calls)
			}
			if (err != nil) != (c.err != "") || err != nil && !strings.Contains(err.Error(), c.err) {
				t.Errorf("error %v, want %q", err, c.err)
			}
		})
	}
}

func TestTestCmdlineWatchdog(t *testing.T) {
	base := "root=UUID=x rw quiet panic=0 systemd.watchdog_sec=60 watchdog.handle_boot_enabled=0 watchdog.open_timeout=5"
	got := testCmdline(base, api.StageArgs{}, "j1")
	for _, want := range []string{"systemd.watchdog_sec=0", "watchdog.open_timeout=120", "panic=10", "maclab.job=j1"} {
		if strings.Count(got, want) != 1 {
			t.Errorf("cmdline %q: want %q once", got, want)
		}
	}
	for _, gone := range []string{"systemd.watchdog_sec=60", "watchdog.handle_boot_enabled=", "watchdog.open_timeout=5 ", "panic=0"} {
		if strings.Contains(got+" ", gone) {
			t.Errorf("cmdline %q still has %q", got, gone)
		}
	}
}

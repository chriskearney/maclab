package agent

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// airCycle is a pm_test=devices cycle as an M1 MacBook Air's kernel logged it
// (trimmed): the devices suspended, the kernel waited, and they resumed.
const airCycle = `PM: suspend entry (s2idle)
Filesystems sync: 0.041 seconds
Freezing user space processes
Freezing user space processes completed (elapsed 0.001 seconds)
OOM killer disabled.
Freezing remaining freezable tasks
Freezing remaining freezable tasks completed (elapsed 0.001 seconds)
printk: Suspending console(s) (use no_console_suspend to debug)
apple-dcp 231c00000.dcp: dcp_poweroff() done
nvme-apple 27bcc0000.nvme: RTKit: syslog message: cmd.c:7963: NVMe shutdown start seg->lba: 0, seg->size: 0
PM: suspend debug: Waiting for 5 second(s).
nvme-apple 27bcc0000.nvme: RTKit: Initializing (protocol version 12)
apple-dcp 231c00000.dcp: dcp_poweron() starting
apple-dcp 231c00000.dcp: RTKit: syslog message: eoInterfaceIOAV.cpp:237: bool VideoInterfaceIOAV::open_ioav_gated(): IOAVVideoInterface open failed
apple-dcp 231c00000.dcp: RTKit: syslog message: UPPipe.cpp:3767: IOMFB read_pmu_data_sync: pmu ram read error (e00800d8)
OOM killer enabled.
Restarting tasks: Starting
snd-soc-macaudio sound: Speaker volumes locked: Lock timeout
Restarting tasks: Done
random: crng reseeded on system resumption
PM: suspend exit
`

// Cycles that end early still log "PM: suspend exit".
const (
	devicesFailedCycle = `PM: suspend entry (s2idle)
Filesystems sync: 0.040 seconds
Freezing user space processes
Freezing user space processes completed (elapsed 0.001 seconds)
OOM killer disabled.
Freezing remaining freezable tasks
Freezing remaining freezable tasks completed (elapsed 0.001 seconds)
printk: Suspending console(s) (use no_console_suspend to debug)
macsmc-rtc macsmc-rtc: PM: dpm_run_callback(): platform_pm_suspend returns -16
macsmc-rtc macsmc-rtc: PM: failed to suspend: error -16
PM: Some devices failed to suspend, or early wake event detected
OOM killer enabled.
Restarting tasks: Starting
Restarting tasks: Done
PM: suspend exit
`
	freezerFailedCycle = `PM: suspend entry (s2idle)
Filesystems sync: 0.040 seconds
Freezing user space processes
Freezing user space processes failed after 20.006 seconds (1 tasks refusing to freeze, wq_busy=0):
task:fsfreeze        state:D stack:0     pid:4242  tgid:4242  ppid:1     flags:0x00000004
OOM killer enabled.
Restarting tasks: Starting
Restarting tasks: Done
PM: suspend exit
`
	stoppedShortCycle = `PM: suspend entry (s2idle)
Filesystems sync: 0.040 seconds
PM: suspend exit
`
)

var resumeFailedCycle = strings.Replace(airCycle, "OOM killer enabled.\n",
	"brcmfmac 0000:01:00.0: PM: failed to resume async: error -110\nOOM killer enabled.\n", 1)

// The GUI user lab's systemctl --user, as the agent runs it, and their
// lock-before-suspend unit.
const (
	labSystemctl = "runuser -u lab -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user "
	lockUnit     = "omarchy-sleep-lock.service"
)

// fakeSuspend stands in for /sys/power/pm_test, systemctl, busctl, journalctl
// and ip, and for the GUI user lab and their systemctl --user. It never runs
// a real command: these tests run on a real Mac.
type fakeSuspend struct {
	mu        sync.Mutex
	klog      string // this boot's kernel log
	cycle     string // what systemctl suspend adds to it; "" for nothing
	failStart error  // systemctl suspend fails
	routeDown int    // ip polls without a default route after the suspend; -1 for good
	suspends  int
	modeSeen  string // pm_test when systemctl suspend ran

	jobs       string // systemctl list-jobs --no-legend
	failCancel bool
	cancelled  string // ids passed to systemctl cancel
	// After a cancel, systemd-sleep keeps systemd-suspend.service activating
	// for this many is-active polls, then suspends; -1 keeps it going.
	lateSleep int
	sleeping  bool
	// logind is still waiting on its delay inhibitors for this many polls,
	// and then suspends.
	preparing   int
	modeAtSleep string // pm_test when a late suspend happened

	// lab's omarchy-sleep-lock.service: "active" or "inactive", or "" when lab
	// has no service manager running (not logged in).
	lock                    string
	failLockStop            bool
	failLockStart           bool
	lockCmds                []string // systemctl --user commands run, in order
	lockAtSuspend           string   // the unit's state when systemctl suspend ran
	modeAtLockStart         string   // pm_test when the unit was started again
	lockStartedAfterSuspend bool

	// The deadlines systemctl suspend and the lock unit's start ran with;
	// zero for none.
	suspendDeadline, lockStartDeadline time.Time
}

func newFakeSuspend(t *testing.T, pmTest string) *fakeSuspend {
	f := &fakeSuspend{klog: "Booting Linux on physical CPU 0x0000000000\n", cycle: airCycle, lock: "active"}
	dir := t.TempDir()
	oldPath, oldCmd, oldUser, oldResume, oldSettle, oldNet, oldPoll := pmTestPath, suspendCmd, lookupUser, suspendResumeWait, suspendSettleWait, suspendNetWait, suspendPoll
	t.Cleanup(func() {
		pmTestPath, suspendCmd, lookupUser, suspendResumeWait, suspendSettleWait, suspendNetWait, suspendPoll = oldPath, oldCmd, oldUser, oldResume, oldSettle, oldNet, oldPoll
	})
	pmTestPath = filepath.Join(dir, "pm_test")
	if pmTest != "" {
		os.WriteFile(pmTestPath, []byte(pmTest+"\n"), 0o644)
	}
	suspendResumeWait, suspendSettleWait, suspendNetWait, suspendPoll = 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond, 10*time.Millisecond
	lookupUser = func(name string) (*user.User, error) {
		if name != "lab" {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{Username: "lab", Uid: "1000"}, nil
	}
	suspendCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		mode := func() string { b, _ := os.ReadFile(pmTestPath); return string(b) }
		cmd := strings.Join(append([]string{name}, args...), " ")
		if ids, ok := strings.CutPrefix(cmd, "systemctl cancel "); ok {
			f.cancelled = ids
			if f.failCancel {
				return "Failed to cancel job\n", errors.New("exit status 1")
			}
			f.jobs, f.sleeping = "", f.lateSleep != 0
			return "", nil
		}
		if c, ok := strings.CutPrefix(cmd, labSystemctl); ok {
			f.lockCmds = append(f.lockCmds, c)
			switch {
			case f.lock == "":
				return "Failed to connect to user scope bus via local transport: No such file or directory\n", errors.New("exit status 1")
			case c == "is-active "+lockUnit && f.lock == "active":
				return "active\n", nil
			case c == "is-active "+lockUnit:
				return f.lock + "\n", errors.New("exit status 3")
			case c == "stop "+lockUnit && f.failLockStop:
				return "Failed to stop " + lockUnit + ": Access denied\n", errors.New("exit status 1")
			case c == "stop "+lockUnit:
				f.lock = "inactive"
				return "", nil
			case c == "start "+lockUnit:
				f.modeAtLockStart, f.lockStartedAfterSuspend = mode(), f.suspends > 0
				f.lockStartDeadline, _ = ctx.Deadline()
				if f.failLockStart {
					return "Job for " + lockUnit + " failed because the control process exited with error code.\n", errors.New("exit status 1")
				}
				f.lock = "active"
				return "", nil
			}
		}
		switch cmd {
		case "systemctl list-jobs --no-legend":
			return f.jobs, nil
		case "systemctl is-active sleep.target suspend.target systemd-suspend.service":
			if f.sleeping && f.lateSleep != 0 {
				if f.lateSleep > 0 {
					f.lateSleep--
				}
				return "inactive\ninactive\nactivating\n", errors.New("exit status 3")
			}
			if f.sleeping {
				// systemd-sleep's hooks are done: it suspends, a test suspend if pm_test is still devices
				f.sleeping, f.modeAtSleep = false, mode()
				f.klog += airCycle
			}
			return "inactive\ninactive\ninactive\n", errors.New("exit status 3")
		case "busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager PreparingForSleep":
			if f.preparing > 0 {
				if f.preparing--; f.preparing == 0 {
					f.modeAtSleep = mode() // logind's delay is over: it suspends
					f.klog += airCycle
				}
				return "b true\n", nil
			}
			return "b false\n", nil
		case "systemctl suspend":
			f.modeSeen, f.lockAtSuspend = mode(), f.lock
			f.suspendDeadline, _ = ctx.Deadline()
			f.suspends++
			if f.failStart != nil {
				return "Call to Suspend failed: Access denied\n", f.failStart
			}
			f.klog += f.cycle
			return "", nil
		case "journalctl -k -b 0 -o cat --no-pager":
			return f.klog, nil
		case "ip route show default":
			if f.suspends > 0 && f.routeDown != 0 {
				if f.routeDown > 0 {
					f.routeDown--
				}
				return "", nil
			}
			return "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n", nil
		}
		t.Errorf("unexpected command %s %v", name, args)
		return "", errors.New("unexpected command")
	}
	return f
}

// lockPausedForSuspend checks that lab's desktop lock was stopped for the
// suspend and is running again, started once pm_test was back to want.
func (f *fakeSuspend) lockPausedForSuspend(t *testing.T, want string) {
	t.Helper()
	if f.suspends > 0 && f.lockAtSuspend != "inactive" {
		t.Errorf("suspended with %s %s", lockUnit, f.lockAtSuspend)
	}
	if f.lock != "active" || !f.lockStartedAfterSuspend || f.modeAtLockStart != want {
		t.Errorf("%s %s, started again after the suspend %v, with pm_test=%q (want %q); commands %q",
			lockUnit, f.lock, f.lockStartedAfterSuspend, f.modeAtLockStart, want, f.lockCmds)
	}
}

// runSuspendDevices runs the builtin on a Mac whose GUI user is gui.
func runSuspendDevices(t *testing.T, gui string, spec api.TestSpec) api.TestResult {
	t.Helper()
	return runSuspendDevicesQuiet(t, gui, spec, nil)
}

// runSuspendDevicesQuiet runs it telling labd through quiet.
func runSuspendDevicesQuiet(t *testing.T, gui string, spec api.TestSpec, quiet Quieter) api.TestResult {
	t.Helper()
	spec.Name, spec.Builtin = "suspend-devices", "suspend-devices"
	l := &Linux{WorkDir: t.TempDir(), GUIUser: gui}
	return l.RunTest(context.Background(), "j1", spec, nil, quiet, t.TempDir())
}

func pmTestNow(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(pmTestPath)
	return string(b)
}

const pmTestModes = "[none] core processors platform devices freezer"

// A kernel without pm_test's devices mode can't run the test: it is
// skipped, which is not a pass, and nothing is suspended.
func TestSuspendDevicesSkips(t *testing.T) {
	const why = "the kernel has no pm_test devices mode (CONFIG_PM_DEBUG): "
	for _, c := range []struct{ name, pmTest, want string }{
		{"no pm_test", "", why + "no "},
		{"no devices mode", "[none] core processors", why},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeSuspend(t, c.pmTest)
			r := runSuspendDevices(t, "lab", api.TestSpec{})
			if r.Passed || !r.Skipped || r.TimedOut || !strings.HasPrefix(r.Error, c.want) || !strings.Contains(r.Tail, "SKIP: "+c.want) ||
				f.suspends != 0 || len(f.lockCmds) != 0 {
				t.Fatalf("passed=%v skipped=%v error %q suspends=%d lock commands %q tail:\n%s", r.Passed, r.Skipped, r.Error, f.suspends, f.lockCmds, r.Tail)
			}
			if c.pmTest == "" {
				if _, err := os.Stat(pmTestPath); !os.IsNotExist(err) {
					t.Fatalf("created %s", pmTestPath)
				}
			}
		})
	}
}

// Only this cycle counts: an earlier failed one doesn't fail it. pm_test goes
// back to the mode it had, and lab's desktop lock runs again.
func TestSuspendDevicesPasses(t *testing.T) {
	for _, c := range []struct{ pmTest, mode string }{
		{pmTestModes, "none"},
		{"none core processors platform devices [freezer]", "freezer"},
	} {
		t.Run(c.mode, func(t *testing.T) {
			f := newFakeSuspend(t, c.pmTest)
			f.klog += devicesFailedCycle
			f.routeDown = 3 // Wi-Fi takes a few polls to come back
			r := runSuspendDevices(t, "lab", api.TestSpec{})
			if !r.Passed || r.ExitCode != 0 || f.suspends != 1 || f.modeSeen != "devices" {
				t.Fatalf("passed=%v exit=%d suspends=%d pm_test=%q tail:\n%s", r.Passed, r.ExitCode, f.suspends, f.modeSeen, r.Tail)
			}
			for _, want := range []string{"1 suspend cycles so far", "stopped " + lockUnit + ", so that the suspend doesn't lock lab's desktop",
				"devices suspended and resumed", "pm_test restored to " + c.mode, "default route back", "started " + lockUnit} {
				if !strings.Contains(r.Tail, want) {
					t.Errorf("tail lacks %q:\n%s", want, r.Tail)
				}
			}
			if m := pmTestNow(t); m != c.mode {
				t.Errorf("pm_test left at %q", m)
			}
			f.lockPausedForSuspend(t, c.mode)
		})
	}
}

// A cycle that logs "PM: suspend exit" without reaching the devices test
// point fails, even after an earlier cycle that passed.
func TestSuspendDevicesFails(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*fakeSuspend)
		want string
	}{
		{"device failed to suspend", func(f *fakeSuspend) { f.klog += airCycle; f.cycle = devicesFailedCycle },
			"the kernel logged: macsmc-rtc macsmc-rtc: PM: failed to suspend: error -16; PM: Some devices failed to suspend"},
		{"freezer failed", func(f *fakeSuspend) { f.cycle = freezerFailedCycle },
			"the kernel logged: Freezing user space processes failed after 20.006 seconds"},
		{"device failed to resume", func(f *fakeSuspend) { f.cycle = resumeFailedCycle },
			"the kernel logged: brcmfmac 0000:01:00.0: PM: failed to resume async: error -110"},
		{"stopped short", func(f *fakeSuspend) { f.cycle = stoppedShortCycle },
			"the suspend stopped before the devices' suspend phase was done"},
		{"suspend refused", func(f *fakeSuspend) { f.failStart = errors.New("exit status 1") },
			"systemctl suspend: exit status 1: Call to Suspend failed"},
		{"no network", func(f *fakeSuspend) { f.routeDown = -1 },
			"no default route"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeSuspend(t, pmTestModes)
			c.set(f)
			r := runSuspendDevices(t, "lab", api.TestSpec{})
			if r.Passed || r.TimedOut || r.ExitCode != 1 || !strings.Contains(r.Tail, "FAIL: "+c.want) {
				t.Fatalf("passed=%v timed out=%v exit=%d tail:\n%s", r.Passed, r.TimedOut, r.ExitCode, r.Tail)
			}
			if f.modeSeen != "devices" {
				t.Errorf("suspended with pm_test=%q", f.modeSeen)
			}
			if m := pmTestNow(t); m != "none" {
				t.Errorf("pm_test left at %q", m)
			}
			f.lockPausedForSuspend(t, "none")
		})
	}
}

// A device that fails is the verdict, also when the test's time runs out
// while pm_test waits for logind to be done with the suspend. The wait ends
// with the test's time, and pm_test stays at devices.
func TestSuspendDevicesFailureIsNotATimeout(t *testing.T) {
	f := newFakeSuspend(t, pmTestModes)
	f.cycle, f.preparing = devicesFailedCycle, 150 // 1.5s of polls, past the test's 1s
	suspendSettleWait = 10 * time.Second
	r := runSuspendDevices(t, "lab", api.TestSpec{TimeoutSec: 1})
	if r.Passed || r.TimedOut || r.ExitCode != 1 || !strings.Contains(r.Tail, "FAIL: the kernel logged: macsmc-rtc") {
		t.Fatalf("passed=%v timed out=%v exit=%d after %.1fs, tail:\n%s", r.Passed, r.TimedOut, r.ExitCode, r.Seconds, r.Tail)
	}
	if r.Seconds < 0.9 || r.Seconds > 1.3 {
		t.Fatalf("took %.1fs, want the test's 1s", r.Seconds)
	}
	if !strings.Contains(r.Tail, "left pm_test at devices, so that a later suspend isn't a real one: as the test's time ran out, logind is preparing for sleep") {
		t.Errorf("tail:\n%s", r.Tail)
	}
	if m := pmTestNow(t); m != "devices" {
		t.Errorf("pm_test %q after the test", m)
	}
	f.lockPausedForSuspend(t, "devices")
}

// The test always has a deadline, 5 minutes without a timeout of its own,
// and the cycle leaves part of it for putting things back, which ends by the
// test's deadline too (each step there has 30 s at most).
func TestSuspendDevicesDeadline(t *testing.T) {
	for _, c := range []struct {
		spec          api.TestSpec
		cycle, tidied time.Duration // the deadlines from the start
	}{
		{api.TestSpec{}, 5*time.Minute - suspendTidyWait, 30 * time.Second},
		{api.TestSpec{TimeoutSec: 600}, 10*time.Minute - suspendTidyWait, 30 * time.Second},
		{api.TestSpec{TimeoutSec: 20}, 10 * time.Second, 20 * time.Second},
	} {
		f := newFakeSuspend(t, pmTestModes)
		start := time.Now()
		r := runSuspendDevices(t, "lab", c.spec)
		if !r.Passed {
			t.Fatalf("timeout %ds: failed, tail:\n%s", c.spec.TimeoutSec, r.Tail)
		}
		near := func(what string, got time.Time, want time.Duration) {
			if got.IsZero() || got.Sub(start) < want-time.Second || got.Sub(start) > want+time.Second {
				t.Errorf("timeout %ds: %s with deadline %v, want %s from the start", c.spec.TimeoutSec, what, got.Sub(start), want)
			}
		}
		near("systemctl suspend", f.suspendDeadline, c.cycle)
		near("starting the lock unit again", f.lockStartDeadline, c.tidied)
	}
}

// However slowly a cycle fails, the test ends within its timeout, putting
// things back too, and so inside the watchdog's budget for it: a suspend
// that never ends, and never settles once cancelled.
func TestSuspendDevicesSlowFailureEndsInTime(t *testing.T) {
	f := newFakeSuspend(t, pmTestModes)
	f.cycle, f.jobs, f.lateSleep = "", "1062 systemd-suspend.service start running\n", -1
	suspendResumeWait, suspendSettleWait, suspendNetWait = time.Minute, 5*time.Second, time.Minute
	spec := api.TestSpec{TimeoutSec: 2}
	r := runSuspendDevices(t, "lab", spec)
	if r.Passed || !r.TimedOut {
		t.Fatalf("passed=%v timed out=%v tail:\n%s", r.Passed, r.TimedOut, r.Tail)
	}
	if took := time.Duration(r.Seconds * float64(time.Second)); took > testTimeout(spec)+300*time.Millisecond {
		t.Fatalf("took %s with a %s timeout (watchdog budget %s), tail:\n%s", took, testTimeout(spec), testBudget(spec), r.Tail)
	}
	for _, want := range []string{"FAIL: no suspend cycle ended before the test stopped (context deadline exceeded); cancelled sleep jobs 1062",
		"left pm_test at devices, so that a later suspend isn't a real one: as the test's time ran out, systemd-suspend.service is activating"} {
		if !strings.Contains(r.Tail, want) {
			t.Errorf("tail lacks %q:\n%s", want, r.Tail)
		}
	}
	if m := pmTestNow(t); m != "devices" {
		t.Errorf("pm_test %q after the test", m)
	}
}

// Just before it suspends, with pm_test at devices, the test tells labd how
// long the Mac may be off the network: until the cycle, its settling and the
// network have had their time, or the test's time is up. If labd doesn't
// hear it, the test carries on.
func TestSuspendDevicesTellsLabd(t *testing.T) {
	for _, c := range []struct {
		name     string
		spec     api.TestSpec
		net      time.Duration
		fail     error
		min, max time.Duration
		want     string
	}{
		{"waits", api.TestSpec{}, 300 * time.Millisecond, nil, 900 * time.Millisecond, 900 * time.Millisecond,
			"told labd the Mac may be off the network for up to 1s"},
		{"time left", api.TestSpec{TimeoutSec: 2}, time.Minute, nil, 1500 * time.Millisecond, 2 * time.Second,
			"told labd the Mac may be off the network for up to 2s"},
		{"labd unreachable", api.TestSpec{}, 300 * time.Millisecond, errors.New("connection refused"), 900 * time.Millisecond, 900 * time.Millisecond,
			"could not tell labd the Mac may be off the network for 1s: connection refused"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeSuspend(t, pmTestModes)
			suspendNetWait = c.net
			var told []time.Duration
			var mode string
			var suspended int
			r := runSuspendDevicesQuiet(t, "lab", c.spec, func(ctx context.Context, d time.Duration) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				told, mode, suspended = append(told, d), pmTestNow(t), f.suspends
				return c.fail
			})
			if !r.Passed || !strings.Contains(r.Tail, c.want) {
				t.Fatalf("passed=%v tail:\n%s", r.Passed, r.Tail)
			}
			if len(told) != 1 || told[0] < c.min || told[0] > c.max || mode != "devices" || suspended != 0 {
				t.Fatalf("told labd %v, with pm_test=%q after %d suspends; want once, %s to %s, devices, before suspending", told, mode, suspended, c.min, c.max)
			}
		})
	}
}

// A suspend that hasn't ended in time is cancelled, and pm_test stays at
// devices until nothing is left that could suspend the Mac: systemd-sleep
// keeps running after its job is cancelled, and suspends once its hooks are
// done, and logind suspends once its delay is over, so either has to be a
// test suspend too. If it never settles, pm_test stays at devices, unless it
// was at another mode that stops short of sleeping. Either way lab's desktop
// lock runs again.
func TestSuspendDevicesLateSuspend(t *testing.T) {
	jobs := "1061 suspend.target           start waiting\n1062 systemd-suspend.service start running\n1070 fwupd.service start waiting\n"
	for _, c := range []struct {
		name                 string
		pmTest               string
		jobs                 string
		lateSleep, preparing int
		failCancel           bool
		spec                 api.TestSpec
		want                 []string
		mode                 string // pm_test after the test
	}{
		{"systemd-sleep runs on", pmTestModes, jobs, 3, 0, false, api.TestSpec{},
			[]string{`FAIL: no suspend cycle ended ("PM: suspend exit") in the kernel log`, "cancelled sleep jobs 1061 1062", "pm_test restored to none"}, "none"},
		{"logind still delaying", pmTestModes, "", 0, 3, false, api.TestSpec{},
			[]string{"FAIL: no suspend cycle ended", "no sleep job was left to cancel", "pm_test restored to none"}, "none"},
		{"test timeout", pmTestModes, jobs, 3, 0, false, api.TestSpec{TimeoutSec: 1},
			[]string{"FAIL: no suspend cycle ended before the test stopped (context deadline exceeded); cancelled sleep jobs 1061 1062"}, "none"},
		{"never settles", pmTestModes, jobs, -1, 0, false, api.TestSpec{},
			[]string{"cancelled sleep jobs 1061 1062; left pm_test at devices, so that a later suspend isn't a real one: after 300ms, systemd-suspend.service is activating"}, "devices"},
		{"never settles, freezer before", "none core processors platform devices [freezer]", jobs, -1, 0, false, api.TestSpec{},
			[]string{"with pm_test=freezer that suspend wouldn't be a real one either", "pm_test restored to freezer"}, "freezer"},
		{"cancel fails", pmTestModes, jobs, 0, 0, true, api.TestSpec{},
			[]string{"cancelling the suspend failed: systemctl cancel 1061 1062: exit status 1", "left pm_test at devices", "sleep jobs 1061 1062 are queued"}, "devices"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeSuspend(t, c.pmTest)
			f.cycle, f.jobs, f.lateSleep, f.preparing, f.failCancel = "", c.jobs, c.lateSleep, c.preparing, c.failCancel
			if c.spec.TimeoutSec > 0 {
				suspendResumeWait = time.Minute // the test's own timeout ends the wait
			}
			r := runSuspendDevices(t, "lab", c.spec)
			if r.Passed {
				t.Fatalf("passed tail:\n%s", r.Tail)
			}
			for _, w := range c.want {
				if !strings.Contains(r.Tail, w) {
					t.Errorf("tail lacks %q:\n%s", w, r.Tail)
				}
			}
			if want := map[bool]string{true: "1061 1062"}[c.jobs != ""]; f.cancelled != want {
				t.Errorf("cancelled %q, want %q", f.cancelled, want)
			}
			if (c.lateSleep > 0 || c.preparing > 0) && f.modeAtSleep != "devices" {
				t.Errorf("the late suspend ran with pm_test=%q", f.modeAtSleep)
			}
			if m := pmTestNow(t); m != c.mode {
				t.Errorf("pm_test %q, want %q", m, c.mode)
			}
			if timedOut := c.spec.TimeoutSec > 0; r.TimedOut != timedOut {
				t.Errorf("timed out %v, want %v", r.TimedOut, timedOut)
			}
			f.lockPausedForSuspend(t, c.mode)
		})
	}
}

// Omarchy locks the desktop before a suspend, and only the user's password
// unlocks it: the GUI user's lock unit is stopped for the cycle and started
// again however it ends. Without a GUI user, a session or a running lock
// unit there is nothing to do. A lock unit that can't be stopped fails the
// test before anything is suspended.
func TestSuspendDevicesKeepsTheDesktopUnlocked(t *testing.T) {
	for _, c := range []struct {
		name       string
		gui        string
		set        func(*fakeSuspend)
		passed     bool
		suspends   int
		mode       string   // pm_test after the test
		cmds       []string // lab's systemctl --user commands
		lock, want string   // the lock unit after the test; in the log
	}{
		{"no GUI user", "", func(f *fakeSuspend) {}, true, 1, "none", nil, "active", "pm_test restored to none"},
		{"not logged in", "lab", func(f *fakeSuspend) { f.lock = "" }, true, 1, "none", []string{"is-active " + lockUnit}, "",
			"no desktop of lab to keep unlocked: systemctl --user is-active: exit status 1: Failed to connect"},
		{"no such user", "nobody", func(f *fakeSuspend) {}, true, 1, "none", nil, "active",
			"no desktop of nobody to keep unlocked: systemctl --user is-active: user: unknown user nobody"},
		{"lock not running", "lab", func(f *fakeSuspend) { f.lock = "inactive" }, true, 1, "none", []string{"is-active " + lockUnit}, "inactive",
			"pm_test restored to none"},
		{"stop fails", "lab", func(f *fakeSuspend) { f.failLockStop = true }, false, 0, pmTestModes + "\n",
			[]string{"is-active " + lockUnit, "stop " + lockUnit, "start " + lockUnit}, "active",
			"FAIL: stopping " + lockUnit + ", which would lock lab's desktop: exit status 1: Failed to stop"},
		{"start fails", "lab", func(f *fakeSuspend) { f.failLockStart = true }, false, 1, "none",
			[]string{"is-active " + lockUnit, "stop " + lockUnit, "start " + lockUnit}, "inactive",
			"FAIL: starting " + lockUnit + ": exit status 1: Job for " + lockUnit + " failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeSuspend(t, pmTestModes)
			c.set(f)
			r := runSuspendDevices(t, c.gui, api.TestSpec{})
			if r.Passed != c.passed || r.TimedOut || f.suspends != c.suspends || !strings.Contains(r.Tail, c.want) {
				t.Fatalf("passed=%v timed out=%v suspends=%d tail:\n%s", r.Passed, r.TimedOut, f.suspends, r.Tail)
			}
			if m := pmTestNow(t); m != c.mode {
				t.Errorf("pm_test %q, want %q", m, c.mode)
			}
			if !slices.Equal(f.lockCmds, c.cmds) || f.lock != c.lock {
				t.Errorf("systemctl --user %q, %s %q; want %q, %q", f.lockCmds, lockUnit, f.lock, c.cmds, c.lock)
			}
		})
	}
}

func TestSuspendDevicesIsABuiltin(t *testing.T) {
	for _, n := range Builtins() {
		if n == "suspend-devices" {
			return
		}
	}
	t.Fatalf("Builtins() = %v", Builtins())
}

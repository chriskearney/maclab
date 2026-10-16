package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/iconidentify/maclab/internal/api"
)

// A test boot is watched by the hardware watchdog once Linux runs, to the last
// test, with no controller Mac or serial needed:
//
//   - Apple Silicon's U-Boot starts apple_wdt and leaves it running into
//     Linux. (U-Boot feeds it itself while it or Limine waits, so a Mac
//     sitting at a U-Boot prompt or the Limine menu is not reset.) The kernel
//     pings it only until watchdog.open_timeout, and systemd.watchdog_sec=0
//     keeps systemd, in the initramfs too, from taking it over. A boot that
//     hasn't opened it by then is reset within 30 s, a healthy one too, so
//     the agent must open it on every test boot, and keeps trying until that
//     deadline has passed; a boot that hangs, or stays alive but stuck before
//     the agent runs (waiting forever for its root device, say), is reset.
//     The deadline comes from labd's boot timeout (bootDeadline).
//   - Once up, the agent holds /dev/watchdog0 itself and feeds it only while
//     PID 1 answers and the current step is within its budget. A test that
//     hangs where its own timeout can't reach it (a process stuck in the
//     kernel, the agent wedged) stops the feeding while systemd and the
//     kernel stay healthy, and the hardware resets the Mac. So does a wedged
//     PID 1, which systemd's own watchdog would have caught: it is off on a
//     test boot.
//
// Either way the one-shot is already spent, so the Mac comes back on its
// known-good kernel and labd sees the fallback. Measured on an M1 MacBook Air:
// a test boot stuck waiting for a missing root device was back on the
// known-good kernel 198 s after the reboot, and a test that froze lab-agent
// was reset and back 113 s after it froze.
const (
	watchdogDev = "/dev/watchdog0"
	// labBootDeadline is watchdog.open_timeout on a test boot when labd
	// doesn't say how long it waits for the boot (an older labd): the time
	// from apple_wdt probing to the agent opening the watchdog (5 s on an M1
	// Air). The kernel stops pinging it then, and apple_wdt's 30 s boot
	// timeout resets the Mac within 30 s. It is what bootDeadline makes of
	// labd's default 4-minute --boot-timeout.
	labBootDeadline = 120 * time.Second
	// bootFallback is the part of labd's boot timeout a test boot's deadline
	// leaves for the reset and the known-good kernel's boot after it. On an
	// M1 Air, with a 120 s deadline, a boot stuck at 150 s was back on the
	// known-good kernel 228 s after the reboot, 12 s inside labd's default
	// 4-minute --boot-timeout; 2 minutes leaves room for slower firmware, so
	// labd sees the fallback before it would call for a person.
	bootFallback = 2 * time.Minute
	// minBootDeadline is the least a test boot gets to open the watchdog,
	// however short labd's boot timeout: lab-agent starts only after
	// network-online.target.
	minBootDeadline = time.Minute
	// watchdogTimeout is the hardware timeout once the agent holds it.
	watchdogTimeout = 60 * time.Second
	// watchdogIdle is how long the agent keeps feeding, outside a test, after
	// a check-in reached labd or a command started or finished.
	watchdogIdle = 10 * time.Minute
	// watchdogMargin is added to a test's budget, to kill it and report. A
	// test that overruns its budget has about a minute more before the
	// hardware resets the Mac, so a hung test is reset within 80 s of its
	// timeout (2 minutes later for a GUI test), 40 s before labd would give
	// up waiting for it (labd waits 2 minutes past the same point): labd sees
	// the Mac go away during that test and blames it, not the step after it.
	watchdogMargin = 20 * time.Second
	watchdogTick   = 5 * time.Second
	// pid1Ask is how often the agent asks PID 1 for its version, and how long
	// it gives it to answer.
	pid1Ask = 10 * time.Second
	// pid1Silence is how long PID 1 may go without answering before the agent
	// stops feeding, test or not. A wedged PID 1 is then reset within 90 s
	// of its last answer, where systemd's own watchdog (RuntimeWatchdogSec=30s
	// from setup) takes 30 s; a PID 1 too busy to answer for this long counts
	// as wedged. The clock doesn't run while the Mac is suspended.
	pid1Silence = 30 * time.Second

	wdiocSetTimeout = 0xC0045706 // _IOWR('W', 6, int)
)

// labWatchdog feeds the hardware watchdog until a deadline, while PID 1
// answers. While a test runs the deadline is the test's budget and nothing
// else moves it, so a test hung in the kernel ends in a reset although the
// agent keeps checking in. Outside tests every sign of labd moves it to
// watchdogIdle from then, if PID 1 answers: the Mac stays up for as long as
// labd is in touch, however long a command takes. It never stops the
// watchdog: if the agent exits, the Mac resets watchdogTimeout later unless
// something reopens it.
type labWatchdog struct {
	w   io.Writer
	now func() time.Time

	mu     sync.Mutex
	until  time.Time
	tests  int       // tests running
	pid1At time.Time // when PID 1 last answered
	silent bool      // feeding stopped because PID 1 went quiet

	logf func(format string, args ...any) // nil: tests
}

// testBudget is how long the watchdog is fed for a test: its timeout and
// watchdogMargin, and for a GUI test guiSessionWait more, as the wait for the
// desktop session can outlast a short timeout.
func testBudget(t api.TestSpec) time.Duration {
	b := testTimeout(t) + watchdogMargin
	if t.GUI {
		b += guiSessionWait
	}
	return b
}

// newLabWatchdog starts with PID 1 answering: it has just started the agent.
func newLabWatchdog(w io.Writer, now func() time.Time) *labWatchdog {
	d := &labWatchdog{w: w, now: now, pid1At: now()}
	d.idle()
	return d
}

// OpenWatchdog opens the watchdog device and sets its timeout. It fails with
// EBUSY if systemd holds it (an installed-mode boot, or a test boot staged by
// an older agent).
func (l *Linux) OpenWatchdog() (io.Writer, error) {
	f, err := os.OpenFile(watchdogDev, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	// apple_wdt takes up to ~178 s; a driver that refuses keeps its default.
	_ = unix.IoctlSetPointerInt(int(f.Fd()), wdiocSetTimeout, int(watchdogTimeout/time.Second))
	return f, nil
}

// systemctl runs systemctl; tests stand in for it.
var systemctl = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
}

// Tests stand in for the time since boot and how often the agent tries to
// open the watchdog again.
var (
	watchdogUptime = uptime
	watchdogRetry  = time.Second
)

// bootDeadline is watchdog.open_timeout for a test boot that labd waits up to
// boot for: what is left of it once the reset and the fallback boot are
// allowed for, but at least minBootDeadline. A boot slow to start the agent
// (a probe timing out, a nofail mount or network-online.target waiting) gets
// as long as labd would wait for it anyway.
func bootDeadline(boot time.Duration) time.Duration {
	if boot <= 0 {
		return labBootDeadline
	}
	return max(boot-bootFallback, minBootDeadline)
}

// openDeadline is the boot's watchdog.open_timeout, or labBootDeadline if its
// command line has none.
func openDeadline(cmdline string) time.Duration {
	d := labBootDeadline
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "watchdog.open_timeout="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				d = time.Duration(n) * time.Second
			}
		}
	}
	return d
}

// leavesWatchdog is whether the command line keeps systemd off the watchdog,
// for the agent to hold, as a test boot's does (testCmdline). An
// installed-mode boot's doesn't: systemd holds the watchdog there.
func leavesWatchdog(cmdline string) bool {
	return slices.Contains(strings.Fields(cmdline), "systemd.watchdog_sec=0")
}

// PingInit asks systemd for its version. Run as root, systemctl asks PID 1
// over its private socket, without D-Bus or logind.
func (l *Linux) PingInit(ctx context.Context) error {
	if out, err := systemctl(ctx, "show", "-p", "Version", "--value"); err != nil {
		return fmt.Errorf("systemctl show: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// idle feeds the watchdog for watchdogIdle from now, unless a test is running
// or PID 1 hasn't answered lately. A nil watchdog ignores idle and test, so
// callers need no check on boots where the agent doesn't hold one.
func (d *labWatchdog) idle() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.idleLocked()
}

func (d *labWatchdog) idleLocked() {
	if d.tests == 0 && d.pid1Locked() {
		d.until = d.now().Add(watchdogIdle)
	}
}

// pid1Locked is whether PID 1 answered within pid1Silence. d.mu is held.
func (d *labWatchdog) pid1Locked() bool { return d.now().Sub(d.pid1At) < pid1Silence }

// test feeds the watchdog for a test's budget and returns the func that ends
// the test. labd runs one test at a time, so a test that starts while another
// still runs (one labd gave up waiting for) gets no time of its own: the stuck
// one still ends in a reset.
func (d *labWatchdog) test(budget time.Duration) (done func()) {
	if d == nil {
		return func() {}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tests == 0 {
		d.until = d.now().Add(budget)
	}
	d.tests++
	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.tests--
		d.idleLocked()
	}
}

// tick feeds the watchdog if PID 1 answers and the current step is still
// within its budget.
func (d *labWatchdog) tick() bool {
	d.mu.Lock()
	pid1 := d.pid1Locked()
	ok := d.now().Before(d.until) && pid1
	if !pid1 && !d.silent && d.logf != nil {
		d.logf("PID 1 hasn't answered for %s: no longer feeding the hardware watchdog, the Mac resets within %s", pid1Silence, watchdogTimeout)
	}
	d.silent = !pid1
	d.mu.Unlock()
	if ok {
		d.w.Write([]byte{'1'})
	}
	return ok
}

func (d *labWatchdog) feed(ctx context.Context) {
	t := time.NewTicker(watchdogTick)
	defer t.Stop()
	for {
		d.tick()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// askPID1 asks PID 1 once, giving it pid1Ask to answer.
func (d *labWatchdog) askPID1(ctx context.Context, ask func(context.Context) error) {
	actx, cancel := context.WithTimeout(ctx, pid1Ask)
	defer cancel()
	if ask(actx) == nil {
		d.mu.Lock()
		d.pid1At = d.now()
		d.mu.Unlock()
	}
}

// watchPID1 asks PID 1 every pid1Ask until ctx ends.
func (d *labWatchdog) watchPID1(ctx context.Context, ask func(context.Context) error) {
	t := time.NewTicker(pid1Ask)
	defer t.Stop()
	for {
		d.askPID1(ctx, ask)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

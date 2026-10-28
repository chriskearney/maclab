package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// suspendDevicesTest is the builtin that suspends and resumes the devices
// without a person. Apple Silicon's RTC (macsmc-rtc) has no wakealarm, so a
// real suspend stays asleep until someone presses a key. With pm_test=devices
// the kernel freezes tasks and runs the devices' prepare and suspend callbacks
// (dpm_suspend_start: not the late and noirq phases, nor the sleep itself),
// waits 5s and resumes them.
const suspendDevicesTest = "suspend-devices"

// Tests stand in for the sysfs file, the commands, the GUI user and the waits.
var (
	pmTestPath = "/sys/power/pm_test"
	suspendCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil && ctx.Err() != nil {
			err = fmt.Errorf("%w (%s: %v)", ctx.Err(), name, err) // killed as ctx ended
		}
		return string(out), err
	}
	lookupUser        = user.Lookup
	suspendResumeWait = 60 * time.Second
	suspendSettleWait = 30 * time.Second
	suspendNetWait    = 2 * time.Minute
	suspendPoll       = 2 * time.Second
	// suspendTidyWait is the part of the test's timeout the cycle leaves for
	// putting things back after it: mostly waiting up to suspendSettleWait
	// for a suspend cut short to settle. A short timeout leaves half of it.
	suspendTidyWait = 45 * time.Second
)

// errNoPMTest is a kernel that can't run the test. It is skipped, which is
// not a pass.
var errNoPMTest = errors.New("the kernel has no pm_test devices mode (CONFIG_PM_DEBUG)")

// sleepUnits are the units `systemctl suspend` runs.
var sleepUnits = []string{"sleep.target", "suspend.target", "systemd-suspend.service"}

// sleepLockUnits are the GUI user's units that lock the desktop when logind
// announces a suspend. Omarchy's omarchy-sleep-lock.service holds a delay
// inhibitor and has the shell lock the session; only the user's password
// unlocks it, and the lock screen turns the panel off 5s later.
var sleepLockUnits = []string{"omarchy-sleep-lock.service"}

// suspendDevices runs one pm_test=devices cycle. Everything it does ends
// within the test's timeout (testTimeout), putting things back too, so that
// a failure however slow ends as one, inside the watchdog's budget for the
// test (testBudget). The cycle gets the timeout less suspendTidyWait, and
// putting things back gets the rest, and runs even once the cycle's time is
// up. A kernel without pm_test's devices mode skips the test, which fails
// the job: the kernel wasn't tested.
//
// labd mostly doesn't hear of the suspend from WatchSleep: NetworkManager
// takes the network down as soon as logind announces it, so WatchSleep's
// report to labd fails, after holding the suspend for 4s. So just before it
// suspends, the test tells labd how long the Mac may be off the network
// (quiet), and labd waits that long on this boot before it counts the Mac as
// lost; once the network is back, it tells labd so (quiet 0), and labd stops
// waiting. On an M1 Air the Mac is quiet for 10-15s (Wi-Fi is back a second
// after the resume); without the warning labd would wait out up to
// quietGrace (60s) from the last check-in.
func suspendDevices(ctx context.Context, t api.TestSpec, outDir, gui string, quiet Quieter) api.TestResult {
	res := api.TestResult{Name: t.Name}
	timeout := testTimeout(t)
	tidy, cancelTidy := context.WithTimeout(context.Background(), timeout)
	defer cancelTidy()
	ctx, cancel := context.WithTimeout(ctx, timeout-min(suspendTidyWait, timeout/2))
	defer cancel()
	logPath := filepath.Join(outDir, "log.txt")
	f, err := os.Create(logPath)
	if err != nil {
		res.Error, res.ExitCode = err.Error(), -1
		return res
	}
	logf := func(format string, a ...any) { fmt.Fprintf(f, format+"\n", a...) }
	start := time.Now()
	err = suspendCycle(ctx, tidy, gui, quiet, logf)
	switch {
	case errors.Is(err, errNoPMTest):
		logf("SKIP: %v", err)
		res.Skipped, res.Error, res.ExitCode = true, err.Error(), -1
	case err != nil:
		logf("FAIL: %v", err)
		res.ExitCode = 1
		// Only if time ran out before a verdict: a failure found in time stays
		// one, however long putting things back takes.
		if errors.Is(err, context.DeadlineExceeded) {
			res.TimedOut, res.ExitCode = true, -1
		}
	}
	f.Close()
	res.Passed = err == nil
	res.Seconds = time.Since(start).Seconds()
	res.Tail = tail(logPath, 40)
	return res
}

// suspendCycle runs the cycle within ctx, and puts things back within tidy.
func suspendCycle(ctx, tidy context.Context, gui string, quiet Quieter, logf func(string, ...any)) error {
	b, err := os.ReadFile(pmTestPath)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: no %s", errNoPMTest, pmTestPath)
	}
	if err != nil {
		return err
	}
	shown := strings.TrimSpace(string(b))
	modes, prev := parsePMTest(shown)
	if !slices.Contains(modes, "devices") {
		return fmt.Errorf("%w: %s offers %s", errNoPMTest, pmTestPath, shown)
	}
	route := defaultRoute(ctx)
	cycles, err := suspendLog(ctx)
	if err != nil {
		return fmt.Errorf("reading this boot's kernel log: %w", err)
	}
	logf("pm_test: %s; %d suspend cycles so far this boot; default route: %v", shown, len(cycles), route)
	told, tell := false, quiet // told: labd heard the Mac may go off the network
	if quiet != nil {
		tell = func(ctx context.Context, d time.Duration) error { told = true; return quiet(ctx, d) }
	}
	t0 := time.Now()
	err = pmTestDevices(ctx, tidy, gui, prev, len(cycles), tell, logf)
	if err == nil {
		logf("devices suspended and resumed in %.0fs", time.Since(t0).Seconds())
		err = routeBack(ctx, route, logf)
	}
	// Once the network is back, the spell off it labd was told of is over,
	// so that labd sees a hang in the next test at once, not once the spell
	// would have ended. Without the network, labd waits the spell out.
	if told && (err == nil || !route || defaultRoute(tidy)) {
		if qerr := quiet(tidy, 0); qerr != nil {
			logf("could not tell labd the Mac is back on the network: %v; it waits out the spell instead", qerr)
		} else {
			logf("told labd the Mac is back on the network")
		}
	}
	return err
}

// routeBack waits for the default route to come back after the resume, if
// there was one before the suspend.
func routeBack(ctx context.Context, route bool, logf func(string, ...any)) error {
	if !route {
		logf("no default route before suspending; not waiting for one")
		return nil
	}
	t1 := time.Now()
	for !defaultRoute(ctx) {
		switch {
		case ctx.Err() != nil:
			return fmt.Errorf("no default route after resuming before the test stopped (%w)", ctx.Err())
		case time.Since(t1) > suspendNetWait:
			return fmt.Errorf("no default route %s after resuming (it was up before suspending)", suspendNetWait)
		}
		sleepCtx(ctx, WallClock, suspendPoll)
	}
	logf("default route back %.0fs after resuming", time.Since(t1).Seconds())
	return nil
}

// parsePMTest lists pm_test's modes, and the one set, which the kernel shows
// in brackets: "[none] core processors platform devices freezer".
func parsePMTest(shown string) (modes []string, cur string) {
	cur = "none"
	for _, m := range strings.Fields(shown) {
		if t, ok := strings.CutPrefix(m, "["); ok {
			m = strings.TrimSuffix(t, "]")
			cur = m
		}
		modes = append(modes, m)
	}
	return modes, cur
}

// pmTestDevices suspends with pm_test=devices and judges the first cycle the
// kernel logs after the `before` it had logged already (devicesSuspended). A
// cycle that hasn't ended in time is cancelled. However it ends, pm_test goes
// back to prev, but not to none while anything is left that could suspend the
// Mac (restorePMTest): that would be a real suspend, and nothing but a key
// press wakes the Mac. The GUI user's desktop lock is stopped for the cycle
// (stopSleepLock) and started again after that. Putting things back runs
// within tidy, which outlasts ctx. Just before it suspends, it tells labd how
// long the Mac may be off the network: until the cycle, its settling and the
// network's return have had their time, or the test's time is up.
func pmTestDevices(ctx, tidy context.Context, gui, prev string, before int, quiet Quieter, logf func(string, ...any)) (err error) {
	locks, err := stopSleepLock(tidy, gui, logf)
	defer func() { err = joinErr(err, startSleepLock(tidy, gui, locks, logf)) }()
	if err != nil {
		return err
	}
	if err := os.WriteFile(pmTestPath, []byte("devices"), 0o644); err != nil {
		return fmt.Errorf("setting pm_test=devices: %w", err)
	}
	defer func() { err = joinErr(err, restorePMTest(tidy, prev, logf)) }()
	if quiet != nil {
		off := suspendResumeWait + suspendSettleWait + suspendNetWait
		if d, ok := tidy.Deadline(); ok {
			off = min(off, time.Until(d))
		}
		if err := quiet(ctx, off); err != nil {
			logf("could not tell labd the Mac may be off the network for %s: %v", off.Round(time.Second), err)
		} else {
			logf("told labd the Mac may be off the network for up to %s", off.Round(time.Second))
		}
	}
	start := time.Now()
	if out, err := suspendCmd(ctx, "systemctl", "suspend"); err != nil {
		return fmt.Errorf("systemctl suspend: %w: %s", err, strings.TrimSpace(out))
	}
	logf("systemctl suspend with pm_test=devices: the kernel resumes by itself after 5s")
	for {
		if cycles, err := suspendLog(ctx); err == nil && len(cycles) > before && cycleEnded(cycles[before]) {
			return devicesSuspended(cycles[before])
		}
		var why error
		switch {
		case time.Since(start) > suspendResumeWait:
			why = fmt.Errorf(`no suspend cycle ended ("PM: suspend exit") in the kernel log %s after systemctl suspend`, suspendResumeWait)
		case ctx.Err() != nil:
			why = fmt.Errorf("no suspend cycle ended before the test stopped (%w)", ctx.Err())
		default:
			sleepCtx(ctx, WallClock, suspendPoll)
			continue
		}
		jobs, cerr := cancelSleepJobs(tidy)
		switch {
		case cerr != nil:
			return fmt.Errorf("%w; cancelling the suspend failed: %v", why, cerr)
		case len(jobs) == 0:
			return fmt.Errorf("%w; no sleep job was left to cancel", why)
		}
		return fmt.Errorf("%w; cancelled sleep jobs %s", why, strings.Join(jobs, " "))
	}
}

// restorePMTest puts pm_test back to prev once nothing is left that could
// suspend the Mac, waiting up to suspendSettleWait for that, or until just
// before ctx's deadline, whichever comes first. If something still could and
// prev is none, pm_test stays at devices: a later suspend is then a test one
// too, until sysfs resets on the next boot. Every other mode stops short of
// sleeping too, so it goes back regardless. ctx is the test's tidy one: the
// cycle's may be over.
func restorePMTest(ctx context.Context, prev string, logf func(string, ...any)) error {
	ctx, cancel := context.WithTimeout(ctx, suspendSettleWait+30*time.Second)
	defer cancel()
	deadline, waited := time.Now().Add(suspendSettleWait), "after "+suspendSettleWait.String()
	// Stop two polls before ctx ends: the last look, which can come a poll
	// after the deadline, still needs time to ask.
	if d, ok := ctx.Deadline(); ok && d.Add(-2*suspendPoll).Before(deadline) {
		deadline, waited = d.Add(-2*suspendPoll), "as the test's time ran out"
	}
	for {
		pending, err := sleepPending(ctx)
		if err != nil {
			pending = err.Error()
		}
		if pending == "" {
			break
		}
		if !time.Now().Before(deadline) {
			if prev != "none" {
				logf("%s, %s; with pm_test=%s that suspend wouldn't be a real one either", waited, pending, prev)
				break
			}
			logf("left pm_test at devices: %s", pending)
			return fmt.Errorf("left pm_test at devices, so that a later suspend isn't a real one: %s, %s", waited, pending)
		}
		sleepCtx(ctx, WallClock, suspendPoll)
	}
	if err := os.WriteFile(pmTestPath, []byte(prev), 0o644); err != nil {
		return fmt.Errorf("restoring pm_test=%s: %w", prev, err)
	}
	logf("pm_test restored to %s", prev)
	return nil
}

// sleepPending says what could still suspend the Mac, or "" if nothing can:
// logind preparing a sleep, a sleep job, or a sleep unit not yet inactive.
// Cancelling a running systemd-suspend.service job doesn't stop systemd-sleep:
// the unit stays activating, and it suspends once its hooks are done.
func sleepPending(ctx context.Context) (string, error) {
	out, err := suspendCmd(ctx, "busctl", "get-property", "org.freedesktop.login1", "/org/freedesktop/login1",
		"org.freedesktop.login1.Manager", "PreparingForSleep")
	if err != nil {
		return "", fmt.Errorf("busctl get-property PreparingForSleep: %v: %s", err, strings.TrimSpace(out))
	}
	if strings.TrimSpace(out) != "b false" {
		return "logind is preparing for sleep", nil
	}
	jobs, err := sleepJobs(ctx)
	if err != nil {
		return "", err
	}
	if len(jobs) > 0 {
		return "sleep jobs " + strings.Join(jobs, " ") + " are queued", nil
	}
	// is-active exits non-zero when the units are inactive: read what it prints.
	out, _ = suspendCmd(ctx, "systemctl", append([]string{"is-active"}, sleepUnits...)...)
	states := strings.Fields(out)
	if len(states) != len(sleepUnits) {
		return "", fmt.Errorf("systemctl is-active %s: %q", strings.Join(sleepUnits, " "), strings.TrimSpace(out))
	}
	for i, s := range states {
		if s != "inactive" && s != "failed" {
			return sleepUnits[i] + " is " + s, nil
		}
	}
	return "", nil
}

// sleepJobs lists the ids of queued or running sleep jobs.
func sleepJobs(ctx context.Context) ([]string, error) {
	out, err := suspendCmd(ctx, "systemctl", "list-jobs", "--no-legend")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-jobs: %v: %s", err, strings.TrimSpace(out))
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && slices.Contains(sleepUnits, f[1]) {
			ids = append(ids, f[0])
		}
	}
	return ids, nil
}

// cancelSleepJobs cancels queued or running sleep jobs, and returns their
// ids. ctx is the test's tidy one: the cycle's may be over.
func cancelSleepJobs(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ids, err := sleepJobs(ctx)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	if out, err := suspendCmd(ctx, "systemctl", append([]string{"cancel"}, ids...)...); err != nil {
		return ids, fmt.Errorf("systemctl cancel %s: %v: %s", strings.Join(ids, " "), err, strings.TrimSpace(out))
	}
	return ids, nil
}

// stopSleepLock stops the GUI user's sleepLockUnits that are running, and
// returns them, so that the cycle leaves the desktop as it was for the GUI
// tests and screenshots after it, not locked and dark. Without a GUI user, or
// a service manager running for them, there is nothing to stop. If stopping
// fails, the units are returned anyway: starting a unit that still runs does
// nothing.
func stopSleepLock(ctx context.Context, gui string, logf func(string, ...any)) ([]string, error) {
	if gui == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := guiSystemctl(ctx, gui, append([]string{"is-active"}, sleepLockUnits...)...)
	states := strings.Fields(out)
	if len(states) != len(sleepLockUnits) {
		logf("no desktop of %s to keep unlocked: systemctl --user is-active: %v: %s", gui, err, strings.TrimSpace(out))
		return nil, nil
	}
	var units []string
	for i, s := range states {
		if s == "active" || s == "activating" || s == "reloading" {
			units = append(units, sleepLockUnits[i])
		}
	}
	if len(units) == 0 {
		return nil, nil
	}
	if out, err := guiSystemctl(ctx, gui, append([]string{"stop"}, units...)...); err != nil {
		return units, fmt.Errorf("stopping %s, which would lock %s's desktop: %v: %s", strings.Join(units, " "), gui, err, strings.TrimSpace(out))
	}
	logf("stopped %s, so that the suspend doesn't lock %s's desktop", strings.Join(units, " "), gui)
	return units, nil
}

// startSleepLock starts the units stopSleepLock returned. ctx is the test's
// tidy one: the cycle's may be over.
func startSleepLock(ctx context.Context, gui string, units []string, logf func(string, ...any)) error {
	if len(units) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := guiSystemctl(ctx, gui, append([]string{"start"}, units...)...); err != nil {
		return fmt.Errorf("starting %s: %v: %s", strings.Join(units, " "), err, strings.TrimSpace(out))
	}
	logf("started %s", strings.Join(units, " "))
	return nil
}

// guiSystemctl runs systemctl --user as the GUI user, against the service
// manager of their session.
func guiSystemctl(ctx context.Context, gui string, args ...string) (string, error) {
	u, err := lookupUser(gui)
	if err != nil {
		return "", err
	}
	return suspendCmd(ctx, "runuser", append([]string{"-u", u.Username, "--", "env", "XDG_RUNTIME_DIR=/run/user/" + u.Uid,
		"systemctl", "--user"}, args...)...)
}

// joinErr adds a clean-up's error to err, which stays the one errors.Is sees.
func joinErr(err, cerr error) error {
	switch {
	case cerr == nil:
		return err
	case err == nil:
		return cerr
	}
	return fmt.Errorf("%w; %v", err, cerr)
}

// suspendLog returns this boot's suspend cycles from its kernel log: the
// lines from each "PM: suspend entry" to its "PM: suspend exit", which the
// kernel logs however the cycle went.
func suspendLog(ctx context.Context) ([][]string, error) {
	out, err := suspendCmd(ctx, "journalctl", "-k", "-b", "0", "-o", "cat", "--no-pager")
	if err != nil {
		return nil, err
	}
	var cycles [][]string
	open := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(l, "PM: suspend entry"):
			cycles, open = append(cycles, []string{l}), true
		case open:
			cycles[len(cycles)-1] = append(cycles[len(cycles)-1], l)
			open = !strings.Contains(l, "PM: suspend exit")
		}
	}
	return cycles, nil
}

func cycleEnded(cycle []string) bool {
	return strings.Contains(cycle[len(cycle)-1], "PM: suspend exit")
}

// devicesSuspended judges a pm_test=devices cycle by its kernel log. The
// kernel logs "PM: suspend debug: Waiting for N second(s)" there only once
// the tasks are frozen and dpm_suspend_start (the devices' prepare and suspend
// callbacks) has succeeded; a cycle that ended without it stopped short. Lines
// saying a device failed to suspend or resume, or the freezer failed, say why.
func devicesSuspended(cycle []string) error {
	var bad []string
	reached := false
	for _, l := range cycle {
		switch {
		case strings.Contains(l, "PM: suspend debug: Waiting for"):
			reached = true
		case strings.Contains(l, "failed to suspend"), strings.Contains(l, "failed to resume"),
			strings.Contains(l, "Freezing ") && (strings.Contains(l, " failed after ") || strings.Contains(l, " aborted after ")):
			bad = append(bad, strings.TrimSpace(l))
		}
	}
	switch {
	case len(bad) > 0:
		return fmt.Errorf("the kernel logged: %s", strings.Join(bad, "; "))
	case !reached:
		return errors.New(`the suspend stopped before the devices' suspend phase was done (no "PM: suspend debug: Waiting" in its kernel log)`)
	}
	return nil
}

func defaultRoute(ctx context.Context) bool {
	out, err := suspendCmd(ctx, "ip", "route", "show", "default")
	return err == nil && strings.TrimSpace(out) != ""
}

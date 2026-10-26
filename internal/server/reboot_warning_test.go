package server

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// The reboot warning (#29): about 5 minutes before a job's first reboot, the
// Volunteer's desktop shows one notice, with a Pause button. These tests step
// the fake clock through the warning's wait (rwThroughTheWarning), in steps
// the Mac's check-ins keep up with (rwStep), stopping short of its end, and
// leave the clock at wall speed from there, so the Lab boot that follows gets
// its deadlines in wall time.

// rwWarning is the reboot warning labd is configured with (rwConfig).
const rwWarning = 5 * time.Minute

// rwStepSize is how far the tests move the clock in one step.
const rwStepSize = 500 * time.Millisecond

// rwStep moves the clock on by d (at most rwStepSize) once labd has heard from
// the Mac within the last rwStepSize of lab time, so no step leaves the Mac
// silent past aliveWindow or quietGrace. If the Mac stays silent for 5 s of
// wall time (rebooting, say), it steps anyway.
func (l *lab) rwStep(clock *agent.FakeClock, d time.Duration) {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if clock.Now().Sub(l.s.dev(l.name).snapshot().LastSeen) < rwStepSize {
			break
		}
	}
	clock.Advance(d)
}

// rwStepUntil steps the clock (rwStep), up to max, until cond holds, and
// reports how far it stepped. Only for stretches with no Lab boot in flight.
func (l *lab) rwStepUntil(clock *agent.FakeClock, max time.Duration, cond func() bool) (time.Duration, bool) {
	var e time.Duration
	for ; e < max; e += rwStepSize {
		if cond() {
			return e, true
		}
		l.rwStep(clock, rwStepSize)
	}
	return e, cond()
}

// rwWarnedAbout is whether the Mac's Audit log has the job's reboot warning
// line, which lab-agent writes as the warning's wait begins.
func (l *lab) rwWarnedAbout(id string) bool {
	return len(l.rwAuditWarningLinesFor(id)) > 0
}

// rwThroughTheWarning waits for the job's reboot warning to begin, then steps
// the clock (rwStep) to 3 seconds short of the warning's end, and leaves the
// rest to wall speed: a step never lands after the Mac arms the Lab boot, so
// no Lab boot deadline or quietGrace is jumped past.
func (l *lab) rwThroughTheWarning(clock *agent.FakeClock, id string) {
	l.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); !l.rwWarnedAbout(id); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			j, _ := l.jobNow(id)
			l.t.Fatalf("the Mac never began the reboot warning for job %s: %s %v", id, j.State, j.Events)
		}
	}
	end := clock.Now().Add(rwWarning - 3*time.Second)
	for d := end.Sub(clock.Now()); d > 0; d = end.Sub(clock.Now()) {
		l.rwStep(clock, min(d, rwStepSize))
	}
}

// rwWaitReboot waits up to d of wall time for the Mac to leave boot.
func (l *lab) rwWaitReboot(boot string, d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if l.rwRebooted(boot)() {
			return true
		}
	}
	return l.rwRebooted(boot)()
}

// rwLab is windowLab with labd's reboot warning on (c is rwConfig's). Like any
// job on a Volunteer's Mac, its baseline is warned, so the clock is stepped
// through that warning. With open, the Mac is then open to the lab for two
// hours, as windowEndLab leaves it. It returns how many notices the baseline
// left on the Mac's desktop: one, naming it.
func rwLab(t *testing.T, c labConfig, open bool) (*lab, *agent.FakeClock, int) {
	t.Helper()
	clock := agent.NewFakeClock(time.Now())
	c.clock, c.volunteer = clock, true
	l := newLabWith(t, c)
	t.Cleanup(pumpClock(clock))
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	l.addWindow(weekly(clock.Now().Add(5*24*time.Hour+12*time.Hour), time.Hour)) // parked, as windowLab's
	w := weekly(clock.Now().Add(-time.Minute), 6*time.Hour)
	l.addWindow(w)
	id := l.submitJob(api.JobSpec{Baseline: true})
	l.rwThroughTheWarning(clock, id)
	j := l.jobAPI(id, 60*time.Second)
	if j.Outcome != api.OutcomePass {
		t.Fatalf("baseline: %s: %s\n%v", j.Outcome, j.Summary, j.Events)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	ns := l.sim.Notices()
	if len(ns) != 1 || !strings.Contains(ns[0], id) {
		t.Fatalf("the baseline %s on a Volunteer's Mac should have shown one reboot warning naming it, got %q", id, ns)
	}
	l.removeWindow(w)
	if open {
		l.mustVolunteer("open", "--until", clock.Now().Add(2*time.Hour).Format("15:04"))
		time.Sleep(time.Second) // check-ins carry it to labd
	}
	return l, clock, len(ns)
}

// rwWaitNotices waits up to d of wall time for the Mac to have shown n notices.
func (l *lab) rwWaitNotices(n int, d time.Duration) []string {
	l.t.Helper()
	deadline := time.Now().Add(d)
	for {
		ns := l.sim.Notices()
		if len(ns) >= n {
			return ns
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("the Mac showed %d desktop notices, want %d: %q", len(ns), n, ns)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// rwRebooted is whether the Mac is on a boot other than boot.
func (l *lab) rwRebooted(boot string) func() bool {
	return func() bool { b, _, _ := l.sim.Identity(); return b != boot }
}

// rwKernelJob submits a kernel job and returns its ID.
func (l *lab) rwKernelJob(krel string) string {
	l.t.Helper()
	return l.submitJob(api.JobSpec{Kernel: l.artifact("krel=" + krel + " behavior=ok")})
}

// rwRunToTheEnd waits for the job to be staged, checks the Mac is holding off
// its first reboot, then steps the clock through the warning until the Mac
// reboots and returns the finished job.
func (l *lab) rwRunToTheEnd(clock *agent.FakeClock, id string) *api.Job {
	l.t.Helper()
	boot, _, _ := l.sim.Identity()
	deadline := time.Now().Add(30 * time.Second)
	for {
		j, _ := l.jobNow(id)
		if slices.ContainsFunc(j.Events, func(e api.JobEvent) bool { return strings.Contains(e.Msg, "staged") }) {
			break
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("job %s was never staged: %s %v", id, j.State, j.Events)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(time.Second)
	if l.rwRebooted(boot)() {
		l.t.Fatalf("the Mac rebooted for the job at once; it must wait about 5 minutes after the warning")
	}
	l.rwThroughTheWarning(clock, id)
	if !l.rwWaitReboot(boot, 30*time.Second) {
		l.t.Fatalf("the job's Mac never rebooted at the end of its warning")
	}
	return l.jobAPI(id, 60*time.Second)
}

// rwAuditWarningLines are the Audit log lines (from lab-agent log) about the
// reboot warning.
func (l *lab) rwAuditWarningLines() []string {
	var out []string
	for _, ln := range strings.Split(l.mustVolunteer("log"), "\n") {
		if strings.Contains(strings.ToLower(ln), "warning") {
			out = append(out, ln)
		}
	}
	return out
}

// rwAuditWarningLinesFor are the Audit log's reboot warning lines naming job id.
func (l *lab) rwAuditWarningLinesFor(id string) []string {
	var out []string
	for _, ln := range l.rwAuditWarningLines() {
		if strings.Contains(ln, id) {
			out = append(out, ln)
		}
	}
	return out
}

var rwNotShown = regexp.MustCompile(`(?i)not shown|no desktop session|n't (be )?shown|not be shown`)

func TestRebootWarningIsOneDesktopNoticeAboutFiveMinutesBeforeTheFirstReboot(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	boot, _, _ := l.sim.Identity()
	id := l.rwKernelJob("7.2-warned")
	l.rwWaitNotices(base+1, 30*time.Second)
	seen := clock.Now()
	if l.rwRebooted(boot)() {
		t.Fatalf("the Mac had already rebooted when the warning appeared")
	}
	l.rwThroughTheWarning(clock, id)
	if !l.rwWaitReboot(boot, 30*time.Second) {
		t.Fatalf("the Mac never rebooted for the job")
	}
	lead := clock.Now().Sub(seen)
	if lead < 4*time.Minute || lead > 6*time.Minute {
		t.Fatalf("the warning came %v before the first reboot, want about 5 minutes", lead)
	}
	if ns := l.sim.Notices(); len(ns) != base+1 {
		t.Fatalf("the job gave %d warnings, want 1: %q", len(ns)-base, ns[base:])
	}
}

func TestRebootWarningNamesTheJobAndWhenTheMacReboots(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	id := l.rwKernelJob("7.2-named")
	ns := l.rwWaitNotices(base+1, 30*time.Second)
	seen := clock.Now()
	text := ns[base]
	if !strings.Contains(text, id) {
		t.Fatalf("the warning does not name the job %s: %q", id, text)
	}
	var times []string
	for _, d := range []time.Duration{4 * time.Minute, 5 * time.Minute, 6 * time.Minute} {
		times = append(times, seen.Add(d).Format("15:04"))
	}
	found := false
	for _, tm := range times {
		found = found || strings.Contains(text, tm)
	}
	if !found {
		t.Fatalf("the warning does not say when the reboot is (one of %v, Mac local time): %q", times, text)
	}
}

func TestRebootWarningIsShownOnlyOnceTheJobHasStarted(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), false) // no window open
	id := l.rwKernelJob("7.2-queued")
	l.staysQueued(id, 2*time.Second, "the Volunteer has no window open")
	advance(clock, 30*time.Second)
	if ns := l.sim.Notices(); len(ns) != base {
		t.Fatalf("a job that has not started got a reboot warning: %q", ns[base:])
	}
}

func TestRebootWarningIsNotRepeatedForTheLaterRebootsOfTheSameJob(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	id := l.rwKernelJob("7.2-twice") // reboots into the kernel, then back to the Known-good kernel
	l.rwWaitNotices(base+1, 30*time.Second)
	l.expect(l.rwRunToTheEnd(clock, id), api.OutcomePass)
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	time.Sleep(2 * time.Second)
	if ns := l.sim.Notices(); len(ns) != base+1 {
		t.Fatalf("a job with two reboots gave %d warnings, want 1: %q", len(ns)-base, ns[base:])
	}
}

func TestRebootWarningIsNotRepeatedWhenTheJobsKernelPanicsAndTheMacRebootsAgain(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-panics behavior=panic")})
	l.rwWaitNotices(base+1, 30*time.Second)
	j := l.rwRunToTheEnd(clock, id)
	if j.Outcome == api.OutcomePass {
		t.Fatalf("a panicking kernel passed")
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	if ns := l.sim.Notices(); len(ns) != base+1 {
		t.Fatalf("a job whose Mac rebooted after a panic gave %d warnings, want 1: %q", len(ns)-base, ns[base:])
	}
}

func TestEachJobGetsItsOwnRebootWarning(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	first := l.rwKernelJob("7.2-first")
	l.rwWaitNotices(base+1, 30*time.Second)
	l.expect(l.rwRunToTheEnd(clock, first), api.OutcomePass)
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	second := l.rwKernelJob("7.2-second")
	ns := l.rwWaitNotices(base+2, 30*time.Second)
	if !strings.Contains(ns[base+1], second) || strings.Contains(ns[base+1], first) {
		t.Fatalf("the second warning is not about the second job %s: %q", second, ns[base+1])
	}
	l.expect(l.rwRunToTheEnd(clock, second), api.OutcomePass)
	if ns := l.sim.Notices(); len(ns) != base+2 {
		t.Fatalf("two jobs gave %d warnings, want 2: %q", len(ns)-base, ns[base:])
	}
}

// rwStopsBeforeTheReboot checks that, from the warning on, the Mac never
// reboots over ten minutes of lab time, and that the job ends incomplete with
// the Mac on its own system. The paused job arms no Lab boot, so stepping the
// clock jumps past no boot's deadline.
func (l *lab) rwStopsBeforeTheReboot(clock *agent.FakeClock, id, boot string) {
	l.t.Helper()
	if _, ok := l.rwStepUntil(clock, 10*time.Minute, l.rwRebooted(boot)); ok {
		l.t.Fatalf("the Mac rebooted into the Lab boot after the Volunteer paused")
	}
	j := l.jobAPI(id, 30*time.Second)
	l.expect(j, api.OutcomeIncomplete)
	if _, k, c := l.sim.Identity(); k != agent.SimKnownGood || agent.IsLabBoot(c) {
		l.t.Fatalf("the Mac is not on its own system after the pause: %s (%s)", k, c)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
	// A Pause closes the current window: the next job waits.
	next := l.rwKernelJob("7.2-after-pause")
	l.staysQueued(next, 2*time.Second, "the Volunteer paused")
}

func TestPauseFromTheRebootWarningStopsTheJobBeforeTheRebootIncomplete(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	boot, _, _ := l.sim.Identity()
	id := l.rwKernelJob("7.2-paused")
	l.rwWaitNotices(base+1, 30*time.Second)
	if err := l.sim.PressNoticePause(); err != nil {
		t.Fatalf("pressing Pause on the warning: %v", err)
	}
	l.rwStopsBeforeTheReboot(clock, id, boot)
}

func TestPauseCommandDuringTheRebootWarningWaitStopsTheJobBeforeTheRebootIncomplete(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	boot, _, _ := l.sim.Identity()
	id := l.rwKernelJob("7.2-pause-cmd")
	l.rwWaitNotices(base+1, 30*time.Second)
	l.mustVolunteer("pause")
	l.rwStopsBeforeTheReboot(clock, id, boot)
}

func TestPauseFromTheRebootWarningIsRecordedLikePause(t *testing.T) {
	l, _, base := rwLab(t, rwConfig(), true)
	l.rwKernelJob("7.2-paused-log")
	l.rwWaitNotices(base+1, 30*time.Second)
	if err := l.sim.PressNoticePause(); err != nil {
		t.Fatalf("pressing Pause on the warning: %v", err)
	}
	// The window is closed for the lab exactly as after `pause`: another Pause
	// has nothing left to end, or says so, but never reopens it.
	out := l.mustVolunteer("window", "show")
	if !strings.Contains(strings.ToLower(out), "pause") {
		t.Fatalf("window show does not show the Pause the warning's button made:\n%s", out)
	}
}

func TestNoRebootWarningOnALabOwnedMac(t *testing.T) {
	l := newLabWith(t, rwConfig())
	l.baseline()
	start := time.Now()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-lab-owned behavior=ok")})
	l.expect(j, api.OutcomePass)
	if d := time.Since(start); d > 2*time.Minute {
		t.Fatalf("a Lab-owned Mac's job took %v: it must not wait to reboot", d)
	}
	if ns := l.sim.Notices(); len(ns) != 0 {
		t.Fatalf("a Lab-owned Mac showed a desktop notice: %q", ns)
	}
}

func TestRebootWarningNotShownBecauseNoDesktopSessionStillLetsTheJobGoAheadInTheWindow(t *testing.T) {
	l, clock, base := rwLab(t, rwConfig(), true)
	l.sim.SetDesktopSession(false)
	id := l.rwKernelJob("7.2-greeter")
	j := l.rwRunToTheEnd(clock, id)
	l.expect(j, api.OutcomePass)
	if ns := l.sim.Notices(); len(ns) != base {
		t.Fatalf("a notice was shown with no desktop session: %q", ns[base:])
	}
}

// rwAuditHasOneLineFor checks the Audit log's reboot warning lines are the
// baseline's one and job id's one, and returns id's.
func (l *lab) rwAuditHasOneLineFor(id string) string {
	l.t.Helper()
	all, mine := l.rwAuditWarningLines(), l.rwAuditWarningLinesFor(id)
	if len(mine) != 1 || len(all) != 2 {
		l.t.Fatalf("the Audit log should have one reboot warning line for %s (and one for the baseline), got %q", id, all)
	}
	return mine[0]
}

func TestAuditLogRecordsThatTheRebootWarningWasNotShownWithNoDesktopSession(t *testing.T) {
	l, clock, _ := rwLab(t, rwConfig(), true)
	l.sim.SetDesktopSession(false)
	id := l.rwKernelJob("7.2-greeter-log")
	l.expect(l.rwRunToTheEnd(clock, id), api.OutcomePass)
	if ln := l.rwAuditHasOneLineFor(id); !rwNotShown.MatchString(ln) {
		t.Fatalf("the Audit log should say the warning for %s was not shown, got %q", id, ln)
	}
	l.rwLabdAuditCopyHas(id, true)
}

func TestAuditLogRecordsThatTheRebootWarningWasShown(t *testing.T) {
	l, clock, _ := rwLab(t, rwConfig(), true)
	id := l.rwKernelJob("7.2-shown-log")
	l.expect(l.rwRunToTheEnd(clock, id), api.OutcomePass)
	if ln := l.rwAuditHasOneLineFor(id); rwNotShown.MatchString(ln) || !strings.Contains(strings.ToLower(ln), "shown") {
		t.Fatalf("the Audit log should say the warning for %s was shown, got %q", id, ln)
	}
	l.rwLabdAuditCopyHas(id, false)
}

// rwLabdAuditCopyHas checks labd's copy of the Audit log has one entry for the
// job's warning, saying "not shown" or not.
func (l *lab) rwLabdAuditCopyHas(id string, notShown bool) {
	l.t.Helper()
	var body string
	var mine []api.AuditEntry
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		_, body = l.get("GET", "/api/devices/"+l.name+"/audit")
		var es []api.AuditEntry
		_ = json.Unmarshal([]byte(body), &es)
		mine = slices.DeleteFunc(es, func(e api.AuditEntry) bool {
			return !strings.Contains(strings.ToLower(e.Action), "warning") || !strings.Contains(e.Job+" "+e.Action, id)
		})
		if len(mine) > 0 {
			break
		}
	}
	if len(mine) != 1 || rwNotShown.MatchString(mine[0].Action) != notShown {
		l.t.Fatalf("labd's Audit log copy lacks the one warning record for %s (not shown = %v):\n%s", id, notShown, body)
	}
}

// rwConfig is a lab whose labd warns Volunteers 5 minutes before a job's
// first reboot (the production default; the harness default is no warning).
func rwConfig() labConfig {
	return labConfig{config: func(c *Config) { c.SetRebootWarning(rwWarning) }}
}

func TestNoRebootWarningNorWaitWhenLabdsRebootWarningIsZero(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{}) // RebootWarning zero
	start := time.Now()
	l.expect(l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-unwarned behavior=ok")}), api.OutcomePass)
	if d := time.Since(start); d > 2*time.Minute {
		t.Fatalf("the job waited %v with no reboot warning configured", d)
	}
	if ns := l.sim.Notices(); len(ns) != 0 {
		t.Fatalf("a notice was shown with RebootWarning zero: %q", ns)
	}
}

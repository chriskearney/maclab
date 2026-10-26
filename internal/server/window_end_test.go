package server

import (
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// The window's end in these tests comes by the clock: the Volunteer moves
// their Open now's end to the next minute while a job runs, then the clock
// gets there. labd only starts a job that fits in what's left of the window,
// and a job's own hard ceiling comes before that, so a schedule that simply
// runs out never ends inside a job in the harness.

// windowEndLab is windowLab with the Mac open to the lab for two hours from
// now, long enough for any job here to fit.
func windowEndLab(t *testing.T, c labConfig) (*lab, *agent.FakeClock) {
	t.Helper()
	l, clock, _ := windowLab(t, c)
	l.mustVolunteer("open", "--until", clock.Now().Add(2*time.Hour).Format("15:04"))
	time.Sleep(time.Second) // check-ins carry it to labd
	return l, clock
}

// endOpenNowSoon moves the Open now's end to the next whole minute at least
// 15 seconds away, as the Volunteer does on the Mac, and returns that end.
func (l *lab) endOpenNowSoon(clock *agent.FakeClock) time.Time {
	l.t.Helper()
	now := clock.Now()
	end := now.Truncate(time.Minute).Add(time.Minute)
	if end.Sub(now) < 15*time.Second {
		end = end.Add(time.Minute)
	}
	l.mustVolunteer("open", "--until", end.Format("15:04"))
	return end
}

// advanceTo steps the clock to t (a second at a time, as advance does);
// from there it runs at wall speed again, so a boot after t gets its time.
func advanceTo(clock *agent.FakeClock, t time.Time) {
	if d := t.Sub(clock.Now()); d > 0 {
		advance(clock, d)
	}
}

// longJob submits a kernel job whose test runs for a minute, and returns
// once the Mac is in the job's Lab boot running it.
func (l *lab) longJob(krel string) (id, kernel string) {
	l.t.Helper()
	l.sim.SetTestLength(time.Minute)
	kernel = l.artifact("krel=" + krel + " behavior=ok")
	id = l.submitJob(api.JobSpec{Kernel: kernel, Tests: []api.TestSpec{{Name: "long-work", Builtin: "x"}}})
	l.waitTesting(id, krel)
	return id, kernel
}

// waitTesting waits until the job is testing in its Lab boot of krel, and
// checks it is still testing a second later: a job here must hold the Mac.
func (l *lab) waitTesting(id, krel string) {
	l.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		j, _ := l.jobNow(id)
		_, k, _ := l.sim.Identity()
		if j.State == api.JobTesting && k == krel {
			break
		}
		if j.State == api.JobDone || time.Now().After(deadline) {
			l.t.Fatalf("job %s never got to its tests in a Lab boot of %s: %s %s %s", id, krel, j.State, j.Outcome, j.Summary)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(time.Second)
	if j, _ := l.jobNow(id); j.State != api.JobTesting {
		l.t.Fatalf("job %s's tests did not hold the Mac (the Sim's SetTestLength): %s %s %s", id, j.State, j.Outcome, j.Summary)
	}
}

// backOnItsOwnSystem waits up to d of wall time for the Mac to be up on its
// Known-good kernel on a boot other than lab, and fails the test otherwise.
func (l *lab) backOnItsOwnSystem(labBoot string, d time.Duration, why string) {
	l.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if b, k, c := l.sim.Identity(); b != labBoot && k == agent.SimKnownGood && !agent.IsLabBoot(c) && l.sim.Alive() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, k, c := l.sim.Identity()
	l.t.Fatalf("%s, yet %s after the Mac still runs %s (%s)", why, d, k, c)
}

// cutByTheWindowEnd runs a long kernel job and brings the clock to the end
// of the window, checking the job still held the Mac three seconds before.
func cutByTheWindowEnd(t *testing.T, c labConfig) (l *lab, clock *agent.FakeClock, id, kernel, labBoot string) {
	t.Helper()
	l, clock = windowEndLab(t, c)
	id, kernel = l.longJob("7.2-cut")
	labBoot, _, _ = l.sim.Identity()
	end := l.endOpenNowSoon(clock)
	advanceTo(clock, end.Add(-3*time.Second))
	if b, k, _ := l.sim.Identity(); b != labBoot || k != "7.2-cut" {
		t.Fatalf("the Lab boot ended before its window did: now %s on boot %s", k, b)
	}
	advanceTo(clock, end.Add(time.Second))
	return l, clock, id, kernel, labBoot
}

func TestWindowEndMidJobReturnsAKernelJobToTheKnownGoodKernel(t *testing.T) {
	l, _, id, _, labBoot := cutByTheWindowEnd(t, labConfig{})
	l.backOnItsOwnSystem(labBoot, 5*time.Second, "the window ended")
	j := l.jobAPI(id, 30*time.Second)
	if j.Outcome == api.OutcomePass {
		t.Fatalf("a job its window cut short passed: %v", j.Events)
	}
	l.waitDevice(func(d api.Device) bool {
		return d.State == api.StateReady && d.Kernel == agent.SimKnownGood && d.Health.JobTag == ""
	})
}

func TestJobTheWindowCutShortEndsIncompleteNotFailed(t *testing.T) {
	l, _, id, _, _ := cutByTheWindowEnd(t, labConfig{})
	l.expect(l.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady }) // not needs_hands: nothing failed
}

func TestJobTheWindowCutShortIsRetriedInALaterWindow(t *testing.T) {
	l, clock, id, kernel, _ := cutByTheWindowEnd(t, labConfig{})
	l.expect(l.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
	l.sim.SetTestLength(0)
	l.retryWaits(id, kernel, 2*time.Second, "the Mac's window has ended")
	l.mustVolunteer("open", "--until", clock.Now().Add(2*time.Hour).Format("15:04"))
	retry := l.retryOf(id, kernel, 60*time.Second)
	l.expect(retry, api.OutcomePass)
	if retry.Result.BootKernel != "7.2-cut" {
		t.Fatalf("the retry did not boot the job's kernel: %+v", retry.Result)
	}
}

// retryWaits checks for d of wall time that no other job of the kernel
// starts after job id.
func (l *lab) retryWaits(id, kernel string, d time.Duration, why string) {
	l.t.Helper()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, j := range l.jobsOf() {
			if j.ID != id && j.Spec.Kernel == kernel && j.State != api.JobQueued {
				l.t.Fatalf("%s, yet job %s retrying %s is %s", why, j.ID, id, j.State)
			}
		}
	}
}

// retryOf waits up to d for a job other than id, of the same kernel, to
// finish, and returns it.
func (l *lab) retryOf(id, kernel string, d time.Duration) *api.Job {
	l.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, j := range l.jobsOf() {
			if j.ID != id && j.Spec.Kernel == kernel && j.State == api.JobDone {
				return &j
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatalf("labd never retried job %s in the later window: jobs %v", id, jobIDs(l.jobsOf()))
	return nil
}

func TestWindowEndMidJobWithLabdUnreachableStillReturnsTheMacOnTime(t *testing.T) {
	sw := &labdSwitch{}
	l, clock := windowEndLab(t, labConfig{wrap: sw.wrap})
	id, _ := l.longJob("7.2-cut")
	labBoot, _, _ := l.sim.Identity()
	end := l.endOpenNowSoon(clock)
	advanceTo(clock, end.Add(-2*time.Second))
	sw.down.Store(true) // labd and the tailnet are gone for the window's end
	advanceTo(clock, end.Add(time.Second))
	l.backOnItsOwnSystem(labBoot, 5*time.Second, "the window ended, with labd out of reach")
	sw.down.Store(false)
	l.expect(l.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
}

func TestWindowEndWhileStagingLeavesTheMacOnItsOwnSystem(t *testing.T) {
	w := newWire(t)
	l, clock := windowEndLab(t, labConfig{wrap: w.wrap})
	sha := l.artifact("krel=7.2-staging behavior=ok")
	w.stall(sha)
	boot, _, _ := l.sim.Identity()
	id := l.submitJob(api.JobSpec{Kernel: sha})
	select {
	case <-w.hung:
	case <-time.After(20 * time.Second):
		t.Fatal("the Mac never started staging the job's kernel")
	}
	end := l.endOpenNowSoon(clock)
	advanceTo(clock, end.Add(time.Second))
	l.expect(l.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
	if b, k, _ := l.sim.Identity(); b != boot || k != agent.SimKnownGood {
		t.Fatalf("a job stopped while staging rebooted the Mac: now %s on boot %s", k, b)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Health.JobTag == "" })
}

func TestJobThatFinishedJustBeforeTheWindowEndIsLeftAlone(t *testing.T) {
	l, clock := windowEndLab(t, labConfig{})
	kernel := l.artifact("krel=7.2-early behavior=ok")
	id := l.submitJob(api.JobSpec{Kernel: kernel})
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
	boot, _, _ := l.sim.Identity()
	end := l.endOpenNowSoon(clock)
	advanceTo(clock, end.Add(time.Second))
	time.Sleep(2 * time.Second)
	if b, _, _ := l.sim.Identity(); b != boot {
		t.Fatal("the window's end rebooted a Mac no job held")
	}
	if j, _ := l.jobNow(id); j.Outcome != api.OutcomePass {
		t.Fatalf("the window's end changed a finished job to %s: %v", j.Outcome, j.Events)
	}
	l.retryWaits(id, kernel, time.Second, "the job passed before its window ended")
	for _, j := range l.jobsOf() {
		if j.ID != id && j.Spec.Kernel == kernel {
			t.Fatalf("labd retried a job that passed: %s %s", j.ID, j.State)
		}
	}
}

func TestPauseMidJobStopsItAsTheWindowEndWould(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	id, _ := l.longJob("7.2-paused")
	labBoot, _, _ := l.sim.Identity()
	l.mustVolunteer("pause")
	l.backOnItsOwnSystem(labBoot, 5*time.Second, "the Volunteer paused")
	l.expect(l.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
	l.waitDevice(func(d api.Device) bool {
		return d.State == api.StateReady && d.Kernel == agent.SimKnownGood && d.Health.JobTag == ""
	})
}

// A Lab boot that hasn't reached labd yet is stopped by a Pause too, well
// before its no-contact deadline would have rebooted it, and the job is
// incomplete rather than lost_contact.
func TestPauseDuringALabBootThatHasNotReachedLabdReturnsTheMacAtOnce(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-offline behavior=no-network")})
	labBoot := l.lostBoot("7.2-offline")
	l.mustVolunteer("pause")
	l.backOnItsOwnSystem(labBoot, 3*time.Second, "the Volunteer paused during the Lab boot (its no-contact deadline is 8s)")
	l.expect(l.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
}

// leaseNow is the Mac's lease as labd's API shows it.
func (l *lab) leaseNow() *api.Lease {
	l.t.Helper()
	var d api.Device
	if err := json.Unmarshal([]byte(l.deviceBody()), &d); err != nil {
		l.t.Fatal(err)
	}
	return d.Lease
}

func (l *lab) takeLease(holder string, ttl time.Duration) {
	l.t.Helper()
	if r, body := l.post("/api/devices/"+l.name+"/lease", api.LeaseRequest{Holder: holder, TTLSec: int(ttl / time.Second)}); r.StatusCode != 200 {
		l.t.Fatalf("lease: %s %s", r.Status, body)
	}
}

// leaseEndsBy waits up to five seconds for the Mac to hold no lease past t.
func (l *lab) leaseEndsBy(t time.Time, why string) {
	l.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ls := l.leaseNow()
		if ls == nil || !ls.Expires.After(t) {
			return
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("%s at %s, yet %s holds a lease until %s", why, t.Format(time.TimeOnly), ls.Holder, ls.Expires.Format(time.TimeOnly))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestLeaseOnAVolunteerMacEndsWithTheWindow(t *testing.T) {
	l, clock := windowEndLab(t, labConfig{})
	l.takeLease("connor (homework)", 3*time.Hour)
	end := l.endOpenNowSoon(clock)
	time.Sleep(time.Second) // check-ins carry the new end to labd
	if ls := l.leaseNow(); ls == nil || ls.Holder != "connor (homework)" || !ls.Expires.After(clock.Now()) {
		t.Fatalf("the lease ended before its window did: %+v", ls)
	}
	advanceTo(clock, end.Add(time.Second))
	l.leaseEndsBy(end, "the window ended")
}

func TestPauseEndsALeaseOnAVolunteerMac(t *testing.T) {
	l, clock := windowEndLab(t, labConfig{})
	l.takeLease("connor (homework)", 3*time.Hour)
	l.mustVolunteer("pause")
	paused := clock.Now()
	l.leaseEndsBy(paused.Add(5*time.Second), "the Volunteer paused")
}

func TestLeaseOnALabOwnedMacKeepsItsTimeToLive(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	l.takeLease("connor (homework)", time.Hour)
	time.Sleep(2 * time.Second)
	if ls := l.leaseNow(); ls == nil || time.Until(ls.Expires) < 50*time.Minute {
		t.Fatalf("a Lab-owned Mac's one-hour lease was cut: %+v", ls)
	}
}

func TestPauseDoesNothingToALabOwnedMacsJob(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	l.sim.SetTestLength(3 * time.Second)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-owned behavior=ok"), Tests: []api.TestSpec{{Name: "long-work", Builtin: "x"}}})
	l.waitTesting(id, "7.2-owned")
	l.volunteer("pause") // a Lab-owned Mac has no window to pause, whatever this answers
	j := l.jobAPI(id, 60*time.Second)
	l.expect(j, api.OutcomePass)
	if j.Result.BootKernel != "7.2-owned" {
		t.Fatalf("result: %+v", j.Result)
	}
}

// inhibitorsSeen records every inhibitor the Mac holds until stop.
func (l *lab) inhibitorsSeen() (stop func() []string) {
	var mu sync.Mutex
	var seen []string
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			for _, w := range l.sim.Inhibitors() {
				mu.Lock()
				if !slices.Contains(seen, w) {
					seen = append(seen, w)
				}
				mu.Unlock()
			}
			select {
			case <-quit:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	return func() []string { close(quit); <-done; mu.Lock(); defer mu.Unlock(); return seen }
}

func TestLabAgentInhibitsSuspendWhileAJobHoldsTheMacAndReleasesItAfter(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	if in := l.sim.Inhibitors(); slices.Contains(in, "sleep") {
		t.Fatalf("suspend is inhibited with no job: %q", in)
	}
	l.sim.SetTestLength(3 * time.Second)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-awake behavior=ok"), Tests: []api.TestSpec{{Name: "long-work", Builtin: "x"}}})
	l.waitTesting(id, "7.2-awake")
	if in := l.sim.Inhibitors(); !slices.Contains(in, "sleep") {
		t.Fatalf("the Mac may suspend in the middle of a job: inhibitors %q", in)
	}
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
	for deadline := time.Now().Add(5 * time.Second); slices.Contains(l.sim.Inhibitors(), "sleep"); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("suspend is still inhibited after the job ended: %q", l.sim.Inhibitors())
		}
	}
}

func TestLabAgentNeverTouchesTheIdleLockOrScreensaverDuringAJob(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	stop := l.inhibitorsSeen()
	l.sim.SetTestLength(2 * time.Second)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-locked behavior=ok"), Tests: []api.TestSpec{{Name: "long-work", Builtin: "x"}}})
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
	time.Sleep(time.Second)
	seen := stop()
	if !slices.Contains(seen, "sleep") {
		t.Fatalf("the job never held the Mac awake: inhibitors seen %q", seen)
	}
	if slices.Contains(seen, "idle") {
		t.Fatalf("lab-agent inhibited the idle lock and screensaver: inhibitors seen %q", seen)
	}
}

// Nothing wakes a sleeping Mac: a window that opens and closes while it
// sleeps is missed, and its queued job waits for the next one.
func TestWindowTheMacSleepsThroughIsMissed(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	l.addWindow(weekly(clock.Now().Add(10*time.Minute), 2*time.Hour))
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-asleep behavior=ok")})
	l.staysQueued(id, time.Second, "the window opens in ten minutes")
	boot, _, _ := l.sim.Identity()
	l.sim.Sleep()
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 14; i++ { // the whole window passes
		clock.Advance(10 * time.Minute)
		time.Sleep(100 * time.Millisecond)
	}
	if l.sim.Alive() {
		t.Fatal("something woke the sleeping Mac")
	}
	if b, _, _ := l.sim.Identity(); b != boot {
		t.Fatal("something rebooted the sleeping Mac")
	}
	if j, _ := l.jobNow(id); j.State != api.JobQueued {
		t.Fatalf("a job ran on a sleeping Mac: %s %s %v", j.State, j.Outcome, j.Events)
	}
	l.sim.Wake()
	l.staysQueued(id, 2*time.Second, "the window the Mac slept through has ended")
}

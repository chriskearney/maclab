package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// weekly is the `window add` arguments for a window that starts at start
// (to the minute, in the Mac's local time) and lasts d (under a day), on
// start's weekday: "mon", "19:00-23:00".
func weekly(start time.Time, d time.Duration) []string {
	start = start.Truncate(time.Minute)
	return []string{strings.ToLower(start.Format("Mon")), start.Format("15:04") + "-" + start.Add(d).Format("15:04")}
}

// daily is weekly for every day of the week.
func daily(start time.Time, d time.Duration) []string {
	w := weekly(start, d)
	return []string{"mon-sun", w[1]}
}

func (l *lab) mustVolunteer(args ...string) string {
	l.t.Helper()
	out, err := l.volunteer(args...)
	if err != nil {
		l.t.Fatalf("lab-agent %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// deviceBody is the Mac as labd's API shows a Maintainer.
func (l *lab) deviceBody() string {
	l.t.Helper()
	r, body := l.get("GET", "/api/devices/"+l.name)
	if r.StatusCode != 200 {
		l.t.Fatalf("device %s: %s %s", l.name, r.Status, body)
	}
	return body
}

// waitSynced waits until labd's copy of the Mac's windows has (or lacks) the
// window w, as the Mac's check-ins carry it.
func (l *lab) waitSynced(w []string, has bool) {
	l.t.Helper()
	text := strings.Join(w, " ")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(l.deviceBody(), text) == has {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	l.t.Fatalf("labd's device never came to show window %q = %v:\n%s", text, has, l.deviceBody())
}

// addWindow adds a weekly window on the Mac and waits for labd to know it.
func (l *lab) addWindow(w []string) {
	l.t.Helper()
	l.mustVolunteer(append([]string{"window", "add"}, w...)...)
	l.waitSynced(w, true)
}

func (l *lab) removeWindow(w []string) {
	l.t.Helper()
	l.mustVolunteer(append([]string{"window", "remove"}, w...)...)
	l.waitSynced(w, false)
}

// windowLab is a Volunteer lab on a fake clock that runs at wall speed. Its
// Mac is baselined inside a window that is then removed. It keeps one weekly
// window, parked: it opens five and a half days on, later than any test
// moves the clock, so whether a Mac with no window at all is open doesn't
// matter to the tests that use it.
func windowLab(t *testing.T, c labConfig) (l *lab, clock *agent.FakeClock, parked []string) {
	t.Helper()
	// Keep schedule tests away from DST transitions; DST itself is covered in internal/window.
	clock = agent.NewFakeClock(time.Date(2026, time.October, 19, 12, 0, 0, 0, time.Local))
	c.clock, c.volunteer = clock, true
	l = newLabWith(t, c)
	t.Cleanup(pumpClock(clock))
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	parked = weekly(clock.Now().Add(5*24*time.Hour+12*time.Hour), time.Hour)
	l.addWindow(parked)
	w := weekly(clock.Now().Add(-time.Minute), 6*time.Hour)
	l.addWindow(w)
	l.baseline()
	l.removeWindow(w)
	return l, clock, parked
}

// jobNow is a job as labd's API shows it now.
func (l *lab) jobNow(id string) (api.Job, string) {
	l.t.Helper()
	r, body := l.get("GET", "/api/jobs/"+id)
	var j api.Job
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil {
		l.t.Fatalf("job %s: %s %s", id, r.Status, body)
	}
	return j, body
}

// staysQueued checks for d of wall time that the job hasn't started and the
// Mac hasn't rebooted.
func (l *lab) staysQueued(id string, d time.Duration, why string) {
	l.t.Helper()
	boot, _, _ := l.sim.Identity()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if j, _ := l.jobNow(id); j.State != api.JobQueued {
			l.t.Fatalf("%s, yet the job is %s (%s): %v", why, j.State, j.Outcome, j.Events)
		}
		if b, _, _ := l.sim.Identity(); b != boot {
			l.t.Fatalf("%s, yet the Mac rebooted", why)
		}
	}
}

func TestJobWaitsForTheAvailabilityWindowThenStartsInsideIt(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	l.addWindow(weekly(clock.Now().Add(2*time.Hour), 6*time.Hour))
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "the window opens in two hours")
	clock.Advance(2*time.Hour + time.Minute)
	j := l.jobAPI(id, 60*time.Second)
	l.expect(j, api.OutcomePass)
	if j.Result.BootKernel != "7.2-ok" {
		t.Fatalf("the job inside the window did not boot its kernel: %+v", j.Result)
	}
}

func TestVolunteerMacWithNoWindowRunsNothing(t *testing.T) {
	l, clock, parked := windowLab(t, labConfig{})
	l.removeWindow(parked)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "the Mac has no window")
	clock.Advance(24 * time.Hour)
	l.staysQueued(id, 2*time.Second, "a day later the Mac still has no window")
}

func TestJobThatWouldNotFitInWhatIsLeftOfTheWindowWaitsForOneItFits(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	now := clock.Now()
	l.addWindow(weekly(now.Add(-time.Minute), 3*time.Minute)) // a minute or two left
	l.addWindow(weekly(now.Add(time.Hour), 6*time.Hour))
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok"), BootTimeoutSec: 1800})
	l.staysQueued(id, 2*time.Second, "a job with a 30-minute boot timeout can't fit in the two minutes left of the window")
	clock.Advance(time.Hour + time.Minute)
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
}

func TestJobDoesNotStartOnBattery(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	l.addWindow(weekly(clock.Now().Add(-time.Minute), 6*time.Hour))
	l.sim.SetOnBattery(true)
	time.Sleep(time.Second) // check-ins carry it to labd
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "the Mac is on battery")
	l.sim.SetOnBattery(false)
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
}

func TestPauseEndsOnlyTheCurrentWindow(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	now := clock.Now()
	l.addWindow(weekly(now.Add(-time.Minute), 6*time.Hour))
	l.addWindow(weekly(now.Add(8*time.Hour), 4*time.Hour))
	l.mustVolunteer("pause")
	time.Sleep(time.Second) // check-ins carry it to labd
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "the Volunteer paused the window")
	clock.Advance(8*time.Hour + time.Minute)
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
}

func TestPauseUntilADateSkipsTheWindowsBeforeIt(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	now := clock.Now()
	l.addWindow(daily(now.Add(time.Hour), 4*time.Hour))
	l.mustVolunteer("pause", "--until", now.AddDate(0, 0, 3).Format("2006-01-02"))
	time.Sleep(time.Second) // check-ins carry it to labd
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "the Mac is paused for three days")
	clock.Advance(25*time.Hour + time.Minute) // inside tomorrow's window
	l.staysQueued(id, 2*time.Second, "tomorrow is before the Pause's date")
	clock.Advance(3 * 24 * time.Hour) // inside the window the day after that date
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
}

func TestOpenUntilLendsTheMacOutsideItsSchedule(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "the Mac's window opens in days")
	l.mustVolunteer("open", "--until", clock.Now().Add(3*time.Hour).Format("15:04"))
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
}

func TestOpenNowEndsAtItsUntilTime(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	l.mustVolunteer("open", "--until", clock.Now().Add(30*time.Minute).Format("15:04"))
	time.Sleep(time.Second) // check-ins carry it to labd
	clock.Advance(31 * time.Minute)
	time.Sleep(time.Second)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "the open-now window has ended")
}

// labdSwitch takes labd off the network for the Mac (every /api/agent/
// request fails) while Maintainers still reach it.
type labdSwitch struct{ down atomic.Bool }

func (s *labdSwitch) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.down.Load() && strings.HasPrefix(r.URL.Path, "/api/agent/") {
			http.Error(w, "labd is down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func TestWindowCommandsWorkWithLabdDownAndSyncWhenItIsBack(t *testing.T) {
	sw := &labdSwitch{}
	l, clock, _ := windowLab(t, labConfig{wrap: sw.wrap})
	sw.down.Store(true)
	time.Sleep(500 * time.Millisecond) // check-ins in flight
	w := weekly(clock.Now().Add(2*time.Hour), 2*time.Hour)
	for _, args := range [][]string{
		append([]string{"window", "add"}, w...),
		{"window", "show"},
		{"open", "--until", clock.Now().Add(time.Hour).Format("15:04")},
		{"pause"},
		{"pause", "--until", clock.Now().AddDate(0, 0, 1).Format("2006-01-02")},
	} {
		if out, err := l.volunteer(args...); err != nil {
			t.Fatalf("lab-agent %s with labd down: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	if out := l.mustVolunteer("window", "show"); !strings.Contains(out, strings.Join(w, " ")) {
		t.Fatalf("window add with labd down did not change the Mac's schedule at once:\n%s", out)
	}
	if strings.Contains(l.deviceBody(), strings.Join(w, " ")) {
		t.Fatal("labd knew of the window while it was down")
	}
	sw.down.Store(false)
	l.waitSynced(w, true)
}

func TestCheckinsSyncTheWindowsToLabd(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	a := weekly(clock.Now().Add(2*time.Hour), 2*time.Hour)
	b := []string{"sat-sun", "09:00-17:00"}
	l.addWindow(a)
	l.addWindow(b)
	l.removeWindow(a)
	if !strings.Contains(l.deviceBody(), strings.Join(b, " ")) {
		t.Fatalf("removing one window lost the other on labd:\n%s", l.deviceBody())
	}
}

func TestLabdHasNoAPIToWriteTheWindows(t *testing.T) {
	l, _, _ := windowLab(t, labConfig{})
	always := "mon-sun 00:00-23:59"
	settings := map[string]any{"rules": []string{always}, "windows": []string{always}, "open_until": time.Now().Add(24 * time.Hour)}
	l.as(harnessToken, "PATCH", "/api/devices/"+l.name, map[string]any{
		"availability": settings, "windows": []string{always}, "window": settings, "open_until": time.Now().Add(24 * time.Hour), "paused_until": nil,
	})
	for _, p := range []string{"window", "windows", "availability", "pause", "open", "settings"} {
		for _, m := range []string{"POST", "PUT", "PATCH"} {
			r, body := l.as(harnessToken, m, "/api/devices/"+l.name+"/"+p, settings)
			if r.StatusCode != http.StatusNotFound && r.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s /api/devices/%s/%s: %s %s", m, l.name, p, r.Status, body)
			}
		}
	}
	time.Sleep(time.Second)
	if strings.Contains(l.deviceBody(), always) {
		t.Fatalf("a Maintainer wrote a window on labd:\n%s", l.deviceBody())
	}
	if out := l.mustVolunteer("window", "show"); strings.Contains(out, always) {
		t.Fatalf("a Maintainer wrote a window on the Mac:\n%s", out)
	}
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.staysQueued(id, 2*time.Second, "only the Volunteer can open the Mac")
}

// commandHold holds back the first check-in answer that carries a stage
// command, until the test lets it go: labd's word on the way to the Mac
// while the Volunteer changes their mind.
type commandHold struct {
	armed   atomic.Bool
	once    sync.Once
	held    chan struct{}
	release chan struct{}
}

func newCommandHold() *commandHold {
	return &commandHold{held: make(chan struct{}), release: make(chan struct{})}
}

func (h *commandHold) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.armed.Load() || r.URL.Path != "/api/agent/checkin" {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		if bytes.Contains(body, []byte(fmt.Sprintf(`"kind":%q`, api.CmdStage))) && h.armed.CompareAndSwap(true, false) {
			h.once.Do(func() { close(h.held) })
			select {
			case <-h.release:
			case <-time.After(20 * time.Second):
			}
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(body)
	})
}

func TestLabAgentRefusesALabCommandOutsideTheWindowAndRecordsIt(t *testing.T) {
	h := newCommandHold()
	l, clock, _ := windowLab(t, labConfig{wrap: h.wrap})
	l.addWindow(weekly(clock.Now().Add(-time.Minute), 6*time.Hour))
	h.armed.Store(true)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-refused behavior=ok")})
	select {
	case <-h.held:
	case <-time.After(20 * time.Second):
		t.Fatal("labd never sent the Mac a stage command inside its window")
	}
	// labd decided while the window was open; the Volunteer pauses before
	// its command reaches the Mac.
	l.mustVolunteer("pause")
	close(h.release)

	recorded := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, k, _ := l.sim.Identity(); k == "7.2-refused" {
			t.Fatal("the Mac booted a lab kernel after the Volunteer paused")
		}
		j, body := l.jobNow(id)
		if j.Outcome == api.OutcomePass {
			t.Fatalf("a job refused by the Mac passed: %v", j.Events)
		}
		if strings.Contains(strings.ToLower(body), "refus") {
			recorded = true
			break
		}
	}
	if !recorded {
		j, _ := l.jobNow(id)
		t.Fatalf("the Mac's refusal is not recorded on the job: %s %s %v", j.State, j.Summary, j.Events)
	}
}

func TestOMTEveryRefreshesOnlyInsideAWindow(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{config: func(c *Config) { c.OMT, c.OMTEvery = true, 30*time.Minute }})
	l.addWindow(weekly(clock.Now().Add(3*time.Hour), 6*time.Hour))
	boot, _, _ := l.sim.Identity()
	before := jobIDs(l.jobsOf())
	for i := 0; i < 15; i++ { // 2.5 hours, ticking labd's scheduler on the way
		clock.Advance(10 * time.Minute)
		time.Sleep(100 * time.Millisecond)
		if b, _, _ := l.sim.Identity(); b != boot {
			t.Fatal("an omarchy-m-test refresh rebooted the Mac outside its window")
		}
		for _, j := range l.jobsOf() {
			if !before[j.ID] && j.State != api.JobQueued {
				t.Fatalf("an omarchy-m-test refresh started outside the window: %s %s %v", j.ID, j.State, j.Events)
			}
		}
	}
	// Step to just inside the window, then let the clock run at wall speed: a
	// refresh that starts must stage, reboot and check in within the boot
	// timeout, which further jumps would overrun.
	clock.Advance(20 * time.Minute)
	time.Sleep(100 * time.Millisecond)
	clock.Advance(10*time.Minute + 2*time.Second)
	defer pumpClock(clock)()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for _, j := range l.jobsOf() {
			if !before[j.ID] && j.Spec.Holder == "maclab-omt" && j.State == api.JobDone {
				l.expect(&j, api.OutcomePass)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no omarchy-m-test refresh ran inside the window")
}

// jobsOf lists the Mac's jobs through labd's API.
func (l *lab) jobsOf() []api.Job {
	l.t.Helper()
	r, body := l.get("GET", "/api/jobs?limit=200&device="+l.name)
	var js []api.Job
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &js) != nil {
		l.t.Fatalf("jobs: %s %s", r.Status, body)
	}
	return js
}

func jobIDs(js []api.Job) map[string]bool {
	ids := map[string]bool{}
	for _, j := range js {
		ids[j.ID] = true
	}
	return ids
}

// notYetAVolunteerCommand is what lab-agent answers `open` with before #26
// adds it; openForTheLab tolerates it so the tests that use it keep passing
// until then.
const notYetAVolunteerCommand = `"open" is not a Volunteer command`

// openForTheLab opens the Volunteer's Mac for half a day from now (in the
// Mac's local time), as a Volunteer does for their first baseline.
func (l *lab) openForTheLab(now time.Time) {
	l.t.Helper()
	out, err := l.volunteer("open", "--until", now.Add(12*time.Hour).Format("15:04"))
	if err != nil && err.Error() != notYetAVolunteerCommand {
		l.t.Fatalf("lab-agent open: %v\n%s", err, out)
	}
}

func TestBaselineWaitsForAWindowOnAVolunteerMacWithNone(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	id := l.submitJob(api.JobSpec{Baseline: true})
	l.staysQueued(id, 2*time.Second, "the Volunteer has set no window")
	l.mustVolunteer("open", "--until", time.Now().Add(12*time.Hour).Format("15:04"))
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
}

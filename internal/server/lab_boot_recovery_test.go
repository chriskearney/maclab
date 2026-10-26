package server

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// submitJob submits a job for the lab's Mac through labd's API.
func (l *lab) submitJob(spec api.JobSpec) string {
	l.t.Helper()
	spec.Device = l.name
	r, body := l.post("/api/jobs", spec)
	var j api.Job
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil || j.ID == "" {
		l.t.Fatalf("submit: %s %s", r.Status, body)
	}
	return j.ID
}

// jobAPI waits up to d for a job to finish and returns it as labd's API shows it.
func (l *lab) jobAPI(id string, d time.Duration) *api.Job {
	l.t.Helper()
	l.wait(id, d)
	r, body := l.get("GET", "/api/jobs/"+id)
	var j api.Job
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil {
		l.t.Fatalf("job %s: %s %s", id, r.Status, body)
	}
	return &j
}

// lostBoot waits for the Mac to be up on a kernel and returns that boot's ID.
func (l *lab) lostBoot(kernel string) string {
	l.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if id, k, _ := l.sim.Identity(); k == kernel {
			return id
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.t.Fatalf("the Mac never booted %s", kernel)
	return ""
}

// journalOf is the job's attached journal file that names a boot, or "".
func (l *lab) journalOf(j *api.Job, boot string) string {
	l.t.Helper()
	for _, f := range j.Result.Logs {
		if !strings.Contains(f, "journal") {
			continue
		}
		if r, body := l.get("GET", "/api/jobs/"+j.ID+"/files/"+(&url.URL{Path: f}).EscapedPath()); r.StatusCode == 200 && strings.Contains(body, boot) {
			return f
		}
	}
	return ""
}

// bootIDs records every boot ID the Mac goes through until stop.
func (l *lab) bootIDs() (stop func() []string) {
	var mu sync.Mutex
	var ids []string
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			id, _, _ := l.sim.Identity()
			mu.Lock()
			if len(ids) == 0 || ids[len(ids)-1] != id {
				ids = append(ids, id)
			}
			mu.Unlock()
			select {
			case <-quit:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	return func() []string { close(quit); <-done; mu.Lock(); defer mu.Unlock(); return ids }
}

// lostContactLab is a lab on a fake clock that runs at wall speed; tests jump
// it past a deadline.
func lostContactLab(t *testing.T, c labConfig) (*lab, *agent.FakeClock) {
	t.Helper()
	clock := agent.NewFakeClock(time.Now())
	c.clock = clock
	l := newLabWith(t, c)
	t.Cleanup(pumpClock(clock))
	if c.volunteer {
		l.openForTheLab(clock.Now())
	}
	l.baseline()
	return l, clock
}

// The harness scenario of #30: a Sim kernel that loses the network after
// boot is rebooted by its deadline, and the job fails lost_contact with the
// lost boot's journal attached.
func TestLabBootThatLosesTheNetworkIsRebootedByItsDeadline(t *testing.T) {
	l, clock := lostContactLab(t, labConfig{volunteer: true})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-offline behavior=no-network")})
	lost := l.lostBoot("7.2-offline")
	clock.Advance(2 * 4 * time.Second) // past the no-contact deadline: 2x labd's 4s boot timeout
	j := l.jobAPI(id, 60*time.Second)
	l.expect(j, api.OutcomeLostContact)
	if f := l.journalOf(j, lost); f == "" {
		t.Fatalf("no journal of the lost boot %s attached: %v", lost, j.Result.Logs)
	}
	l.waitDevice(func(d api.Device) bool {
		return d.State == api.StateReady && d.Kernel == agent.SimKnownGood && d.BootID != lost
	})
}

func TestLostContactIsAFailure(t *testing.T) {
	l, clock := lostContactLab(t, labConfig{volunteer: true})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-offline behavior=no-network")})
	l.lostBoot("7.2-offline")
	clock.Advance(2 * 4 * time.Second)
	j := l.jobAPI(id, 60*time.Second)
	l.expect(j, api.OutcomeLostContact)
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		var failed bool
		for _, n := range l.notes {
			failed = failed || strings.Contains(n.Title, id) && strings.Contains(n.Title, api.OutcomeLostContact)
		}
		l.mu.Unlock()
		if failed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no failed-job notice for %s: %+v", id, l.notes)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestLabOwnedMacComesBackThroughItsDeadlineBeforeAnOOBHardReset(t *testing.T) {
	l, clock := lostContactLab(t, labConfig{oob: true})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-offline behavior=no-network")})
	l.lostBoot("7.2-offline")
	clock.Advance(2 * 4 * time.Second)
	j := l.jobAPI(id, 60*time.Second)
	l.expect(j, api.OutcomeLostContact)
	l.oob.mu.Lock()
	resets := l.oob.resets
	l.oob.mu.Unlock()
	if resets != 0 {
		t.Fatalf("%d OOB hard resets before the deadline brought the Mac back; recovery %v", resets, j.Result.Recovery)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
}

func TestPanickedLabBootsJournalComesBackByBootID(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.openForTheLab(time.Now())
	l.baseline()
	ids := l.bootIDs()
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-bad behavior=panic")})
	j := l.jobAPI(id, 60*time.Second)
	boots := ids()
	if j.Outcome == api.OutcomePass || j.Outcome == api.OutcomeLostContact {
		t.Fatalf("a boot that came back through panic=10: outcome %s", j.Outcome)
	}
	if len(boots) < 3 {
		t.Fatalf("boots %v: want the one before, the lost one and the one after", boots)
	}
	lost := boots[1]
	if f := l.journalOf(j, lost); f == "" {
		t.Fatalf("no journal of the panicked boot %s attached: %v", lost, j.Result.Logs)
	}
}

func TestLabBootCmdlineCarriesPanicAndWatchdogTimeouts(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.openForTheLab(time.Now())
	l.baseline()
	j := l.jobAPI(l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")}), 60*time.Second)
	l.expect(j, api.OutcomePass)
	fields := strings.Fields(j.Result.BootCmdline)
	var panic10, wdt bool
	for _, f := range fields {
		panic10 = panic10 || f == "panic=10"
		wdt = wdt || strings.HasPrefix(f, "watchdog.open_timeout=") && f != "watchdog.open_timeout=0"
	}
	if !panic10 || !wdt {
		t.Fatalf("Lab boot cmdline %q lacks panic=10 or watchdog.open_timeout=N", j.Result.BootCmdline)
	}
}

// A Sim kernel artifact marked apple_wdt=n was built without apple_wdt.
func TestJobFlagsATestKernelBuiltWithoutAppleWDT(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.openForTheLab(time.Now())
	l.baseline()
	flagged := func(j *api.Job) bool {
		if strings.Contains(j.Summary, "apple_wdt") {
			return true
		}
		for _, e := range j.Events {
			if strings.Contains(e.Msg, "apple_wdt") {
				return true
			}
		}
		return false
	}
	with := l.jobAPI(l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-wdt behavior=ok")}), 60*time.Second)
	if flagged(with) {
		t.Fatalf("a kernel with apple_wdt was flagged: %s %v", with.Summary, with.Events)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	without := l.jobAPI(l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-nowdt behavior=ok apple_wdt=n")}), 60*time.Second)
	if !flagged(without) {
		t.Fatalf("a kernel without apple_wdt was not flagged: %s %v", without.Summary, without.Events)
	}
}

// withoutLabBootAdditions drops what #30 adds to a Lab boot's command line
// (watchdog.open_timeout=N and the Lab boot marker), so tests that pin the rest
// hold before and after it.
func withoutLabBootAdditions(cmdline string) string {
	var keep []string
	for _, f := range strings.Fields(cmdline) {
		v, wdt := strings.CutPrefix(f, "watchdog.open_timeout=")
		if wdt && v != "" && strings.Trim(v, "0123456789") == "" || agent.IsLabBoot(f) && !strings.HasPrefix(f, "maclab.job=") {
			continue
		}
		keep = append(keep, f)
	}
	return strings.Join(keep, " ")
}

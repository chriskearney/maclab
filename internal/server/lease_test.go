package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// submitAs queues a job on the lab's Mac with the token of a Maintainer and
// returns labd's answer.
func (l *lab) submitAs(token string, spec api.JobSpec) (int, string, string) {
	l.t.Helper()
	spec.Device = l.name
	r, body := l.as(token, "POST", "/api/jobs", spec)
	var j api.Job
	json.Unmarshal([]byte(body), &j)
	return r.StatusCode, j.ID, body
}

// A lease holds back the jobs someone else queued before it: they wait
// aside, the lease holder's own jobs queued after them run first, and they
// run once the lease is released.
func TestALeaseSetsAsideJobsQueuedBeforeIt(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	joshua := l.addMaintainer(harnessToken, "joshua")
	l.sim.SetTestLength(3 * time.Second)
	long := []api.TestSpec{{Name: "long-work", Builtin: "x"}}

	busy := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-busy behavior=ok"), Tests: long, Holder: "ada@laptop"})
	l.waitTesting(busy, "7.2-busy")
	code, theirs, body := l.submitAs(joshua.Token, api.JobSpec{Kernel: l.artifact("krel=7.2-theirs behavior=ok"), Tests: long, Holder: "joshua@mini"})
	if code != 200 {
		t.Fatalf("joshua's job before the lease: %d %s", code, body)
	}
	if r, body := l.post("/api/devices/"+l.name+"/lease", api.LeaseRequest{Holder: "ada@laptop", TTLSec: 3600}); r.StatusCode != 200 {
		t.Fatalf("lease: %s %s", r.Status, body)
	}
	if code, _, body := l.submitAs(joshua.Token, api.JobSpec{Kernel: l.artifact("krel=7.2-late behavior=ok"), Holder: "joshua@mini"}); code != http.StatusConflict || !strings.Contains(body, "leased by ada@laptop") {
		t.Fatalf("joshua's job during the lease: %d %s", code, body)
	}
	mine := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-mine behavior=ok"), Holder: "ada@laptop"})

	l.expect(l.jobAPI(busy, 60*time.Second), api.OutcomePass)
	l.expect(l.jobAPI(mine, 60*time.Second), api.OutcomePass)
	j, _ := l.jobNow(theirs)
	if j.State != api.JobQueued {
		t.Fatalf("joshua's job queued before the lease ran during it: %s %s %s", j.State, j.Outcome, j.Summary)
	}
	if !hasEvent(&j, "leased by ada@laptop") || !hasEvent(&j, "waiting for the lease to end") {
		t.Fatalf("joshua's job doesn't say the lease holds it back: %v", j.Events)
	}
	if q := l.s.dev(l.name).snapshot(); q.Lease == nil || q.Lease.Maintainer != harnessMaintainer {
		t.Fatalf("the lease doesn't record whose token took it: %+v", q.Lease)
	}
	l.staysQueued(theirs, 2*time.Second, "the lease still holds the Mac")

	if r, body := l.get("DELETE", "/api/devices/"+l.name+"/lease?holder=ada@laptop"); r.StatusCode != 200 {
		t.Fatalf("release: %s %s", r.Status, body)
	}
	j2 := l.jobAPI(theirs, 60*time.Second)
	l.expect(j2, api.OutcomePass)
	if j2.Result.BootKernel != "7.2-theirs" {
		t.Fatalf("joshua's job after the lease: %+v", j2.Result)
	}
}

// A job set aside by a lease runs once the lease runs out, too.
func TestAJobSetAsideRunsWhenTheLeaseRunsOut(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	joshua := l.addMaintainer(harnessToken, "joshua")
	l.sim.SetTestLength(3 * time.Second)
	busy := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-busy behavior=ok"), Tests: []api.TestSpec{{Name: "long-work", Builtin: "x"}}, Holder: "ada@laptop"})
	l.waitTesting(busy, "7.2-busy")
	code, theirs, body := l.submitAs(joshua.Token, api.JobSpec{Kernel: l.artifact("krel=7.2-theirs behavior=ok"), Holder: "joshua@mini"})
	if code != 200 {
		t.Fatalf("joshua's job: %d %s", code, body)
	}
	if r, body := l.post("/api/devices/"+l.name+"/lease", api.LeaseRequest{Holder: "ada@laptop", TTLSec: 8}); r.StatusCode != 200 {
		t.Fatalf("lease: %s %s", r.Status, body)
	}
	l.expect(l.jobAPI(busy, 60*time.Second), api.OutcomePass)
	l.expect(l.jobAPI(theirs, 60*time.Second), api.OutcomePass)
	j, _ := l.jobNow(theirs)
	if !hasEvent(&j, "waiting for the lease to end") {
		t.Fatalf("joshua's job ran without waiting for the lease: %v", j.Events)
	}
}

// Only the Maintainer whose token took a lease renews it, releases it or
// runs jobs under it: naming its holder isn't enough.
func TestOnlyTheMaintainerWhoTookALeaseUsesIt(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	joshua := l.addMaintainer(harnessToken, "joshua")
	path := "/api/devices/" + l.name + "/lease"
	if r, body := l.post(path, api.LeaseRequest{Holder: "ada@laptop", TTLSec: 3600}); r.StatusCode != 200 {
		t.Fatalf("lease: %s %s", r.Status, body)
	}
	if r, body := l.as(joshua.Token, "POST", path, api.LeaseRequest{Holder: "ada@laptop", TTLSec: 3600}); r.StatusCode != http.StatusConflict || !strings.Contains(body, "Maintainer ada") {
		t.Fatalf("joshua renewing ada's lease by its holder: %s %s", r.Status, body)
	}
	if code, _, body := l.submitAs(joshua.Token, api.JobSpec{Kernel: l.artifact("krel=7.2-x behavior=ok"), Holder: "ada@laptop"}); code != http.StatusConflict {
		t.Fatalf("joshua's job under ada's holder: %d %s", code, body)
	}
	for _, q := range []string{"", "?holder=ada@laptop"} {
		if r, body := l.as(joshua.Token, "DELETE", path+q, nil); r.StatusCode != http.StatusConflict || !strings.Contains(body, "only ada can release it") {
			t.Fatalf("joshua releasing ada's lease (%q): %s %s", q, r.Status, body)
		}
	}
	if r, body := l.as(joshua.Token, "POST", "/api/devices/"+l.name+"/reset?by=ada@laptop", nil); r.StatusCode != http.StatusConflict {
		t.Fatalf("joshua resetting ada's leased Mac by its holder: %s %s", r.Status, body)
	}
	if l.s.dev(l.name).snapshot().Lease == nil {
		t.Fatal("a refused release ended the lease")
	}
	if r, body := l.get("DELETE", path); r.StatusCode != 200 {
		t.Fatalf("ada releasing the lease: %s %s", r.Status, body)
	}
	if r, body := l.as(joshua.Token, "POST", path, api.LeaseRequest{Holder: "joshua@mini", TTLSec: 60}); r.StatusCode != 200 {
		t.Fatalf("joshua leasing it once released: %s %s", r.Status, body)
	}
}

func hasEvent(j *api.Job, want string) bool {
	for _, e := range j.Events {
		if strings.Contains(e.Msg, want) {
			return true
		}
	}
	return false
}

// unpark runs on deviceLoop, the queue's only reader, so it must never wait
// for room in the queue: with the queue full it puts back what fits and keeps
// the rest parked, in order, for the next pass.
func TestUnparkNeverBlocksOnAFullQueue(t *testing.T) {
	v := newDev(&Server{}, api.Device{Name: "m"}, "")
	v.queue = make(chan string, 2)
	v.queue <- "already-queued"
	v.parked = []parkedJob{{"a", "joshua@mini", "joshua"}, {"b", "joshua@mini", "joshua"}, {"c", "joshua@mini", "joshua"}}

	done := make(chan struct{})
	go func() { v.unpark(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("unpark blocked on a full queue")
	}
	if got := []string{<-v.queue, <-v.queue}; got[0] != "already-queued" || got[1] != "a" {
		t.Fatalf("queue after the first pass: %v", got)
	}
	if len(v.parked) != 2 || v.parked[0].id != "b" || v.parked[1].id != "c" {
		t.Fatalf("what didn't fit should stay parked in order: %+v", v.parked)
	}

	v.unpark()
	if got := []string{<-v.queue, <-v.queue}; got[0] != "b" || got[1] != "c" || len(v.parked) != 0 {
		t.Fatalf("the next pass should queue the rest in order: %v, parked %+v", got, v.parked)
	}
}

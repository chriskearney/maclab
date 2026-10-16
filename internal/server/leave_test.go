package server

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

func (l *lab) adminBody(method, path string) (int, string) {
	l.t.Helper()
	resp, body := l.get(method, path)
	return resp.StatusCode, body
}

// lab forget refuses to end someone's lease, which would also cut their lab
// shell, and to drop a Mac whose agent still checks in; --force does both.
func TestForgetRefusesLeaseAndLiveAgent(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return !d.LastSeen.IsZero() })

	if code, body := l.adminBody("DELETE", "/api/devices/"+l.name); code != http.StatusConflict ||
		!strings.Contains(body, "checked in") || !strings.Contains(body, "sudo lab-agent uninstall") || !strings.Contains(body, "--force") {
		t.Fatalf("forgetting a Mac whose agent checks in: %d %s", code, body)
	}
	if resp, body := l.post("/api/devices/"+l.name+"/lease", api.LeaseRequest{Holder: "alice", TTLSec: 600}); resp.StatusCode != 200 {
		t.Fatalf("lease: %d %s", resp.StatusCode, body)
	}
	if code, body := l.adminBody("DELETE", "/api/devices/"+l.name); code != http.StatusConflict ||
		!strings.Contains(body, "leased by alice") || !strings.Contains(body, "lab release "+l.name+" --holder alice") {
		t.Fatalf("forgetting a leased Mac: %d %s", code, body)
	}
	if l.s.dev(l.name) == nil || l.s.dev(l.name).snapshot().Lease == nil {
		t.Fatal("a refused forget dropped the lease")
	}
	// The lease holder's own lease is no reason to refuse; the live agent still is.
	if code, body := l.adminBody("DELETE", "/api/devices/"+l.name+"?holder=alice"); code != http.StatusConflict || !strings.Contains(body, "checked in") {
		t.Fatalf("the lease holder forgetting it: %d %s", code, body)
	}
	if code, body := l.adminBody("DELETE", "/api/devices/"+l.name+"?force=1"); code != http.StatusOK {
		t.Fatalf("forget --force: %d %s", code, body)
	}
	// Again: no such device, which lab forget reads as done already.
	if code, _ := l.adminBody("DELETE", "/api/devices/"+l.name+"?force=1"); code != http.StatusNotFound {
		t.Fatalf("forgetting it again: %d", code)
	}
}

// lab-agent uninstall --force mid-job tells labd the Mac is leaving: labd
// cancels its running and queued jobs, saying why, and neither resets the
// Mac nor asks for hands once the agent goes quiet. The Mac then stays out of
// the pool until lab forget, which needs no --force for it.
func TestLeaveMidJob(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	l.mu.Lock()
	notes := len(l.notes)
	l.mu.Unlock()

	// The Mac goes quiet during the test, as it does once uninstall stops the agent.
	l.sim.SuspendFor = 20 * time.Second
	running, _, err := l.s.Submit(api.JobSpec{Device: l.name, Kernel: l.artifact("krel=7.2-leave behavior=ok"),
		Tests: []api.TestSpec{{Name: "quiet-suspend-uninstall", Builtin: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	queued, _, err := l.s.Submit(api.JobSpec{Device: l.name})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for !slices.ContainsFunc(l.job(running.ID).Events, func(e api.JobEvent) bool { return e.Msg == "test quiet-suspend-uninstall: running" }) {
		if time.Now().After(deadline) {
			t.Fatalf("the test never started: %v", l.job(running.ID).Events)
		}
		time.Sleep(20 * time.Millisecond)
	}

	resp, err := agent.Leave(&agent.Config{Server: l.url, Secret: l.secret},
		api.LeaveRequest{Reason: "lab-agent uninstall --force with " + running.ID + " in flight", Jobs: []string{running.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Name != l.name || !slices.Contains(resp.Canceled, running.ID) || !slices.Contains(resp.Canceled, queued.ID) {
		t.Fatalf("leave: %+v", resp)
	}
	j := l.wait(running.ID, 10*time.Second)
	if j.Outcome != api.OutcomeCanceled || !strings.Contains(j.Summary, l.name+" left the lab (lab-agent uninstall --force with "+running.ID+" in flight)") ||
		!strings.Contains(j.Summary, "not restored") {
		t.Fatalf("running job: %s: %s", j.Outcome, j.Summary)
	}
	q := l.wait(queued.ID, 10*time.Second)
	if q.Outcome != api.OutcomeCanceled || !q.Canceled || !strings.Contains(q.Summary, "left the lab") {
		t.Fatalf("queued job: %s: %s", q.Outcome, q.Summary)
	}
	d := l.s.dev(l.name).snapshot()
	if d.State != api.StateLeft || !strings.Contains(d.StateReason, "lab forget "+l.name) {
		t.Fatalf("device %s: %s", d.State, d.StateReason)
	}

	// Nothing recovers it on its own: not the job, nor the recovery ladder.
	steps, ok := l.s.dev(l.name).ladder(context.Background(), "lost during a test", time.Second, true)
	if ok || len(steps) != 1 || !strings.HasPrefix(steps[0], "not recovered: "+l.name+" left the lab") {
		t.Fatalf("ladder: %v %v", ok, steps)
	}
	time.Sleep(quietGrace + time.Second) // past the quiet spell that read as a lost Mac
	l.oob.mu.Lock()
	resets := l.oob.resets
	l.oob.mu.Unlock()
	l.mu.Lock()
	newNotes := l.notes[notes:]
	l.mu.Unlock()
	if resets != 0 || len(newNotes) != 0 {
		t.Fatalf("%d out-of-band resets, notifications %+v", resets, newNotes)
	}
	if d := l.s.dev(l.name).snapshot(); d.State != api.StateLeft {
		t.Fatalf("back in the pool: %s %s", d.State, d.StateReason)
	}
	if _, code, err := l.s.Submit(api.JobSpec{Device: l.name}); code != http.StatusConflict || !strings.Contains(err.Error(), "lab forget") {
		t.Fatalf("a job for a Mac that left: %d %v", code, err)
	}

	// Its agent may still check in until uninstall stops it: forget needs no --force.
	if code, body := l.adminBody("DELETE", "/api/devices/"+l.name); code != http.StatusOK {
		t.Fatalf("forget: %d %s", code, body)
	}
}

func (l *lab) job(id string) *api.Job {
	l.t.Helper()
	j, err := l.s.store.job(id)
	if err != nil {
		l.t.Fatal(err)
	}
	return j
}

// leaveAgent tells labd, as the simulated Mac's lab-agent uninstall does,
// that it is leaving, or with undo that it stays after all.
func (l *lab) leaveAgent(undo bool) *api.LeaveResponse {
	l.t.Helper()
	resp, err := agent.Leave(&agent.Config{Server: l.url, Secret: l.secret}, api.LeaveRequest{Reason: "lab-agent uninstall", Undo: undo})
	if err != nil {
		l.t.Fatal(err)
	}
	return resp
}

// An uninstall that stops before it stops the agent takes its leave back:
// the Mac is back in the pool, as it was, and runs jobs again.
func TestLeaveUndo(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	l.leaveAgent(false)
	if d := l.s.dev(l.name).snapshot(); d.State != api.StateLeft || !strings.Contains(d.StateReason, "`lab reset "+l.name+"` puts it back") {
		t.Fatalf("after the leave: %s %s", d.State, d.StateReason)
	}
	if resp := l.leaveAgent(true); !resp.Back || resp.Name != l.name {
		t.Fatalf("undo: %+v", resp)
	}
	if d := l.s.dev(l.name).snapshot(); d.State != api.StateReady || d.StateReason != "" {
		t.Fatalf("after the undo: %s %s", d.State, d.StateReason)
	}
	l.expect(l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-back behavior=ok")}), api.OutcomePass)
	// again, on a Mac in the lab: nothing to undo
	if resp := l.leaveAgent(true); !resp.Back {
		t.Fatalf("undo again: %+v", resp)
	}
	if d := l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady }); d.State != api.StateReady {
		t.Fatalf("after another undo: %s", d.State)
	}
}

// An admin's lab reset recovers a Mac that left the lab and then wedged (mid
// uninstall, say): it puts it back in the lab and runs the recovery ladder,
// out-of-band reset included. Only automatic recovery leaves it alone.
func TestResetLeftMac(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	l.leaveAgent(false)
	// It wedges: no check-ins.
	go l.sim.Quiet(time.Minute)
	l.waitDevice(func(d api.Device) bool { return time.Since(d.LastSeen) > 2*aliveWindow })
	boot := l.s.dev(l.name).snapshot().BootID

	resp, body := l.get("POST", "/api/devices/"+l.name+"/reset?by=alice")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "had left the lab") || !strings.Contains(body, "recovery started") {
		t.Fatalf("reset: %d %s", resp.StatusCode, body)
	}
	d := l.waitDevice(func(d api.Device) bool { return d.BootID != boot && d.State == api.StateReady })
	l.oob.mu.Lock()
	resets := l.oob.resets
	l.oob.mu.Unlock()
	if resets != 1 {
		t.Fatalf("%d out-of-band resets, want 1; device %s %s", resets, d.State, d.StateReason)
	}
	l.expect(l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-back behavior=ok")}), api.OutcomePass)
}

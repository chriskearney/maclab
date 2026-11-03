package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// A Lab boot whose last re-arm, after labd's ack, fails never happens: the
// agent cancels the one-shot and stays up. That is the lab's failure, not the
// test kernel's, which never ran (specs/labboot: bug-f20641b-never-left-is-hung).
func TestRearmFailingAfterTheAckIsAnInfraError(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	// Arm 1 is boot_once's, 2 the re-arm before its report, 3 the one before the reboot.
	l.sim.FailArm(func(n int) (bool, error) {
		if n == 3 {
			return false, errors.New("boot partition lock: held for a minute")
		}
		return false, nil
	})
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-never behavior=ok")})
	l.expect(j, api.OutcomeInfra)
	if !strings.Contains(j.Summary, "never rebooted") {
		t.Fatalf("summary: %s", j.Summary)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
}

// A first arm that fails after writing the one-shot cancels it, as a failed
// re-arm does, and labd, told the arm failed, restores the Mac without
// waiting for a reboot that isn't coming: nothing reboots it into the test
// kernel (specs/labboot: bug-693811d-first-arm-no-cancel).
func TestFirstArmFailingAfterItsWriteLeavesNothingArmed(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	before, _, _ := l.sim.Identity()
	l.sim.FailArm(func(n int) (bool, error) {
		if n == 1 {
			return true, errors.New(`one-shot readback: got "", want the lab entry`)
		}
		return false, nil
	})
	start := time.Now()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-unarmed behavior=ok")})
	l.expect(j, api.OutcomeInfra)
	if a := l.sim.Armed(); a != "" {
		t.Fatalf("the one-shot is still armed: %s", a)
	}
	if after, k, _ := l.sim.Identity(); after != before {
		t.Fatalf("the Mac rebooted (into %s) after an arm that failed", k)
	}
	// labd's boot timeout here is 4s: waiting for a reboot would take 12s.
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the job took %s: labd waited for a reboot after the arm failed", d.Round(time.Second))
	}
}

// A reboot that fails after a good re-arm leaves the Mac up as a failed
// re-arm does, with the one-shot cancelled: the lab's failure.
func TestRebootFailingAfterTheAckIsAnInfraError(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	l.sim.FailReboots(1)
	boots := l.bootIDs()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-panics behavior=panic")})
	l.expect(j, api.OutcomeInfra)
	if !strings.Contains(j.Summary, "never rebooted") {
		t.Fatalf("summary: %s", j.Summary)
	}
	// The ladder's soft reboot is the only one, to the known-good kernel: a
	// one-shot left armed would have booted the test kernel first.
	if ids := boots(); len(ids) != 2 {
		t.Fatalf("the Mac went through %d boots, want the one it was on and one more: %v", len(ids), ids)
	}
}

// If the one-shot can't be cancelled either, the ladder's reboot runs the
// test kernel after all: its panic is its own, not the lab's.
func TestTestKernelTheLadderBootsAfterAFailedRebootIsJudged(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	l.sim.FailReboots(1)
	l.sim.FailCancels(1)
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-panics behavior=panic")})
	l.expect(j, api.OutcomePanicked)
}

// Snapshot syncs stop just before the last re-arm, so none can drop the
// lab's block from limine.conf between it and the firmware reading it; they
// start again only if the reboot doesn't happen (specs/labboot:
// bug-dd4cd55-no-quiesce).
func TestSnapshotSyncsStopBeforeTheLastRearm(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	before := len(l.sim.BootOps())
	l.expect(l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")}), api.OutcomePass)
	ops := strings.Join(l.sim.BootOps()[before:], " ")
	if !strings.HasPrefix(ops, "arm arm quiesce arm reboot") || strings.Contains(ops, "resume") {
		t.Fatalf("boot-menu operations: %s", ops)
	}

	l.sim.FailReboots(1)
	before = len(l.sim.BootOps())
	l.expect(l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok2 behavior=ok")}), api.OutcomeInfra)
	if ops := strings.Join(l.sim.BootOps()[before:], " "); !strings.HasPrefix(ops, "arm arm quiesce arm reboot cancel resume") {
		t.Fatalf("boot-menu operations after a failed reboot: %s", ops)
	}
}

// labd answers a result for a command it gave up waiting for as forgotten,
// and only those: a report retried after its answer was lost is not.
func TestReportAnswersCommandsLabdGaveUpOn(t *testing.T) {
	l := newLab(t, false)
	v := l.s.dev(l.name)
	v.forget("c-gave-up")
	got, _ := v.report(api.Report{Results: []api.CommandResult{{ID: "c-gave-up", OK: true}, {ID: "c-unknown", OK: true}}})
	if len(got) != 1 || got[0] != "c-gave-up" {
		t.Fatalf("forgotten %v, want [c-gave-up]", got)
	}
}

// labd answers which results it wants, so the agent reboots only for those: a
// command labd lost track of (it restarted, or forgot it long ago) is not one.
func TestReportListsWantedResults(t *testing.T) {
	l := newLab(t, false)
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.inflight["c-wanted"] = l.s.now()
	v.mu.Unlock()
	v.forget("c-gave-up")
	rep := api.Report{Results: []api.CommandResult{{ID: "c-wanted", OK: true}, {ID: "c-gave-up", OK: true}, {ID: "c-unknown", OK: true}}}
	forgotten, wanted := v.report(rep)
	if len(wanted) != 1 || wanted[0] != "c-wanted" {
		t.Fatalf("wanted %v, want [c-wanted]", wanted)
	}
	if len(forgotten) != 1 || forgotten[0] != "c-gave-up" {
		t.Fatalf("forgotten %v, want [c-gave-up]", forgotten)
	}
	// The same report again, its first reply lost: labd has the result, so it
	// still wants it, and still after its waiter took it.
	if _, wanted = v.report(api.Report{Results: rep.Results[:1]}); len(wanted) != 1 {
		t.Fatalf("a result labd has is not wanted on a resend: %v", wanted)
	}
	v.mu.Lock()
	_, took := v.takeResultLocked("c-wanted")
	v.mu.Unlock()
	if !took {
		t.Fatal("the result was not there to take")
	}
	if _, wanted = v.report(api.Report{Results: rep.Results[:1]}); len(wanted) != 1 {
		t.Fatalf("a result labd took is not wanted on a resend: %v", wanted)
	}
	// Until labd gives up on it.
	v.forget("c-wanted")
	if forgotten, wanted = v.report(api.Report{Results: rep.Results[:1]}); len(wanted) != 0 || len(forgotten) != 1 {
		t.Fatalf("after forget: wanted %v, forgotten %v", wanted, forgotten)
	}
}

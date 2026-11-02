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
// test kernel's, which never ran (specs/labboot: open-rearm-fails-after-ack).
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
// kernel (specs/labboot: open-arm-fails-after-write).
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

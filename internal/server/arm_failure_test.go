package server

import (
	"errors"
	"strings"
	"testing"

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

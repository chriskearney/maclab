package server

import (
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
)

// labd waits for a Lab boot that never reached it until lab-agent's
// no-contact deadline has rebooted it, on a clock that may run behind, and
// then a boot timeout more for the known-good boot: for any boot timeout,
// not just labd's default (specs/labboot: bug-1b269f5-wait-twice-boot).
func TestNoContactWaitCoversTheAgentsDeadline(t *testing.T) {
	for b := time.Minute; b <= 12*time.Minute; b += 30 * time.Second {
		r := &jobRun{s: &Server{cfg: Config{LabClockSkew: agent.NoContactMargin}}, boot: b}
		if got, need := r.noContactWait(), agent.NoContactDeadline(b)+agent.NoContactMargin; got < need {
			t.Errorf("boot timeout %s: labd waits %s past it, but the deadline and its margin take %s", b, got, need)
		}
	}
}

// A Lab boot labd lost during its test, on a Mac with no hard reset, gets
// until lab-agent's watchdog has reset it and a boot timeout more before a
// person is asked to power cycle it (specs/labboot:
// bug-10f4ab6-hands-before-watchdog): from its last sign of labd, or the end
// of a long test's budget, whichever is later.
func TestLostLabBootWithNoHardResetGetsItsWatchdog(t *testing.T) {
	boot, quiet := 6*time.Minute, 3*time.Minute // labd's defaults
	lastSeen := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	lost := lastSeen.Add(quiet) // callNote gives up on a silent Mac
	timeout := max(boot-quiet, time.Minute)
	for _, testEnd := range []time.Time{{}, lastSeen.Add(30 * time.Minute)} {
		reset := lastSeen.Add(agent.LostLabdReset)
		if testEnd.After(reset) {
			reset = testEnd
		}
		self := lostSelfRecovery(false, false, lastSeen, testEnd, lost, boot, timeout, agent.LostLabdReset)
		if waited, need := lost.Add(timeout+self), reset.Add(boot); waited.Before(need) {
			t.Errorf("test ending %v: labd gives up %s after the last check-in; the watchdog and the known-good boot take %s",
				testEnd, waited.Sub(lastSeen), need.Sub(lastSeen))
		}
	}
	if self := lostSelfRecovery(true, false, lastSeen, time.Time{}, lost, boot, timeout, agent.LostLabdReset); self != 0 {
		t.Errorf("with a hard reset labd waits %s more; want none", self)
	}
	if self := lostSelfRecovery(false, true, lastSeen, time.Time{}, lost, boot, timeout, agent.LostLabdReset); self != 0 {
		t.Errorf("for a Mac labd still hears, it waits %s more; want none", self)
	}
}

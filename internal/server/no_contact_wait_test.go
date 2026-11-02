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
		r := &jobRun{boot: b}
		if got, need := r.noContactWait(), agent.NoContactDeadline(b)+labClockSkew; got < need {
			t.Errorf("boot timeout %s: labd waits %s past it, but the deadline and its margin take %s", b, got, need)
		}
	}
}

// A Lab boot labd lost during its test, on a Mac with no hard reset, gets
// until lab-agent's watchdog has reset it and a boot timeout more before a
// person is asked to power cycle it (specs/labboot: bug-10f4ab6-hands-before-watchdog).
func TestLostLabBootWithNoHardResetGetsItsWatchdog(t *testing.T) {
	boot, quiet := 6*time.Minute, 3*time.Minute // labd's defaults
	lastSeen := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	lost := lastSeen.Add(quiet) // callNote gives up on a silent Mac
	timeout := max(boot-quiet, time.Minute)
	self := lostSelfRecovery(false, lastSeen, lost, boot, timeout)
	if waited, need := lost.Add(timeout+self), lastSeen.Add(agent.LostLabdReset+boot); waited.Before(need) {
		t.Errorf("labd gives up at %s after the last check-in; the watchdog and the known-good boot take %s",
			waited.Sub(lastSeen), need.Sub(lastSeen))
	}
	if self := lostSelfRecovery(true, lastSeen, lost, boot, timeout); self != 0 {
		t.Errorf("with a hard reset labd waits %s more; want none", self)
	}
}

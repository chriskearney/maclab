package server

import (
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
)

// labd waits for a Lab boot that never reached it until lab-agent's
// no-contact deadline has rebooted it, on a clock that may run behind, and
// then a boot timeout more for the known-good boot: for any boot timeout,
// not just labd's default (specs/labboot: open-short-boot-timeout).
func TestNoContactWaitCoversTheAgentsDeadline(t *testing.T) {
	for b := time.Minute; b <= 12*time.Minute; b += 30 * time.Second {
		r := &jobRun{boot: b}
		if got, need := r.noContactWait(), agent.NoContactDeadline(b)+labClockSkew; got < need {
			t.Errorf("boot timeout %s: labd waits %s past it, but the deadline and its margin take %s", b, got, need)
		}
	}
}

package server

import (
	"fmt"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// parkedJob is a queued job someone else's lease holds back: who it is for,
// so labd can tell when the lease no longer holds it.
type parkedJob struct {
	id, holder, maintainer string
}

// leaseHoldsBackLocked says why the Mac's lease keeps a job of holder's,
// submitted by maintainer, from running now, or "" when it doesn't: no lease
// is live, or the job is its holder's own. Caller holds v.mu.
func (v *dev) leaseHoldsBackLocked(holder, maintainer string) string {
	l := v.d.Lease
	if l == nil || !v.s.now().Before(l.Expires) || l.HeldBy(holder, maintainer) {
		return ""
	}
	return fmt.Sprintf("%s is leased by %s until %s", v.d.Name, l.Who(), l.Expires.Format(time.TimeOnly))
}

// park sets a queued job aside while someone else's lease holds the Mac, so
// the lease holder's jobs queued after it run first, and says whether it did.
// unpark queues it again once the lease no longer holds it.
func (r *jobRun) park() bool {
	v := r.v
	v.mu.Lock()
	why := v.leaseHoldsBackLocked(r.j.Spec.Holder, r.j.Maintainer)
	if why != "" {
		v.parked = append(v.parked, parkedJob{r.j.ID, r.j.Spec.Holder, r.j.Maintainer})
	}
	v.mu.Unlock()
	if why == "" {
		return false
	}
	r.state(api.JobQueued)
	r.ev("%s; waiting for the lease to end", why)
	return true
}

// unpark queues again, in the order they were set aside, the jobs a lease no
// longer holds back: it ended, ran out or was released. It never waits for
// room in the queue: deviceLoop, the queue's only reader, calls it, so a
// full queue would stop the Mac for good. What doesn't fit stays parked, in
// order, for the next pass.
func (v *dev) unpark() {
	v.mu.Lock()
	defer v.mu.Unlock()
	keep := v.parked[:0]
	full := false
	for _, p := range v.parked {
		if !full && v.leaseHoldsBackLocked(p.holder, p.maintainer) == "" {
			select {
			case v.queue <- p.id:
				continue
			default:
				full = true
			}
		}
		keep = append(keep, p)
	}
	clear(v.parked[len(keep):])
	v.parked = keep
}

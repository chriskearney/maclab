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

// endLease ends v's lease and queues again the jobs it held back. When l, the
// lease as the caller saw it, is ended by someone other than its own
// Maintainer, why says by whom: labd's log records it, and so does each job
// it had set aside. It says whether it ended the lease: not when l is no
// longer v's lease, renewed or ended meanwhile. Caller doesn't hold v.mu.
func (s *Server) endLease(v *dev, l *api.Lease, why string) bool {
	v.mu.Lock()
	if l != nil && v.d.Lease != l {
		v.mu.Unlock()
		return false
	}
	v.d.Lease = nil
	v.saveLocked()
	var aside []string
	for _, p := range v.parked {
		aside = append(aside, p.id)
	}
	name := v.d.Name
	v.mu.Unlock()
	if l != nil {
		msg := fmt.Sprintf("%s's lease by %s, until %s, %s", name, l.Who(), l.Expires.Format(time.DateTime), why)
		s.log.Printf("%s", msg)
		for _, id := range aside {
			s.updateJobByID(id, func(j *api.Job) { j.Events = append(j.Events, api.JobEvent{Time: s.now(), Msg: msg}) })
		}
	}
	v.unpark()
	return true
}

// endLeasesOf ends the leases the Maintainer name holds, as when they are
// removed: nobody else could release them, and the jobs they hold back
// would wait for them to run out.
func (s *Server) endLeasesOf(name, why string) {
	for _, v := range s.allDevs() {
		v.mu.Lock()
		l := v.d.Lease
		mine := l != nil && l.Owner() == name && s.now().Before(l.Expires)
		v.mu.Unlock()
		if mine {
			s.endLease(v, l, why)
		}
	}
}

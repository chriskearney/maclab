package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/window"
)

// windowHoldLocked is why a job expected to take d may not start on the Mac
// now, or "" if it may. A Volunteer's Mac takes a job only inside its
// Availability window, on AC power, and when the job fits in what's left of
// the window; one whose Volunteer has set no window is closed. Lab-owned Macs
// are never held. Caller holds v.mu.
func (v *dev) windowHoldLocked(d time.Duration) string {
	if !v.d.IsVolunteer() {
		return ""
	}
	var s window.Settings
	if v.d.Window != nil {
		s = *v.d.Window
	}
	now := v.s.now()
	st := window.Evaluate(s, now)
	when := func(t time.Time) string { return t.In(s.Location()).Format("Mon 2 Jan 15:04 MST") }
	switch {
	case !st.Open && st.Next.IsZero():
		return fmt.Sprintf("%s has no Availability window ahead", v.d.Name)
	case !st.Open:
		return fmt.Sprintf("%s's Availability window is closed until %s", v.d.Name, when(st.Next))
	case v.d.Health.OnBattery:
		return fmt.Sprintf("%s is on battery; jobs start only on AC power", v.d.Name)
	case st.End.Sub(now) < d:
		return fmt.Sprintf("the job (expected to take %s) doesn't fit in what's left of %s's Availability window, which ends %s", d.Round(time.Minute), v.d.Name, when(st.End))
	}
	return ""
}

// syncWindowLocked takes the window settings a check-in carried as labd's
// copy, and says whether they changed. Only a Volunteer's Mac has them.
func (v *dev) syncWindowLocked(s *window.Settings) bool {
	if s == nil || !v.d.IsVolunteer() {
		return false
	}
	old, _ := json.Marshal(v.d.Window)
	now, _ := json.Marshal(s)
	v.d.Window = s
	return string(old) != string(now)
}

// openUntilLocked is when a Volunteer's Mac's Availability window, open now,
// ends; zero while it is closed. Caller holds v.mu.
func (v *dev) openUntilLocked() time.Time {
	var s window.Settings
	if v.d.Window != nil {
		s = *v.d.Window
	}
	if st := window.Evaluate(s, v.s.now()); st.Open {
		return st.End
	}
	return time.Time{}
}

// capLeaseLocked ends a lease on a Volunteer's Mac with its Availability
// window at the latest: at the window's end, or now once it has closed (a
// Pause). An end that moves later doesn't stretch a lease again. It says
// whether the lease changed. Caller holds v.mu.
func (v *dev) capLeaseLocked() bool {
	l := v.d.Lease
	if l == nil || !v.d.IsVolunteer() {
		return false
	}
	end := v.openUntilLocked()
	if end.IsZero() {
		end = v.s.now()
	}
	if !l.Expires.After(end) {
		return false
	}
	v.d.Lease = &api.Lease{Holder: l.Holder, Expires: end}
	return true
}

// windowClosed is whether labd's copy of a Volunteer's Mac's Availability
// window is closed now; a Lab-owned Mac's never is.
func (v *dev) windowClosed() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.d.IsVolunteer() && v.openUntilLocked().IsZero()
}

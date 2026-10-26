package server

import (
	"encoding/json"
	"fmt"
	"time"

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

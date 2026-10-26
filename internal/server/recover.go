package server

import (
	"context"
	"fmt"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
)

// Serial-based early detection: don't sit out the whole boot timeout when the
// console already shows the Mac is stuck.
var (
	panicGrace  = 60 * time.Second  // panic=10 should have rebooted it well within this
	serialStall = 120 * time.Second // console silent mid-boot for this long = hung
)

// waitBack waits for the Mac to come up on a new boot after `since`. When it
// doesn't, it gives the Mac selfRecovery more to come back by itself (a Lab
// boot's deadlines reboot it), then walks the recovery ladder. It returns the
// ladder steps used and whether the Mac is back.
func (v *dev) waitBack(ctx context.Context, oldBoot string, since time.Time, timeout, selfRecovery time.Duration) ([]string, bool, error) {
	var reason string
	err := v.waitFor(ctx, timeout+selfRecovery, func() bool {
		if v.d.BootID != oldBoot && v.d.LastSeen.After(since) {
			return true
		}
		now := v.s.now()
		if v.d.IsVolunteer() {
			// A Volunteer's Mac gets to recover by itself until its Hard ceiling plus a boot timeout.
			return false
		}
		for _, e := range v.events {
			if e.Time.After(since) && e.Kind == detect.Panic && now.Sub(e.Time) > panicGrace {
				reason = "kernel panicked and did not reboot within " + panicGrace.String()
				return true
			}
		}
		if v.oob != nil && v.serialUp && v.serialLast.After(since) && now.Sub(v.serialLast) > serialStall &&
			v.marker != detect.MarkUserspace && !v.aliveLocked() {
			reason = fmt.Sprintf("boot stalled: serial console silent for %s after %q", now.Sub(v.serialLast).Round(time.Second), v.serialLine)
			return true
		}
		return false
	})
	if err != nil && err != context.DeadlineExceeded {
		return nil, false, err
	}
	v.mu.Lock()
	back := v.d.BootID != oldBoot && v.d.LastSeen.After(since)
	// A Mac that is going down stops talking within seconds. Only one still
	// checking in well after the reboot request never went down at all.
	stillUp := v.d.BootID == oldBoot && v.aliveLocked() && v.d.LastSeen.After(since.Add(15*time.Second))
	v.mu.Unlock()
	if back {
		return nil, true, nil
	}
	if reason == "" {
		switch {
		case stillUp:
			reason = fmt.Sprintf("still on the old boot %s after asking it to reboot", timeout+selfRecovery)
		case selfRecovery > 0:
			reason = fmt.Sprintf("did not check in within %s, nor come back by itself %s after that", timeout, selfRecovery)
		default:
			reason = fmt.Sprintf("did not check in within %s", timeout)
		}
	}
	steps, ok := v.ladder(ctx, reason, timeout, stillUp)
	return steps, ok, nil
}

// ladder is the recovery ladder: soft reboot, hard reset (twice), then a
// human. It returns the steps taken and whether the Mac came back.
//
// A Mac that left the lab (lab-agent uninstall) is never reset or handed to a
// human: its agent stopped on purpose.
func (v *dev) ladder(ctx context.Context, reason string, bootTimeout time.Duration, trySoft bool) ([]string, bool) {
	if why := v.leaving(); why != "" {
		return []string{"not recovered: " + why}, false
	}
	v.mu.Lock()
	stuck := v.d.BootID
	alive := trySoft && v.aliveLocked()
	ctl := v.oob
	prev := v.d.State
	v.mu.Unlock()
	v.setState(api.StateRecovering, reason)
	v.s.log.Printf("%s: recovering: %s", v.d.Name, reason)
	steps := []string{"detected: " + reason}

	backSince := func(t time.Time) func() bool {
		return func() bool { return v.d.BootID != stuck && v.d.LastSeen.After(t) }
	}
	done := func() ([]string, bool) {
		v.setState(prev, "")
		return steps, true
	}

	if alive {
		steps = append(steps, "soft reboot via agent")
		t0 := v.s.now()
		v.send(api.CmdReboot, "", nil)
		v.rearmSerial(3 * time.Minute)
		if v.waitFor(ctx, bootTimeout, backSince(t0)) == nil {
			return done()
		}
		steps = append(steps, "soft reboot did not bring it back")
	}
	if ctl != nil {
		for i := 1; i <= 2; i++ {
			if ctx.Err() != nil {
				return steps, false
			}
			if why := v.leaving(); why != "" {
				return append(steps, "stopped: "+why), false
			}
			t0 := v.s.now()
			steps = append(steps, fmt.Sprintf("hard reset %d via %s", i, ctl.Name()))
			rctx, cancel := context.WithTimeout(ctx, time.Minute)
			err := ctl.Reset(rctx)
			cancel()
			if err != nil {
				steps = append(steps, "hard reset failed: "+err.Error())
				continue
			}
			if v.waitFor(ctx, bootTimeout, backSince(t0)) == nil {
				return done()
			}
			steps = append(steps, fmt.Sprintf("no check-in %s after hard reset %d", bootTimeout, i))
		}
	}
	if ctx.Err() != nil {
		return steps, false
	}
	if why := v.leaving(); why != "" {
		return append(steps, "stopped: "+why), false
	}
	v.mu.Lock()
	act := humanAction(v.d, reason, v.lastLogLocked(), v.s.now())
	n := Notification{Device: v.d.Name, Title: act.Title, Body: act.Text(), Priority: "urgent"}
	if v.d.IsVolunteer() {
		n.Volunteer, n.MacTopic = true, v.s.macTopicURL(v.d.Enrollment)
	}
	v.d.Action = act
	v.restore = ""
	v.setStateLocked(api.StateNeedsHands, reason)
	v.dirty = true
	v.mu.Unlock()
	steps = append(steps, "asked a human to power cycle it")
	v.s.notify(n)
	return steps, false
}

func (v *dev) lastLogLocked() string {
	for i := len(v.events) - 1; i >= 0; i-- {
		if detect.Fatal(v.events[i].Kind) {
			return v.events[i].Line
		}
	}
	if v.serialLine != "" {
		return v.serialLine
	}
	return ""
}

// humanAction writes the instruction for the person at the desk: which
// machine, exactly what to press, and that nothing else is needed.
func humanAction(d api.Device, reason, lastLog string, now time.Time) *api.HumanAction {
	where := d.Name
	if d.Label != "" {
		where = fmt.Sprintf("%s (%s)", d.Name, d.Label)
	}
	a := &api.HumanAction{Title: d.Name + " needs a power cycle", LastLog: lastLog, Since: now}
	switch d.Model {
	case api.ModelDesktop:
		a.Steps = []string{
			"Find " + where + ".",
			"Unplug its power cable and wait 10 seconds.",
			"Plug it back in. If it doesn't start, press the power button on the back once.",
		}
	default:
		a.Steps = []string{
			"Find " + where + ". Open the lid if it's closed.",
			"Hold the power button (the Touch ID key, top right of the keyboard) for 10 seconds, until the screen stays black.",
			"Wait 5 seconds, then press it once to turn it back on.",
		}
	}
	a.Steps = append(a.Steps, "That's it. The lab notices when it checks in again and picks up from there.")
	a.Why = reason
	if d.OOB == nil {
		a.Why += ". No out-of-band controller is attached, so the lab can't reset it remotely"
	} else {
		a.Why += ". Two remote resets did not bring it back"
	}
	return a
}

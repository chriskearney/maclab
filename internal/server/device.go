package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
	"github.com/iconidentify/maclab/internal/oob"
)

// aliveWindow is how stale the last heartbeat may be before a device counts as unresponsive.
var aliveWindow = 20 * time.Second

var errDeviceLost = errors.New("device stopped responding or rebooted")

// dev is labd's live view of one Mac.
type dev struct {
	s          *Server
	secretHash string
	// volunteeredBy is d.VolunteeredBy, which never changes: labd counts a
	// volunteer's Macs under s.mu alone, without each Mac's mu.
	volunteeredBy string

	mu       sync.Mutex
	d        api.Device
	pending  []api.Command
	inflight map[string]time.Time
	sent     map[string]api.Command
	target   map[string]string // command ID -> the boot it was issued for
	results  map[string]api.CommandResult
	changed  chan struct{}
	events   []api.KernelEvent
	dirty    bool // a lab kernel may still be staged on the Mac
	restore  api.DeviceState
	queue    chan string
	gone     chan struct{} // closed when the device is forgotten: ends deviceLoop
	oob      oob.Controller
	oobStop  context.CancelFunc

	// forgotten: lab forget deleted the device's row. Set under mu, which
	// every save holds, so nothing still holding the device writes it back.
	forgotten bool
	// leftBy is what took the Mac out of the lab ("lab-agent uninstall
	// --force"), set with StateLeft; empty after labd restarts.
	leftBy string

	shotMu     sync.Mutex
	screenAt   time.Time
	screenName string

	serialUp   bool
	serialLast time.Time
	serialLine string
	marker     string
	markerTime time.Time

	asleep time.Time // when the agent said the Mac is going to sleep; zero while awake
	awoke  time.Time // when it said it woke up: quietGrace counts from here
	// The agent said boot quietBoot may be off the network until quietUntil
	// (api.Quiet): until then its silence doesn't make it lost or offline.
	quietBoot  string
	quietUntil time.Time

	// heard is the last check-in from the Mac itself, or its report that it
	// is back on the network. LastSeen also moves when labd answers a held
	// check-in, which a Mac that just died can't hear.
	heard time.Time
	// The last reboot labd saw: the boot that ended, the last check-in heard
	// from it, and the first check-in of the boot after it.
	endedBoot            string
	endedHeard, nextSeen time.Time
}

func newDev(s *Server, d api.Device, secretHash string) *dev {
	v := &dev{s: s, d: d, secretHash: secretHash, volunteeredBy: d.VolunteeredBy, inflight: map[string]time.Time{}, sent: map[string]api.Command{}, target: map[string]string{},
		results: map[string]api.CommandResult{}, changed: make(chan struct{}), queue: make(chan string, 256), gone: make(chan struct{})}
	return v
}

// bump wakes everything waiting on this device. Caller holds mu.
func (v *dev) bump() {
	close(v.changed)
	v.changed = make(chan struct{})
}

func (v *dev) snapshot() api.Device {
	v.mu.Lock()
	defer v.mu.Unlock()
	d := v.d
	return d
}

var errForgotten = errors.New("the device was forgotten (lab forget)")

// storeLocked saves the device, unless lab forget deleted its row: a
// check-in, the monitor or a promotion still holding it must not bring the
// row back, where it would clash with a Mac enrolled again under its name.
func (v *dev) storeLocked() error {
	if v.forgotten {
		return errForgotten
	}
	return v.s.store.saveDevice(&v.d, v.secretHash)
}

func (v *dev) saveLocked() {
	if err := v.storeLocked(); err != nil && !errors.Is(err, errForgotten) {
		v.s.log.Printf("save device %s: %v", v.d.Name, err)
	}
}

// leaving says that lab-agent uninstall took the Mac out of the lab, and
// how, or "" while it is still in the lab.
func (v *dev) leaving() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.d.State != api.StateLeft {
		return ""
	}
	return fmt.Sprintf("%s left the lab (%s)", v.d.Name, orStr(v.leftBy, "lab-agent uninstall"))
}

func (v *dev) aliveLocked() bool {
	return !v.d.LastSeen.IsZero() && v.s.since(v.d.LastSeen) < aliveWindow
}

func (v *dev) setState(st api.DeviceState, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.setStateLocked(st, reason)
}

func (v *dev) setStateLocked(st api.DeviceState, reason string) {
	if v.d.State == st && v.d.StateReason == reason {
		return
	}
	// A Mac that left the lab stays left until lab forget: a job ending or a
	// recovery finishing must not put it back in the pool.
	if v.d.State == api.StateLeft {
		return
	}
	v.d.State, v.d.StateReason = st, reason
	if st != api.StateNeedsHands {
		v.d.Action = nil
	}
	v.saveLocked()
	v.publishLocked()
	v.bump()
}

// idleState is where a device goes when nothing is happening to it.
func (v *dev) idleStateLocked() api.DeviceState {
	if v.d.KnownGood == "" {
		return api.StateNew
	}
	return api.StateReady
}

// heartbeat records a check-in. Commands are handed out separately by deliver.
func (v *dev) heartbeat(ci api.Checkin) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.s.now()
	rebooted := v.d.BootID != "" && ci.BootID != v.d.BootID
	persist := rebooted || v.d.BootID == "" || ci.Facts != nil || v.d.Kernel != ci.Kernel
	if rebooted {
		v.endedBoot, v.endedHeard, v.nextSeen = v.d.BootID, v.heard, now
	}
	v.d.LastSeen, v.heard = now, now
	// Checking in means awake, except for a poll that raced the sleep announcement.
	if !v.asleep.IsZero() && now.Sub(v.asleep) > 5*time.Second {
		v.asleep = time.Time{}
	}
	v.d.BootID, v.d.Kernel, v.d.Cmdline, v.d.Health = ci.BootID, ci.Kernel, ci.Cmdline, ci.Health
	if ci.Facts != nil {
		v.d.Facts = *ci.Facts
	}
	if rebooted {
		// Whatever was executing on the previous boot is gone.
		for id := range v.inflight {
			v.results[id] = api.CommandResult{ID: id, Error: errDeviceLost.Error()}
		}
		v.inflight = map[string]time.Time{}
		v.sent = map[string]api.Command{}
		v.s.log.Printf("%s: new boot %s kernel %s", v.d.Name, short(ci.BootID), ci.Kernel)
		if v.oob != nil {
			go v.rearmSerial(20 * time.Second) // unplanned reboots too: keep the console live
		}
	}
	for _, r := range ci.Results {
		if _, ok := v.inflight[r.ID]; ok {
			delete(v.inflight, r.ID)
			v.results[r.ID] = r
		}
	}
	for _, e := range ci.Events {
		v.addEventLocked(e)
	}
	switch v.d.State {
	case api.StateOffline, api.StateNeedsHands:
		was := v.d.State
		back := v.restore
		if back == "" {
			back = v.idleStateLocked()
		}
		v.setStateLocked(back, "")
		v.restore = ""
		if was == api.StateNeedsHands {
			v.s.notify(Notification{Device: v.d.Name, Title: v.d.Name + " is back", Body: "Checked in on " + ci.Kernel + ". Nothing else to do.", Priority: "default"})
		}
		persist = true
	}
	// A command handed to a connection that died (a Mac reset mid long-poll)
	// never arrives. Redeliver it; the agent ignores IDs it has already seen.
	running := map[string]bool{}
	for _, id := range ci.Running {
		running[id] = true
	}
	for id, at := range v.inflight {
		if !running[id] && now.Sub(at) > 15*time.Second {
			if c, ok := v.sent[id]; ok {
				delete(v.inflight, id)
				v.pending = append(v.pending, c)
			}
		}
	}
	if persist {
		v.saveLocked()
	}
	v.bump()
	v.publishLocked()
}

// deliver hands pending commands to a check-in from the current boot.
func (v *dev) deliver(bootID string) api.CheckinResponse {
	v.mu.Lock()
	defer v.mu.Unlock()
	resp := api.CheckinResponse{IntervalMS: int(v.s.cfg.Interval / time.Millisecond)}
	if bootID != v.d.BootID {
		return resp
	}
	now := v.s.now()
	v.d.LastSeen = now
	for _, c := range v.pending {
		// A command is for the boot it was issued against. A reboot aimed at a
		// stuck boot must never reach the fresh boot that replaced it.
		if t := v.target[c.ID]; t != "" && t != bootID {
			v.results[c.ID] = api.CommandResult{ID: c.ID, Error: errDeviceLost.Error()}
			delete(v.target, c.ID)
			continue
		}
		v.inflight[c.ID] = now
		v.sent[c.ID] = c
		resp.Commands = append(resp.Commands, c)
	}
	v.pending = nil
	if len(resp.Commands) == 0 {
		v.bump()
	}
	return resp
}

func (v *dev) report(rep api.Report) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if q := rep.Quiet; q != nil && q.BootID == v.d.BootID {
		switch now := v.s.now(); {
		case q.Seconds > 0:
			d := min(time.Duration(q.Seconds)*time.Second, maxQuiet)
			v.quietBoot, v.quietUntil = q.BootID, now.Add(d)
			v.s.log.Printf("%s: may be off the network for up to %s on boot %s", v.d.Name, d, short(q.BootID))
		case v.quietLocked(now):
			// Back on the network: from now on a silence is quietGrace's
			// again, so a hang in the next step shows at once. The report
			// is the Mac itself, heard now, maybe before its next check-in.
			v.quietBoot, v.quietUntil = "", time.Time{}
			v.d.LastSeen, v.heard = now, now
			v.s.log.Printf("%s: back on the network on boot %s; no longer waiting out its spell off it", v.d.Name, short(q.BootID))
		}
	}
	for _, r := range rep.Results {
		if _, ok := v.inflight[r.ID]; ok {
			delete(v.inflight, r.ID)
			delete(v.sent, r.ID)
			delete(v.target, r.ID)
			v.results[r.ID] = r
		}
	}
	for _, e := range rep.Events {
		v.addEventLocked(e)
	}
	v.bump()
}

func (v *dev) addEventLocked(e api.KernelEvent) {
	if e.Time.IsZero() {
		e.Time = v.s.now()
	}
	switch e.Kind {
	case detect.Sleep:
		v.asleep = v.s.now()
	case detect.Wake:
		v.asleep, v.awoke = time.Time{}, v.s.now()
	}
	v.events = append(v.events, e)
	v.s.hub.publish("kevent", v.d.Name, struct {
		api.KernelEvent
		Device string `json:"device"`
	}{e, v.d.Name})
	if len(v.events) > 1000 {
		v.events = v.events[len(v.events)-1000:]
	}
	v.s.log.Printf("%s: kernel event %s (%s): %s", v.d.Name, e.Kind, e.Source, e.Line)
}

// silentFor is how long the Mac was out of touch when boot ended: from the
// last check-in labd heard on it to the first one on the boot after it.
func (v *dev) silentFor(boot string) (time.Duration, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if boot == "" || v.endedBoot != boot || v.endedHeard.IsZero() {
		return 0, false
	}
	return v.nextSeen.Sub(v.endedHeard), true
}

func (v *dev) eventsSince(t time.Time) []api.KernelEvent {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []api.KernelEvent
	for _, e := range v.events {
		if !e.Time.Before(t) {
			out = append(out, e)
		}
	}
	return out
}

// onSerial ingests one serial console line.
func (v *dev) onSerial(line string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.s.now()
	v.serialLast, v.serialLine = now, line
	v.s.hub.publish("serial", v.d.Name, map[string]any{"device": v.d.Name, "time": now, "line": line})
	if m := detect.Marker(line); m != "" {
		v.marker, v.markerTime = m, now
	}
	if k := detect.Classify(line); k != "" {
		v.addEventLocked(api.KernelEvent{Time: now, Kind: k, Source: "serial", Line: line})
	}
	v.bump()
}

var cmdSeq struct {
	sync.Mutex
	n int
}

func nextCmdID() string {
	cmdSeq.Lock()
	defer cmdSeq.Unlock()
	cmdSeq.n++
	return fmt.Sprintf("c%d-%d", time.Now().Unix(), cmdSeq.n)
}

func (v *dev) send(kind, job string, args any) string {
	b, _ := json.Marshal(args)
	c := api.Command{ID: nextCmdID(), Kind: kind, JobID: job, Args: b}
	v.mu.Lock()
	v.pending = append(v.pending, c)
	v.target[c.ID] = v.d.BootID
	v.bump()
	v.mu.Unlock()
	return c.ID
}

// waitFor blocks until cond (called with mu held) returns true, the timeout
// passes, or ctx ends. Conditions are also re-checked every second.
func (v *dev) waitFor(ctx context.Context, timeout time.Duration, cond func() bool) error {
	var deadline <-chan time.Time
	if timeout > 0 {
		deadline = v.s.clock().After(timeout)
	}
	tick := v.s.clock().NewTicker(time.Second)
	defer tick.Stop()
	for {
		v.mu.Lock()
		ok := cond()
		ch := v.changed
		v.mu.Unlock()
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return context.DeadlineExceeded
		case <-ch:
		case <-tick.C():
		}
	}
}

// errAgentRefused matches an error the agent itself returned, as opposed to
// the command being lost or timing out, when it may or may not have run.
var errAgentRefused = errors.New("the agent returned an error")

type agentError struct{ kind, msg string }

func (e agentError) Error() string        { return e.kind + ": " + e.msg }
func (e agentError) Is(target error) bool { return target == errAgentRefused }

// call sends a command and waits for its result. It gives up early with
// errDeviceLost if the Mac reboots or stops heartbeating.
func (v *dev) call(ctx context.Context, kind, job string, args any, timeout time.Duration, out any) error {
	return v.callNote(ctx, kind, job, args, timeout, out, nil)
}

// quietGrace is how long a Mac may go silent on the same boot, without having
// said it is going to sleep, before a command on it counts as lost. Wi-Fi
// reconnecting after a resume takes tens of seconds.
var quietGrace = 60 * time.Second

// maxSleep is how long a command waits for a Mac that went to sleep.
var maxSleep = time.Hour

// maxQuiet is the longest spell off the network an agent can announce
// (api.Quiet) that labd honours.
var maxQuiet = 15 * time.Minute

// quietLocked is whether the Mac is within a spell off the network it
// announced for the boot it is on. Caller holds mu.
func (v *dev) quietLocked(now time.Time) bool {
	return v.quietBoot != "" && v.quietBoot == v.d.BootID && now.Before(v.quietUntil)
}

// lostLocked is whether a Mac silent on the same boot, and not asleep, has
// been silent too long: quietGrace from its last check-in and from its last
// wake-up, and past any spell off the network it announced for this boot.
// Caller holds mu.
func (v *dev) lostLocked(now time.Time) bool {
	return now.Sub(v.d.LastSeen) > quietGrace && now.Sub(v.awoke) > quietGrace && !v.quietLocked(now)
}

// callNote is call for commands that may outlive a quiet spell. A Mac that
// goes quiet on the same boot is asleep or off the network, and the command
// is still running there: it waits, with the command's clock stopped, for as
// long as the Mac said it is asleep (up to maxSleep), as long as it said it
// may be off the network (up to maxQuiet), and quietGrace otherwise. note, if
// set, hears about sleeping and waking.
func (v *dev) callNote(ctx context.Context, kind, job string, args any, timeout time.Duration, out any, note func(string)) error {
	v.mu.Lock()
	boot := v.d.BootID
	name := v.d.Name
	v.mu.Unlock()
	id := v.send(kind, job, args)
	deadline := v.s.now().Add(timeout)
	var (
		res            api.CommandResult
		lost, timedOut bool
		quietSince     time.Time // last check-in before the Mac went quiet
		sleptNoted     bool
		askedHuman     bool
		notes          []string
	)
	tick := v.s.clock().NewTicker(time.Second)
	defer tick.Stop()
	for {
		v.mu.Lock()
		done := func() bool {
			if r, ok := v.results[id]; ok {
				res = r
				delete(v.results, id)
				return true
			}
			if v.d.BootID != boot {
				lost = true
				return true
			}
			now := v.s.now()
			if v.aliveLocked() {
				if !quietSince.IsZero() {
					away := v.d.LastSeen.Sub(quietSince)
					deadline = deadline.Add(away)
					what := "unreachable"
					if sleptNoted {
						what = "asleep"
					}
					notes = append(notes, fmt.Sprintf("%s is back on the same boot after %s %s; still waiting for %s", name, away.Round(time.Second), what, kind))
					quietSince, sleptNoted, askedHuman = time.Time{}, false, false
				}
				if now.After(deadline) {
					timedOut = true
					return true
				}
				return false
			}
			if quietSince.IsZero() {
				quietSince = v.d.LastSeen
			}
			if !v.asleep.IsZero() {
				if !sleptNoted {
					sleptNoted = true
					notes = append(notes, fmt.Sprintf("%s went to sleep; waiting for it to wake. The lab can't wake it: a key press, the power button or opening the lid does", name))
				}
				if !askedHuman && now.Sub(v.asleep) > 2*time.Minute {
					askedHuman = true
					notes = append(notes, "!asleep")
				}
				if now.Sub(v.asleep) > maxSleep {
					lost = true
					return true
				}
				return false
			}
			if v.lostLocked(now) {
				lost = true
				return true
			}
			return false
		}()
		ch := v.changed
		v.mu.Unlock()
		for _, n := range notes {
			if n == "!asleep" {
				v.s.notify(Notification{Device: name, Title: name + " is asleep during a test",
					Body: "Press a key on " + name + " to wake it; the lab can't. The job continues when it wakes.", Priority: "high"})
				continue
			}
			v.s.log.Printf("%s: %s", name, n)
			if note != nil {
				note(n)
			}
		}
		notes = nil
		if done {
			break
		}
		select {
		case <-ctx.Done():
			v.forget(id)
			return ctx.Err()
		case <-ch:
		case <-tick.C():
		}
	}
	if timedOut {
		v.forget(id)
		return fmt.Errorf("%s: no result after %s", kind, timeout)
	}
	if lost {
		v.forget(id)
		return errDeviceLost
	}
	if !res.OK {
		if res.Error == errDeviceLost.Error() {
			return errDeviceLost
		}
		return agentError{kind, res.Error}
	}
	if out != nil && len(res.Output) > 0 {
		return json.Unmarshal(res.Output, out)
	}
	return nil
}

func (v *dev) forget(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.inflight, id)
	delete(v.sent, id)
	delete(v.target, id)
	delete(v.results, id)
	for i, c := range v.pending {
		if c.ID == id {
			v.pending = append(v.pending[:i], v.pending[i+1:]...)
			break
		}
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
)

// A fatal console line from the boot the Mac is still on is not the test
// kernel's: the test kernel never ran, and a Mac that went on checking in did
// not die. Without this the job read panicked and the ladder hard-reset a Mac
// that was up and waiting. (chriskearney/maclab#63, found by its review.)
func TestOldBootFatalLineIsNotTheTestKernels(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	l.sim.FailArm(func(n int) (bool, error) {
		if n == 3 {
			// The console of the boot the Mac is on, before the reboot that never happens.
			l.s.dev(l.name).onSerial("Kernel panic - not syncing: old-boot noise")
			return false, errors.New("boot partition lock: held for a minute")
		}
		return false, nil
	})
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-never behavior=ok")})
	l.expect(j, api.OutcomeInfra)
	if !strings.Contains(j.Summary, "never rebooted") {
		t.Fatalf("summary: %s", j.Summary)
	}
	for _, step := range j.Result.Recovery {
		if strings.Contains(step, "hard reset") {
			t.Fatalf("a Mac that stayed up was hard reset: %v", j.Result.Recovery)
		}
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
}

// The guard for the rule above: a test kernel that panics before it checks in
// is still its own panic.
func TestTestKernelPanicBeforeCheckinStillPanicked(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-panics behavior=panic")})
	l.expect(j, api.OutcomePanicked)
}

// Serial events carry the boot the Mac was last heard on, like kmsg ones.
func TestSerialEventsAreStampedWithTheBoot(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	v := l.s.dev(l.name)
	boot := v.snapshot().BootID
	v.onSerial("Kernel panic - not syncing: noise")
	ev := v.eventsSince(time.Time{})
	if len(ev) == 0 || boot == "" || ev[len(ev)-1].BootID != boot {
		t.Fatalf("events %+v, want the last stamped %q", ev, boot)
	}
}

// A fatal event the waited-on boot outlived (it was heard after it), one
// lab-agent read on that boot, or one of the boot before it is superseded; a
// serial line it has not outlived, one of a boot labd has not heard from, or
// one of a boot not waited on, is not.
func TestSupersededEvents(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	v := l.s.dev(l.name)
	boot := v.snapshot().BootID
	v.mu.Lock()
	v.endedBoot = "earlier"
	v.mu.Unlock()
	now := l.s.now()
	for _, c := range []struct {
		name string
		e    api.KernelEvent
		want bool
	}{
		{"before the last check-in, no boot", api.KernelEvent{Time: now.Add(-time.Hour), Kind: detect.Panic}, true},
		{"before the last check-in, same boot", api.KernelEvent{Time: now.Add(-time.Hour), Kind: detect.Panic, BootID: boot}, true},
		{"serial, after the last check-in", api.KernelEvent{Time: now.Add(time.Hour), Kind: detect.Panic, Source: "serial", BootID: boot}, false},
		{"lab-agent's, after the last check-in", api.KernelEvent{Time: now.Add(time.Hour), Kind: detect.Oops, Source: "kmsg", BootID: boot}, true},
		{"the boot before's, reported late", api.KernelEvent{Time: now.Add(time.Hour), Kind: detect.Panic, Source: "kmsg", BootID: "earlier"}, true},
		{"a boot labd has not heard from", api.KernelEvent{Time: now.Add(time.Hour), Kind: detect.Oops, Source: "kmsg", BootID: "test-kernel"}, false},
	} {
		v.mu.Lock()
		got := v.supersededLocked(c.e, boot)
		v.mu.Unlock()
		if got != c.want {
			t.Errorf("%s: superseded %v, want %v", c.name, got, c.want)
		}
	}
	// Waiting on another boot than the Mac is on: nothing is superseded.
	v.mu.Lock()
	got := v.supersededLocked(api.KernelEvent{Time: now.Add(-time.Hour), Kind: detect.Panic}, "not-this-one")
	v.mu.Unlock()
	if got {
		t.Error("an event was superseded for a boot the Mac was never on")
	}
}

// lab-agent on the boot the Mac is leaving reads a fatal line as it shuts
// down for the reboot, after its last check-in: it is that boot's, not the
// test kernel's, which then hangs. (chriskearney/maclab#63's review of the
// fix for its review.)
func TestOldBootKmsgLineAfterItsLastCheckinIsNotTheTestKernels(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	v := l.s.dev(l.name)
	old := v.snapshot().BootID
	l.sim.FailArm(func(n int) (bool, error) {
		if n == 3 {
			v.report(api.Report{Events: []api.KernelEvent{{Kind: detect.Oops, Source: "kmsg", BootID: old, Line: "Unable to handle kernel NULL pointer dereference (old boot, shutting down)"}}})
		}
		return false, nil
	})
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-silent behavior=silent")})
	l.expect(j, api.OutcomeHung)
}

// The test kernel's own Oops, reported before its first check-in, is its own,
// even if the Mac never checks in on it: labd has not heard from that boot,
// so it is not the boot before's, reported late.
func TestTestKernelOopsBeforeItsFirstCheckinIsItsOwn(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	v := l.s.dev(l.name)
	l.sim.FailArm(func(n int) (bool, error) {
		if n == 3 {
			v.report(api.Report{Events: []api.KernelEvent{{Kind: detect.Oops, Source: "kmsg", BootID: "the-test-kernels-boot", Line: "Internal error: Oops: 96000004 [#1] SMP"}}})
		}
		return false, nil
	})
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-silent behavior=silent")})
	l.expect(j, api.OutcomePanicked)
}

// A fatal event of an earlier boot, reported while the Lab boot was up, is not
// why that boot lost the network for a while.
func TestLostDuringTestIgnoresEarlierBootEvent(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	old := l.s.dev(l.name).snapshot().BootID
	l.sim.SuspendFor = 8 * time.Second
	l.s.cfg.TestGrace = 2 * time.Second
	j, _, err := l.s.Submit(api.JobSpec{Device: l.name, Kernel: l.artifact("krel=7.2-ok behavior=ok"), Tests: []api.TestSpec{{Name: "quiet-suspend-wifi", Builtin: "x", TimeoutSec: 10}}})
	if err != nil {
		t.Fatal(err)
	}
	l.waitDevice(func(d api.Device) bool { return d.BootID != old && d.Kernel != agent.SimKnownGood })
	l.s.dev(l.name).report(api.Report{Events: []api.KernelEvent{{Kind: detect.Panic, Source: "kmsg", BootID: old, Line: "Kernel panic - not syncing: from the boot before"}}})
	j = l.wait(j.ID, 2*time.Minute)
	l.expect(j, api.OutcomeLostContact)
	if !strings.Contains(j.Summary, "came back on the same boot") {
		t.Fatalf("summary: %s", j.Summary)
	}
}

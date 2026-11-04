package server

import (
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// upgradeKernel is a distro update on the lab's Mac (pacman -Syu replacing its
// kernel package), optionally followed by the reboot onto it. labd hears the
// Mac's preflight at once, as it would from a restarted agent.
func (l *lab) upgradeKernel(krel string, reboot bool) {
	l.t.Helper()
	l.sim.UpgradeKernel(krel)
	if reboot {
		l.sim.Reboot()
		l.waitDevice(func(d api.Device) bool { return d.Kernel == krel })
	}
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Facts = l.sim.Facts()
	v.mu.Unlock()
}

func (l *lab) jobEvents(j *api.Job) string {
	var ev []string
	for _, e := range j.Events {
		ev = append(ev, e.Msg)
	}
	return strings.Join(ev, "\n")
}

// A kernel update removes the known-good kernel's package. Every job is
// refused, with lab baseline as the fix, and lab baseline itself runs: it
// records the running kernel as the known-good on the Mac and, once it
// passes, on labd (malik-na/maclab#43).
func TestBaselineAfterKernelUpdateRecordsTheRunningKernel(t *testing.T) {
	const updated = "7.2.11-good"
	l := newLab(t, false)
	l.baseline()
	l.upgradeKernel(updated, true)

	_, code, err := l.s.Submit(api.JobSpec{Device: l.name, Kernel: l.artifact("krel=7.3-rc1 behavior=ok")})
	if code != 409 || err == nil || !strings.Contains(err.Error(), "known-good kernel "+agent.SimKnownGood+" is no longer installed") ||
		!strings.Contains(err.Error(), "lab baseline "+l.name) || !strings.Contains(err.Error(), updated) {
		t.Fatalf("a job on a stale known-good: %d %v", code, err)
	}

	j := l.run(api.JobSpec{Baseline: true})
	l.expect(j, api.OutcomePass)
	if j.Result.BootKernel != updated {
		t.Fatalf("the baseline booted %s, not the running kernel %s", j.Result.BootKernel, updated)
	}
	if ev := l.jobEvents(j); !strings.Contains(ev, "recording the running kernel "+updated) {
		t.Fatalf("the baseline did not say it recorded the running kernel:\n%s", ev)
	}
	d := l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Facts.PreflightOK })
	if d.KnownGood != updated {
		t.Fatalf("labd's known-good is %s, not %s", d.KnownGood, updated)
	}
	if f := l.sim.Facts(); !f.PreflightOK {
		t.Fatalf("the Mac still fails preflight: %v", f.Problems)
	}
	l.expect(l.run(api.JobSpec{Kernel: l.artifact("krel=7.3-rc1 behavior=ok")}), api.OutcomePass)
}

// A Mac that took the update but has not rebooted is running a kernel that is
// no longer installed either: the baseline can't record it, says so, and
// leaves labd's known-good as it was. After the reboot it passes.
func TestBaselineBeforeRebootingOntoAKernelUpdate(t *testing.T) {
	const updated = "7.2.11-good"
	l := newLab(t, false)
	l.baseline()
	l.upgradeKernel(updated, false)

	j := l.run(api.JobSpec{Baseline: true})
	l.expect(j, api.OutcomeInfra)
	if !strings.Contains(j.Summary, "recording the running kernel "+agent.SimKnownGood) || !strings.Contains(j.Summary, "reboot") {
		t.Fatalf("summary: %s", j.Summary)
	}
	if d := l.s.dev(l.name).snapshot(); d.KnownGood != agent.SimKnownGood {
		t.Fatalf("labd's known-good became %q", d.KnownGood)
	}

	l.sim.Reboot()
	l.waitDevice(func(d api.Device) bool { return d.Kernel == updated && d.State == api.StateReady })
	l.expect(l.run(api.JobSpec{Baseline: true}), api.OutcomePass)
	if d := l.s.dev(l.name).snapshot(); d.KnownGood != updated {
		t.Fatalf("labd's known-good is %s, not %s", d.KnownGood, updated)
	}
}

// The known-good kernel is the one a plain reboot returns to. A baseline that
// recorded a running kernel the bootloader doesn't default to does not pass,
// and the Mac stays out of the pool until one does.
func TestBaselineAfterKernelUpdateNeedsTheDefaultEntry(t *testing.T) {
	const picked, other = "7.2.10-good", "7.2.11-good"
	l := newLab(t, false)
	l.baseline()
	l.upgradeKernel(picked, true)
	l.sim.SetDefaultKernel(other)

	j := l.run(api.JobSpec{Baseline: true})
	l.expect(j, api.OutcomeInfra)
	if !strings.Contains(j.Summary, "not the Mac's default entry") {
		t.Fatalf("summary: %s", j.Summary)
	}
	if d := l.s.dev(l.name).snapshot(); d.KnownGood != "" {
		t.Fatalf("labd's known-good is %q after a baseline that did not pass", d.KnownGood)
	}
	if _, code, err := l.s.Submit(api.JobSpec{Device: l.name, Kernel: l.artifact("krel=7.3-rc1 behavior=ok")}); code != 409 || err == nil || !strings.Contains(err.Error(), "has not passed a baseline") {
		t.Fatalf("a job with no known-good: %d %v", code, err)
	}
}

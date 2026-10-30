package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
	"github.com/iconidentify/maclab/internal/installed"
	"github.com/iconidentify/maclab/internal/mesa"
	"github.com/iconidentify/maclab/internal/window"
)

type jobRun struct {
	s       *Server
	v       *dev
	j       *api.Job
	boot    time.Duration
	started time.Time
	serial0 int64

	bootID   string // the test kernel's boot, once it is up
	bootedAt time.Time

	armedBoot string    // the boot that was running when this job armed its one-shot and rebooted
	armedAt   time.Time // when it did

	mesaManifest string
	ir           *installedRun // installed-kernel jobs only

	omtRef []byte // a known-good run's omarchy-m-test reference, written only if the job passes

	failedOwn  int  // tests that failed by themselves, not cut short by a cancel
	noAppleWDT bool // the test kernel was built without apple_wdt

	volunteerTold bool // a Volunteer was told this job is starting, so they are told when it is done
}

func (r *jobRun) ev(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.s.log.Printf("job %s (%s): %s", r.j.ID, r.j.Spec.Device, msg)
	r.s.updateJob(r.j, func(j *api.Job) { j.Events = append(j.Events, api.JobEvent{Time: r.s.now(), Msg: msg}) })
}

func (r *jobRun) state(st api.JobState) {
	r.s.updateJob(r.j, func(j *api.Job) { j.State = st })
}

// deviceLoop runs one device's jobs in order and tidies up after incidents.
func (s *Server) deviceLoop(v *dev) {
	tick := s.clock().NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-v.gone:
		case <-v.stop:
			return
		case id := <-v.queue:
			j, err := s.store.job(id)
			if err != nil || j.State == api.JobDone {
				continue
			}
			ctx, cancel := context.WithCancel(s.ctx)
			s.mu.Lock()
			s.cancels[id] = cancel
			s.mu.Unlock()
			s.runJob(ctx, v, j)
			cancel()
			s.mu.Lock()
			delete(s.cancels, id)
			s.mu.Unlock()
		case <-tick.C():
			v.mu.Lock()
			need := v.dirty && v.aliveLocked() && (v.d.State == api.StateReady || v.d.State == api.StateNew)
			v.mu.Unlock()
			if need {
				if err := v.call(s.ctx, api.CmdCleanup, "", api.CleanupArgs{All: true}, 2*time.Minute, nil); err == nil {
					v.mu.Lock()
					v.dirty = false
					v.mu.Unlock()
					s.log.Printf("%s: removed leftover lab kernels", v.d.Name)
				}
			}
		}
	}
}

func (s *Server) runJob(ctx context.Context, v *dev, j *api.Job) {
	r := &jobRun{s: s, v: v, j: j, boot: s.cfg.BootTimeout}
	if err := s.beginJobRecoveryMode(ctx, v, j); err != nil {
		r.finish(api.OutcomeInfra, "recovery mode admission failed before device commands: "+err.Error())
		return
	}
	if j.Spec.BootTimeoutSec > 0 {
		r.boot = time.Duration(j.Spec.BootTimeoutSec) * time.Second
	}

	if j.Spec.Mesa != nil {
		if _, err := s.validateMesa(j.Spec, v.snapshot()); err != nil {
			r.finish(api.OutcomeInfra, "stored Mesa job refused before device commands: "+err.Error())
			return
		}
		s.updateJob(j, func(j *api.Job) {
			j.Result.Mesa = &api.MesaResult{Mode: api.MesaStaged, Semantics: mesa.Semantics, Packages: append([]api.MesaPackage{}, j.Spec.Mesa.Packages...), Verdict: "INCOMPLETE"}
		})
	}

	// A source is built (or an identical earlier build reused) before the Mac is needed.
	if j.Spec.Source != "" && j.Spec.Kernel == "" {
		if outcome, summary := r.build(ctx); outcome != "" {
			if why := v.leaving(); why != "" {
				outcome, summary = api.OutcomeCanceled, "canceled: "+why
			}
			r.finish(outcome, summary)
			return
		}
	}

	// Queued jobs wait for the Mac, including for a human to power cycle it,
	// and on a Volunteer's Mac for its Availability window, but not for one
	// that left the lab.
	length := r.expectedLength()
	holdLocked := func() string {
		if v.d.State == api.StateLeft {
			return ""
		}
		if !v.aliveLocked() || (v.d.State != api.StateReady && v.d.State != api.StateNew) {
			return fmt.Sprintf("waiting for %s to be ready (%s)", j.Spec.Device, v.d.State)
		}
		return v.windowHoldLocked(length)
	}
	for {
		v.mu.Lock()
		why := holdLocked()
		v.mu.Unlock()
		if why == "" {
			break
		}
		r.state(api.JobQueued) // a job built from source waits as queued, too
		r.ev("%s", why)
		err := v.waitFor(ctx, 0, func() bool { return holdLocked() != why })
		if v.leaving() != "" {
			break
		}
		if err != nil {
			r.finish(api.OutcomeCanceled, "canceled while waiting for the device")
			return
		}
	}
	if why := v.leaving(); why != "" {
		r.finish(api.OutcomeCanceled, "canceled: "+why)
		return
	}

	if j.Spec.Mesa != nil {
		if _, err := s.validateMesa(j.Spec, v.snapshot()); err != nil {
			r.finish(api.OutcomeInfra, "Mesa admission changed before device commands: "+err.Error())
			return
		}
	}
	v.mu.Lock()
	v.d.ActiveJob = j.ID
	v.setStateLocked(api.StateBusy, "job "+j.ID)
	v.mu.Unlock()
	r.started = s.now()
	r.tellVolunteerJobStarting()
	if r.serialEnabled() {
		r.serial0 = s.serialOffset(v.d.Name)
	}
	defer func() {
		if r.serialEnabled() {
			s.copySerial(v.d.Name, r.serial0, j.ID)
		}
		v.mu.Lock()
		v.d.ActiveJob = ""
		if v.d.State == api.StateBusy || v.d.State == api.StateRecovering {
			v.setStateLocked(v.idleStateLocked(), "")
		}
		v.sendOwedDoneLocked()
		v.saveLocked()
		v.mu.Unlock()
	}()

	// A Mac still on a lab entry (an earlier job's restore failed or was cut
	// short) goes back to its known-good kernel before this job stages anything.
	if tag := v.snapshot().Health.JobTag; tag != "" {
		r.ev("%s is still on lab entry %s; restoring its known-good kernel first", j.Spec.Device, tag)
		if err := r.restore(ctx); err != nil {
			r.finish(api.OutcomeInfra, "could not restore the known-good kernel before the job: "+err.Error())
			return
		}
	}
	// Remove whatever earlier jobs left staged, every time: the agent's preflight
	// counts staged test kernels as free space, and labd's dirty flag doesn't
	// survive a restart. Cleanup is cheap when there's nothing to do.
	if err := v.call(ctx, api.CmdCleanup, "", api.CleanupArgs{All: true}, 2*time.Minute, nil); err == nil {
		v.mu.Lock()
		v.dirty = false
		v.mu.Unlock()
	}

	outcome, summary := r.execute(ctx)
	if ctx.Err() != nil && outcome != api.OutcomeCanceled {
		outcome, summary = r.canceledAfter(outcome, summary)
	}
	left := v.leaving()
	if left != "" {
		// Canceled whatever was seen: the agent stopping reads as the Mac
		// going down, which the job can't tell from the kernel's doing.
		outcome, summary = api.OutcomeCanceled, "canceled: "+left
	}
	// A Mac that left the lab mid-job leaves nothing to restore, and the job
	// is not a failure: it is cut short, as when a window closes.
	gone := v.goneReason()
	if gone != "" {
		outcome, summary = api.OutcomeIncomplete, "the Mac left the lab: "+gone
	}

	// Always put the Mac back on its known-good kernel, even after a cancel,
	// unless it is leaving the lab: its agent is stopping, so a restore would
	// only time out and walk the recovery ladder.
	rctx, cancel := s.withTimeout(s.ctx, 3*r.boot+5*time.Minute)
	defer cancel()
	switch {
	case gone != "":
		// nothing to put back: lab-agent returned the Mac to its own system as it left
	case left != "":
		r.ev("not restoring the known-good kernel: %s", left)
		summary += "; not restored: lab-agent uninstall clears the lab's one-shot and staged kernels"
	case v.snapshot().State != api.StateNeedsHands:
		if err := r.restore(rctx); err != nil {
			r.ev("restore: %v", err)
			if outcome == api.OutcomePass {
				outcome = api.OutcomeInfra
			}
			summary += "; restore failed: " + err.Error()
		}
	default:
		d := v.snapshot()
		who := "needs a human power cycle"
		if d.IsVolunteer() {
			// Maintainers can't; the Volunteer was asked on the Mac's own topic.
			who = "is waiting for its Volunteer to reset it"
		}
		summary += ". " + d.Name + " " + who + "; the lab cleans up the staged kernel when it is back"
	}
	if j.Spec.Baseline && outcome == api.OutcomePass {
		v.mu.Lock()
		v.d.KnownGood = v.d.Kernel
		v.saveLocked()
		v.mu.Unlock()
		summary += fmt.Sprintf(". %s is in the pool (known-good kernel %s)", j.Spec.Device, v.snapshot().Kernel)
	}
	if r.omtRef != nil {
		r.promoteOMT(outcome)
	}
	if r.noAppleWDT {
		summary += "; " + noAppleWDTNote
	}
	at := s.now()
	if r.ir != nil {
		// the evidence copy carries the final record, and can still fail the job
		outcome, summary = r.ir.seal(outcome, summary, at)
	}
	r.finishAt(outcome, summary, at)
	if outcome == api.OutcomeIncomplete && gone == "" {
		r.retry()
	}
}

// windowCut is the outcome of a job the Mac's Availability window closing
// (its end, or the Volunteer's Pause) cut short, what: incomplete, not failed.
// lab-agent stopped it by itself.
func windowCut(what string) (string, string) {
	return api.OutcomeIncomplete, "the Mac's Availability window closed " + what
}

// retry queues an incomplete job again as a new job; like any job on a
// Volunteer's Mac, it waits for a window it fits in. labd's own omarchy-m-test
// refreshes aren't retried: the next one is due anyway.
func (r *jobRun) retry() {
	if r.j.Spec.Holder == omtHolder {
		return
	}
	spec := r.j.Spec
	if spec.Source != "" && spec.Kernel != "" {
		// the kernel is built: the retry boots it again
		spec.Source, spec.Config = "", ""
	}
	j, _, err := r.s.submit(r.j.Maintainer, spec, r.j.ID)
	if err != nil {
		r.ev("not retried: %v", err)
		return
	}
	r.ev("retried in a later window as job %s", j.ID)
}

// canceledAfter is the outcome of a job canceled while it ran, given what
// execute made of it. A kernel failure seen before the cancel (a panic, a
// reboot or hang during a test, a test that failed by itself) is the
// kernel's whatever came next: it stays the outcome, with the cancel in the
// summary, so lab gate counts it and a retry's pass doesn't read as clean.
// Anything else, tests the cancel cut short among it, is the cancel's.
func (r *jobRun) canceledAfter(outcome, summary string) (string, string) {
	kernel := gateResult(outcome) == api.GateFail
	if outcome == api.OutcomeTestsFailed && r.failedOwn == 0 {
		kernel = false // only tests the cancel cut short failed
	}
	if kernel {
		r.ev("canceled after the kernel failed (%s): that stays the outcome", outcome)
		return outcome, summary + "; then the job was canceled"
	}
	return api.OutcomeCanceled, "canceled: " + summary
}

func (r *jobRun) finish(outcome, summary string) { r.finishAt(outcome, summary, r.s.now()) }

func (r *jobRun) finishAt(outcome, summary string, at time.Time) {
	r.s.updateJob(r.j, func(j *api.Job) {
		j.State, j.Outcome, j.Summary = api.JobDone, outcome, summary
		if j.Result.Mesa != nil && outcome != api.OutcomePass {
			j.Result.Mesa.Verdict = "FAIL"
			if outcome == api.OutcomeCanceled {
				j.Result.Mesa.Verdict = "INCOMPLETE"
			}
		}
		j.Events = append(j.Events, api.JobEvent{Time: at, Msg: "done: " + outcome + ": " + summary})
	})
	r.s.log.Printf("job %s done: %s: %s", r.j.ID, outcome, summary)
	r.tellVolunteerJobDone(outcome)
	if outcome != api.OutcomePass && outcome != api.OutcomeCanceled && outcome != api.OutcomeIncomplete {
		r.s.notify(Notification{Device: r.j.Spec.Device, Title: fmt.Sprintf("job %s on %s: %s", r.j.ID, r.j.Spec.Device, outcome), Body: summary, Priority: "low"})
	}
}

func (r *jobRun) execute(ctx context.Context) (string, string) {
	v, j := r.v, r.j

	if j.Spec.InstalledManifest != "" {
		ir, err := r.newInstalled()
		if err != nil {
			return api.OutcomeInfra, "installed job: " + err.Error()
		}
		r.ir = ir
		if v.snapshot().IsVolunteer() {
			r.ev("installed %s: manifest %s", ir.c.release, short(ir.c.manSHA))
			if o, sum := ir.volunteerInstall(ctx); o != "" {
				return o, sum
			}
		} else {
			r.ev("installed %s: manifest %s, installer entry %s", ir.c.release, short(ir.c.manSHA), short(ir.c.entrySHA))
		}
		// identity-before runs on whatever boot is current; it is not one of the job's tests
		r.state(api.JobTesting)
		tr := r.runTest(ctx, ir.test(installed.PhaseBefore))
		reason := ""
		if ir.c.entry == nil && !tr.Passed {
			reason = "identity-before did not observe the installer's entry: " + testVerdict(tr) + " " + tr.Error
		} else if ir.c.entry == nil {
			if err := ir.freezeObservedEntry(); err != nil {
				reason = "the installer's entry on the Mac can't be frozen: " + err.Error()
			}
		}
		if reason == "" {
			reason = ir.identity(installed.PhaseBefore, &tr)
		}
		ir.res.Before = &tr
		r.s.updateJob(j, func(j *api.Job) { j.Result.Installed = &ir.res })
		if reason != "" {
			return api.OutcomeTestsFailed, "installed state does not match the frozen expectation before boot: " + reason
		}
	}

	r.state(api.JobStaging)
	what := "current kernel"
	if j.Spec.Kernel != "" {
		what = "kernel " + short(j.Spec.Kernel)
	}
	if r.ir != nil {
		what = "installed " + r.ir.c.man.Kernel.Release + " through the installer's entry"
	}
	r.ev("staging %s", what)
	d := v.snapshot()
	args := api.StageArgs{Artifact: j.Spec.Kernel, Cmdline: j.Spec.Cmdline, Serial: r.serialEnabled(),
		CmdlineBase: j.Spec.CmdlineBase, CmdlineStrip: j.Spec.CmdlineStrip, Verbose: j.Spec.VerboseBoot,
		BootTimeoutSec: int(r.boot / time.Second)}
	if r.ir != nil {
		args = api.StageArgs{Serial: r.serialEnabled(), Installed: r.ir.stageArgs()}
	}
	args.WatchdogOpenTimeoutSec = int(r.s.cfg.WatchdogOpenTimeout / time.Second)
	sr, outcome, why := r.stage(ctx, args)
	if outcome != "" {
		return outcome, why
	}
	v.mu.Lock()
	v.dirty = true
	v.mu.Unlock()
	r.ev("staged %s as boot entry %s", sr.KernelRelease, sr.Entry)
	if sr.Cmdline != "" {
		r.ev("cmdline: %s", sr.Cmdline)
	}
	if sr.NoAppleWDT {
		r.noAppleWDT = true
		r.ev("warning: %s", noAppleWDTNote)
	}

	r.state(api.JobBooting)
	oldBoot := v.snapshot().BootID
	t0 := r.s.now()
	r.armedBoot, r.armedAt = oldBoot, t0
	arm := api.BootOnceArgs{Entry: sr.Entry, BootTimeoutSec: int(r.boot / time.Second), JobSec: int(r.labBootJob() / time.Second)}
	if j.Spec.Crash == "" {
		arm.Tests = r.tests()
	}
	armTimeout := 2 * time.Minute
	if d := v.snapshot(); d.IsVolunteer() && r.s.cfg.RebootWarning > 0 {
		arm.RebootWarningSec = int(r.s.cfg.RebootWarning / time.Second)
		armTimeout += r.s.cfg.RebootWarning
	}
	if err := v.call(ctx, api.CmdBootOnce, j.ID, arm, armTimeout, nil); errors.Is(err, errWindowClosed) {
		r.armedBoot = "" // nothing was armed: there is no reboot for restore to wait for
		return windowCut("before the Lab boot (" + err.Error() + ")")
	} else if errors.Is(err, errAccessLevel) {
		r.armedBoot = ""
		return accessCut("before the Lab boot (" + err.Error() + ")")
	} else if err != nil {
		return api.OutcomeInfra, "arming the one-shot boot failed: " + err.Error()
	}
	if arm.RebootWarningSec > 0 {
		// the boot's clocks start once armed, not when the Volunteer's warning did
		t0 = r.s.now()
		r.armedAt = t0
	}
	r.ev("one-shot armed, rebooting into %s", sr.Entry)
	v.rearmSerial(3 * time.Minute)
	steps, ok, err := v.waitBack(ctx, oldBoot, t0, r.boot, r.selfRecovery())
	r.addRecovery(steps)
	if err != nil {
		return api.OutcomeCanceled, "canceled while booting"
	}
	if !ok {
		o, cause := r.classify(t0, steps)
		return o, cause
	}
	d = v.snapshot()
	if d.Health.JobTag != j.ID {
		o, cause := r.classify(t0, steps)
		r.s.updateJob(j, func(j *api.Job) { j.Result.FellBack = true })
		r.ev("came back on %s instead of the test entry: %s", d.Kernel, cause)
		if lost := r.collectLost(ctx); lost.Deadline == api.DeadlineWindowClosed {
			return windowCut("during the Lab boot of " + sr.KernelRelease + ", which went back to " + d.Kernel + " before it reached labd")
		} else if lost.Deadline == api.DeadlineAccessLowered {
			return accessCut("during the Lab boot of " + sr.KernelRelease + ", which went back to " + d.Kernel + " before it reached labd")
		} else if lost.Deadline != "" {
			return api.OutcomeLostContact, fmt.Sprintf("%s booted but never reached labd; its %s deadline rebooted the Mac to %s",
				sr.KernelRelease, lost.Deadline, d.Kernel)
		}
		if j.Spec.Baseline {
			return api.OutcomeInfra, "the one-shot did not select the lab entry (check the maclab hook in custom.cfg): " + cause
		}
		if o == api.OutcomeBootFailed {
			cause = "test kernel did not come up; the Mac fell back to " + d.Kernel + ". " + cause
		}
		return o, cause
	}
	r.bootID, r.bootedAt = d.BootID, r.s.now()
	secs := r.s.since(t0).Seconds()
	r.s.updateJob(j, func(j *api.Job) {
		j.Result.Booted, j.Result.BootKernel, j.Result.BootSeconds, j.Result.BootCmdline = true, d.Kernel, secs, d.Cmdline
	})
	r.ev("booted %s in %.0fs", d.Kernel, secs)
	r.capture("after-boot")

	if j.Spec.Crash != "" {
		return r.crashTest(ctx)
	}

	if j.Spec.Mesa != nil {
		var mr api.MesaStageResult
		args := api.MesaStageArgs{Spec: *j.Spec.Mesa, BootID: r.bootID, Kernel: d.Kernel, CmdlineSHA256: mesa.Sum([]byte(d.Cmdline + "\n"))}
		if err := v.call(ctx, api.CmdMesaStage, j.ID, args, 4*time.Minute, &mr); err != nil {
			return api.OutcomeStageFailed, "staged Mesa: " + err.Error()
		}
		if !reSHA.MatchString(mr.ManifestSHA256) {
			return api.OutcomeInfra, "Mesa stage returned no manifest pin"
		}
		r.mesaManifest = mr.ManifestSHA256
		r.ev("staged Mesa packages in job-owned prefix; installed desktop unchanged")
	}
	r.state(api.JobTesting)
	failed := 0
	tests := r.tests()
	for _, t := range tests {
		if n := realSleepNote(v.snapshot(), t); n != "" {
			r.ev("warning: %s", n)
		}
		r.ev("test %s: running", t.Name)
		var tr api.TestResult
		err := v.callNote(ctx, api.CmdRunTest, j.ID, t, r.testTimeout(t), &tr, func(n string) { r.ev("%s", n) })
		if errors.Is(err, errDeviceLost) {
			return r.lostDuringTest(ctx, t.Name)
		}
		if errors.Is(err, errWindowClosed) {
			return windowCut("before test " + t.Name + " (" + err.Error() + ")")
		}
		if errors.Is(err, errAccessLevel) {
			return accessCut("during test " + t.Name + " (" + err.Error() + ")")
		}
		cut := err != nil && ctx.Err() != nil // by a cancel
		if err != nil {
			tr = api.TestResult{Name: t.Name, ExitCode: -1, Error: err.Error()}
		}
		if cut {
			tr.Error = "the job was canceled during this test"
		}
		if t.Builtin == omtTest && err == nil {
			r.omtResult(&tr)
		}
		if r.ir != nil && err == nil {
			switch t.Name {
			case installed.TestName(installed.PhaseBooted):
				r.ir.identity(installed.PhaseBooted, &tr)
			case installed.TestName(installed.PhaseAfter):
				r.ir.identity(installed.PhaseAfter, &tr)
			}
			r.s.updateJob(j, func(j *api.Job) { j.Result.Installed = &r.ir.res })
		}
		if t.Builtin == "mesa-provider" {
			if why := r.acceptMesa(&tr); why != "" {
				tr.Passed = false
				tr.Error = why
				tr.ExitCode = -1
			}
			r.s.updateJob(j, func(j *api.Job) {
				if tr.Mesa != nil {
					j.Result.Mesa = tr.Mesa
				}
			})
		}
		if !tr.Passed {
			failed++
			if !cut {
				r.failedOwn++
			}
		}
		r.s.updateJob(j, func(j *api.Job) { j.Result.Tests = append(j.Result.Tests, tr) })
		r.ev("test %s: %s", t.Name, testVerdict(tr))
		if j.Spec.Mesa != nil && t.Builtin == "boot-health" && !tr.Passed {
			r.ev("boot-health did not pass; remaining Mesa GPU suites/tests were not run")
			break
		}
	}
	nTests := len(tests)
	if omt := r.currentOMT(); omt != nil && (j.Spec.Publish || (r.s.cfg.OMTPublish && j.Spec.Baseline)) {
		if url, err := r.s.omtPublish(ctx, j); err != nil {
			r.ev("omarchy-m-test report not published: %v", err)
		} else {
			r.ev("omarchy-m-test report published: %s", url)
		}
	}

	r.capture("after-tests")
	r.state(api.JobCollecting)
	files, collectErr := r.collectE(ctx, "0")
	if b, err := os.ReadFile(filepath.Join(r.s.jobDir(j.ID), "boot0", "systemd-analyze.txt")); err == nil {
		if first, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n"); first != "" {
			r.ev("systemd-analyze: %s", first)
		}
	}
	var newLines []string
	var dmesgFatal []string
	var logsErr error
	if r.ir != nil {
		// an installed job is judged on its kernel log: without it, it can't pass
		if kern, warn, err := kernelLogs(r.s.jobDir(j.ID), "boot0", files, collectErr); err != nil {
			logsErr = err
			r.ir.fail("kernel log: %v", err)
		} else {
			dc := r.ir.dmesg(warn)
			newLines = dc.NewLines
			for _, h := range dc.FatalHits {
				dmesgFatal = append(dmesgFatal, h.Kind+": "+h.Line)
			}
			// the warning filter goes by priority; a fatal event logged lower
			// must still fail the job, so the full kernel log is checked too
			for _, h := range installed.FatalHits(string(kern)) {
				r.ir.res.KernelLogFatal = append(r.ir.res.KernelLogFatal, h.Kind+": "+h.Line)
				dmesgFatal = append(dmesgFatal, "kernel.txt "+h.Kind+": "+h.Line)
			}
		}
		r.s.updateJob(j, func(j *api.Job) { j.Result.Installed = &r.ir.res })
	}
	for _, f := range files {
		if strings.HasSuffix(f, "/dmesg-errors.txt") && r.ir == nil {
			got, _ := os.ReadFile(filepath.Join(r.s.jobDir(j.ID), f))
			if j.Spec.Baseline {
				// atomic, so a read-only reference (promotions before 0.7.3) is replaced too
				if err := writeFileAtomic(r.s.baselinePath(d.Name), got); err != nil {
					r.ev("kernel error baseline not updated: %v", err)
				}
			} else if base, err := os.ReadFile(r.s.baselinePath(d.Name)); err == nil {
				newLines = detect.NewLines(string(base), string(got))
			}
		}
	}
	events := v.eventsSince(r.started)
	var fatal []api.KernelEvent
	for _, e := range events {
		if e.BootID == r.bootID && detect.Fatal(e.Kind) {
			fatal = append(fatal, e)
		}
	}
	r.s.updateJob(j, func(j *api.Job) {
		j.Result.NewErrorLines = newLines
		j.Result.KernelEvents = events
	})
	health := v.snapshot().Health

	switch {
	case logsErr != nil:
		return api.OutcomeInfra, fmt.Sprintf("booted %s, but its kernel log is missing, so the installed run can't be judged: %v", d.Kernel, logsErr)
	case failed > 0:
		return api.OutcomeTestsFailed, fmt.Sprintf("booted %s; %d of %d tests failed", d.Kernel, failed, nTests)
	case len(dmesgFatal) > 0:
		return api.OutcomeUnhealthy, fmt.Sprintf("booted %s but its kernel errors include %s", d.Kernel, dmesgFatal[0])
	case len(fatal) > 0:
		return api.OutcomeUnhealthy, fmt.Sprintf("booted %s but the kernel logged %s: %s", d.Kernel, fatal[0].Kind, fatal[0].Line)
	case health.SystemState != "running" && health.SystemState != "degraded":
		return api.OutcomeUnhealthy, fmt.Sprintf("booted %s but systemd is %q", d.Kernel, health.SystemState)
	}
	sum := fmt.Sprintf("booted %s in %.0fs, %d tests passed", d.Kernel, secs, nTests)
	if r.ir != nil {
		sum += fmt.Sprintf(", identity %s/%s/%s, omt %s, kernel errors %s", r.ir.res.Verdicts[installed.PhaseBefore],
			r.ir.res.Verdicts[installed.PhaseBooted], r.ir.res.Verdicts[installed.PhaseAfter], r.ir.res.OMT, r.ir.res.Dmesg)
	}
	if len(newLines) > 0 {
		sum += fmt.Sprintf(", %d new kernel warning/error lines vs baseline", len(newLines))
	}
	return api.OutcomePass, sum
}

// stageBackoff is the pause before each further staging attempt.
var stageBackoff = []time.Duration{30 * time.Second, 2 * time.Minute}

// stage stages the job's kernel, or says why it couldn't. A failure may be a
// passing lab problem (a dropped download, a held ESP lock, leftovers filling
// the ESP), so it tries again after a pause, once the agent has removed what
// the failed attempt left half staged. That needs the attempt to be over: the
// agent answered with an error, or the Mac rebooted under it. After labd's
// timeout, or with the Mac quiet on the same boot, the agent may still be
// staging, and a cleanup and a second attempt would race it over the job's
// files, modules and boot entry; the job fails instead. The same error twice
// in a row looks permanent (a broken package, a refused cmdline) and ends it
// early.
func (r *jobRun) stage(ctx context.Context, args api.StageArgs) (sr api.StageResult, outcome, why string) {
	attempts := len(stageBackoff) + 1
	how := fmt.Sprintf(". Retry with `lab retry %s`", r.j.ID)
	last := ""
	for n := 1; ; n++ {
		sr = api.StageResult{}
		boot := r.v.snapshot().BootID
		err := r.v.call(ctx, api.CmdStage, r.j.ID, args, r.s.cfg.StageTimeout, &sr)
		if err == nil {
			return sr, "", ""
		}
		if ctx.Err() != nil {
			return sr, api.OutcomeStageFailed, "staging failed: " + err.Error()
		}
		if errors.Is(err, errWindowClosed) {
			outcome, why := windowCut("while staging (" + err.Error() + ")")
			return sr, outcome, why
		}
		if errors.Is(err, errDeviceLost) && r.v.windowClosed() {
			// Out of reach as its window closed: lab-agent stops staging by itself.
			outcome, why := windowCut("while staging, with the Mac out of reach")
			return sr, outcome, why
		}
		reason := strings.TrimPrefix(err.Error(), api.CmdStage+": ")
		if !errors.Is(err, errAgentRefused) && r.v.snapshot().BootID == boot {
			return sr, api.OutcomeStageFailed, "staging failed: " + reason + " (not tried again: the Mac may still be staging it)" + how
		}
		r.ev("staging attempt %d of %d failed: %s", n, attempts, reason)
		if errText(reason) == last {
			return sr, api.OutcomeStageFailed, "couldn't stage: " + reason + " (the same error twice: looks permanent, not retrying)" + how
		}
		if n == attempts {
			return sr, api.OutcomeStageFailed, fmt.Sprintf("couldn't stage: %s (%d attempts failed)%s", reason, attempts, how)
		}
		last = errText(reason)
		// what the failed attempt left behind may be what is in the way
		if err := r.v.call(ctx, api.CmdCleanup, r.j.ID, api.CleanupArgs{}, 2*time.Minute, nil); err != nil {
			r.ev("cleanup after the failed attempt: %v", err)
		}
		r.ev("staging again in %s", stageBackoff[n-1])
		select {
		case <-ctx.Done():
			return sr, api.OutcomeStageFailed, "canceled between staging attempts"
		case <-time.After(stageBackoff[n-1]):
		}
	}
}

var reDigits = regexp.MustCompile(`[0-9]+`)

// errText is an error's text with case, spacing and numbers (byte counts,
// free space, temporary names) evened out, to tell one error from another.
func errText(msg string) string {
	return reDigits.ReplaceAllString(strings.ToLower(strings.Join(strings.Fields(msg), " ")), "#")
}

// tests are the tests a job runs on its Lab boot.
func (r *jobRun) tests() []api.TestSpec {
	tests := testsFor(r.j.Spec)
	if r.ir != nil {
		tests = append(append([]api.TestSpec{r.ir.test(installed.PhaseBooted)}, tests...), r.ir.test(installed.PhaseAfter))
	}
	return tests
}

// testTimeout is how long labd gives a test: its own timeout and TestGrace,
// and a GUI test guiWait more.
func (r *jobRun) testTimeout(t api.TestSpec) time.Duration {
	timeout := time.Duration(t.TimeoutSec)*time.Second + r.s.cfg.TestGrace
	if t.TimeoutSec == 0 {
		timeout = 7 * time.Minute
	}
	return timeout + r.s.guiWait(t)
}

// labBootJob is how long the job can take from arming its Lab boot: the
// boot (with the time labd gives it to come back by itself), every test's
// timeout, collecting its logs. The Lab boot's hard ceiling is that far off;
// on a Volunteer's Mac lab-agent caps it at the Availability window's end.
func (r *jobRun) labBootJob() time.Duration {
	d := r.boot + r.noContactWait() + 5*time.Minute
	for _, t := range r.tests() {
		d += r.testTimeout(t)
	}
	return d
}

// expectedLength is how long the job is expected to hold the Mac, which on a
// Volunteer's Mac must fit in what's left of the Availability window: its
// staging, its Lab boot and, before an Installed run has its tests, its
// identity checks before, booted and after, and on a Volunteer's Mac the
// Reboot warning's wait.
func (r *jobRun) expectedLength() time.Duration {
	d := r.s.cfg.StageTimeout + r.labBootJob()
	if r.v.snapshot().IsVolunteer() {
		d += r.s.cfg.RebootWarning
	}
	if r.j.Spec.InstalledManifest != "" && r.ir == nil {
		const identityChecks = 3
		d += identityChecks * r.testTimeout(api.TestSpec{})
		if r.v.snapshot().IsVolunteer() {
			// the preinstall references and the install itself
			d += r.testTimeout(omtSpec()) + collectTimeout + api.InstallTimeout
		}
	}
	return d
}

// noContactWait is how long past its boot timeout a Lab boot gets to come back
// by itself: lab-agent's early unit reboots one that never reaches labd at its
// no-contact deadline (twice the boot timeout), and the Mac then needs a boot
// to check in.
func (r *jobRun) noContactWait() time.Duration { return 2 * r.boot }

// selfRecovery is how long past its boot timeout labd waits for a Lab boot to
// come back by itself before the recovery ladder. A Lab-owned Mac's OOB hard
// resets are the next rung. A Volunteer's Mac is asked for nothing until its
// Lab boot's hard ceiling (the job's end, or the Availability window's end if
// that comes first) plus one boot timeout have passed with no check-in: only
// then can it not have recovered by itself.
func (r *jobRun) selfRecovery() time.Duration {
	r.v.mu.Lock()
	defer r.v.mu.Unlock()
	if !r.v.d.IsVolunteer() {
		return r.noContactWait()
	}
	ceiling := r.labBootJob()
	if r.v.d.Window != nil {
		if st := window.Evaluate(*r.v.d.Window, r.s.now()); st.Open {
			ceiling = min(ceiling, st.End.Sub(r.s.now()))
		}
	}
	return max(ceiling, r.noContactWait())
}

const noAppleWDTNote = "the test kernel was built without apple_wdt: the watchdog U-Boot leaves running resets it about 60 s into every boot, healthy or not"

// runTest runs one test outside the job's test list (identity-before).
func (r *jobRun) runTest(ctx context.Context, t api.TestSpec) api.TestResult {
	r.ev("test %s: running", t.Name)
	var tr api.TestResult
	if err := r.v.callNote(ctx, api.CmdRunTest, r.j.ID, t, time.Duration(t.TimeoutSec)*time.Second+2*time.Minute, &tr, func(n string) { r.ev("%s", n) }); err != nil {
		tr = api.TestResult{Name: t.Name, ExitCode: -1, Error: err.Error()}
	}
	r.ev("test %s: %s", t.Name, testVerdict(tr))
	return tr
}

// guiWait is the extra time labd waits for test t: cfg.GUIGrace for a GUI
// test. The agent may wait up to 2 minutes for the desktop session, which a
// short timeout doesn't cut short, so its watchdog gives a GUI test that much
// more; waiting as long means a GUI test hung past its timeout on a test boot
// is reset while labd still waits for it, and the job blames it.
func (s *Server) guiWait(t api.TestSpec) time.Duration {
	if t.GUI {
		return s.cfg.GUIGrace
	}
	return 0
}

func (r *jobRun) currentOMT() *api.OMTResult {
	j, err := r.s.store.job(r.j.ID)
	if err != nil {
		return nil
	}
	return j.Result.OMT
}

func testVerdict(t api.TestResult) string {
	switch {
	case t.Passed:
		return fmt.Sprintf("pass (%.0fs)", t.Seconds)
	case t.Skipped:
		return "skipped (not a pass): " + t.Error
	case t.TimedOut:
		return "timed out"
	case t.Error != "":
		return "error: " + t.Error
	}
	return fmt.Sprintf("fail (exit %d)", t.ExitCode)
}

// realSleepNote warns that a suspend-* test needs a person on an Apple
// Silicon Mac: its RTC has no wakealarm, so neither the Mac nor the lab can
// wake it, and an OOB reset only ends the boot. The builtin suspend-devices
// resumes by itself (pm_test).
func realSleepNote(d api.Device, t api.TestSpec) string {
	if !strings.HasPrefix(t.Name, "suspend-") || t.Builtin == "suspend-devices" || !strings.HasPrefix(d.Facts.DTModel, "Apple ") {
		return ""
	}
	n := fmt.Sprintf("test %s puts %s to sleep, and it can't wake itself (Apple Silicon's RTC has no wakealarm): someone must press a key on it", t.Name, d.Name)
	if d.OOB != nil {
		n += "; an OOB reset would end the test"
	}
	return n
}

func testsFor(spec api.JobSpec) []api.TestSpec {
	tests := append([]api.TestSpec{}, spec.Tests...)
	if spec.Mesa != nil {
		timeout := 120
		if spec.Mesa.OfficialGPU {
			timeout = 2100
		}
		health := api.TestSpec{Name: "boot-health", Builtin: "boot-health", TimeoutSec: 180}
		rest := make([]api.TestSpec, 0, len(tests))
		found := false
		for _, test := range tests {
			if test.Builtin == "boot-health" {
				if !found {
					health = test
					found = true
					continue
				}
			}
			rest = append(rest, test)
		}
		// Explicit caller-selected boot-health settings are preserved, but it
		// always precedes mandatory GL/Vulkan and any future official suite.
		return append([]api.TestSpec{health, {Name: "mesa-provider", Builtin: "mesa-provider", TimeoutSec: timeout}}, rest...)
	}
	for _, test := range tests {
		if test.Builtin == "boot-health" {
			return tests
		}
	}
	return append([]api.TestSpec{{Name: "boot-health", Builtin: "boot-health", TimeoutSec: 180}}, tests...)
}

func (r *jobRun) addRecovery(steps []string) {
	if len(steps) == 0 {
		return
	}
	r.s.updateJob(r.j, func(j *api.Job) { j.Result.Recovery = append(j.Result.Recovery, steps...) })
	for _, s := range steps {
		r.ev("recovery: %s", s)
	}
}

// classify names what went wrong from the kernel events seen since t0.
func (r *jobRun) classify(t0 time.Time, steps []string) (string, string) {
	events := r.v.eventsSince(t0)
	r.s.updateJob(r.j, func(j *api.Job) { j.Result.KernelEvents = events })
	var worst *api.KernelEvent
	for i := range events {
		if worst == nil || detect.Severity(events[i].Kind) > detect.Severity(worst.Kind) {
			worst = &events[i]
		}
	}
	if worst != nil && detect.Fatal(worst.Kind) {
		switch worst.Kind {
		case detect.SoftLockup, detect.HardLockup, detect.RCUStall, detect.HungTask:
			return api.OutcomeHung, fmt.Sprintf("kernel hung (%s): %s", worst.Kind, worst.Line)
		}
		return api.OutcomePanicked, fmt.Sprintf("kernel crashed (%s): %s", worst.Kind, worst.Line)
	}
	if r.networkOnly() {
		d := r.v.snapshot()
		if d.State == api.StateNeedsHands || !r.v.alive() {
			return api.OutcomeUnknown, "network-only: no return was observed; serial diagnosis and hard reset were disabled"
		}
	}
	for _, s := range steps {
		if strings.HasPrefix(s, "detected: ") {
			return api.OutcomeHung, "stopped responding with no kernel error captured (" + strings.TrimPrefix(s, "detected: ") + ")"
		}
	}
	return api.OutcomeBootFailed, "no kernel error was captured; see serial.log and prevboot/journal.txt"
}

// quickReboot splits a reboot during a test that left no kernel error by how
// long the Mac was silent: from the last check-in labd heard on the test boot
// to the first one on the next boot. Within it reads as a crash, beyond it as
// a watchdog reset after a hang. It is an inference, not a diagnosis. On an M1
// MacBook Air without serial, a sysrq crash (panic=10) was back ~67s after its
// test started (10s to reboot, ~55s to boot). The hardware watchdog waits 60s
// before it resets: a stopped lab-agent was back after ~114s, and a test stuck
// in the kernel, reset once its time budget ran out, after ~233s.
var quickReboot = 90 * time.Second

func (r *jobRun) lostDuringTest(ctx context.Context, test string) (string, string) {
	r.ev("lost the Mac during test %s; waiting for it to come back", test)
	lost := r.s.now()
	// A hang has already had quietGrace of silence to show itself.
	steps, ok, err := r.v.waitBack(ctx, r.bootID, r.bootedAt, max(r.boot-r.s.quietGrace(), time.Minute), 0)
	r.addRecovery(steps)
	o, cause := r.classify(r.bootedAt.Add(-time.Second), steps)
	if o == api.OutcomeBootFailed {
		// Nothing says panic: only how long it took to come back hints at what happened.
		o, cause = api.OutcomeCrashedOrHung, "the Mac rebooted with no kernel error captured"
		if gap, back := r.v.silentFor(r.bootID); back {
			cause = fmt.Sprintf("back %.0f s after it went silent: ", gap.Seconds())
			if gap <= quickReboot {
				cause += "quick, like a kernel panic (panic=10 reboots in seconds)"
			} else {
				cause += "slow, like a watchdog reset after a hang (a crash usually comes back in about a minute)"
			}
		}
	}
	r.s.updateJob(r.j, func(j *api.Job) {
		j.Result.Tests = append(j.Result.Tests, api.TestResult{Name: test, ExitCode: -1, Error: "the kernel went down during this test"})
	})
	if err == nil && ok {
		r.ev("back after %.0fs", r.s.since(lost).Seconds())
		switch lostBoot := r.collectLost(ctx); lostBoot.Deadline {
		case "":
		case api.DeadlineWindowClosed:
			return windowCut("during test " + test + ": lab-agent rebooted the Mac to " + r.v.snapshot().Kernel)
		case api.DeadlineAccessLowered:
			return accessCut("during test " + test + ": lab-agent rebooted the Mac to " + r.v.snapshot().Kernel)
		default:
			o, cause = api.OutcomeLostContact, fmt.Sprintf("labd lost the Lab boot and its %s deadline rebooted it", lostBoot.Deadline)
		}
	}
	if o == api.OutcomeCrashedOrHung {
		return o, fmt.Sprintf("crashed or hung during test %s: %s", test, cause)
	}
	return o, fmt.Sprintf("during test %s: %s", test, cause)
}

func (r *jobRun) crashTest(ctx context.Context) (string, string) {
	r.state(api.JobTesting)
	old := r.bootID
	t0 := r.s.now()
	r.ev("triggering a deliberate kernel %s", r.j.Spec.Crash)
	r.v.send(api.CmdCrash, r.j.ID, api.CrashArgs{Mode: r.j.Spec.Crash})
	r.v.rearmSerial(3 * time.Minute)
	steps, ok, err := r.v.waitBack(ctx, old, t0, r.boot, 0)
	r.addRecovery(steps)
	if err != nil {
		return api.OutcomeCanceled, "canceled during crash test"
	}
	if !ok {
		return api.OutcomeHung, "the Mac did not recover from a deliberate panic"
	}
	r.collectLost(ctx)
	d := r.v.snapshot()
	took := r.s.since(t0).Seconds()
	if len(steps) == 0 {
		return api.OutcomePass, fmt.Sprintf("recovered by itself in %.0fs (panic reboot + one-shot fallback to %s)", took, d.Kernel)
	}
	return api.OutcomePass, fmt.Sprintf("recovered in %.0fs, but only via the recovery ladder (%s); check kernel.panic", took, strings.Join(steps, "; "))
}

// collectLost brings back what is left of the Lab boot the Mac came back
// from: its journal by boot ID and any pstore/ramoops records.
func (r *jobRun) collectLost(ctx context.Context) api.LostBoot {
	var lost api.LostBoot
	if err := r.v.call(ctx, api.CmdCollectLost, r.j.ID, nil, 5*time.Minute, &lost); err != nil {
		r.ev("collect the lost boot's logs: %v", err)
		return lost
	}
	r.s.updateJob(r.j, func(j *api.Job) { j.Result.Logs = append(j.Result.Logs, lost.Files...) })
	switch {
	case lost.BootID == "":
		r.ev("the lost boot left no journal")
	case lost.Deadline != "":
		r.ev("lost boot %s never reached labd; the %s deadline rebooted it", lost.BootID, lost.Deadline)
	default:
		r.ev("collected the lost boot %s", lost.BootID)
	}
	return lost
}

func (r *jobRun) collectE(ctx context.Context, boot string) ([]string, error) {
	return r.collectInto(ctx, boot, "")
}

// collectTimeout is how long labd gives a Mac to collect a boot's logs.
const collectTimeout = 5 * time.Minute

// collectInto collects a boot's logs into the job's dir: "" is lab-agent's
// own choice (boot0, or prevboot for "-1").
func (r *jobRun) collectInto(ctx context.Context, boot, dir string) ([]string, error) {
	var files []string
	if err := r.v.call(ctx, api.CmdCollect, r.j.ID, api.CollectArgs{Boot: boot, Dir: dir}, collectTimeout, &files); err != nil {
		r.ev("collect logs (boot %s): %v", boot, err)
		return nil, err
	}
	r.s.updateJob(r.j, func(j *api.Job) { j.Result.Logs = append(j.Result.Logs, files...) })
	return files, nil
}

// restore gets the Mac back onto its known-good kernel and removes the staged one.
func (r *jobRun) restore(ctx context.Context) error {
	v := r.v
	r.state(api.JobRestoring)
	// A job canceled while the Mac reboots into its test kernel must let that
	// boot finish: deciding now would see the old boot, skip the reboot to the
	// known-good kernel, and leave the Mac on the test kernel.
	if r.armedBoot != "" {
		v.mu.Lock()
		pending := v.d.BootID == r.armedBoot || !v.aliveLocked()
		v.mu.Unlock()
		if pending {
			r.ev("waiting for %s to finish rebooting before restoring", r.j.Spec.Device)
			steps, _, err := v.waitBack(ctx, r.armedBoot, r.armedAt, r.boot, r.selfRecovery())
			r.addRecovery(steps)
			if err != nil {
				return err
			}
		}
	}
	d := v.snapshot()
	if d.Health.JobTag != "" {
		r.ev("rebooting back to the known-good kernel")
		t0 := r.s.now()
		v.send(api.CmdReboot, r.j.ID, nil)
		v.rearmSerial(3 * time.Minute)
		steps, ok, err := v.waitBack(ctx, d.BootID, t0, r.boot, 0)
		r.addRecovery(steps)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("did not come back after rebooting to the known-good kernel")
		}
		d = v.snapshot()
		if d.Health.JobTag != "" {
			v.setState(api.StateNew, "one-shot boot did not clear")
			return fmt.Errorf("the one-shot did not clear: a normal reboot came back on lab entry %s. The bootloader did not clear the one-shot (GRUB's ESP env file, or Limine's LoaderEntryOneShot); the Mac is out of the pool until this is fixed", d.Health.JobTag)
		}
		r.ev("back on %s", d.Kernel)
	}
	if err := v.call(ctx, api.CmdCleanup, r.j.ID, api.CleanupArgs{}, 2*time.Minute, nil); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	v.mu.Lock()
	v.dirty = false
	kg := v.d.KnownGood
	v.mu.Unlock()
	if kg != "" && d.Kernel != kg {
		r.ev("warning: running %s, but the known-good kernel is %s", d.Kernel, kg)
	}
	return nil
}

// build resolves the job's source and waits for its kernel. It returns an
// outcome only on failure.
func (r *jobRun) build(ctx context.Context) (string, string) {
	r.state(api.JobBuilding)
	r.ev("resolving %s", r.j.Spec.Source)
	b, err := r.s.EnsureBuild(ctx, api.BuildRequest{Source: r.j.Spec.Source, Device: r.j.Spec.Device, Config: r.j.Spec.Config})
	if err != nil {
		return api.OutcomeBuildFailed, err.Error()
	}
	r.s.updateJob(r.j, func(j *api.Job) { j.Spec.Build = b.ID })
	src := b.Source
	ref := src.Ref
	if ref == "" {
		ref = "HEAD"
	}
	if b.State == api.BuildDone {
		r.ev("reusing %s: already built from %s@%s %s (build %s)", b.Release, shortRepo(src.Repo), ref, src.SHA[:12], b.ID)
	} else {
		whose := r.j.Spec.Device + "'s config"
		if b.ConfigName != "" || r.j.Spec.Config != "" {
			whose = "config " + orStr(b.ConfigName, short(r.j.Spec.Config))
		}
		r.ev("building %s@%s %s with %s (build %s)", shortRepo(src.Repo), ref, src.SHA[:12], whose, b.ID)
		r.s.builds.mu.Lock()
		builders := 0
		for _, t := range r.s.builds.builders {
			if r.s.since(t) < time.Minute {
				builders++
			}
		}
		r.s.builds.mu.Unlock()
		if builders == 0 {
			r.ev("no builder host is connected; the build waits until one is")
		}
	}
	lastStage := ""
	b, err = r.s.waitBuild(ctx, b.ID, func(b *api.Build) {
		if b.State == api.BuildRunning && b.Stage != "" && b.Stage != lastStage && b.Stage != "done" {
			lastStage = b.Stage
			r.ev("build: %s", b.Stage)
		}
	})
	if err != nil {
		return api.OutcomeCanceled, "canceled while building"
	}
	if log, err := os.ReadFile(filepath.Join(r.s.buildDir(b.ID), "build.log")); err == nil {
		os.MkdirAll(r.s.jobDir(r.j.ID), 0o755)
		os.WriteFile(filepath.Join(r.s.jobDir(r.j.ID), "build.log"), log, 0o644)
		r.s.updateJob(r.j, func(j *api.Job) { j.Result.Logs = append(j.Result.Logs, "build.log") })
	}
	if b.State != api.BuildDone {
		tail := strings.Join(r.s.buildLogTail(b.ID, 4), " | ")
		return api.OutcomeBuildFailed, fmt.Sprintf("build %s %s: %s. %s", b.ID, b.State, b.Error, tail)
	}
	r.s.updateJob(r.j, func(j *api.Job) { j.Spec.Kernel = b.Artifact })
	r.ev("kernel %s ready (%d MB, built in %s)", b.Release, b.Size>>20, time.Duration(b.Seconds)*time.Second)
	return "", ""
}

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
	"github.com/iconidentify/maclab/internal/installed"
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

	ir *installedRun // installed-kernel jobs only

	omtRef []byte // a known-good run's omarchy-m-test reference, written only if the job passes
}

func (r *jobRun) ev(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.s.log.Printf("job %s (%s): %s", r.j.ID, r.j.Spec.Device, msg)
	r.s.updateJob(r.j, func(j *api.Job) { j.Events = append(j.Events, api.JobEvent{Time: time.Now(), Msg: msg}) })
}

func (r *jobRun) state(st api.JobState) {
	r.s.updateJob(r.j, func(j *api.Job) { j.State = st })
}

// deviceLoop runs one device's jobs in order and tidies up after incidents.
func (s *Server) deviceLoop(v *dev) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-v.gone:
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
		case <-tick.C:
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
	if j.Spec.BootTimeoutSec > 0 {
		r.boot = time.Duration(j.Spec.BootTimeoutSec) * time.Second
	}

	// A source is built (or an identical earlier build reused) before the Mac is needed.
	if j.Spec.Source != "" && j.Spec.Kernel == "" {
		if outcome, summary := r.build(ctx); outcome != "" {
			r.finish(outcome, summary)
			return
		}
	}

	// Queued jobs wait for the Mac, including for a human to power cycle it.
	v.mu.Lock()
	ready := v.aliveLocked() && (v.d.State == api.StateReady || v.d.State == api.StateNew)
	v.mu.Unlock()
	if !ready {
		r.ev("waiting for %s to be ready (%s)", j.Spec.Device, v.snapshot().State)
		if err := v.waitFor(ctx, 0, func() bool {
			return v.aliveLocked() && (v.d.State == api.StateReady || v.d.State == api.StateNew)
		}); err != nil {
			r.finish(api.OutcomeCanceled, "canceled while waiting for the device")
			return
		}
	}

	v.mu.Lock()
	v.d.ActiveJob = j.ID
	v.setStateLocked(api.StateBusy, "job "+j.ID)
	v.mu.Unlock()
	r.started = time.Now()
	r.serial0 = s.serialOffset(v.d.Name)
	defer func() {
		s.copySerial(v.d.Name, r.serial0, j.ID)
		v.mu.Lock()
		v.d.ActiveJob = ""
		if v.d.State == api.StateBusy || v.d.State == api.StateRecovering {
			v.setStateLocked(v.idleStateLocked(), "")
		}
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
		outcome, summary = api.OutcomeCanceled, "canceled: "+summary
	}

	// Always put the Mac back on its known-good kernel, even after a cancel.
	rctx, cancel := context.WithTimeout(s.ctx, 3*r.boot+5*time.Minute)
	defer cancel()
	if v.snapshot().State != api.StateNeedsHands {
		if err := r.restore(rctx); err != nil {
			r.ev("restore: %v", err)
			if outcome == api.OutcomePass {
				outcome = api.OutcomeInfra
			}
			summary += "; restore failed: " + err.Error()
		}
	} else {
		summary += ". " + v.snapshot().Name + " needs a human power cycle; the lab cleans up the staged kernel when it is back"
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
	at := time.Now()
	if r.ir != nil {
		// the evidence copy carries the final record, and can still fail the job
		outcome, summary = r.ir.seal(outcome, summary, at)
	}
	r.finishAt(outcome, summary, at)
}

func (r *jobRun) finish(outcome, summary string) { r.finishAt(outcome, summary, time.Now()) }

func (r *jobRun) finishAt(outcome, summary string, at time.Time) {
	r.s.updateJob(r.j, func(j *api.Job) {
		j.State, j.Outcome, j.Summary = api.JobDone, outcome, summary
		j.Events = append(j.Events, api.JobEvent{Time: at, Msg: "done: " + outcome + ": " + summary})
	})
	r.s.log.Printf("job %s done: %s: %s", r.j.ID, outcome, summary)
	if outcome != api.OutcomePass && outcome != api.OutcomeCanceled {
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
		r.ev("installed %s: manifest %s, installer entry %s", ir.c.release, short(ir.c.manSHA), short(ir.c.entrySHA))
		// identity-before runs on whatever boot is current; it is not one of the job's tests
		r.state(api.JobTesting)
		tr := r.runTest(ctx, ir.test(installed.PhaseBefore))
		reason := ir.identity(installed.PhaseBefore, &tr)
		ir.res.Before = &tr
		r.s.updateJob(j, func(j *api.Job) { j.Result.Installed = &ir.res })
		if reason != "" {
			return api.OutcomeTestsFailed, "installed state does not match the frozen expectation before boot: " + reason
		}
	}

	r.state(api.JobStaging)
	var sr api.StageResult
	what := "current kernel"
	if j.Spec.Kernel != "" {
		what = "kernel " + short(j.Spec.Kernel)
	}
	if r.ir != nil {
		what = "installed " + r.ir.c.man.Kernel.Release + " through the installer's entry"
	}
	r.ev("staging %s", what)
	d := v.snapshot()
	args := api.StageArgs{Artifact: j.Spec.Kernel, Cmdline: j.Spec.Cmdline, Serial: d.OOB != nil,
		CmdlineBase: j.Spec.CmdlineBase, CmdlineStrip: j.Spec.CmdlineStrip, Verbose: j.Spec.VerboseBoot}
	if r.ir != nil {
		args = api.StageArgs{Serial: d.OOB != nil, Installed: r.ir.stageArgs()}
	}
	if err := v.call(ctx, api.CmdStage, j.ID, args, 20*time.Minute, &sr); err != nil {
		return api.OutcomeStageFailed, "staging failed: " + err.Error()
	}
	v.mu.Lock()
	v.dirty = true
	v.mu.Unlock()
	r.ev("staged %s as boot entry %s", sr.KernelRelease, sr.Entry)
	if sr.Cmdline != "" {
		r.ev("cmdline: %s", sr.Cmdline)
	}

	r.state(api.JobBooting)
	oldBoot := v.snapshot().BootID
	t0 := time.Now()
	r.armedBoot, r.armedAt = oldBoot, t0
	if err := v.call(ctx, api.CmdBootOnce, j.ID, api.BootOnceArgs{Entry: sr.Entry}, 2*time.Minute, nil); err != nil {
		return api.OutcomeInfra, "arming the one-shot boot failed: " + err.Error()
	}
	r.ev("one-shot armed, rebooting into %s", sr.Entry)
	v.rearmSerial(3 * time.Minute)
	steps, ok, err := v.waitBack(ctx, oldBoot, t0, r.boot)
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
		r.collect(ctx, "-1")
		if j.Spec.Baseline {
			return api.OutcomeInfra, "the one-shot did not select the lab entry (check the maclab hook in custom.cfg): " + cause
		}
		if o == api.OutcomeBootFailed {
			cause = "test kernel did not come up; the Mac fell back to " + d.Kernel + ". " + cause
		}
		return o, cause
	}
	r.bootID, r.bootedAt = d.BootID, time.Now()
	secs := time.Since(t0).Seconds()
	r.s.updateJob(j, func(j *api.Job) {
		j.Result.Booted, j.Result.BootKernel, j.Result.BootSeconds, j.Result.BootCmdline = true, d.Kernel, secs, d.Cmdline
	})
	r.ev("booted %s in %.0fs", d.Kernel, secs)
	r.capture("after-boot")

	if j.Spec.Crash != "" {
		return r.crashTest(ctx)
	}

	r.state(api.JobTesting)
	failed := 0
	tests := testsFor(j.Spec)
	if r.ir != nil {
		tests = append(append([]api.TestSpec{r.ir.test(installed.PhaseBooted)}, tests...), r.ir.test(installed.PhaseAfter))
	}
	for _, t := range tests {
		timeout := time.Duration(t.TimeoutSec)*time.Second + 2*time.Minute
		if t.TimeoutSec == 0 {
			timeout = 7 * time.Minute
		}
		r.ev("test %s: running", t.Name)
		var tr api.TestResult
		err := v.callNote(ctx, api.CmdRunTest, j.ID, t, timeout, &tr, func(n string) { r.ev("%s", n) })
		if errors.Is(err, errDeviceLost) {
			return r.lostDuringTest(ctx, t.Name)
		}
		if err != nil {
			tr = api.TestResult{Name: t.Name, ExitCode: -1, Error: err.Error()}
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
		if !tr.Passed {
			failed++
		}
		r.s.updateJob(j, func(j *api.Job) { j.Result.Tests = append(j.Result.Tests, tr) })
		r.ev("test %s: %s", t.Name, testVerdict(tr))
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
		if kern, warn, err := kernelLogs(r.s.jobDir(j.ID), files, collectErr); err != nil {
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
	case t.TimedOut:
		return "timed out"
	case t.Error != "":
		return "error: " + t.Error
	}
	return fmt.Sprintf("fail (exit %d)", t.ExitCode)
}

func testsFor(spec api.JobSpec) []api.TestSpec {
	tests := spec.Tests
	for _, t := range tests {
		if t.Builtin == "boot-health" {
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
	lost := time.Now()
	// A hang has already had quietGrace of silence to show itself.
	steps, ok, err := r.v.waitBack(ctx, r.bootID, r.bootedAt, max(r.boot-quietGrace, time.Minute))
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
		r.ev("back after %.0fs", time.Since(lost).Seconds())
		r.collect(ctx, "-1")
	}
	if o == api.OutcomeCrashedOrHung {
		return o, fmt.Sprintf("crashed or hung during test %s: %s", test, cause)
	}
	return o, fmt.Sprintf("during test %s: %s", test, cause)
}

func (r *jobRun) crashTest(ctx context.Context) (string, string) {
	r.state(api.JobTesting)
	old := r.bootID
	t0 := time.Now()
	r.ev("triggering a deliberate kernel %s", r.j.Spec.Crash)
	r.v.send(api.CmdCrash, r.j.ID, api.CrashArgs{Mode: r.j.Spec.Crash})
	r.v.rearmSerial(3 * time.Minute)
	steps, ok, err := r.v.waitBack(ctx, old, t0, r.boot)
	r.addRecovery(steps)
	if err != nil {
		return api.OutcomeCanceled, "canceled during crash test"
	}
	if !ok {
		return api.OutcomeHung, "the Mac did not recover from a deliberate panic"
	}
	r.collect(ctx, "-1")
	d := r.v.snapshot()
	took := time.Since(t0).Seconds()
	if len(steps) == 0 {
		return api.OutcomePass, fmt.Sprintf("recovered by itself in %.0fs (panic reboot + one-shot fallback to %s)", took, d.Kernel)
	}
	return api.OutcomePass, fmt.Sprintf("recovered in %.0fs, but only via the recovery ladder (%s); check kernel.panic", took, strings.Join(steps, "; "))
}

func (r *jobRun) collect(ctx context.Context, boot string) []string {
	files, _ := r.collectE(ctx, boot)
	return files
}

func (r *jobRun) collectE(ctx context.Context, boot string) ([]string, error) {
	var files []string
	if err := r.v.call(ctx, api.CmdCollect, r.j.ID, api.CollectArgs{Boot: boot}, 5*time.Minute, &files); err != nil {
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
			steps, _, err := v.waitBack(ctx, r.armedBoot, r.armedAt, r.boot)
			r.addRecovery(steps)
			if err != nil {
				return err
			}
		}
	}
	d := v.snapshot()
	if d.Health.JobTag != "" {
		r.ev("rebooting back to the known-good kernel")
		t0 := time.Now()
		v.send(api.CmdReboot, r.j.ID, nil)
		v.rearmSerial(3 * time.Minute)
		steps, ok, err := v.waitBack(ctx, d.BootID, t0, r.boot)
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
			if time.Since(t) < time.Minute {
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

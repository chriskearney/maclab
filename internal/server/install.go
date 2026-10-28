package server

// An Installed run on a Volunteer's Mac installs the Release itself, through
// the named install operation lab-agent allows at Qualification and records
// in its Audit log. Before the install, the run takes the preinstall
// references from the Volunteer's own system; after it, identity-before
// reads the installer's entry on the Mac and the run freezes it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/installed"
)

// preinstallTest is the omarchy-m-test run that takes a Volunteer's Mac's
// preinstall reference, on its own system before the install.
const preinstallTest = omtTest + "-preinstall"

// volunteerInstall takes the preinstall references, unless this Release's
// are already frozen for the Mac, and installs the Release. It returns an
// outcome only when the run ends there.
func (ir *installedRun) volunteerInstall(ctx context.Context) (string, string) {
	r := ir.r
	if ir.c.noPreinstall == nil {
		r.ev("installed: %s's preinstall references for %s are already frozen", r.j.Spec.Device, ir.c.release)
	} else if o, sum := ir.takePreinstall(ctx); o != "" {
		return o, sum
	}
	return ir.install(ctx)
}

// takePreinstall runs omarchy-m-test and collects the kernel's error lines on
// the Volunteer's own system, and freezes them as the Release's preinstall
// references for the Mac, pinned in PINS.preinstall.
func (ir *installedRun) takePreinstall(ctx context.Context) (string, string) {
	r, dev := ir.r, ir.r.j.Spec.Device
	r.state(api.JobTesting)
	r.ev("taking the preinstall references from %s's own system", dev)
	t := omtSpec()
	t.Name, t.SkipOnScreen = preinstallTest, true
	var tr api.TestResult
	err := r.v.callNote(ctx, api.CmdRunTest, r.j.ID, t, r.testTimeout(t), &tr, func(n string) { r.ev("%s", n) })
	if o, sum := ir.cut(err, "while taking the preinstall references"); o != "" {
		return o, sum
	}
	if err == nil && !tr.Passed {
		err = errors.New(testVerdict(tr) + " " + tr.Error)
	}
	if err != nil {
		return api.OutcomeInfra, "the preinstall omarchy-m-test failed: " + err.Error()
	}
	jobDir := r.s.jobDir(r.j.ID)
	report, err := os.ReadFile(filepath.Join(jobDir, "test-"+preinstallTest, "omt-report.json"))
	if err != nil {
		return api.OutcomeInfra, "the preinstall omarchy-m-test wrote no report"
	}
	status, _, kernel, err := installed.ReportStatus(report)
	if err != nil {
		return api.OutcomeInfra, "the preinstall omarchy-m-test report: " + err.Error()
	}
	files, err := r.collectInto(ctx, "0", "preinstall")
	if o, sum := ir.cut(err, "while taking the preinstall references"); o != "" {
		return o, sum
	}
	_, warn, err := kernelLogs(jobDir, "preinstall", files, err)
	if err != nil {
		return api.OutcomeInfra, "the preinstall kernel errors: " + err.Error()
	}
	if err := ir.freezePreinstall(report, status, warn); err != nil {
		return api.OutcomeInfra, "freezing the preinstall references: " + err.Error()
	}
	r.ev("froze %s's preinstall references for %s, taken on %s", dev, ir.c.release, kernel)
	return "", ""
}

// freezePreinstall publishes the Mac's preinstall references into the frozen
// store, whole or not at all, and pins them.
func (ir *installedRun) freezePreinstall(report []byte, status map[string]string, dmesg []byte) error {
	r, dev := ir.r, ir.r.j.Spec.Device
	stage := filepath.Join(r.s.jobDir(r.j.ID), "preinstall-references")
	sb, _ := json.Marshal(status)
	jb, _ := json.Marshal(map[string]string{"id": r.j.ID})
	files := map[string][]byte{"omt-report.json": report, "omt-status.json": sb, "dmesg-errors.txt": dmesg, "baseline-job.json": jb}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(stage, name), b, 0o644); err != nil {
			return err
		}
	}
	dst := filepath.Join(ir.c.dir, "preinstall", dev)
	if err := moveUnpinned(dst, r.j.ID); err != nil {
		return err
	}
	if err := publishDir(stage, dst, ""); err != nil {
		return err
	}
	pins := fmt.Sprintf("# preinstall/%s %s by maclab, from %s's own system in job %s: do not rewrite\n", dev, r.s.now().Format(time.RFC3339), dev, r.j.ID)
	for _, name := range []string{"baseline-job.json", "dmesg-errors.txt", "omt-report.json", "omt-status.json"} {
		pins += installed.SHA256(files[name]) + "  preinstall/" + dev + "/" + name + "\n"
	}
	// one append, so runs on two Macs of the Release don't interleave lines
	if err := appendSynced(filepath.Join(ir.c.dir, "PINS.preinstall"), pins); err != nil {
		return err
	}
	c, err := r.s.loadInstalled(r.j.Spec.InstalledManifest, dev)
	if err == nil && c.noPreinstall != nil {
		err = c.noPreinstall
	}
	if err != nil {
		return err
	}
	ir.c = c
	return nil
}

// moveUnpinned moves aside what a freeze that failed before its pins left at
// path: nothing ever trusted it, and the frozen store is written once.
func moveUnpinned(path, job string) error {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	return os.Rename(path, filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".unpinned-"+job))
}

// install installs the Release on the Mac through the named install
// operation.
func (ir *installedRun) install(ctx context.Context) (string, string) {
	r, m := ir.r, ir.c.man
	args := api.InstallArgs{Release: ir.c.release, Kernel: m.Kernel.Release}
	for _, a := range m.Artifacts {
		args.Packages = append(args.Packages, api.InstallPackage{Name: a.Name, File: a.File, SHA256: a.SHA256})
	}
	r.state(api.JobStaging)
	r.ev("installing Release %s", ir.c.release)
	err := r.v.call(ctx, api.CmdInstall, r.j.ID, args, api.InstallTimeout, nil)
	if o, sum := ir.cut(err, "while installing Release "+ir.c.release); o != "" {
		return o, sum
	}
	if err != nil {
		return api.OutcomeInfra, fmt.Sprintf("the install of Release %s failed: %v", ir.c.release, err)
	}
	r.ev("installed Release %s", ir.c.release)
	return "", ""
}

// cut is the outcome of a step the Mac's Availability window closing cut
// short, or "".
func (ir *installedRun) cut(err error, what string) (string, string) {
	switch {
	case errors.Is(err, errWindowClosed):
		return windowCut(what + " (" + err.Error() + ")")
	case errors.Is(err, errDeviceLost) && ir.r.v.windowClosed():
		return windowCut(what + ", with the Mac out of reach")
	}
	return "", ""
}

// freezeObservedEntry freezes the installer entry identity-before observed
// on the Mac, once the Release is installed.
func (ir *installedRun) freezeObservedEntry() error {
	r, dev := ir.r, ir.r.j.Spec.Device
	raw, err := os.ReadFile(filepath.Join(r.s.jobDir(r.j.ID), "test-"+installed.TestName(installed.PhaseBefore), "observed.json"))
	if err != nil {
		return fmt.Errorf("identity-before wrote no observation")
	}
	var o installed.Observed
	if err := json.Unmarshal(raw, &o); err != nil {
		return fmt.Errorf("identity-before's observation: %v", err)
	}
	e, err := installed.FreezeEntry(&o, ir.c.man)
	if err != nil {
		return err
	}
	if err := moveUnpinned(filepath.Join(ir.c.dir, "installer-entry", dev+".json"), r.j.ID); err != nil {
		return err
	}
	if _, _, err := r.s.freezeEntry(ir.c.dir, dev, ir.c.manSHA, e); err != nil {
		return err
	}
	c, err := r.s.loadInstalled(r.j.Spec.InstalledManifest, dev)
	if err != nil {
		return err
	}
	ir.c, ir.res.EntrySHA256 = c, c.entrySHA
	r.ev("froze %s's installer entry %s (%s)", dev, short(c.entrySHA), c.entry.Path)
	return nil
}

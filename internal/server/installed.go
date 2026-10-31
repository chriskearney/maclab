package server

// Installed-kernel jobs: an acceptance run of a release as its installer
// installed it. The expectation lives in a frozen, pinned store
// (frozen/<release>/), never in anything a later run can replace:
//
//	PINS.preinstall                 pins preinstall/<mac>/*  (before any install)
//	expected/manifest.json          maclab.installed-manifest/2  } pinned by PINS.expected
//	expected/payload/*.sha256       payload file list            }
//	installer-entry/<mac>.json      maclab.installer-entry/1, pinned by PINS.installer-entry.<mac>
//	preinstall/<mac>/omt-report.json, omt-status.json, dmesg-errors.txt, ...
//
// On a Lab-owned Mac a Maintainer installs the Release and freezes its
// preinstall references and installer entry by hand. On a Volunteer's Mac
// only the expected manifest is frozen beforehand: the Installed run takes
// the preinstall references from the Volunteer's own system, installs the
// Release through the named install operation, and freezes the installer
// entry from its identity-before check.
//	installed/<mac>/<job>/          append-only evidence copies
//	promotions.log                  append-only
//
// A job never promotes anything: KnownGood, the live OMT reference and the live
// kernel-error baseline stay as they are until `lab installed promote`.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/installed"
)

const installedMinAgent = "0.8.0" // the lab's own identity checks, the install operation

// promoteMinAgent records the promoted kernel as the agent's own known-good.
const promoteMinAgent = "0.7.3"

var recordKnownGoodTimeout = time.Minute

var reRelease = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)

func (s *Server) frozenDir(release string) string {
	return filepath.Join(s.cfg.DataDir, "frozen", release)
}

// installedCtx is everything frozen that an installed job is judged against.
type installedCtx struct {
	release   string
	dir       string
	man       *installed.Manifest
	manSHA    string
	payload   map[string]string
	entry     *installed.InstallerEntry
	entrySHA  string
	frozenJob string
	omtReport string
	omtSHA    string
	omtStatus map[string]string
	omtTool   string
	omtKernel string
	// omtUnattended: the frozen report is from an unattended run.
	omtUnattended bool
	dmesgPath     string
	dmesgSHA      string
	dmesg         string
	// noPreinstall is why the device has no preinstall references yet: a
	// Volunteer's Installed run takes them, a Lab-owned Mac's can't run.
	noPreinstall error
}

// pins reads a sha256sum-format pins file into path -> sha.
func readPins(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sha, p, ok := strings.Cut(line, " ")
		if ok && len(sha) == 64 {
			out[strings.TrimSpace(p)] = sha
		}
	}
	return out, sc.Err()
}

// pinned reads dir/rel and checks it against its pin.
func pinned(dir, rel string, pins map[string]string) ([]byte, string, error) {
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		return nil, "", err
	}
	sha := installed.SHA256(b)
	if want, ok := pins[rel]; !ok {
		return nil, "", fmt.Errorf("%s is not pinned", rel)
	} else if want != sha {
		return nil, "", fmt.Errorf("%s is %s but its pin is %s", rel, sha, want)
	}
	return b, sha, nil
}

// findManifest locates the frozen release whose expected manifest has this sha256.
func (s *Server) findManifest(sha string) (string, error) {
	dirs, _ := filepath.Glob(filepath.Join(s.cfg.DataDir, "frozen", "*", "expected", "manifest.json"))
	for _, p := range dirs {
		if b, err := os.ReadFile(p); err == nil && installed.SHA256(b) == sha {
			return filepath.Base(filepath.Dir(filepath.Dir(p))), nil
		}
	}
	return "", fmt.Errorf("no frozen release has an expected manifest with sha256 %s", sha)
}

// loadInstalled loads and pin-checks the frozen store for one device.
func (s *Server) loadInstalled(manifestSHA, device string) (*installedCtx, error) {
	release, err := s.findManifest(manifestSHA)
	if err != nil {
		return nil, err
	}
	c := &installedCtx{release: release, dir: s.frozenDir(release)}
	exp, err := readPins(filepath.Join(c.dir, "PINS.expected"))
	if err != nil {
		return nil, fmt.Errorf("release %s: no PINS.expected (lab installed freeze-manifest): %w", release, err)
	}
	mb, msha, err := pinned(c.dir, "expected/manifest.json", exp)
	if err != nil {
		return nil, err
	}
	c.man, c.manSHA = &installed.Manifest{}, msha
	if err := json.Unmarshal(mb, c.man); err != nil {
		return nil, err
	}
	pb, _, err := pinned(c.dir, filepath.Join("expected", c.man.Kernel.PayloadManifest), exp)
	if err != nil {
		return nil, err
	}
	if err := c.man.Validate(pb); err != nil {
		return nil, fmt.Errorf("frozen manifest: %w", err)
	}
	if c.payload, err = installed.ParsePayload(pb); err != nil {
		return nil, err
	}
	if _, ok := c.man.Macs[device]; !ok {
		return nil, fmt.Errorf("the %s manifest has no entry for %s", release, device)
	}
	if ep, err := readPins(filepath.Join(c.dir, "PINS.installer-entry."+device)); err == nil {
		eb, esha, err := pinned(c.dir, "installer-entry/"+device+".json", ep)
		if err != nil {
			return nil, err
		}
		c.entry, c.entrySHA = &installed.InstallerEntry{}, esha
		if err := json.Unmarshal(eb, c.entry); err != nil {
			return nil, err
		}
	}
	pre, err := readPins(filepath.Join(c.dir, "PINS.preinstall"))
	if err != nil {
		c.noPreinstall = fmt.Errorf("release %s: no PINS.preinstall: %w", release, err)
		return c, nil
	}
	if _, ok := pre["preinstall/"+device+"/omt-report.json"]; !ok {
		c.noPreinstall = fmt.Errorf("release %s: PINS.preinstall has no preinstall references for %s", release, device)
		return c, nil
	}
	rep, rsha, err := pinned(c.dir, "preinstall/"+device+"/omt-report.json", pre)
	if err != nil {
		return nil, err
	}
	sb, _, err := pinned(c.dir, "preinstall/"+device+"/omt-status.json", pre)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sb, &c.omtStatus); err != nil {
		return nil, err
	}
	_, c.omtTool, c.omtKernel, _ = installed.ReportStatus(rep)
	c.omtReport, c.omtSHA = filepath.Join(c.dir, "preinstall", device, "omt-report.json"), rsha
	var frozen omtReport
	if json.Unmarshal(rep, &frozen) == nil {
		c.omtUnattended = frozen.Unattended
	}
	db, dsha, err := pinned(c.dir, "preinstall/"+device+"/dmesg-errors.txt", pre)
	if err != nil {
		return nil, err
	}
	c.dmesg, c.dmesgSHA, c.dmesgPath = string(db), dsha, filepath.Join(c.dir, "preinstall", device, "dmesg-errors.txt")
	if jb, err := os.ReadFile(filepath.Join(c.dir, "preinstall", device, "baseline-job.json")); err == nil {
		var j struct {
			ID string `json:"id"`
		}
		json.Unmarshal(jb, &j)
		c.frozenJob = j.ID
	}
	return c, nil
}

// validateInstalled refuses everything an installed job can't take.
func (s *Server) validateInstalled(spec api.JobSpec, d api.Device) (int, error) {
	switch {
	case !reSHA.MatchString(spec.InstalledManifest):
		return 400, errors.New("installed_manifest must be the full sha256 of a frozen expected manifest")
	case spec.Kernel != "" || spec.Source != "" || spec.Config != "":
		return 400, errors.New("an installed job boots the installed release: drop --kernel/--config and the source URL")
	case spec.Cmdline != "" || spec.CmdlineBase != "" || len(spec.CmdlineStrip) > 0 || spec.VerboseBoot:
		return 400, errors.New("an installed job boots the installer's own cmdline: --cmdline, --cmdline-base, --cmdline-strip and --verbose-boot are refused")
	case spec.Baseline || spec.Crash != "" || spec.Publish || len(spec.OMTAllow) > 0:
		return 400, errors.New("an installed job is not a baseline, crash test or publication, and takes no --omt-allow (exceptions belong to the gate)")
	case d.Lease == nil || d.Lease.Holder != spec.Holder || s.now().After(d.Lease.Expires):
		return 409, fmt.Errorf("%s must be leased by the job's holder (%q) for an installed job", d.Name, spec.Holder)
	case !versionAtLeast(d.Facts.AgentVersion, installedMinAgent):
		return 409, fmt.Errorf("%s runs lab-agent %s; installed jobs need %s or later", d.Name, orStr(d.Facts.AgentVersion, "(unknown)"), installedMinAgent)
	}
	// Every test's files are bound to it by name (result.tests[*].files and
	// test-<name>/), so a name that runs twice would make that ambiguous.
	seen, omt := map[string]bool{}, 0
	for _, t := range testsFor(spec) {
		switch {
		case strings.HasPrefix(t.Name, "identity-"):
			return 400, fmt.Errorf("test name %s is reserved for the installed identity checks", t.Name)
		case t.Name == "" || seen[t.Name]:
			return 400, fmt.Errorf("test %q appears more than once (or has no name); each test of an installed job runs exactly once", t.Name)
		}
		seen[t.Name] = true
		if t.Builtin == omtTest {
			omt++
		}
	}
	if omt != 1 {
		return 409, fmt.Errorf("an installed job is judged by omarchy-m-test against the frozen baseline, and %s can't run it (no GUI user, OMT off or an old agent)", d.Name)
	}
	c, err := s.loadInstalled(spec.InstalledManifest, d.Name)
	if err != nil {
		return 409, err
	}
	if d.IsVolunteer() {
		// the run takes the rest from the Mac itself
		return 0, nil
	}
	if c.noPreinstall != nil {
		return 409, c.noPreinstall
	}
	if c.entry == nil {
		return 409, fmt.Errorf("no frozen installer entry for %s yet: run `lab installed freeze-entry %s --release %s` after the install", d.Name, d.Name, c.release)
	}
	return 0, nil
}

// installedPreflight lets an installed job past the one preflight problem the
// install causes by design: the old known-good kernel package is gone.
func installedPreflight(problems []string) []string {
	var rest []string
	for _, p := range problems {
		if !(strings.HasPrefix(p, "known-good kernel ") && strings.HasSuffix(p, " is no longer installed")) {
			rest = append(rest, p)
		}
	}
	return rest
}

// installedRun is one installed job's frozen context and the evidence so far.
type installedRun struct {
	r      *jobRun
	c      *installedCtx
	serial bool
	booted *installed.Identity
	res    api.InstalledResult
	errs   []string // evidence that could not be collected or written: the job can't pass
}

// fail records evidence the job is missing. An installed job with any of these
// is not a pass, whatever its tests said.
func (ir *installedRun) fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ir.errs = append(ir.errs, msg)
	ir.r.ev("installed: %s", msg)
}

func (r *jobRun) newInstalled() (*installedRun, error) {
	c, err := r.s.loadInstalled(r.j.Spec.InstalledManifest, r.j.Spec.Device)
	if err != nil {
		return nil, err
	}
	if !r.v.snapshot().IsVolunteer() {
		if c.noPreinstall != nil {
			return nil, c.noPreinstall
		}
		if c.entry == nil {
			return nil, errors.New("no frozen installer entry")
		}
	}
	return &installedRun{r: r, c: c, serial: r.serialEnabled(),
		res: api.InstalledResult{Release: c.release, ManifestSHA256: c.manSHA, EntrySHA256: c.entrySHA, Verdicts: map[string]string{}}}, nil
}

// test is the lab's own identity check of a phase, which lab-agent runs
// with its read-only collector at any Access level. Before the installer
// entry is frozen, the check finds the installer's entry itself.
func (ir *installedRun) test(phase string) api.TestSpec {
	ic := &api.IdentityCheck{Phase: phase, Device: ir.r.j.Spec.Device, Kernel: ir.c.man.Kernel.Release}
	for _, a := range ir.c.man.Artifacts {
		ic.Packages = append(ic.Packages, a.Name)
	}
	if ir.c.entry != nil {
		ic.EntryPath = ir.c.entry.Path
	}
	return api.TestSpec{Name: installed.TestName(phase), Identity: ic, TimeoutSec: 600}
}

func (ir *installedRun) stageArgs() *api.InstalledStage {
	e := ir.c.entry
	return &api.InstalledStage{Path: e.Path, UKISHA256: e.UKISHA256, Release: ir.c.man.Kernel.Release,
		Cmdline: installed.Cmdline(e.CmdlineTokens, ir.r.j.ID, ir.serial)}
}

func (ir *installedRun) evDir() string { return filepath.Join(ir.r.s.jobDir(ir.r.j.ID), "installed") }

func (ir *installedRun) write(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		err = ir.writeRaw(name, append(b, '\n'))
	}
	if err != nil {
		ir.fail("writing installed/%s: %v", name, err)
		return
	}
	ir.addEvidence(name)
}

func (ir *installedRun) writeRaw(name string, b []byte) error {
	if err := os.MkdirAll(ir.evDir(), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(ir.evDir(), name), b, 0o644)
}

func (ir *installedRun) addEvidence(name string) {
	rel := "installed/" + name
	for _, e := range ir.res.Evidence {
		if e == rel {
			return
		}
	}
	ir.res.Evidence = append(ir.res.Evidence, rel)
}

// identity judges one phase's observation. It reports a failure reason, or "".
func (ir *installedRun) identity(phase string, tr *api.TestResult) string {
	raw, err := os.ReadFile(filepath.Join(ir.r.s.jobDir(ir.r.j.ID), "test-"+installed.TestName(phase), "observed.json"))
	if err != nil {
		ir.res.Verdicts[phase] = "MISSING"
		return fmt.Sprintf("identity-%s wrote no observation", phase)
	}
	var booted *installed.Identity
	if phase == installed.PhaseAfter {
		booted = ir.booted
	}
	id, err := installed.Compare(phase, raw, ir.c.man, ir.c.manSHA, ir.c.payload, ir.c.entry, ir.c.entrySHA, ir.serial, booted)
	if err != nil {
		ir.res.Verdicts[phase] = "MISSING"
		return err.Error()
	}
	if id.Job != ir.r.j.ID {
		id.Verdict = "MISMATCH"
		id.Mismatches = append(id.Mismatches, fmt.Sprintf("observation names job %q, not %s", id.Job, ir.r.j.ID))
	}
	if phase == installed.PhaseBooted {
		ir.booted = id
	}
	ir.res.Verdicts[phase] = id.Verdict
	ir.write("identity-"+phase+".json", id)
	ir.r.ev("identity-%s: %s%s", phase, id.Verdict, firstOf(id.Mismatches))
	if id.Verdict != "MATCH" {
		if tr != nil {
			tr.Passed = false
			tr.Error = "identity " + id.Verdict + ": " + strings.Join(id.Mismatches, "; ")
		}
		return "identity-" + phase + " " + id.Verdict + firstOf(id.Mismatches)
	}
	return ""
}

func firstOf(l []string) string {
	if len(l) == 0 {
		return ""
	}
	if len(l) == 1 {
		return ": " + l[0]
	}
	return fmt.Sprintf(": %s (and %d more)", l[0], len(l)-1)
}

// omt compares the run's omarchy-m-test report with the frozen one.
func (ir *installedRun) omt(tr *api.TestResult, res *api.OMTResult, report []byte) {
	cur, tool, kernel, err := installed.ReportStatus(report)
	if err != nil {
		tr.Passed, tr.Error = false, "omarchy-m-test report: "+err.Error()
		return
	}
	c := installed.CompareOMT(ir.r.j.ID, ir.r.j.Spec.Device,
		installed.OMTSide{Job: ir.c.frozenJob, Report: ir.c.omtReport, ReportSHA256: ir.c.omtSHA, Tool: ir.c.omtTool, Kernel: ir.c.omtKernel}, ir.c.omtStatus,
		installed.OMTSide{Job: ir.r.j.ID, Report: filepath.Join(ir.r.s.jobDir(ir.r.j.ID), res.Report), ReportSHA256: installed.SHA256(report), Tool: tool, Kernel: kernel}, cur)
	ir.write("omt-compare.json", c)
	ir.res.OMT = c.Verdict
	res.ComparedTo = "the frozen pre-install run " + ir.c.frozenJob + " (" + ir.c.release + ")"
	res.Regressions = nil
	for _, t := range c.Regressions {
		res.Regressions = append(res.Regressions, api.OMTCheck{ID: t.ID, Outcome: t.Frozen + " -> " + t.Current})
	}
	if c.Verdict != "NO_REGRESSION" {
		ids := make([]string, len(c.Regressions))
		for i, t := range c.Regressions {
			ids[i] = t.ID + " (" + t.Frozen + " -> " + t.Current + ")"
		}
		tr.Passed = false
		tr.Error = "regressed against the frozen pre-install baseline: " + strings.Join(ids, ", ")
	}
}

// kernelLogs returns a boot's full kernel log and its warning lines, as
// collected into the job's dir (boot0 for the test boot), or why the job
// can't be judged without them: a collection that failed, a file that didn't
// arrive or can't be read, an empty kernel log, or journalctl reporting an
// error.
func kernelLogs(jobDir, dir string, files []string, collectErr error) (kernel, warnings []byte, err error) {
	if collectErr != nil {
		return nil, nil, fmt.Errorf("collecting logs failed: %v", collectErr)
	}
	read := func(name string) ([]byte, error) {
		if !slices.Contains(files, dir+"/"+name) {
			return nil, fmt.Errorf("%s/%s was not collected", dir, name)
		}
		b, err := os.ReadFile(filepath.Join(jobDir, dir, name))
		if err != nil {
			return nil, err
		}
		if bytes.Contains(b, []byte("\n[journalctl: ")) {
			return nil, fmt.Errorf("%s/%s: journalctl failed: %s", dir, name, lastLine(string(b)))
		}
		return b, nil
	}
	st, err := read("collect-status.txt")
	if err != nil {
		return nil, nil, err
	}
	// exactly one status line per required log, and it says ok
	for _, name := range []string{"kernel.txt", "dmesg-errors.txt"} {
		var lines []string
		for _, l := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(l, name+" ") {
				lines = append(lines, strings.TrimPrefix(l, name+" "))
			}
		}
		switch {
		case len(lines) == 0:
			return nil, nil, fmt.Errorf("%s/%s is not valid evidence: collect-status.txt doesn't report it", dir, name)
		case len(lines) > 1:
			return nil, nil, fmt.Errorf("%s/%s is not valid evidence: collect-status.txt reports it %d times", dir, name, len(lines))
		case lines[0] != "ok":
			return nil, nil, fmt.Errorf("%s/%s is not valid evidence: %s", dir, name, lines[0])
		}
	}
	kern, err := read("kernel.txt")
	if err != nil {
		return nil, nil, err
	}
	if len(bytes.TrimSpace(kern)) == 0 {
		return nil, nil, fmt.Errorf("%s/kernel.txt is empty: the journal has no kernel log for the boot", dir)
	}
	warn, err := read("dmesg-errors.txt")
	if err != nil {
		return nil, nil, err
	}
	return kern, warn, nil
}

// dmesg compares the run's kernel error lines with the frozen ones.
func (ir *installedRun) dmesg(got []byte) *installed.DmesgCompare {
	if err := ir.writeRaw("dmesg-errors.txt", got); err != nil {
		ir.fail("writing installed/dmesg-errors.txt: %v", err)
	} else {
		ir.addEvidence("dmesg-errors.txt")
	}
	d := installed.CompareDmesg(ir.r.j.ID, ir.r.j.Spec.Device,
		installed.FileRef{File: ir.c.dmesgPath, SHA256: ir.c.dmesgSHA}, ir.c.dmesg,
		installed.FileRef{File: filepath.Join(ir.evDir(), "dmesg-errors.txt"), SHA256: installed.SHA256(got)}, string(got))
	ir.write("dmesg-compare.json", d)
	ir.res.Dmesg = d.Disposition
	return d
}

// installedEvidence is what a passing installed job must leave in installed/.
var installedEvidence = []string{"identity-before.json", "identity-booted.json", "identity-after.json",
	"omt-compare.json", "dmesg-compare.json", "dmesg-errors.txt"}

// seal writes installed/job.json and the frozen store's append-only copy, and
// returns the job's final outcome: a pass whose evidence is missing, couldn't
// be written or couldn't be copied is not a pass. job.json is the record the
// job will have once finishAt(outcome, summary, at) runs, and it is copied
// last, so the frozen store never holds a pass record without its evidence.
func (ir *installedRun) seal(outcome, summary string, at time.Time) (string, string) {
	if outcome == api.OutcomePass {
		for _, f := range installedEvidence {
			if _, err := os.Stat(filepath.Join(ir.evDir(), f)); err != nil {
				ir.fail("installed/%s is missing", f)
			}
		}
	}
	downgrade := func(why string) {
		if outcome == api.OutcomePass {
			outcome = api.OutcomeInfra
		}
		summary += "; installed evidence incomplete: " + why
	}
	if len(ir.errs) > 0 {
		downgrade(strings.Join(ir.errs, "; "))
	}
	dst := filepath.Join(ir.c.dir, "installed", ir.r.j.Spec.Device, ir.r.j.ID)
	record := func() error {
		j, err := ir.r.s.store.job(ir.r.j.ID)
		if err != nil {
			return err
		}
		res := ir.res
		j.State, j.Outcome, j.Summary = api.JobDone, outcome, summary
		j.Events = append(j.Events, api.JobEvent{Time: at, Msg: "done: " + outcome + ": " + summary})
		j.Result.Installed = &res
		b, err := json.MarshalIndent(j, "", "  ")
		if err != nil {
			return err
		}
		if err := ir.writeRaw("job.json", append(b, '\n')); err != nil {
			return err
		}
		ir.addEvidence("job.json")
		return nil
	}
	ir.res.Frozen = dst
	err := record()
	if err == nil {
		err = ir.copyFrozen(dst)
	}
	if err != nil {
		ir.res.Frozen = ""
		ir.r.ev("installed: %v", err)
		downgrade(err.Error())
		// the job's own copy says what happened; the frozen store has no job.json
		if err := record(); err != nil {
			ir.r.ev("installed: rewriting installed/job.json: %v", err)
		}
	}
	ir.r.s.updateJob(ir.r.j, func(j *api.Job) { res := ir.res; j.Result.Installed = &res })
	return outcome, summary
}

// copyFrozen publishes installed/ as the frozen store's append-only copy.
func (ir *installedRun) copyFrozen(dst string) error {
	if err := publishDir(ir.evDir(), dst, "job.json"); err != nil {
		return fmt.Errorf("frozen copy: %v", err)
	}
	return nil
}

// --- freezing and promotion (Maintainers) ---

// writeOnce writes a file that must not exist yet, read-only and synced. The
// create is exclusive, so two writers can't both succeed.
func writeOnce(path string, b []byte) error {
	return writeExclusive(path, b, 0o444)
}

// writeExclusive is writeOnce with the file's mode: promotion stages the live
// references 0644, since lab baseline rewrites them later.
func writeExclusive(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; frozen files are written once", path)
	} else if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syncDir(filepath.Dir(path)) // the new name is durable too
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// publishDir copies the files of src into a new directory dst, read-only, each
// read back, last file last, and makes dst appear only once it is complete: it
// is built beside dst and renamed into place, refusing to replace anything.
func publishDir(src, dst, last string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s already exists; the frozen store is append-only", dst)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// the rename is only durable once the parent is synced: fail before
	// writing anything if it can't be
	if err := syncDir(filepath.Dir(dst)); err != nil {
		return fmt.Errorf("syncing %s: %w", filepath.Dir(dst), err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".partial-")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok { // the staging directory holds only files: unlink them, then it
			if ents, err := os.ReadDir(tmp); err == nil {
				for _, e := range ents {
					os.Remove(filepath.Join(tmp, e.Name()))
				}
			}
			os.Remove(tmp)
		}
	}()
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if !e.Type().IsRegular() {
			return fmt.Errorf("%s/%s is not a regular file", src, e.Name())
		}
		if e.Name() != last {
			names = append(names, e.Name())
		}
	}
	if last != "" {
		if _, err := os.Stat(filepath.Join(src, last)); err != nil {
			return err
		}
		names = append(names, last)
	}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			return err
		}
		if err := writeOnce(filepath.Join(tmp, name), b); err != nil {
			return err
		}
		if back, err := os.ReadFile(filepath.Join(tmp, name)); err != nil || !bytes.Equal(back, b) {
			return fmt.Errorf("%s did not read back identical (%v)", name, err)
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := syncDir(tmp); err != nil {
		return fmt.Errorf("syncing %s: %w", tmp, err)
	}
	if err := renameNoReplace(tmp, dst); err != nil {
		return fmt.Errorf("publishing %s: %w", dst, err)
	}
	if err := syncDir(filepath.Dir(dst)); err != nil {
		// not durably published: take it back out of the frozen store's view
		if qerr := renameNoReplace(dst, tmp); qerr != nil {
			return fmt.Errorf("syncing %s after publishing %s: %v; and moving it aside failed: %v", filepath.Dir(dst), dst, err, qerr)
		}
		return fmt.Errorf("syncing %s after publishing %s: %w; moved aside", filepath.Dir(dst), dst, err)
	}
	ok = true
	return nil
}

// syncDir fsyncs a directory, so the entries in it are durable. A test can
// replace it to make it fail.
var syncDir = func(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

type freezeManifestReq struct {
	Manifest   string   `json:"manifest"` // artifact sha256s of the uploaded files
	Payload    string   `json:"payload"`
	ApprovedBy []string `json:"approved_by"`
}

func (s *Server) hFreezeManifest(w http.ResponseWriter, r *http.Request) {
	release := r.PathValue("release")
	var req freezeManifestReq
	if !reRelease.MatchString(release) || json.NewDecoder(r.Body).Decode(&req) != nil || !reSHA.MatchString(req.Manifest) || !reSHA.MatchString(req.Payload) {
		httpErr(w, 400, "need a release name and the manifest and payload artifact sha256s")
		return
	}
	mb, err1 := os.ReadFile(s.artifactPath(req.Manifest))
	pb, err2 := os.ReadFile(s.artifactPath(req.Payload))
	if err1 != nil || err2 != nil {
		httpErr(w, 400, "upload the manifest and payload first")
		return
	}
	var m installed.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		httpErr(w, 400, "manifest: %v", err)
		return
	}
	if m.Release != release {
		httpErr(w, 400, "manifest is for release %q, not %q", m.Release, release)
		return
	}
	if err := m.Validate(pb); err != nil {
		httpErr(w, 400, "manifest: %v", err)
		return
	}
	dir := s.frozenDir(release)
	if _, err := os.Stat(filepath.Join(dir, "PINS.expected")); err == nil {
		httpErr(w, 409, "release %s already has a frozen expected manifest", release)
		return
	}
	rel := filepath.Join("expected", m.Kernel.PayloadManifest)
	if err := writeOnce(filepath.Join(dir, "expected", "manifest.json"), mb); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	if err := writeOnce(filepath.Join(dir, rel), pb); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	pins := fmt.Sprintf("# PINS.expected %s by maclab (approved by %s): do not rewrite\n%s  expected/manifest.json\n%s  %s\n",
		s.now().Format(time.RFC3339), strings.Join(req.ApprovedBy, ", "), installed.SHA256(mb), installed.SHA256(pb), rel)
	if err := writeOnce(filepath.Join(dir, "PINS.expected"), []byte(pins)); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	writeJSON(w, map[string]any{"release": release, "manifest_sha256": installed.SHA256(mb), "pins": pins, "pins_sha256": installed.SHA256([]byte(pins))})
}

// hFreezeEntry observes the installed Mac and freezes its installer boot entry.
func (s *Server) hFreezeEntry(w http.ResponseWriter, r *http.Request) {
	release, device := r.PathValue("release"), r.PathValue("device")
	v := s.dev(device)
	if v == nil || !reRelease.MatchString(release) {
		httpErr(w, 404, "no device %q or bad release", device)
		return
	}
	dir := s.frozenDir(release)
	exp, err := readPins(filepath.Join(dir, "PINS.expected"))
	if err != nil {
		httpErr(w, 409, "release %s has no frozen expected manifest", release)
		return
	}
	mb, msha, err := pinned(dir, "expected/manifest.json", exp)
	if err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	var m installed.Manifest
	json.Unmarshal(mb, &m)
	if _, err := os.Stat(filepath.Join(dir, "PINS.installer-entry."+device)); err == nil {
		httpErr(w, 409, "%s's installer entry for %s is already frozen", device, release)
		return
	}
	script := installed.Script("freeze", device, m.Kernel.Release, "", nil, false)
	cmd := "export MACLAB_OUT=$(mktemp -d); MACLAB_JOB= bash -s >&2 <<'MACLAB_FREEZE_EOF'\n" + script + "MACLAB_FREEZE_EOF\ncat \"$MACLAB_OUT/observed.json\"; rm -rf \"$MACLAB_OUT\""
	var res api.ExecResult
	if err := v.call(r.Context(), api.CmdExec, "", api.ExecArgs{Command: cmd, TimeoutSec: 300}, 6*time.Minute, &res); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	var o installed.Observed
	if err := json.Unmarshal([]byte(res.Stdout), &o); err != nil {
		httpErr(w, 502, "collector output: %v (stderr: %s)", err, lastLine(res.Stderr))
		return
	}
	e, err := installed.FreezeEntry(&o, &m)
	if err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	esha, pins, err := s.freezeEntry(dir, device, msha, e)
	if err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	writeJSON(w, map[string]any{"device": device, "release": release, "entry": e, "entry_sha256": esha, "pins": pins})
}

// freezeEntry writes a device's installer entry into the frozen store, once,
// with its pins.
func (s *Server) freezeEntry(dir, device, manifestSHA string, e *installed.InstallerEntry) (entrySHA, pins string, err error) {
	eb, _ := json.MarshalIndent(e, "", "  ")
	eb = append(eb, '\n')
	if err := writeOnce(filepath.Join(dir, "installer-entry", device+".json"), eb); err != nil {
		return "", "", err
	}
	pins = fmt.Sprintf("# PINS.installer-entry.%s %s by maclab, manifest %s: do not rewrite\n%s  installer-entry/%s.json\n",
		device, s.now().Format(time.RFC3339), manifestSHA, installed.SHA256(eb), device)
	if err := writeOnce(filepath.Join(dir, "PINS.installer-entry."+device), []byte(pins)); err != nil {
		return "", "", err
	}
	return installed.SHA256(eb), pins, nil
}

type promoteReq struct {
	Device string `json:"device"`
	Job    string `json:"job"`
}

// hPromote makes an accepted installed run the device's reference and
// known-good, accepted by the Maintainer whose token asked.
func (s *Server) hPromote(w http.ResponseWriter, r *http.Request) {
	release := r.PathValue("release")
	var req promoteReq
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Job == "" {
		httpErr(w, 400, "need device and job")
		return
	}
	j, err := s.store.job(req.Job)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	ir := j.Result.Installed
	switch {
	case j.Spec.Device != req.Device:
		httpErr(w, 400, "job %s ran on %s, not %s", j.ID, j.Spec.Device, req.Device)
		return
	case ir == nil || ir.Release != release:
		httpErr(w, 400, "job %s is not an installed job of release %s", j.ID, release)
		return
	case j.State != api.JobDone || j.Outcome != api.OutcomePass || ir.Verdicts[installed.PhaseBefore] != "MATCH" ||
		ir.Verdicts[installed.PhaseBooted] != "MATCH" || ir.Verdicts[installed.PhaseAfter] != "MATCH":
		httpErr(w, 409, "job %s did not pass with matching identity (outcome %s, verdicts %v)", j.ID, j.Outcome, ir.Verdicts)
		return
	case ir.OMT != "NO_REGRESSION":
		httpErr(w, 409, "job %s's omarchy-m-test comparison is %q, not NO_REGRESSION", j.ID, ir.OMT)
		return
	case ir.Dmesg != "NONE_NEW" && ir.Dmesg != "REVIEW_REQUIRED":
		httpErr(w, 409, "job %s's kernel errors were not compared cleanly (%q)", j.ID, ir.Dmesg)
		return
	case ir.Frozen == "":
		httpErr(w, 409, "job %s has no frozen evidence copy", j.ID)
		return
	}
	// the frozen copy must still be the job's evidence, byte for byte
	if err := sameFiles(filepath.Join(s.jobDir(j.ID), "installed"), ir.Frozen); err != nil {
		httpErr(w, 409, "job %s's frozen copy: %v", j.ID, err)
		return
	}
	file := omtFile // jobs from before the report's place was recorded
	if j.Result.OMT != nil && j.Result.OMT.Report != "" {
		file = j.Result.OMT.Report
	}
	report, err := os.ReadFile(filepath.Join(s.jobDir(j.ID), file))
	if err != nil {
		httpErr(w, 409, "job %s has no omarchy-m-test report: %v", j.ID, err)
		return
	}
	status, tool, kernel, err := installed.ReportStatus(report)
	if err != nil {
		httpErr(w, 409, "job %s's omarchy-m-test report: %v", j.ID, err)
		return
	}
	dm, err := os.ReadFile(filepath.Join(ir.Frozen, "dmesg-errors.txt"))
	if err != nil {
		httpErr(w, 409, "job %s's frozen kernel errors: %v", j.ID, err)
		return
	}
	// what becomes the reference must be what the frozen comparisons judged
	if err := s.promotionInputs(j, report, status, tool, kernel, dm); err != nil {
		httpErr(w, 409, "job %s: %v", j.ID, err)
		return
	}
	ob, err := json.MarshalIndent(omtBaseline{Job: j.ID, Time: s.now(), Kernel: kernel, Tool: tool, Status: status}, "", "  ")
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	ledger := filepath.Join(s.frozenDir(release), "promotions.log")
	if b, err := os.ReadFile(ledger); err == nil && promotedIn(b, j.ID) {
		httpErr(w, 409, "job %s is already promoted in %s", j.ID, ledger)
		return
	} else if err != nil && !os.IsNotExist(err) {
		httpErr(w, 500, "reading %s: %v", ledger, err)
		return
	}
	v := s.dev(req.Device)
	if v == nil {
		httpErr(w, 404, "no device %s", req.Device)
		return
	}
	// the agent records the promoted kernel as its own known-good last, so the
	// Mac must be on it now, idle, outside a lab boot
	v.mu.Lock()
	d := v.d
	alive := v.aliveLocked()
	v.mu.Unlock()
	switch {
	case !alive:
		httpErr(w, 409, "%s is not checking in; promotion records the known-good on the Mac too", d.Name)
		return
	case !versionAtLeast(d.Facts.AgentVersion, promoteMinAgent):
		httpErr(w, 409, "%s runs lab-agent %s; promotion needs %s or later to record the known-good on the Mac", d.Name, orStr(d.Facts.AgentVersion, "(unknown)"), promoteMinAgent)
		return
	case d.ActiveJob != "":
		httpErr(w, 409, "%s is running job %s", d.Name, d.ActiveJob)
		return
	case d.Kernel != j.Result.BootKernel || strings.Contains(d.Cmdline, "maclab.job="):
		httpErr(w, 409, "%s is running %s (cmdline %q), not the installed %s outside a lab boot: boot it first", d.Name, d.Kernel, d.Cmdline, j.Result.BootKernel)
		return
	}
	line, err := s.promote(r.Context(), v, release, j, maintainerName(r), ledger, map[string][]byte{s.omtBaselinePath(req.Device): ob, s.baselinePath(req.Device): dm})
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	writeJSON(w, map[string]any{"promoted": req.Device, "job": j.ID, "known_good": j.Result.BootKernel, "log": strings.TrimSpace(line)})
}

// promotionInputs checks that the report and kernel errors a promotion would
// make the references are the bytes the job's frozen comparisons were made
// from, and that comparing that report with the frozen pre-install one again
// still gives the frozen transitions and NO_REGRESSION.
func (s *Server) promotionInputs(j *api.Job, report []byte, status map[string]string, tool, kernel string, dm []byte) error {
	ir := j.Result.Installed
	var oc installed.OMTCompare
	b, err := os.ReadFile(filepath.Join(ir.Frozen, "omt-compare.json"))
	if err == nil {
		err = json.Unmarshal(b, &oc)
	}
	if err != nil {
		return fmt.Errorf("frozen omt-compare.json: %v", err)
	}
	if got := installed.SHA256(report); got != oc.Current.ReportSHA256 {
		return fmt.Errorf("its omarchy-m-test report is now %s, not the %s its frozen comparison judged", got, oc.Current.ReportSHA256)
	}
	c, err := s.loadInstalled(j.Spec.InstalledManifest, j.Spec.Device)
	if err == nil {
		err = c.noPreinstall
	}
	if err != nil {
		return err
	}
	if oc.Frozen.ReportSHA256 != c.omtSHA {
		return fmt.Errorf("its frozen comparison was made against report %s, not the frozen pre-install %s", oc.Frozen.ReportSHA256, c.omtSHA)
	}
	re := installed.CompareOMT(j.ID, j.Spec.Device,
		installed.OMTSide{Job: c.frozenJob, Report: c.omtReport, ReportSHA256: c.omtSHA, Tool: c.omtTool, Kernel: c.omtKernel}, c.omtStatus,
		installed.OMTSide{Job: j.ID, Report: oc.Current.Report, ReportSHA256: oc.Current.ReportSHA256, Tool: tool, Kernel: kernel}, status)
	if re.Verdict != "NO_REGRESSION" {
		return fmt.Errorf("its omarchy-m-test report regresses against the frozen pre-install report: %v", re.Regressions)
	}
	if a, _ := json.Marshal(re.Transitions); string(a) != func() string { b, _ := json.Marshal(oc.Transitions); return string(b) }() {
		return errors.New("recomparing its omarchy-m-test report does not give the frozen transitions")
	}
	var dc installed.DmesgCompare
	b, err = os.ReadFile(filepath.Join(ir.Frozen, "dmesg-compare.json"))
	if err == nil {
		err = json.Unmarshal(b, &dc)
	}
	if err != nil {
		return fmt.Errorf("frozen dmesg-compare.json: %v", err)
	}
	if got := installed.SHA256(dm); got != dc.Current.SHA256 || dc.Disposition != ir.Dmesg || len(dc.FatalHits) > 0 {
		return fmt.Errorf("its kernel errors (%s, %s) are not what the frozen comparison judged (%s, %s)", got, ir.Dmesg, dc.Current.SHA256, dc.Disposition)
	}
	return nil
}

// promote replaces a Mac's references and known-good kernel with an accepted
// installed job's, all or nothing: the new references are written beside the
// live ones first, the decision goes into the ledger before anything changes,
// the old references are kept as <file>.before-<job>, the agent records the
// kernel as its own known-good last, and any failure puts the old ones back
// and says so in the ledger.
func (s *Server) promote(ctx context.Context, v *dev, release string, j *api.Job, by, ledger string, refs map[string][]byte) (string, error) {
	var paths []string
	for p := range refs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	staged := map[string]string{}
	cleanup := func() {
		for _, t := range staged {
			os.Remove(t)
		}
	}
	for _, p := range paths {
		t := p + ".promote-" + j.ID
		os.Remove(t)
		if err := writeExclusive(t, refs[p], 0o644); err != nil {
			cleanup()
			return "", fmt.Errorf("staging %s: %v; nothing was changed", p, err)
		}
		staged[p] = t
	}
	line := fmt.Sprintf("%s\t%s\t%s\t%s\taccepted-by=%s\n", s.now().Format(time.RFC3339), j.Spec.Device, j.ID, j.Result.BootKernel, by)
	fail := func(why string) string {
		return fmt.Sprintf("%s\t%s\t%s\tFAILED\t%s\n", s.now().Format(time.RFC3339), j.Spec.Device, j.ID, why)
	}
	if err := appendSynced(ledger, line); err != nil {
		cleanup()
		// the line may be in the file without being durable: say it didn't happen
		appendSynced(ledger, fail("not recorded: "+err.Error()))
		return "", fmt.Errorf("recording the promotion in %s: %v; nothing was changed", ledger, err)
	}
	var kept []string // .before-<job> copies this attempt made
	failed := func(applied []string, why error) error {
		var undo []string
		for _, p := range applied {
			if b, err := os.ReadFile(p + ".before-" + j.ID); err == nil {
				if werr := writeFileAtomic(p, b); werr != nil {
					undo = append(undo, p+": "+werr.Error())
				}
			} else if os.IsNotExist(err) {
				if rerr := os.Remove(p); rerr == nil {
					if serr := syncDir(filepath.Dir(p)); serr != nil {
						undo = append(undo, p+": "+serr.Error())
					}
				} else {
					undo = append(undo, p+": "+rerr.Error())
				}
			} else {
				undo = append(undo, p+": "+err.Error())
			}
		}
		cleanup()
		if len(undo) == 0 { // the live references are the old ones again: their copies can go
			for _, k := range kept {
				os.Remove(k)
			}
		}
		lerr := appendSynced(ledger, fail(why.Error()))
		msg := fmt.Sprintf("promotion of %s failed: %v; the previous references were put back", j.ID, why)
		if len(undo) > 0 {
			msg = fmt.Sprintf("promotion of %s failed: %v; and putting back the previous references failed: %s (copies are in <file>.before-%s)", j.ID, why, strings.Join(undo, "; "), j.ID)
		}
		if lerr != nil {
			msg += fmt.Sprintf("; the ledger could not record the failure: %v", lerr)
		}
		return errors.New(msg)
	}
	var applied []string
	for _, p := range paths {
		if old, err := os.ReadFile(p); err == nil {
			if err := writeOnce(p+".before-"+j.ID, old); err != nil {
				return "", failed(applied, fmt.Errorf("keeping the previous %s: %v", p, err))
			}
			kept = append(kept, p+".before-"+j.ID)
		} else if !os.IsNotExist(err) {
			return "", failed(applied, err)
		}
		if err := os.Rename(staged[p], p); err != nil {
			return "", failed(applied, err)
		}
		delete(staged, p)
		applied = append(applied, p)
		if err := syncDir(filepath.Dir(p)); err != nil {
			return "", failed(applied, fmt.Errorf("syncing %s after replacing %s: %v", filepath.Dir(p), p, err))
		}
	}
	v.mu.Lock()
	prev := v.d.KnownGood
	v.d.KnownGood = j.Result.BootKernel
	err := v.storeLocked()
	if err != nil {
		v.d.KnownGood = prev
	}
	v.mu.Unlock()
	if err != nil {
		return "", failed(applied, fmt.Errorf("saving the known-good kernel: %v", err))
	}
	if err := v.call(ctx, api.CmdRecordKnownGood, "", api.RecordKnownGoodArgs{Kernel: j.Result.BootKernel}, recordKnownGoodTimeout, nil); err != nil {
		why := fmt.Errorf("the agent did not record %s as its known-good: %v", j.Result.BootKernel, err)
		if !errors.Is(err, errAgentRefused) {
			why = fmt.Errorf("%v (it may have; its previous record is known-good.json.prev on the Mac)", why)
		}
		v.mu.Lock()
		v.d.KnownGood = prev
		serr := v.storeLocked()
		v.mu.Unlock()
		if serr != nil {
			why = fmt.Errorf("%v; and putting back labd's known-good %s failed: %v", why, prev, serr)
		}
		return "", failed(applied, why)
	}
	return line, nil
}

// appendSynced appends a line to a file and syncs it and its directory.
func appendSynced(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(line); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syncDir(filepath.Dir(path))
	}
	return err
}

// promotedIn says whether a job's last ledger record is a promotion (a FAILED
// record after it means the attempt was undone).
func promotedIn(ledger []byte, job string) bool {
	promoted := false
	for _, l := range strings.Split(string(ledger), "\n") {
		if f := strings.Split(l, "\t"); len(f) >= 4 && f[2] == job {
			promoted = f[3] != "FAILED"
		}
	}
	return promoted
}

// sameFiles says whether two directories hold the same regular files, byte for byte.
func sameFiles(a, b string) error {
	list := func(d string) ([]string, error) {
		ents, err := os.ReadDir(d)
		if err != nil {
			return nil, err
		}
		var n []string
		for _, e := range ents {
			n = append(n, e.Name())
		}
		return n, nil
	}
	na, err := list(a)
	if err != nil {
		return err
	}
	nb, err := list(b)
	if err != nil {
		return err
	}
	if !slices.Equal(na, nb) {
		return fmt.Errorf("files differ: %v vs %v", na, nb)
	}
	for _, n := range na {
		x, err1 := os.ReadFile(filepath.Join(a, n))
		y, err2 := os.ReadFile(filepath.Join(b, n))
		if err1 != nil || err2 != nil || !bytes.Equal(x, y) {
			return fmt.Errorf("%s differs (%v %v)", n, err1, err2)
		}
	}
	return nil
}

// hInstalledStatus lists a release's frozen files and their pins.
func (s *Server) hInstalledStatus(w http.ResponseWriter, r *http.Request) {
	release := r.PathValue("release")
	if !reRelease.MatchString(release) {
		httpErr(w, 404, "bad release %q", release)
		return
	}
	dir := s.frozenDir(release)
	var files []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			files = append(files, rel)
		}
		return nil
	})
	sort.Strings(files)
	writeJSON(w, map[string]any{"dir": dir, "files": files})
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}

var _ = context.Background
var _ = io.EOF

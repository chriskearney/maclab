package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/installed"
)

// Installing a Release becomes a named lab operation (#34). An Installed run
// on a Volunteer's Mac installs the Release itself, through one named
// operation instead of a Maintainer's root command, so a Mac at the default
// Qualification Access level takes it, and records it in its Audit log with
// the Maintainer and the Release. The preinstall references come from the
// Volunteer's system as it is when the run starts: nobody writes them by
// hand, and nobody freezes the installer's entry with an exec.

// ioRelease is the Release these tests install.
const ioRelease = "9.9"

// ioRecorder records every command labd hands the Mac in its check-in and
// report answers, and every result the Mac sends back.
type ioRecorder struct {
	mu   sync.Mutex
	cmds []api.Command
}

func (r *ioRecorder) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/agent/checkin" && req.URL.Path != "/api/agent/report" {
			next.ServeHTTP(rw, req)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, req)
		var resp struct {
			Commands []api.Command `json:"commands"`
		}
		json.Unmarshal(rec.Body.Bytes(), &resp)
		r.mu.Lock()
		r.cmds = append(r.cmds, resp.Commands...)
		r.mu.Unlock()
		for k, v := range rec.Header() {
			rw.Header()[k] = v
		}
		rw.WriteHeader(rec.Code)
		rw.Write(rec.Body.Bytes())
	})
}

func (r *ioRecorder) commands() []api.Command {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]api.Command(nil), r.cmds...)
}

// ioInstalls is the install commands labd sent the Mac.
func (r *ioRecorder) ioInstalls() []api.Command {
	var out []api.Command
	for _, c := range r.commands() {
		if c.Kind == api.CmdInstall {
			out = append(out, c)
		}
	}
	return out
}

// ioLab is a Volunteer's Mac at its default Access level, open to the lab
// for two hours, with omarchy-m-test on, a lease held by "io-tester" and
// Release 9.9's expected manifest frozen through labd's endpoint. Nothing
// else of the Release is prepared: no preinstall references, no installer
// entry, nothing installed. The Sim answers the identity checks as a Mac
// that took the install would. It returns the manifest's sha256 and the
// installer entry the Mac shows once the Release is installed.
func ioLab(t *testing.T, c labConfig) (*lab, *agent.FakeClock, string, installed.Entry) {
	t.Helper()
	c.config = func(cfg *Config) { cfg.OMT = true }
	l, clock := windowEndLab(t, c)
	name := l.name

	payload := tVml + "  vmlinuz\n" + tDtbA + "  dtbs/t-a.dtb\n" + tDtbB + "  dtbs/t-b.dtb\n" + tMtr + "  modules.dep\n"
	m := installed.Manifest{Schema: installed.ManifestSchema, Release: ioRelease,
		Artifacts: []installed.Artifact{{Name: "linux-aurora", File: "linux-aurora-9.9.pkg.tar.zst", SHA256: tVml, Version: "9.9-1", MtreeSHA256: tMtr}},
		DTBs:      []installed.DTB{{Name: "t-a.dtb", SHA256: tDtbA}, {Name: "t-b.dtb", SHA256: tDtbB}},
		Macs:      map[string]installed.MacExpect{name: {Board: "apple,sim", BoardDTB: "t-a.dtb", UbootGzSHA256: tUbt, BootBinSHA256: tBoot}}}
	m.DTBsSHA256 = installed.DTBsDigest(m.DTBs)
	m.Kernel.Release, m.Kernel.VmlinuzSHA256 = tKrel, tVml
	m.Kernel.PayloadManifest, m.Kernel.PayloadManifestSHA256, m.Kernel.PayloadCount = "payload/linux-aurora.files.sha256", installed.SHA256([]byte(payload)), 4
	m.Kernel.RegeneratedOnMac = []string{"modules.dep"}
	m.M1n1.BinSHA256, m.M1n1.Version = tM1n1, "v1.6.1-omarchy.sim"
	mb, _ := json.MarshalIndent(m, "", "  ")
	if resp, body := l.post("/api/installed/"+ioRelease+"/manifest", map[string]any{"manifest": l.artifact(string(mb)), "payload": l.artifact(payload), "approved_by": []string{"boss", "dave"}}); resp.StatusCode != 200 {
		t.Fatalf("freeze manifest: %s %s", resp.Status, body)
	}

	tokens := []string{"root=UUID=sim", "rw", "quiet", "splash"}
	path := "boot():/EFI/Linux/omarchy_linux-aurora.efi#" + tB2
	lines := []string{"  //linux-aurora", "  protocol: efi", "  path: " + path, "  cmdline: root=UUID=sim rw quiet splash"}
	entry := installed.Entry{Found: true, Name: "Omarchy / linux-aurora", Protocol: "efi", Path: path,
		Cmdline: strings.Join(tokens, " "), CmdlineTokens: tokens, EntryLines: lines, EntrySHA256: installed.EntryDigest(lines), UKISHA256: tUKI, UKIBlake2b: tB2,
		UKISections: map[string]installed.Section{".linux": {SHA256: tVml}, ".initrd": {SHA256: tIrd}, ".cmdline": {SHA256: "cc", Text: strings.Join(tokens, " ")}, ".uname": {SHA256: "uu", Text: tKrel}}}
	l.sim.SetInstalledObs(func(phase, job, bootID, kernel, cmdline string) []byte {
		stage2 := "v1.6.1-omarchy.sim"
		if phase == installed.PhaseBefore {
			stage2 = "v1.6.1-omarchy.old"
		}
		o := map[string]any{"schema": "maclab.installed-observed/1", "phase": phase, "device": name, "job": job,
			"running":  map[string]any{"boot_id": bootID, "uname_r": kernel, "proc_cmdline": cmdline},
			"packages": map[string]any{"linux-aurora": map[string]any{"version": "9.9-1", "mtree_sha256": tMtr}},
			"payload": map[string]any{"krel": tKrel, "root": "/usr/lib/modules/" + tKrel, "count": 4,
				"files": map[string]string{"vmlinuz": tVml, "dtbs/t-a.dtb": tDtbA, "dtbs/t-b.dtb": tDtbB, "modules.dep": "regenerated"}},
			"installer_entry": entry,
			"boot_bin": map[string]any{"path": "/boot/efi/m1n1/boot.bin", "sha256": tBoot, "parts": map[string]any{"m1n1_sha256": tM1n1,
				"dtb_shas": []string{tDtbA, tDtbB}, "dtb_count": 2, "board_dtb_sha256": tDtbA, "board_dtb_count": 1, "uboot_gz_sha256": tUbt, "trailer": ""}},
			"dt": map[string]any{"board": "apple,sim", "compatible": []string{"apple,sim"}, "live_stage2_version": stage2}}
		b, _ := json.MarshalIndent(o, "", " ")
		return b
	})
	l.takeLease("io-tester", time.Hour)
	return l, clock, installed.SHA256(mb), entry
}

// ioRun is the Installed run of the Release on the Mac, as the holder of
// token submits it through labd's API.
func (l *lab) ioRun(token, msha string) string {
	l.t.Helper()
	r, body := l.as(token, "POST", "/api/jobs", api.JobSpec{Device: l.name, InstalledManifest: msha, Holder: "io-tester"})
	var j api.Job
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil || j.ID == "" {
		l.t.Fatalf("an Installed run on a Volunteer's Mac at Qualification was not accepted: %s %s", r.Status, body)
	}
	return j.ID
}

// ioInstallLine is the Audit log line that records the install of release
// in job, or "".
func ioInstallLine(log, job, release string) string {
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(strings.ToLower(line), "install") && strings.Contains(line, job) && strings.Contains(line, release) {
			return line
		}
	}
	return ""
}

func TestAnInstalledRunInstallsTheReleaseOnAVolunteersMacAtQualification(t *testing.T) {
	l, _, msha, _ := ioLab(t, labConfig{})
	if out := l.mustVolunteer("status"); alStatusLevel(out) != "qualification" {
		t.Fatalf("the Mac is not at Qualification:\n%s", out)
	}
	j := l.jobAPI(l.ioRun(harnessToken, msha), 180*time.Second)
	l.expect(j, api.OutcomePass)
	if got := l.sim.Installs(); len(got) != 1 || got[0] != ioRelease {
		t.Fatalf("the Mac's installer ran for %v, want once for %s", got, ioRelease)
	}
	ir := j.Result.Installed
	if ir == nil || ir.Verdicts["before"] != "MATCH" || ir.Verdicts["booted"] != "MATCH" || ir.Verdicts["after"] != "MATCH" {
		t.Fatalf("the Installed run's identity checks at Qualification: %+v", ir)
	}
	if j.Result.BootKernel != tKrel {
		t.Fatalf("the Installed run booted %q, not the Release's %s", j.Result.BootKernel, tKrel)
	}
	if out := l.mustVolunteer("log"); strings.Contains(strings.ToLower(out), "refus") {
		t.Fatalf("lab-agent refused part of an Installed run at Qualification:\n%s", out)
	}
}

func TestTheInstallIsANamedLabOperationNotAnExecOrAScript(t *testing.T) {
	rec := &ioRecorder{}
	l, _, msha, _ := ioLab(t, labConfig{wrap: rec.wrap})
	id := l.ioRun(harnessToken, msha)
	l.expect(l.jobAPI(id, 180*time.Second), api.OutcomePass)
	ins := rec.ioInstalls()
	if len(ins) != 1 || ins[0].JobID != id || ins[0].Maintainer != harnessMaintainer || !strings.Contains(string(ins[0].Args), ioRelease) {
		t.Fatalf("labd sent the Mac install commands %+v, want one %q command for job %s by %s naming %s", ins, api.CmdInstall, id, harnessMaintainer, ioRelease)
	}
	for _, c := range rec.commands() {
		switch c.Kind {
		case api.CmdExec:
			t.Errorf("an Installed run sent the Mac an exec: %s", c.Args)
		case api.CmdRunTest:
			var ts api.TestSpec
			json.Unmarshal(c.Args, &ts)
			if ts.MaintainerScript() {
				t.Errorf("an Installed run sent the Mac a script as test %s", ts.Name)
			}
		case api.CmdBootOnce:
			var b api.BootOnceArgs
			json.Unmarshal(c.Args, &b)
			for _, ts := range b.Tests {
				if ts.MaintainerScript() {
					t.Errorf("an Installed run's Lab boot holds a script, test %s", ts.Name)
				}
			}
		}
	}
}

func TestTheInstallIsRecordedInTheAuditLogWithTheMaintainerAndTheRelease(t *testing.T) {
	l, clock, msha, _ := ioLab(t, labConfig{})
	grace := l.addMaintainer(harnessToken, "grace")
	id := l.ioRun(grace.Token, msha)
	l.expect(l.jobAPI(id, 180*time.Second), api.OutcomePass)
	out := l.alWaitLog(id, ioRelease)
	line := ioInstallLine(out, id, ioRelease)
	if line == "" || !strings.Contains(line, "grace") {
		t.Fatalf("the Audit log has no entry for grace installing %s in job %s:\n%s", ioRelease, id, out)
	}
	if !alHasWhen(out, clock.Now()) {
		t.Fatalf("the Audit log does not say when:\n%s", out)
	}
	var body string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, body = l.get("GET", "/api/devices/"+l.name+"/audit"); ioInstallLine(body, id, ioRelease) != "" {
			break
		}
	}
	if line := ioInstallLine(body, id, ioRelease); line == "" || !strings.Contains(line, "grace") {
		t.Fatalf("labd's copy of the Audit log lacks grace's install of %s:\n%s", ioRelease, body)
	}
}

// lab-agent writes the entry before it acts: an install still running is
// already in the log.
func TestTheInstallIsAuditedBeforeItRuns(t *testing.T) {
	l, _, msha, _ := ioLab(t, labConfig{})
	started, release := make(chan string, 1), make(chan struct{})
	l.sim.SetInstallHook(func(r string) error {
		started <- r
		<-release
		return nil
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	id := l.ioRun(harnessToken, msha)
	select {
	case <-started:
	case <-time.After(90 * time.Second):
		t.Fatal("the Mac's installer never ran")
	}
	if out := l.mustVolunteer("log"); ioInstallLine(out, id, ioRelease) == "" {
		t.Fatalf("the install is running, yet the Audit log has no entry for it:\n%s", out)
	}
	close(release)
	l.expect(l.jobAPI(id, 180*time.Second), api.OutcomePass)
}

func TestPreinstallReferencesAreTakenFromTheVolunteersCurrentSystem(t *testing.T) {
	l, _, msha, _ := ioLab(t, labConfig{})
	before := strings.Count(l.mustVolunteer("log"), "omarchy-m-test")
	id := l.ioRun(harnessToken, msha)
	j := l.jobAPI(id, 180*time.Second)
	l.expect(j, api.OutcomePass)
	if ir := j.Result.Installed; ir == nil || ir.OMT != "NO_REGRESSION" {
		t.Fatalf("the Installed run was not compared with preinstall references: %+v", ir)
	}

	// The frozen store holds them, pinned, as the acceptance gate reads them.
	dir := l.s.frozenDir(ioRelease)
	pre := filepath.Join(dir, "preinstall", l.name)
	rep, err := os.ReadFile(filepath.Join(pre, "omt-report.json"))
	if err != nil {
		t.Fatalf("no preinstall omarchy-m-test reference was taken: %v", err)
	}
	var r struct {
		Machine struct{ Kernel string } `json:"machine"`
	}
	if json.Unmarshal(rep, &r) != nil || r.Machine.Kernel != agent.SimKnownGood {
		t.Fatalf("the preinstall reference is of kernel %q, not the Volunteer's own %s", r.Machine.Kernel, agent.SimKnownGood)
	}
	if _, err := os.Stat(filepath.Join(pre, "dmesg-errors.txt")); err != nil {
		t.Fatalf("no preinstall kernel error reference was taken: %v", err)
	}
	pins, _ := os.ReadFile(filepath.Join(dir, "PINS.preinstall"))
	if !strings.Contains(string(pins), installed.SHA256(rep)+"  preinstall/"+l.name+"/omt-report.json") {
		t.Fatalf("PINS.preinstall does not pin the reference:\n%s", pins)
	}

	// They were taken in this run, on the Volunteer's system, before the install.
	out := l.alWaitLog(id, ioRelease)
	line := ioInstallLine(out, id, ioRelease)
	if line == "" {
		t.Fatalf("the Audit log has no install entry for %s:\n%s", id, out)
	}
	if n := strings.Count(out[:strings.Index(out, line)], "omarchy-m-test"); n <= before {
		t.Fatalf("no omarchy-m-test ran on the Volunteer's system between the run's start and the install:\n%s", out)
	}
}

// The installer's entry is read on the Mac by the run itself, once the
// Release is installed, not frozen beforehand through a Maintainer's exec.
func TestTheInstalledRunTakesTheInstallerEntryFromTheMacItself(t *testing.T) {
	l, _, msha, entry := ioLab(t, labConfig{})
	id := l.ioRun(harnessToken, msha)
	j := l.jobAPI(id, 180*time.Second)
	l.expect(j, api.OutcomePass)
	if ir := j.Result.Installed; ir == nil || ir.EntrySHA256 == "" {
		t.Fatalf("the Installed run has no installer entry: %+v", ir)
	}
	b, err := os.ReadFile(filepath.Join(l.s.frozenDir(ioRelease), "installer-entry", l.name+".json"))
	var ie installed.InstallerEntry
	if err != nil || json.Unmarshal(b, &ie) != nil {
		t.Fatalf("the installer entry was not frozen: %v", err)
	}
	if ie.Release != ioRelease || ie.Device != l.name || ie.Entry.Path != entry.Path || ie.Entry.EntrySHA256 != entry.EntrySHA256 {
		t.Fatalf("the frozen installer entry is not the one the Mac shows: %+v", ie)
	}
}

func TestAFailedInstallEndsTheRunBeforeAnyLabBoot(t *testing.T) {
	l, _, msha, _ := ioLab(t, labConfig{})
	l.sim.SetInstallHook(func(string) error { return os.ErrPermission })
	boot, _, _ := l.sim.Identity()
	id := l.ioRun(harnessToken, msha)
	j := l.jobAPI(id, 120*time.Second)
	if j.Outcome == api.OutcomePass || j.Result.Booted {
		t.Fatalf("a run whose install failed: %s booted=%v (%s)", j.Outcome, j.Result.Booted, j.Summary)
	}
	if !strings.Contains(strings.ToLower(j.Summary), "install") {
		t.Fatalf("the run's summary does not say the install failed: %s", j.Summary)
	}
	if b, k, _ := l.sim.Identity(); b != boot || k != agent.SimKnownGood {
		t.Fatalf("the Mac rebooted after a failed install: now %s on boot %s", k, b)
	}
	if got := l.sim.Installs(); len(got) != 0 {
		t.Fatalf("the Sim counts a failed install as installed: %v", got)
	}
	if out := l.mustVolunteer("log"); ioInstallLine(out, id, ioRelease) == "" {
		t.Fatalf("the Audit log lacks the install that failed:\n%s", out)
	}
}

// lab-agent holds the install to the Availability window like anything
// else from the lab: labd's own install command, sent again once the
// Volunteer paused, is refused.
func TestLabAgentRefusesTheInstallOutsideAWindow(t *testing.T) {
	rec, w := &ioRecorder{}, newALWire()
	l, _, msha, _ := ioLab(t, labConfig{wrap: func(h http.Handler) http.Handler { return w.wrap(rec.wrap(h)) }})
	l.expect(l.jobAPI(l.ioRun(harnessToken, msha), 180*time.Second), api.OutcomePass)
	ins := rec.ioInstalls()
	if len(ins) != 1 {
		t.Fatalf("labd sent %d install commands, want 1", len(ins))
	}
	l.mustVolunteer("pause")
	time.Sleep(time.Second)
	res := w.result(t, w.send(ins[0].Kind, ins[0].JobID, ins[0].Maintainer, ins[0].Args))
	if res.OK || !res.WindowClosed {
		t.Fatalf("lab-agent took an install with its window closed: %+v", res)
	}
	if got := l.sim.Installs(); len(got) != 1 {
		t.Fatalf("installs on the Mac: %v", got)
	}
}

// An Installed run is Qualification work: the Volunteer lowering the
// Access level to Qualification leaves it running.
func TestLoweringTheAccessLevelLeavesAnInstalledRunRunning(t *testing.T) {
	l, _, msha, _ := ioLab(t, labConfig{})
	l.alSetAccess("full")
	l.sim.SetTestLength(3 * time.Second)
	id := l.ioRun(harnessToken, msha)
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		j, _ := l.jobNow(id)
		if j.State == api.JobTesting {
			break
		}
		if j.State == api.JobDone || time.Now().After(deadline) {
			t.Fatalf("the Installed run never got to its tests: %s %s %s", j.State, j.Outcome, j.Summary)
		}
	}
	l.mustVolunteer("access", "qualification")
	l.expect(l.jobAPI(id, 180*time.Second), api.OutcomePass)
}

// The install doesn't open a door: at Qualification labd still refuses
// exec, and an Installed run that carries a Maintainer's script.
func TestExecAndScriptsStayRefusedAtLabdAlongsideTheInstall(t *testing.T) {
	l, _, msha, _ := ioLab(t, labConfig{})
	if r, _, body := l.alExec(harnessToken, "pacman -U /tmp/linux-aurora-9.9.pkg.tar.zst"); !alIs4xx(r) {
		t.Fatalf("lab exec of an installer at Qualification: %s %s", r.Status, body)
	}
	for _, gui := range []bool{false, true} {
		spec := api.JobSpec{Device: l.name, InstalledManifest: msha, Holder: "io-tester",
			Tests: []api.TestSpec{{Name: "io-extra", Script: l.artifact("echo as root"), GUI: gui}}}
		if r, body := l.post("/api/jobs", spec); !alIs4xx(r) || !strings.Contains(strings.ToLower(body), "access level") {
			t.Fatalf("an Installed run with a Maintainer's script (gui %v) at Qualification: %s %s", gui, r.Status, body)
		}
	}
	if got := l.sim.Installs(); len(got) != 0 {
		t.Fatalf("a refused job installed %v", got)
	}
}

// Allowing the Installed run's identity checks doesn't let a Maintainer's
// script through under their name.
func TestLabAgentRefusesAScriptNamedLikeAnIdentityCheckAtQualification(t *testing.T) {
	w := newALWire()
	l, _, _, _ := ioLab(t, labConfig{wrap: w.wrap})
	script := l.artifact("#!/bin/sh\ntouch /io-bypassed\n")
	for _, name := range []string{"identity-before", "identity-booted", "identity-after"} {
		id := w.send(api.CmdRunTest, "io-job-bypass", "mallory", api.TestSpec{Name: name, Script: script})
		if res := w.result(t, id); res.OK || strings.Contains(string(res.Output), "sim identity") {
			t.Fatalf("lab-agent at Qualification ran a script named %s: %+v", name, res)
		}
	}
	exec := w.send(api.CmdExec, "io-job-bypass", "mallory", api.ExecArgs{Command: "pacman -U linux-aurora-9.9.pkg.tar.zst"})
	if res := w.result(t, exec); res.OK {
		t.Fatalf("lab-agent at Qualification ran an exec of the installer: %+v", res)
	}
}

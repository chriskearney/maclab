package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/installed"
)

const (
	tKrel = "7.1.12-sim-9.9"
	tVml  = "1111111111111111111111111111111111111111111111111111111111111111"
	tDtbA = "2222222222222222222222222222222222222222222222222222222222222222"
	tDtbB = "3333333333333333333333333333333333333333333333333333333333333333"
	tM1n1 = "4444444444444444444444444444444444444444444444444444444444444444"
	tUbt  = "5555555555555555555555555555555555555555555555555555555555555555"
	tBoot = "6666666666666666666666666666666666666666666666666666666666666666"
	tUKI  = "7777777777777777777777777777777777777777777777777777777777777777"
	tIrd  = "8888888888888888888888888888888888888888888888888888888888888888"
	tMtr  = "9999999999999999999999999999999999999999999999999999999999999999"
)

var tB2 = strings.Repeat("b2", 64) // the UKI's measured BLAKE2b-512, which its path pins

func (l *lab) post(path string, body any) (*http.Response, string) {
	l.t.Helper()
	return l.as(harnessToken, "POST", path, body)
}

func pinsFor(dir string, rels ...string) string {
	var b strings.Builder
	b.WriteString("# test pins\n")
	for _, r := range rels {
		data, _ := os.ReadFile(filepath.Join(dir, r))
		b.WriteString(installed.SHA256(data) + "  " + r + "\n")
	}
	return b.String()
}

// installedLab is a simulated Mac with release 9.9 "installed": a frozen
// pre-install baseline (taken from a real sim baseline job), a frozen expected
// manifest (through the HTTP freeze endpoint) and a frozen installer entry.
func installedLab(t *testing.T, tamper func(phase string, o map[string]any)) (*lab, string, installed.Entry) {
	l := newLab(t, false)
	l.s.cfg.OMT = true
	l.waitDevice(func(d api.Device) bool { return d.Facts.AgentVersion != "" })
	l.baseline()
	jobs, _ := l.s.store.jobs("sim-mac", 5, false)
	bj := jobs[0].ID
	dir := l.s.frozenDir("9.9")
	pre := filepath.Join(dir, "preinstall", "sim-mac")
	os.MkdirAll(pre, 0o755)
	rep, _ := os.ReadFile(filepath.Join(l.s.jobDir(bj), omtFile))
	os.WriteFile(filepath.Join(pre, "omt-report.json"), rep, 0o444)
	st, _, _, _ := installed.ReportStatus(rep)
	sb, _ := json.Marshal(st)
	os.WriteFile(filepath.Join(pre, "omt-status.json"), sb, 0o444)
	dm, _ := os.ReadFile(l.s.baselinePath("sim-mac"))
	os.WriteFile(filepath.Join(pre, "dmesg-errors.txt"), dm, 0o444)
	os.WriteFile(filepath.Join(pre, "baseline-job.json"), []byte(`{"id":"`+bj+`"}`), 0o444)
	os.WriteFile(filepath.Join(dir, "PINS.preinstall"), []byte(pinsFor(dir, "preinstall/sim-mac/omt-report.json",
		"preinstall/sim-mac/omt-status.json", "preinstall/sim-mac/dmesg-errors.txt", "preinstall/sim-mac/baseline-job.json")), 0o444)

	payload := tVml + "  vmlinuz\n" + tDtbA + "  dtbs/t-a.dtb\n" + tDtbB + "  dtbs/t-b.dtb\n" + tMtr + "  modules.dep\n"
	m := installed.Manifest{Schema: installed.ManifestSchema, Release: "9.9",
		Artifacts: []installed.Artifact{{Name: "linux-aurora", File: "linux-aurora-9.9.pkg.tar.zst", SHA256: tVml, Version: "9.9-1", MtreeSHA256: tMtr}},
		DTBs:      []installed.DTB{{Name: "t-a.dtb", SHA256: tDtbA}, {Name: "t-b.dtb", SHA256: tDtbB}},
		Macs:      map[string]installed.MacExpect{"sim-mac": {Board: "apple,sim", BoardDTB: "t-a.dtb", UbootGzSHA256: tUbt, BootBinSHA256: tBoot}}}
	m.DTBsSHA256 = installed.DTBsDigest(m.DTBs)
	m.Kernel.Release, m.Kernel.VmlinuzSHA256 = tKrel, tVml
	m.Kernel.PayloadManifest, m.Kernel.PayloadManifestSHA256, m.Kernel.PayloadCount = "payload/linux-aurora.files.sha256", installed.SHA256([]byte(payload)), 4
	m.Kernel.RegeneratedOnMac = []string{"modules.dep"}
	m.M1n1.BinSHA256, m.M1n1.Version = tM1n1, "v1.6.1-omarchy.sim"
	mb, _ := json.MarshalIndent(m, "", "  ")
	resp, body := l.post("/api/installed/9.9/manifest", map[string]any{"manifest": l.artifact(string(mb)), "payload": l.artifact(payload), "approved_by": []string{"boss", "dave"}})
	if resp.StatusCode != 200 {
		t.Fatalf("freeze manifest: %s %s", resp.Status, body)
	}
	// written once
	if resp, _ := l.post("/api/installed/9.9/manifest", map[string]any{"manifest": l.artifact(string(mb)), "payload": l.artifact(payload)}); resp.StatusCode != 409 {
		t.Fatalf("second freeze: %s", resp.Status)
	}

	tokens := []string{"root=UUID=sim", "rw", "quiet", "splash"}
	path := "boot():/EFI/Linux/omarchy_linux-aurora.efi#" + tB2
	lines := []string{"  //linux-aurora", "  protocol: efi", "  path: " + path, "  cmdline: root=UUID=sim rw quiet splash"}
	entry := installed.Entry{Found: true, Name: "Omarchy / linux-aurora", Protocol: "efi", Path: path,
		Cmdline: strings.Join(tokens, " "), CmdlineTokens: tokens, EntryLines: lines, EntrySHA256: installed.EntryDigest(lines), UKISHA256: tUKI, UKIBlake2b: tB2,
		UKISections: map[string]installed.Section{".linux": {SHA256: tVml}, ".initrd": {SHA256: tIrd}, ".cmdline": {SHA256: "cc"}, ".uname": {SHA256: "uu", Text: tKrel}}}
	eb, _ := json.MarshalIndent(installed.InstallerEntry{Schema: "maclab.installer-entry/1", Device: "sim-mac", Release: "9.9", Entry: entry}, "", "  ")
	os.MkdirAll(filepath.Join(dir, "installer-entry"), 0o755)
	os.WriteFile(filepath.Join(dir, "installer-entry", "sim-mac.json"), eb, 0o444)
	os.WriteFile(filepath.Join(dir, "PINS.installer-entry.sim-mac"), []byte(pinsFor(dir, "installer-entry/sim-mac.json")), 0o444)

	l.sim.PackagedKernels = []string{tKrel}
	l.sim.DefaultKernel = tKrel // the installer has run: a plain reboot comes up on it
	l.sim.InstalledObs = func(phase, job, bootID, kernel, cmdline string) []byte {
		stage2 := "v1.6.1-omarchy.sim"
		if phase == installed.PhaseBefore {
			stage2 = "v1.6.1-omarchy.old"
		}
		o := map[string]any{"schema": "maclab.installed-observed/1", "phase": phase, "device": "sim-mac", "job": job,
			"running":  map[string]any{"boot_id": bootID, "uname_r": kernel, "proc_cmdline": cmdline},
			"packages": map[string]any{"linux-aurora": map[string]any{"version": "9.9-1", "mtree_sha256": tMtr}},
			"payload": map[string]any{"krel": tKrel, "root": "/usr/lib/modules/" + tKrel, "count": 4,
				"files": map[string]string{"vmlinuz": tVml, "dtbs/t-a.dtb": tDtbA, "dtbs/t-b.dtb": tDtbB, "modules.dep": "regenerated"}},
			"installer_entry": entry,
			"boot_bin": map[string]any{"path": "/boot/efi/m1n1/boot.bin", "sha256": tBoot, "parts": map[string]any{"m1n1_sha256": tM1n1,
				"dtb_shas": []string{tDtbA, tDtbB}, "dtb_count": 2, "board_dtb_sha256": tDtbA, "board_dtb_count": 1, "uboot_gz_sha256": tUbt, "trailer": ""}},
			"dt": map[string]any{"board": "apple,sim", "compatible": []string{"apple,sim"}, "live_stage2_version": stage2}}
		if tamper != nil {
			tamper(phase, o)
		}
		b, _ := json.MarshalIndent(o, "", " ")
		return b
	}
	v := l.s.dev("sim-mac")
	v.mu.Lock()
	v.d.Lease = &api.Lease{Holder: "tester", Expires: time.Now().Add(time.Hour)}
	v.mu.Unlock()
	return l, installed.SHA256(mb), entry
}

func TestInstalledJob(t *testing.T) {
	l, msha, entry := installedLab(t, nil)
	kg := l.s.dev("sim-mac").snapshot().KnownGood
	refBefore, _ := os.ReadFile(l.s.omtBaselinePath("sim-mac"))

	// refusals: a kernel, cmdline overrides, the wrong holder, an unknown manifest
	for _, spec := range []api.JobSpec{
		{InstalledManifest: msha, Holder: "tester", Cmdline: "foo=1"},
		{InstalledManifest: msha, Holder: "tester", CmdlineBase: "default"},
		{InstalledManifest: msha, Holder: "tester", VerboseBoot: true},
		{InstalledManifest: msha, Holder: "someone-else"},
		{InstalledManifest: strings.Repeat("0", 64), Holder: "tester"},
	} {
		spec.Device = "sim-mac"
		if _, code, err := l.s.Submit(spec); err == nil {
			t.Errorf("accepted %+v", spec)
		} else if code == 200 {
			t.Errorf("code 200 with error %v", err)
		}
	}

	j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester", Tests: []api.TestSpec{{Name: "display-check", Builtin: "x"}}})
	l.expect(j, api.OutcomePass)
	ir := j.Result.Installed
	if ir == nil || ir.Verdicts["before"] != "MATCH" || ir.Verdicts["booted"] != "MATCH" || ir.Verdicts["after"] != "MATCH" || ir.OMT != "NO_REGRESSION" {
		t.Fatalf("installed result %+v", ir)
	}
	if ir.Dmesg != "REVIEW_REQUIRED" { // the sim logs one new warning on any kernel but its known-good
		t.Fatalf("dmesg %s", ir.Dmesg)
	}
	var names []string
	for _, tr := range j.Result.Tests {
		names = append(names, tr.Name)
	}
	if names[0] != "identity-booted" || names[len(names)-1] != "identity-after" || slices.Contains(names, "identity-before") || ir.Before == nil {
		t.Fatalf("tests %v (before %v)", names, ir.Before)
	}
	want := strings.Join(entry.CmdlineTokens, " ") + " maclab.job=" + j.ID + " panic=10"
	if j.Result.BootKernel != tKrel || j.Result.BootCmdline != want {
		t.Fatalf("booted %s with %q, want %q", j.Result.BootKernel, j.Result.BootCmdline, want)
	}
	for _, f := range []string{"identity-before.json", "identity-booted.json", "identity-after.json", "omt-compare.json", "dmesg-compare.json", "dmesg-errors.txt", "job.json"} {
		if _, err := os.Stat(filepath.Join(l.s.jobDir(j.ID), "installed", f)); err != nil {
			t.Errorf("evidence %s: %v", f, err)
		}
		if _, err := os.Stat(filepath.Join(l.s.frozenDir("9.9"), "installed", "sim-mac", j.ID, f)); err != nil {
			t.Errorf("frozen copy %s: %v", f, err)
		}
	}
	// the collected logs are the job's, and the compared error lines are the collected ones
	for _, f := range []string{"boot0/collect-status.txt", "boot0/kernel.txt", "boot0/dmesg-errors.txt"} {
		if !slices.Contains(j.Result.Logs, f) {
			t.Fatalf("result.logs lacks %s: %v", f, j.Result.Logs)
		}
	}
	c0, _ := os.ReadFile(filepath.Join(l.s.jobDir(j.ID), "boot0", "dmesg-errors.txt"))
	c1, _ := os.ReadFile(filepath.Join(l.s.jobDir(j.ID), "installed", "dmesg-errors.txt"))
	if len(c0) == 0 || !bytes.Equal(c0, c1) {
		t.Fatalf("boot0 and installed dmesg-errors.txt differ")
	}
	// the job's evidence and its frozen copy are the same bytes, and record the final pass
	jb, _ := os.ReadFile(filepath.Join(l.s.jobDir(j.ID), "installed", "job.json"))
	fb, _ := os.ReadFile(filepath.Join(l.s.frozenDir("9.9"), "installed", "sim-mac", j.ID, "job.json"))
	var rec api.Job
	if !bytes.Equal(jb, fb) || json.Unmarshal(jb, &rec) != nil || rec.State != api.JobDone || rec.Outcome != api.OutcomePass ||
		rec.Result.Installed.Frozen == "" || ir.Frozen != rec.Result.Installed.Frozen {
		t.Fatalf("job.json %s/%s frozen %q (store %q), copies equal %v", rec.State, rec.Outcome, rec.Result.Installed.Frozen, ir.Frozen, bytes.Equal(jb, fb))
	}
	// nothing promoted
	if got := l.s.dev("sim-mac").snapshot().KnownGood; got != kg {
		t.Fatalf("known-good moved: %s -> %s", kg, got)
	}
	if refAfter, _ := os.ReadFile(l.s.omtBaselinePath("sim-mac")); !bytes.Equal(refBefore, refAfter) {
		t.Fatal("the live OMT reference changed")
	}
	if dir := os.Getenv("MACLAB_INSTALLED_SAMPLE"); dir != "" {
		os.CopyFS(dir, os.DirFS(filepath.Join(l.s.jobDir(j.ID), "installed")))
	}

	// promotion is explicit, and only of a passed installed job
	if resp, _ := l.post("/api/installed/9.9/promote", map[string]any{"device": "sim-mac"}); resp.StatusCode != 400 {
		t.Fatalf("promote without a job: %s", resp.Status)
	}
	// the acceptor is the Maintainer behind the token: a free-text
	// accepted_by in the body is ignored (these attempts all fail; the one
	// that succeeds below sends none)
	grace := l.addMaintainer(harnessToken, "grace")
	promote := func() (*http.Response, string) {
		return l.as(grace.Token, "POST", "/api/installed/9.9/promote", map[string]any{"device": "sim-mac", "job": j.ID, "accepted_by": "dave"})
	}
	unchanged := func(why string) {
		t.Helper()
		ref, _ := os.ReadFile(l.s.omtBaselinePath("sim-mac"))
		if got := l.s.dev("sim-mac").snapshot().KnownGood; got != kg || !bytes.Equal(ref, refBefore) {
			t.Fatalf("%s: known-good %s, reference changed %v", why, got, !bytes.Equal(ref, refBefore))
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(l.s.omtBaselinePath("sim-mac")), "*.promote-*")); len(left) > 0 {
			t.Fatalf("%s: staged files left behind: %v", why, left)
		}
	}
	// a frozen copy that no longer matches the job's evidence
	fd := filepath.Join(l.s.frozenDir("9.9"), "installed", "sim-mac", j.ID)
	os.Chmod(fd, 0o755)
	os.Chmod(filepath.Join(fd, "omt-compare.json"), 0o644)
	orig, _ := os.ReadFile(filepath.Join(fd, "omt-compare.json"))
	os.WriteFile(filepath.Join(fd, "omt-compare.json"), append(orig, ' '), 0o444)
	if resp, body := promote(); resp.StatusCode != 409 || !strings.Contains(body, "frozen copy") {
		t.Fatalf("promote with a changed frozen copy: %s %s", resp.Status, body)
	}
	os.WriteFile(filepath.Join(fd, "omt-compare.json"), orig, 0o444)
	unchanged("changed frozen copy")
	// the job's omarchy-m-test report changed after the run: a pass turned into a fail
	rp := filepath.Join(l.s.jobDir(j.ID), omtFile)
	rep, _ := os.ReadFile(rp)
	var rec2 map[string]any
	json.Unmarshal(rep, &rec2)
	for _, c := range rec2["checks"].([]any) {
		if c := c.(map[string]any); c["status"] == "pass" {
			c["status"] = "fail"
			break
		}
	}
	swapped, _ := json.Marshal(rec2)
	os.WriteFile(rp, swapped, 0o644)
	if resp, body := promote(); resp.StatusCode != 409 || !strings.Contains(body, "not the") {
		t.Fatalf("promote with a changed report: %s %s", resp.Status, body)
	}
	os.WriteFile(rp, rep, 0o644)
	unchanged("changed report")
	// the new references can't be staged
	bdir := filepath.Dir(l.s.omtBaselinePath("sim-mac"))
	os.Chmod(bdir, 0o555)
	if resp, body := promote(); resp.StatusCode != 500 || !strings.Contains(body, "nothing was changed") {
		t.Fatalf("promote with unwritable baselines: %s %s", resp.Status, body)
	}
	os.Chmod(bdir, 0o755)
	unchanged("unwritable baselines")
	// the ledger can't be written
	ledger := filepath.Join(l.s.frozenDir("9.9"), "promotions.log")
	os.WriteFile(ledger, nil, 0o444)
	if resp, body := promote(); resp.StatusCode != 500 || !strings.Contains(body, "recording the promotion") {
		t.Fatalf("promote with an unwritable ledger: %s %s", resp.Status, body)
	}
	os.Remove(ledger)
	unchanged("unwritable ledger")

	// the agent refuses to record the known-good: everything is put back
	ledgerFailures := func() int {
		b, _ := os.ReadFile(ledger)
		return strings.Count(string(b), "\tFAILED\t")
	}
	keptGone := func(why string) {
		t.Helper()
		if left, _ := filepath.Glob(filepath.Join(bdir, "*.before-"+j.ID)); len(left) > 0 {
			t.Fatalf("%s: kept copies left behind: %v", why, left)
		}
	}
	l.sim.SetKnownGoodHook(func(string) error { return errors.New("refused for the test") })
	if resp, body := promote(); resp.StatusCode != 500 || !strings.Contains(body, "did not record") ||
		strings.Contains(body, "it may have") || !strings.Contains(body, "previous references were put back") {
		t.Fatalf("promote with the agent refusing: %s %s", resp.Status, body)
	}
	unchanged("agent refused")
	keptGone("agent refused")
	if n := ledgerFailures(); n != 1 {
		t.Fatalf("agent refused: %d FAILED ledger records, want 1", n)
	}
	// the command gets no answer: put back too, saying the agent may have recorded it
	saved := recordKnownGoodTimeout
	recordKnownGoodTimeout = 300 * time.Millisecond
	l.sim.SetKnownGoodHook(func(string) error { time.Sleep(2 * time.Second); return nil })
	if resp, body := promote(); resp.StatusCode != 500 || !strings.Contains(body, "it may have") {
		t.Fatalf("promote with the agent not answering: %s %s", resp.Status, body)
	}
	recordKnownGoodTimeout = saved
	time.Sleep(2500 * time.Millisecond)
	l.sim.SetKnownGoodHook(nil)
	unchanged("agent did not answer")
	keptGone("agent did not answer")
	if n := ledgerFailures(); n != 2 {
		t.Fatalf("agent did not answer: %d FAILED ledger records, want 2", n)
	}

	resp, body := l.as(grace.Token, "POST", "/api/installed/9.9/promote", map[string]any{"device": "sim-mac", "job": j.ID})
	if resp.StatusCode != 200 || l.s.dev("sim-mac").snapshot().KnownGood != tKrel {
		t.Fatalf("promote: %s %s", resp.Status, body)
	}
	var promoted struct{ Log string }
	if json.Unmarshal([]byte(body), &promoted) != nil || !strings.HasSuffix(promoted.Log, "\taccepted-by=grace") {
		t.Fatalf("promote's log line does not name the accepting Maintainer: %s", body)
	}
	if l.sim.RecordedKnownGood != tKrel {
		t.Fatalf("the agent's known-good is %q, not %s", l.sim.RecordedKnownGood, tKrel)
	}
	// the live references stay writable: lab baseline replaces them later
	for _, p := range []string{l.s.omtBaselinePath("sim-mac"), l.s.baselinePath("sim-mac")} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s after promotion: %v %v", p, fi.Mode(), err)
		}
	}
	if resp, _ := promote(); resp.StatusCode != 409 {
		t.Fatalf("second promote: %s", resp.Status)
	}
	if b, err := os.ReadFile(l.s.omtBaselinePath("sim-mac") + ".before-" + j.ID); err != nil || !bytes.Equal(b, refBefore) {
		t.Fatalf("the previous reference was not kept: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(l.s.frozenDir("9.9"), "promotions.log")); !strings.Contains(string(b), j.ID+"\t"+tKrel+"\taccepted-by=grace") || strings.Contains(string(b), "accepted-by=dave") {
		t.Fatalf("promotions.log: %q", b)
	}
	// a read-only kernel error reference, as an earlier labd's promotion left
	// it, is still replaced by the next baseline
	bp := l.s.baselinePath("sim-mac")
	os.Chmod(bp, 0o644)
	os.WriteFile(bp, []byte("stale\n"), 0o444)
	os.Chmod(bp, 0o444)
	if bj := l.run(api.JobSpec{Baseline: true, Holder: "tester"}); bj.Outcome != api.OutcomePass {
		t.Fatalf("baseline after promotion: %s %s", bj.Outcome, bj.Summary)
	}
	if b, _ := os.ReadFile(bp); string(b) == "stale\n" {
		t.Fatal("the baseline did not replace a read-only kernel error reference")
	}
}

func TestPromoteNeedsTheInstalledKernel(t *testing.T) {
	l, msha, _ := installedLab(t, nil)
	j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
	l.expect(j, api.OutcomePass)
	kg := l.s.dev("sim-mac").snapshot().KnownGood
	ledger := filepath.Join(l.s.frozenDir("9.9"), "promotions.log")
	promote := func() (*http.Response, string) {
		return l.post("/api/installed/9.9/promote", map[string]any{"device": "sim-mac", "job": j.ID, "accepted_by": "dave"})
	}
	refused := func(why, want string) {
		t.Helper()
		if resp, body := promote(); resp.StatusCode != 409 || !strings.Contains(body, want) {
			t.Fatalf("%s: %s %s", why, resp.Status, body)
		}
		if got := l.s.dev("sim-mac").snapshot().KnownGood; got != kg || l.sim.RecordedKnownGood != "" {
			t.Fatalf("%s: known-good %s, agent's %q", why, got, l.sim.RecordedKnownGood)
		}
		if _, err := os.Stat(ledger); !os.IsNotExist(err) {
			t.Fatalf("%s: the ledger was written (%v)", why, err)
		}
	}
	// back on the old kernel
	l.sim.DefaultKernel = ""
	l.sim.Reboot()
	l.waitDevice(func(d api.Device) bool { return d.Kernel == agent.SimKnownGood })
	refused("old kernel", "boot it first")
	l.sim.DefaultKernel = tKrel
	l.sim.Reboot()
	l.waitDevice(func(d api.Device) bool { return d.Kernel == tKrel })
	// an agent that can't record the known-good
	v := l.s.dev("sim-mac")
	v.mu.Lock()
	ver := v.d.Facts.AgentVersion
	v.d.Facts.AgentVersion = "0.7.2"
	v.mu.Unlock()
	refused("old agent", "needs 0.7.3")
	v.mu.Lock()
	v.d.Facts.AgentVersion = ver
	v.mu.Unlock()
	if resp, body := promote(); resp.StatusCode != 200 || l.sim.RecordedKnownGood != tKrel {
		t.Fatalf("promote on the installed kernel: %s %s", resp.Status, body)
	}
}

func TestInstalledJobCatchesInheritedCmdline(t *testing.T) {
	// the Mac boots, but with a bring-up argument the installer's entry doesn't have
	l, msha, _ := installedLab(t, func(phase string, o map[string]any) {
		if phase != installed.PhaseBefore {
			r := o["running"].(map[string]any)
			r["proc_cmdline"] = r["proc_cmdline"].(string) + " asahi.m3_backend=runtime"
		}
	})
	j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
	l.expect(j, api.OutcomeTestsFailed)
	if v := j.Result.Installed.Verdicts; v["booted"] != "MISMATCH" || v["after"] != "MISMATCH" {
		t.Fatalf("verdicts %v", v)
	}
}

func TestInstalledJobStopsBeforeBootOnWrongState(t *testing.T) {
	// the installed boot.bin is not the expected one: fail before rebooting
	l, msha, _ := installedLab(t, func(phase string, o map[string]any) {
		o["boot_bin"].(map[string]any)["sha256"] = tVml
	})
	boot0 := l.s.dev("sim-mac").snapshot().BootID
	j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
	l.expect(j, api.OutcomeTestsFailed)
	if !strings.Contains(j.Summary, "before boot") || j.Result.Booted || l.s.dev("sim-mac").snapshot().BootID != boot0 {
		t.Fatalf("summary %q booted %v", j.Summary, j.Result.Booted)
	}
}

// Regression rows for the installed-mode audit: an installed job that can't
// show its kernel log or keep its evidence is never a pass.
func TestInstalledJobFailsClosedWithoutKernelLogs(t *testing.T) {
	logs := func(status, kernel string, dmesg *string) func(string, string) error {
		return func(_, out string) error {
			if status != "" {
				os.WriteFile(filepath.Join(out, "collect-status.txt"), []byte(status), 0o644)
			}
			os.WriteFile(filepath.Join(out, "kernel.txt"), []byte(kernel), 0o644)
			if dmesg != nil {
				os.WriteFile(filepath.Join(out, "dmesg-errors.txt"), []byte(*dmesg), 0o644)
			}
			return nil
		}
	}
	ok := "kernel.txt ok\ndmesg-errors.txt ok\n"
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		name    string
		collect func(boot, out string) error
		want    string // "" means the job passes
	}{
		{"transport failure", func(string, string) error { return errors.New("injected collector transport failure") }, "collecting logs failed"},
		{"no collect-status.txt (agent before 0.7.1)", logs("", "Linux version x\n", str("")), "boot0/collect-status.txt was not collected"},
		{"journalctl failed", logs("kernel.txt ok\ndmesg-errors.txt journalctl failed: exit status 1\n", "Linux version x\n", str("")), "dmesg-errors.txt is not valid evidence: journalctl failed"},
		{"write failed", logs("kernel.txt write failed: no space left on device\ndmesg-errors.txt ok\n", "", str("")), "kernel.txt is not valid evidence: write failed"},
		{"no dmesg-errors.txt", logs(ok, "Linux version x\n", nil), "boot0/dmesg-errors.txt was not collected"},
		{"contradictory status", logs(ok+"dmesg-errors.txt journalctl failed: exit status 1\n", "Linux version x\n", str("")), "reports it 2 times"},
		{"status missing a log", logs("kernel.txt ok\n", "Linux version x\n", str("")), "doesn't report it"},
		{"empty kernel log", logs(ok, "", str("")), "kernel.txt is empty"},
		{"journalctl error text in an ok file", logs(ok, "Linux version x\n", str("\n[journalctl: exit status 1]\n")), "journalctl failed"},
		{"an empty warning log is valid", logs(ok, "Linux version x\n", str("")), ""},
		// the filtered warnings are empty, but the full kernel log has a fatal event
		{"fatal only in the full kernel log", logs(ok, "Linux version x\n[   12.0] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008\n", str("")), "!unhealthy"},
		{"bare Oops in the full kernel log", logs(ok, "Linux version x\n[   12.0] Oops: 0002 [#1] SMP\n", str("")), "!unhealthy"},
		{"general protection fault in the full kernel log", logs(ok, "Linux version x\n[   12.0] general protection fault, probably for non-canonical address\n", str("")), "!unhealthy"},
		{"double fault in the full kernel log", logs(ok, "Linux version x\n[   12.0] double fault: 0000 [#1] PREEMPT SMP\n", str("")), "!unhealthy"},
		{"recursive fault in the full kernel log", logs(ok, "Linux version x\n[   12.0] Fixing recursive fault but reboot is needed!\n", str("")), "!unhealthy"},
		{"bare Oops in the warnings too", logs(ok, "Linux version x\n[   12.0] Oops: 0002 [#1] SMP\n", str("Oops: 0002 [#1] SMP\n")), "!fatal-both"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, msha, _ := installedLab(t, nil)
			l.sim.CollectHook = c.collect
			j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
			if c.want == "!fatal-both" {
				l.expect(j, api.OutcomeUnhealthy)
				if j.Result.Installed.Dmesg != "FATAL" || len(j.Result.Installed.KernelLogFatal) != 1 {
					t.Fatalf("dmesg %q kernel_log_fatal %v", j.Result.Installed.Dmesg, j.Result.Installed.KernelLogFatal)
				}
				return
			}
			if c.want == "!unhealthy" {
				l.expect(j, api.OutcomeUnhealthy)
				if !strings.Contains(j.Summary, "kernel.txt") || len(j.Result.Installed.KernelLogFatal) != 1 || j.Result.Installed.Dmesg != "NONE_NEW" {
					t.Fatalf("summary %q kernel_log_fatal %v dmesg %q", j.Summary, j.Result.Installed.KernelLogFatal, j.Result.Installed.Dmesg)
				}
				return
			}
			if c.want == "" {
				l.expect(j, api.OutcomePass)
				if j.Result.Installed.Dmesg != "NONE_NEW" {
					t.Fatalf("dmesg %q", j.Result.Installed.Dmesg)
				}
				return
			}
			l.expect(j, api.OutcomeInfra)
			if !strings.Contains(j.Summary, c.want) || j.Result.Installed.Dmesg != "" {
				t.Fatalf("summary %q dmesg %q", j.Summary, j.Result.Installed.Dmesg)
			}
			// the frozen copy is complete, and records the failure, not a pass
			var rec api.Job
			b, err := os.ReadFile(filepath.Join(l.s.frozenDir("9.9"), "installed", "sim-mac", j.ID, "job.json"))
			if err != nil || json.Unmarshal(b, &rec) != nil || rec.Outcome != api.OutcomeInfra || rec.State != api.JobDone {
				t.Fatalf("frozen job.json: %v %s/%s", err, rec.State, rec.Outcome)
			}
			if resp, _ := l.post("/api/installed/9.9/promote", map[string]any{"device": "sim-mac", "job": j.ID, "accepted_by": "dave"}); resp.StatusCode != 409 {
				t.Fatalf("promoting a job without its kernel log: %s", resp.Status)
			}
		})
	}
}

func TestInstalledJobFailsClosedWithoutFrozenCopy(t *testing.T) {
	var l *lab
	l, msha, _ := installedLab(t, func(phase string, o map[string]any) {
		if phase == installed.PhaseAfter { // something in the way of the frozen copy
			if err := os.WriteFile(filepath.Join(l.s.frozenDir("9.9"), "installed"), []byte("obstruction"), 0o444); err != nil {
				t.Fatal(err)
			}
		}
	})
	j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
	l.expect(j, api.OutcomeInfra)
	if !strings.Contains(j.Summary, "frozen copy") || j.Result.Installed.Frozen != "" {
		t.Fatalf("summary %q frozen %q", j.Summary, j.Result.Installed.Frozen)
	}
	var rec api.Job
	b, _ := os.ReadFile(filepath.Join(l.s.jobDir(j.ID), "installed", "job.json"))
	if json.Unmarshal(b, &rec) != nil || rec.Outcome != api.OutcomeInfra {
		t.Fatalf("the job's own job.json says %q", rec.Outcome)
	}
}

func TestInstalledJobFailsClosedOnEvidenceWriteError(t *testing.T) {
	var l *lab
	var id string
	l, msha, _ := installedLab(t, func(phase string, o map[string]any) {
		if phase == installed.PhaseAfter { // installed/ stops being writable before identity-after is merged
			id = o["job"].(string)
			os.Chmod(filepath.Join(l.s.jobDir(id), "installed"), 0o555)
		}
	})
	j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
	os.Chmod(filepath.Join(l.s.jobDir(id), "installed"), 0o755)
	l.expect(j, api.OutcomeInfra)
	if !strings.Contains(j.Summary, "writing installed/identity-after.json") || j.Result.Installed.Frozen != "" {
		t.Fatalf("summary %q frozen %q", j.Summary, j.Result.Installed.Frozen)
	}
	if _, err := os.Stat(filepath.Join(l.s.frozenDir("9.9"), "installed", "sim-mac", j.ID, "job.json")); err == nil {
		t.Fatal("the frozen store has a job.json for a job whose evidence is incomplete")
	}
}

func TestPublishDir(t *testing.T) {
	src, root := t.TempDir(), t.TempDir()
	for n, b := range map[string]string{"a.json": "a", "b.txt": "b", "job.json": "j"} {
		os.WriteFile(filepath.Join(src, n), []byte(b), 0o644)
	}
	dst := filepath.Join(root, "installed", "mac", "j1")
	if err := publishDir(src, dst, "job.json"); err != nil {
		t.Fatal(err)
	}
	if err := sameFiles(src, dst); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dst, "a.json")); st.Mode().Perm() != 0o444 {
		t.Fatalf("mode %v", st.Mode())
	}
	// an existing destination is refused, not trusted or merged into
	if err := publishDir(src, dst, "job.json"); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("second publish: %v", err)
	}
	// a source that can't be read leaves no destination and no partial directory
	os.Chmod(filepath.Join(src, "b.txt"), 0)
	dst2 := filepath.Join(root, "installed", "mac", "j2")
	if err := publishDir(src, dst2, "job.json"); err == nil {
		t.Fatal("published an unreadable source")
	}
	if left, _ := os.ReadDir(filepath.Dir(dst2)); len(left) != 1 {
		t.Fatalf("left behind: %v", left)
	}
	// write-once is exclusive
	if err := writeOnce(filepath.Join(dst, "a.json"), []byte("x")); err == nil {
		t.Fatal("writeOnce replaced a file")
	}
}

// A frozen copy that can't be made durable is not published.
func TestPublishDirSyncFailures(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "job.json"), []byte("frozen"), 0o644)
	// the parent can't be opened to sync it (Darnell's reproduction)
	root := t.TempDir()
	os.Chmod(root, 0o300)
	defer os.Chmod(root, 0o700)
	if err := publishDir(src, filepath.Join(root, "published"), "job.json"); err == nil || !strings.Contains(err.Error(), "syncing") {
		t.Fatalf("unopenable parent: %v", err)
	}
	os.Chmod(root, 0o700)
	if left, _ := os.ReadDir(root); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	// the sync after the rename fails: nothing stays published
	saved := syncDir
	defer func() { syncDir = saved }()
	root2 := t.TempDir()
	parentSyncs := 0
	syncDir = func(p string) error {
		if p == root2 {
			if parentSyncs++; parentSyncs == 2 { // the first is before writing, the second after the rename
				return errors.New("injected sync failure")
			}
		}
		return saved(p)
	}
	dst := filepath.Join(root2, "published")
	if err := publishDir(src, dst, "job.json"); err == nil || !strings.Contains(err.Error(), "moved aside") {
		t.Fatalf("failed sync after rename: %v", err)
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Fatal("an unsynced copy stayed published")
	}
	if left, _ := os.ReadDir(root2); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

// Promotion makes every new name durable: each file it creates, the ledger, and
// each reference it renames into place has its directory synced, and a sync
// that fails at any of those points fails the promotion with the previous
// references and known-good kernel in place, so it can be tried again.
func TestPromotionDurability(t *testing.T) {
	l, msha, _ := installedLab(t, nil)
	j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
	l.expect(j, api.OutcomePass)
	kg := l.s.dev("sim-mac").snapshot().KnownGood
	refs := []string{l.s.omtBaselinePath("sim-mac"), l.s.baselinePath("sim-mac")}
	before := map[string][]byte{}
	for _, p := range refs {
		before[p], _ = os.ReadFile(p)
	}
	saved := syncDir
	defer func() { syncDir = saved }()
	promote := func(failAt int) (int, int) {
		calls := 0
		syncDir = func(p string) error {
			calls++
			if calls == failAt {
				return errors.New("injected directory sync failure")
			}
			return saved(p)
		}
		resp, _ := l.post("/api/installed/9.9/promote", map[string]any{"device": "sim-mac", "job": j.ID, "accepted_by": "dave"})
		syncDir = saved
		return resp.StatusCode, calls
	}
	for k := 1; ; k++ {
		code, calls := promote(k)
		if code == 200 {
			// staged x2, ledger, kept copies x2, renames x2: seven directory syncs at least
			if k <= 7 || calls < 7 {
				t.Fatalf("promotion succeeded with only %d directory syncs (injection at %d)", calls, k)
			}
			break
		}
		if code != 500 {
			t.Fatalf("sync failure %d: HTTP %d", k, code)
		}
		if got := l.s.dev("sim-mac").snapshot().KnownGood; got != kg {
			t.Fatalf("sync failure %d moved known-good to %s", k, got)
		}
		for _, p := range refs {
			if b, _ := os.ReadFile(p); !bytes.Equal(b, before[p]) {
				t.Fatalf("sync failure %d left %s changed", k, p)
			}
			if _, err := os.Stat(p + ".before-" + j.ID); err == nil {
				t.Fatalf("sync failure %d left %s.before-%s", k, p, j.ID)
			}
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(refs[0]), "*.promote-*")); len(left) > 0 {
			t.Fatalf("sync failure %d left %v", k, left)
		}
	}
	if l.s.dev("sim-mac").snapshot().KnownGood != tKrel {
		t.Fatal("the final promotion did not take")
	}
	b, err := os.ReadFile(filepath.Join(l.s.frozenDir("9.9"), "promotions.log"))
	// the two staging failures come before the ledger line; the other five each leave a FAILED record
	if err != nil || !promotedIn(b, j.ID) || strings.Count(string(b), "\tFAILED\t") != 5 {
		t.Fatalf("ledger (%v):\n%s", err, b)
	}
}

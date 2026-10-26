package installed

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/agent"
)

const (
	vml  = "1111111111111111111111111111111111111111111111111111111111111111"
	dtb1 = "2222222222222222222222222222222222222222222222222222222222222222"
	dtb2 = "3333333333333333333333333333333333333333333333333333333333333333"
	m1n1 = "4444444444444444444444444444444444444444444444444444444444444444"
	ubt  = "5555555555555555555555555555555555555555555555555555555555555555"
	boot = "6666666666666666666666666666666666666666666666666666666666666666"
	uki  = "7777777777777777777777777777777777777777777777777777777777777777"
	ird  = "8888888888888888888888888888888888888888888888888888888888888888"
	mtr  = "9999999999999999999999999999999999999999999999999999999999999999"
	krel = "7.1.12-2-12.0-sep-ARCH"
)

var installerTokens = []string{"root=UUID=x", "rw", "quiet", "splash"}

var ukiB2 = strings.Repeat("b2", 64) // the UKI's measured BLAKE2b-512, which its path pins

// fixture builds a consistent manifest, payload, frozen entry and a matching observation.
func fixture(t *testing.T) (*Manifest, map[string]string, *InstallerEntry, func(phase, job, bootID, cmdline string) map[string]any) {
	t.Helper()
	payload := vml + "  vmlinuz\n" + dtb1 + "  dtbs/t-a.dtb\n" + dtb2 + "  dtbs/t-b.dtb\n" + mtr + "  modules.dep\n"
	m := &Manifest{Schema: ManifestSchema, Release: "12.0",
		Artifacts: []Artifact{{Name: "linux-aurora", File: "linux-aurora.pkg", SHA256: vml, Version: "7.1.12.aurora2-12.0", MtreeSHA256: mtr}},
		DTBs:      []DTB{{"t-a.dtb", dtb1}, {"t-b.dtb", dtb2}},
		Macs:      map[string]MacExpect{"mac": {Board: "apple,a", BoardDTB: "t-a.dtb", UbootGzSHA256: ubt, BootBinSHA256: boot}}}
	m.DTBsSHA256 = DTBsDigest(m.DTBs)
	m.Kernel.Release, m.Kernel.VmlinuzSHA256 = krel, vml
	m.Kernel.PayloadManifest, m.Kernel.PayloadManifestSHA256, m.Kernel.PayloadCount = "payload/x", SHA256([]byte(payload)), 4
	m.Kernel.RegeneratedOnMac = []string{"modules.dep"}
	m.M1n1.BinSHA256, m.M1n1.Version = m1n1, "v1.6.1-omarchy.aurora12"
	if err := m.Validate([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	pl, _ := ParsePayload([]byte(payload))
	path := "boot():/EFI/Linux/omarchy_linux-aurora.efi#" + ukiB2
	lines := []string{"  //linux-aurora", "  protocol: efi", "  path: " + path, "  cmdline: " + strings.Join(installerTokens, " ")}
	entry := Entry{Found: true, Name: "Omarchy / linux-aurora", Protocol: "efi", Path: path,
		CmdlineTokens: installerTokens, EntryLines: lines, EntrySHA256: EntryDigest(lines), UKISHA256: uki, UKIBlake2b: ukiB2,
		UKISections: map[string]Section{".linux": {SHA256: vml}, ".initrd": {SHA256: ird}, ".cmdline": {SHA256: "c"}, ".uname": {SHA256: "u", Text: krel}}}
	e := &InstallerEntry{Schema: "maclab.installer-entry/1", Device: "mac", Release: "12.0", Entry: entry}
	obs := func(phase, job, bootID, cmdline string) map[string]any {
		return map[string]any{"schema": "maclab.installed-observed/1", "phase": phase, "device": "mac", "job": job,
			"running":         map[string]any{"boot_id": bootID, "uname_r": krel, "proc_cmdline": cmdline},
			"packages":        map[string]any{"linux-aurora": map[string]any{"version": "7.1.12.aurora2-12.0", "mtree_sha256": mtr}},
			"payload":         map[string]any{"krel": krel, "root": "/usr/lib/modules/" + krel, "count": 4, "files": map[string]string{"vmlinuz": vml, "dtbs/t-a.dtb": dtb1, "dtbs/t-b.dtb": dtb2, "modules.dep": "regen"}},
			"installer_entry": entry,
			"boot_bin": map[string]any{"sha256": boot, "parts": map[string]any{"m1n1_sha256": m1n1, "dtb_shas": []string{dtb1, dtb2}, "dtb_count": 2,
				"board_dtb_sha256": dtb1, "board_dtb_count": 1, "uboot_gz_sha256": ubt, "trailer": ""}},
			"dt": map[string]any{"board": "apple,a", "live_stage2_version": "v1.6.1-omarchy.aurora12"}}
	}
	return m, pl, e, obs
}

func compare(t *testing.T, phase string, o map[string]any, booted *Identity) *Identity {
	t.Helper()
	m, pl, e, _ := fixture(t)
	raw, _ := json.Marshal(o)
	id, err := Compare(phase, raw, m, "msha", pl, e, "esha", false, booted)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCompareMatch(t *testing.T) {
	_, _, _, obs := fixture(t)
	good := Cmdline(installerTokens, "j1", false)
	var pinned []string // all but #30's watchdog.open_timeout=N and Lab boot marker
	for _, f := range strings.Fields(good) {
		if v, ok := strings.CutPrefix(f, "watchdog.open_timeout="); ok && v != "" && strings.Trim(v, "0123456789") == "" || agent.IsLabBoot(f) && !strings.HasPrefix(f, "maclab.job=") {
			continue
		}
		pinned = append(pinned, f)
	}
	if strings.Join(pinned, " ") != "root=UUID=x rw quiet splash maclab.job=j1 panic=10" {
		t.Fatalf("cmdline %q", good)
	}
	b := compare(t, PhaseBooted, obs(PhaseBooted, "j1", "boot1", good), nil)
	if b.Verdict != "MATCH" {
		t.Fatalf("booted: %s %v", b.Verdict, b.Mismatches)
	}
	a := compare(t, PhaseAfter, obs(PhaseAfter, "j1", "boot1", good), b)
	if a.Verdict != "MATCH" {
		t.Fatalf("after: %s %v", a.Verdict, a.Mismatches)
	}
	// the after phase must be on the booted phase's boot
	if a := compare(t, PhaseAfter, obs(PhaseAfter, "j1", "boot2", good), b); a.Verdict != "MISMATCH" {
		t.Fatalf("after on another boot: %s", a.Verdict)
	}
}

func TestCompareBeforeIgnoresRunningKernel(t *testing.T) {
	_, _, _, obs := fixture(t)
	o := obs(PhaseBefore, "j1", "old", "root=UUID=x rw asahi.m3_backend=runtime")
	o["running"].(map[string]any)["uname_r"] = "7.1.12-labf08d2b6f-049a"
	o["dt"].(map[string]any)["live_stage2_version"] = "v1.6.1-omarchy.aurora7"
	if id := compare(t, PhaseBefore, o, nil); id.Verdict != "MATCH" {
		t.Fatalf("before on the old kernel: %s %v", id.Verdict, id.Mismatches)
	}
	// but booted on the old kernel is a mismatch
	if id := compare(t, PhaseBooted, o, nil); id.Verdict != "MISMATCH" {
		t.Fatalf("booted on the old kernel: %s", id.Verdict)
	}
}

func TestCompareCmdlineIsExact(t *testing.T) {
	_, _, _, obs := fixture(t)
	for _, c := range []string{
		"root=UUID=x rw quiet splash maclab.job=j1 panic=10 asahi.m3_backend=runtime", // inherited bring-up arg
		"root=UUID=x rw quiet maclab.job=j1 panic=10",                                 // installer token missing
		"rw root=UUID=x quiet splash maclab.job=j1 panic=10",                          // order
		"root=UUID=x rw quiet splash maclab.job=j1 panic=10 loglevel=7",               // serial addition on a non-serial Mac
	} {
		if id := compare(t, PhaseBooted, obs(PhaseBooted, "j1", "b", c), nil); id.Verdict != "MISMATCH" {
			t.Errorf("%q: %s", c, id.Verdict)
		}
	}
}

func TestCompareStateMismatches(t *testing.T) {
	_, _, _, obs := fixture(t)
	good := Cmdline(installerTokens, "j1", false)
	cases := map[string]func(o map[string]any){
		"payload file": func(o map[string]any) {
			o["payload"].(map[string]any)["files"].(map[string]string)["dtbs/t-b.dtb"] = dtb1
		},
		"payload missing": func(o map[string]any) { delete(o["payload"].(map[string]any)["files"].(map[string]string), "vmlinuz") },
		"package mtree": func(o map[string]any) {
			o["packages"].(map[string]any)["linux-aurora"].(map[string]any)["mtree_sha256"] = vml
		},
		"dtb order": func(o map[string]any) {
			o["boot_bin"].(map[string]any)["parts"].(map[string]any)["dtb_shas"] = []string{dtb2, dtb1}
		},
		"board dtb twice": func(o map[string]any) {
			o["boot_bin"].(map[string]any)["parts"].(map[string]any)["board_dtb_count"] = 2
		},
		"boot.bin": func(o map[string]any) { o["boot_bin"].(map[string]any)["sha256"] = vml },
		"initramfs": func(o map[string]any) {
			e := o["installer_entry"].(Entry)
			e.UKISections = map[string]Section{".linux": {SHA256: vml}, ".initrd": {SHA256: "other"}, ".cmdline": {SHA256: "c"}, ".uname": {SHA256: "u"}}
			o["installer_entry"] = e
		},
		"entry lines": func(o map[string]any) {
			e := o["installer_entry"].(Entry)
			e.EntryLines = append([]string{}, e.EntryLines...)
			e.EntryLines[3] += " extra"
			o["installer_entry"] = e
		},
	}
	for name, mutate := range cases {
		o := obs(PhaseBooted, "j1", "b", good)
		mutate(o)
		if id := compare(t, PhaseBooted, o, nil); id.Verdict != "MISMATCH" {
			t.Errorf("%s: %s", name, id.Verdict)
		}
	}
}

func TestCompareIncompleteWithoutBootBin(t *testing.T) {
	m, pl, e, obs := fixture(t)
	mac := m.Macs["mac"]
	mac.BootBinSHA256 = ""
	m.Macs["mac"] = mac
	raw, _ := json.Marshal(obs(PhaseBooted, "j1", "b", Cmdline(installerTokens, "j1", false)))
	id, _ := Compare(PhaseBooted, raw, m, "", pl, e, "", false, nil)
	if id.Verdict != "INCOMPLETE" {
		t.Fatalf("no expected boot.bin: %s", id.Verdict)
	}
}

func TestDTBsDigest(t *testing.T) {
	got := DTBsDigest([]DTB{{"a.dtb", "AB"}, {"b.dtb", "cd"}})
	if want := SHA256([]byte("a.dtb ab\nb.dtb cd\n")); got != want {
		t.Fatalf("digest %s, want %s", got, want)
	}
}

func TestCompareOMT(t *testing.T) {
	frozen := map[string]string{"a": "pass", "b": "pass", "c": "fail", "d": "pass", "e": "skip"}
	cur := map[string]string{"a": "pass", "b": "skip", "c": "pass", "e": "skip", "n": "fail"}
	c := CompareOMT("j", "mac", OMTSide{}, frozen, OMTSide{}, cur)
	got := map[string]string{}
	for _, r := range c.Regressions {
		got[r.ID] = r.Frozen + ">" + r.Current
	}
	if c.Verdict != "REGRESSION" || got["b"] != "pass>skip" || got["d"] != "pass>missing" || len(got) != 2 {
		t.Fatalf("regressions %v (%s)", got, c.Verdict)
	}
	if len(c.Fixed) != 1 || c.Fixed[0].ID != "c" || len(c.NewChecks) != 1 || c.NewChecks[0] != "n" || len(c.Transitions) != 6 {
		t.Fatalf("fixed %v new %v transitions %d", c.Fixed, c.NewChecks, len(c.Transitions))
	}
}

func TestCompareDmesg(t *testing.T) {
	frozen := "[    1.0] apple-dart: fault\n[    2.0] Kernel panic - not syncing: x\n"
	same := "[    3.5] apple-dart: fault\n[    9.0] Kernel panic - not syncing: x\n"
	d := CompareDmesg("j", "mac", FileRef{}, frozen, FileRef{}, same)
	if d.Disposition != "FATAL" || len(d.NewLines) != 0 {
		t.Fatalf("a fatal line also in the baseline must still block: %+v", d)
	}
	d = CompareDmesg("j", "mac", FileRef{}, "[1] a: x\n", FileRef{}, "[1] a: x\n[2] b: new warning\n")
	if d.Disposition != "REVIEW_REQUIRED" || len(d.NewLines) != 1 {
		t.Fatalf("new line: %+v", d)
	}
	d = CompareDmesg("j", "mac", FileRef{}, "[1] a: x\n[2] b: y\n", FileRef{}, "[5] a: x\n")
	if d.Disposition != "NONE_NEW" || len(d.GoneLines) != 1 {
		t.Fatalf("gone line: %+v", d)
	}
}

// The path's #pin must be the UKI's measured BLAKE2b; its SHA256 can't prove that.
func TestComparePathPinMustBeMeasuredBlake2b(t *testing.T) {
	for name, change := range map[string]func(e map[string]any){
		"UKI no longer measures the pinned BLAKE2b": func(e map[string]any) { e["uki_blake2b"] = strings.Repeat("cd", 64) },
		"no BLAKE2b measured":                       func(e map[string]any) { delete(e, "uki_blake2b") },
	} {
		m, pl, e, obs := fixture(t)
		o := obs(PhaseBooted, "j1", "b-1", Cmdline(installerTokens, "j1", false))
		ent := map[string]any{}
		b, _ := json.Marshal(o["installer_entry"])
		json.Unmarshal(b, &ent)
		change(ent)
		o["installer_entry"] = ent
		raw, _ := json.Marshal(o)
		id, err := Compare(PhaseBooted, raw, m, "msha", pl, e, "esha", false, nil)
		if err != nil || id.Verdict != "MISMATCH" || !strings.Contains(strings.Join(id.Mismatches, " "), "installer_entry") {
			t.Errorf("%s: %v %+v", name, err, id)
		}
	}
	// a frozen entry whose measured BLAKE2b doesn't match the observation's
	m, pl, e, obs := fixture(t)
	e.UKIBlake2b = strings.Repeat("ef", 64)
	raw, _ := json.Marshal(obs(PhaseBooted, "j1", "b-1", Cmdline(installerTokens, "j1", false)))
	if id, _ := Compare(PhaseBooted, raw, m, "msha", pl, e, "esha", false, nil); id.Verdict != "MISMATCH" {
		t.Errorf("frozen BLAKE2b differs: %s", id.Verdict)
	}
}

func TestFreezeEntryChecksPin(t *testing.T) {
	m, _, e, _ := fixture(t)
	ent := e.Entry
	ent.UKISections = map[string]Section{".linux": {SHA256: vml}, ".initrd": {SHA256: ird},
		".cmdline": {SHA256: "c", Text: strings.Join(installerTokens, " ")}, ".uname": {SHA256: "u", Text: krel}}
	o := &Observed{Device: "mac", InstallerEntry: ent}
	if _, err := FreezeEntry(o, m); err != nil {
		t.Fatalf("a matching pin: %v", err)
	}
	for name, b2 := range map[string]string{"pin is not the measured BLAKE2b": strings.Repeat("cd", 64), "not measured": ""} {
		o.InstallerEntry.UKIBlake2b = b2
		if _, err := FreezeEntry(o, m); err == nil || !strings.Contains(err.Error(), "BLAKE2b") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

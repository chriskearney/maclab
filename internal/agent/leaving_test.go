package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const leavingUserLimine = "timeout: 5\n\n/Omarchy\n    protocol: efi\n    path: boot():/EFI/Linux/omarchy.efi\n\n/Omarchy snapshot 12\n    protocol: efi\n    path: boot():/EFI/Linux/snap12.efi\n"

// leavingLimineMac is a temp-dir Mac that booted Limine: the user's entries,
// the lab's marked block with two staged jobs, and the lab's files.
func leavingLimineMac(t *testing.T) (leaveLayout, string) {
	t.Helper()
	root := t.TempDir()
	l := leaveLayout{
		Config:     filepath.Join(root, "etc/maclab/agent.json"),
		LimineConf: filepath.Join(root, "boot/limine.conf"),
		Stage:      filepath.Join(root, "boot/maclab"),
		Units: []string{filepath.Join(root, "etc/systemd/system/lab-agent.service"),
			filepath.Join(root, "etc/systemd/system/"+labBootDeadlineUnitName),
			filepath.Join(root, "etc/systemd/system/"+labBootSessionUnitName),
			filepath.Join(root, "etc/systemd/system/"+labBootLockUnitName)},
		UnitNames: []string{"lab-agent.service", labBootDeadlineUnitName, labBootSessionUnitName, labBootLockUnitName},
		DropIns:   []string{filepath.Join(root, "run/sddm.conf.d/zz-maclab-lab-boot-autologin.conf"), filepath.Join(root, "etc/sysctl.d/90-maclab.conf")},
	}
	lm := &limineLayout{Conf: l.LimineConf, Stage: l.Stage}
	for _, job := range []string{"job-a", "job-b"} {
		dir := filepath.Join(l.Stage, job)
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "uki.efi"), []byte("uki"), 0o644)
		os.WriteFile(filepath.Join(dir, limineEntry), []byte(lm.entryText(entryPrefix[:0]+job, "test "+job)), 0o644)
	}
	for _, p := range append(append([]string{l.Config}, l.Units...), l.DropIns...) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("lab"), 0o600)
	}
	os.MkdirAll(filepath.Dir(l.LimineConf), 0o755)
	os.WriteFile(l.LimineConf, []byte(leavingUserLimine), 0o644)
	if err := lm.writeEntriesLocked(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(l.LimineConf); !strings.Contains(string(b), limineBegin) {
		t.Fatal("fixture: no lab block in limine.conf")
	}
	return l, root
}

func TestLeavingRemovesTheLabsLimineBlockAndKeepsEveryOtherEntryAsItWas(t *testing.T) {
	l, _ := leavingLimineMac(t)
	p, err := leaveCleanup(l)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := p.Rewrite[l.LimineConf]
	if !ok {
		t.Fatalf("limine.conf is not rewritten: %+v", p)
	}
	if strings.Contains(got, limineBegin) || strings.Contains(got, limineEnd) || strings.Contains(got, "job-a") || strings.Contains(got, "maclab") {
		t.Fatalf("the lab's block is still in limine.conf:\n%s", got)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(leavingUserLimine) {
		t.Fatalf("the Volunteer's own entries changed:\n%s\nwant\n%s", got, leavingUserLimine)
	}
}

func TestLeavingRemovesTheStagedKernelsButNeverLimineConfItself(t *testing.T) {
	l, _ := leavingLimineMac(t)
	p, _ := leaveCleanup(l)
	if !slices.Contains(p.Remove, l.Stage) {
		t.Fatalf("the stage directory %s is not removed: %v", l.Stage, p.Remove)
	}
	if slices.Contains(p.Remove, l.LimineConf) {
		t.Fatal("limine.conf itself would be deleted")
	}
}

func TestLeavingRemovesTheDeviceSecretAndTheLabsUnitsAndAutologinDropIn(t *testing.T) {
	l, _ := leavingLimineMac(t)
	p, _ := leaveCleanup(l)
	for _, f := range append(append([]string{l.Config}, l.Units...), l.DropIns...) {
		if !slices.Contains(p.Remove, f) {
			t.Errorf("%s is not removed: %v", f, p.Remove)
		}
	}
	for _, u := range l.UnitNames {
		if !slices.Contains(p.Disable, u) {
			t.Errorf("unit %s is not disabled: %v", u, p.Disable)
		}
	}
}

func TestLeavingRemovesNothingOutsideTheLabsOwnPaths(t *testing.T) {
	l, root := leavingLimineMac(t)
	mine := filepath.Join(root, "home/ada/notes.txt")
	os.MkdirAll(filepath.Dir(mine), 0o755)
	os.WriteFile(mine, []byte("mine"), 0o644)
	p, _ := leaveCleanup(l)
	allowed := append(append([]string{l.Config, l.Stage}, l.Units...), l.DropIns...)
	for _, f := range p.Remove {
		if !slices.Contains(allowed, f) && !strings.HasPrefix(f, l.Stage+"/") {
			t.Errorf("%s is removed, but it is not the lab's", f)
		}
	}
	for _, f := range p.Remove {
		if strings.Contains(f, "audit") {
			t.Errorf("the Volunteer's Audit log %s is removed", f)
		}
	}
	for path := range p.Rewrite {
		if path != l.LimineConf {
			t.Errorf("%s is rewritten, but it is not the lab's file", path)
		}
	}
}

func TestLeavingTellsTheVolunteerWhatIsLeftToRemoveByHand(t *testing.T) {
	l, _ := leavingLimineMac(t)
	p, _ := leaveCleanup(l)
	all := strings.ToLower(strings.Join(p.ByHand, "\n"))
	if !strings.Contains(all, "tailscale") || !strings.Contains(all, "lab-agent") || !strings.Contains(all, "package") {
		t.Fatalf("by hand: %q", p.ByHand)
	}
}

func TestLeavingAMacWithNothingLeftOfTheLabIsANoOp(t *testing.T) {
	l, _ := leavingLimineMac(t)
	p, _ := leaveCleanup(l)
	for path, content := range p.Rewrite {
		os.WriteFile(path, []byte(content), 0o644)
	}
	for _, f := range p.Remove {
		os.RemoveAll(f)
	}
	again, err := leaveCleanup(l)
	if err != nil {
		t.Fatalf("leaving twice: %v", err)
	}
	if len(again.Rewrite) != 0 && again.Rewrite[l.LimineConf] != "" && strings.TrimSpace(again.Rewrite[l.LimineConf]) != strings.TrimSpace(leavingUserLimine) {
		t.Fatalf("a second cleanup rewrote limine.conf: %q", again.Rewrite[l.LimineConf])
	}
	if len(again.Remove) != 0 {
		t.Fatalf("a second cleanup still removes %v", again.Remove)
	}
}

func TestLeavingARoundTripOnAMacThatNeverStagedAnythingKeepsLimineConfAsItWas(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "limine.conf")
	os.WriteFile(conf, []byte(leavingUserLimine), 0o644)
	p, err := leaveCleanup(leaveLayout{LimineConf: conf, Stage: filepath.Join(root, "maclab")})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := p.Rewrite[conf]; ok && strings.TrimSpace(got) != strings.TrimSpace(leavingUserLimine) {
		t.Fatalf("limine.conf changed though the lab never touched it:\n%s", got)
	}
}

func TestLeavingAGrubMacRemovesTheOneShotHookAndKeepsTheUsersCustomCfg(t *testing.T) {
	root := t.TempDir()
	g := &grubLayout{Dir: filepath.Join(root, "boot/grub")}
	os.MkdirAll(g.Dir, 0o755)
	const user = "# my own grub tweaks\nset gfxpayload=keep\n"
	custom := filepath.Join(g.Dir, "custom.cfg")
	os.WriteFile(custom, []byte(user+"\n"+g.hookText()), 0o644)
	maclab := filepath.Join(g.Dir, maclabCfg)
	os.WriteFile(maclab, []byte("menuentry lab {}"), 0o644)
	env := filepath.Join(root, "efi/"+envName)
	os.MkdirAll(filepath.Dir(env), 0o755)
	os.WriteFile(env, []byte("x"), 0o644)

	p, err := leaveCleanup(leaveLayout{GrubDir: g.Dir, GrubEnv: env, Stage: filepath.Join(root, "boot/maclab")})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := p.Rewrite[custom]
	if !ok || strings.Contains(got, hookMarker) || !strings.Contains(got, "set gfxpayload=keep") {
		t.Fatalf("custom.cfg after leaving (%v):\n%s", ok, got)
	}
	for _, f := range []string{maclab, env} {
		if !slices.Contains(p.Remove, f) {
			t.Errorf("%s is not removed: %v", f, p.Remove)
		}
	}
}

func TestDefaultLayoutNamesEverythingSetupWrites(t *testing.T) {
	l := defaultLeaveLayout()
	if l.Config != ConfigPath {
		t.Errorf("config %q, want %q", l.Config, ConfigPath)
	}
	for _, f := range []string{unitPath, labBootDeadlineUnitPath, labBootSessionUnitPath, labBootLockUnitPath} {
		if !slices.Contains(l.Units, f) {
			t.Errorf("unit file %s is not in the default layout: %v", f, l.Units)
		}
	}
	for _, u := range []string{"lab-agent.service", labBootDeadlineUnitName, labBootSessionUnitName, labBootLockUnitName} {
		if !slices.Contains(l.UnitNames, u) {
			t.Errorf("unit %s is not in the default layout: %v", u, l.UnitNames)
		}
	}
	for _, f := range []string{labBootAutologinPath, labBootAutologinLink, sysctlPath, watchdogCfg} {
		if !slices.Contains(l.DropIns, f) {
			t.Errorf("%s is not in the default layout: %v", f, l.DropIns)
		}
	}
}

// After the Lab boot the link in /etc dangles; leaving still removes it.
func TestLeavingRemovesTheDanglingAutologinLink(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "etc/sddm.conf.d/zz-maclab-lab-boot-autologin.conf")
	os.MkdirAll(filepath.Dir(link), 0o755)
	os.Symlink(filepath.Join(root, "run/sddm.conf.d/zz-maclab-lab-boot-autologin.conf"), link)
	p, err := leaveCleanup(leaveLayout{DropIns: []string{link}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Remove, link) {
		t.Errorf("dangling link %s is not removed: %v", link, p.Remove)
	}
}

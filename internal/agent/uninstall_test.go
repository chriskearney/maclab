package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	osuser "os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// labMac is what setup leaves on a Limine Mac, under a temp root.
type labMac struct {
	u     *uninstaller
	lim   *limineLayout
	calls []string
	out   []string
}

var labMacFiles = map[string]string{
	ConfigPath:                    `{"server":"http://labd:7770","name":"m1air","secret":"s3cret"}`,
	binPath:                       "ELF",
	unitPath:                      unit,
	labBootDeadlineUnitPath:       labBootDeadlineUnit(),
	labBootSessionUnitPath:        labBootSessionUnit(),
	labBootLockUnitPath:           labBootLockUnit(),
	sysctlPath:                    "kernel.panic = 10\n",
	watchdogCfg:                   "[Manager]\nRuntimeWatchdogSec=30s\n",
	journaldCfg:                   "[Journal]\nStorage=persistent\n",
	gettyDropIn:                   "[Service]\nExecStart=\n",
	sddmConf:                      "[Autologin]\nUser=alice\nSession=hyprland-uwsm.desktop\n",
	"/home/alice/" + stayAwake:    "",
	workDir + "/known-good.json":  `{"kernel":"7.1-good","stage_dir":"/boot/efi/maclab","loader":"limine"}`,
	"/etc/sysctl.d/10-other.conf": "vm.swappiness = 10\n",
	// modules: an orphaned test kernel, a test kernel that became known-good,
	// the running one, and the distro's
	"/usr/lib/modules/7.2-lab/" + markerFile:     "j1",
	"/usr/lib/modules/7.2-lab/kernel/x.ko":       "",
	"/usr/lib/modules/7.1-good/" + markerFile:    "j0",
	"/usr/lib/modules/7.0-running/" + markerFile: "j2",
	"/usr/lib/modules/6.9-arch/vmlinuz":          "",
}

func newLabMac(t *testing.T) *labMac {
	t.Helper()
	oldLocks, oldVars := bootPartitionLocks, efivarsDir
	t.Cleanup(func() { bootPartitionLocks, efivarsDir = oldLocks, oldVars })
	locks := t.TempDir()
	bootPartitionLocks = []string{filepath.Join(locks, "boot-partition.lock"), filepath.Join(locks, "limine-global.lock")}
	efivarsDir = t.TempDir()

	m := &labMac{lim: testLimine(t)}
	if err := m.lim.writeEntries(); err != nil { // setup's empty block
		t.Fatal(err)
	}
	// the ESP holds limine.conf, and the loader U-Boot boots, as shipped
	m.lim.ESP.Target = filepath.Dir(m.lim.Conf)
	m.lim.Loader = filepath.Join(m.lim.ESP.Target, "EFI/BOOT/BOOTAA64.EFI")
	os.MkdirAll(filepath.Dir(m.lim.Loader), 0o755)
	if err := os.WriteFile(m.lim.Loader, limineBinary(""), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for p, s := range labMacFiles {
		p = filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m.u = &uninstaller{root: root, boot: m.lim, running: "7.0-running", cmdline: "root=UUID=x rw quiet",
		say: func(f string, a ...any) { m.out = append(m.out, fmt.Sprintf(f, a...)) },
		cmd: func(name string, args ...string) error {
			m.calls = append(m.calls, name+" "+strings.Join(args, " "))
			return nil
		},
		home: func(user string) (string, error) { return filepath.Join(root, "home", user), nil },
	}
	return m
}

// again runs uninstall afresh, as a second `lab-agent uninstall` would.
func (m *labMac) again(dry bool) error {
	m.calls, m.out, m.u.acted, m.u.removed, m.u.dry = nil, nil, 0, nil, dry
	return m.u.uninstall()
}

func (m *labMac) gone(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if exists(m.u.path(p)) {
			t.Errorf("%s is still there", p)
		}
	}
}

func (m *labMac) kept(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if !exists(m.u.path(p)) {
			t.Errorf("%s was removed", p)
		}
	}
}

// snapshot is every file and directory under dirs, with its contents.
func snapshot(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	s := map[string]string{}
	for _, d := range dirs {
		filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(p)
			s[p] = string(b)
			return nil
		})
	}
	return s
}

func TestUninstallLimine(t *testing.T) {
	m := newLabMac(t)
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(m.lim.Conf); string(got) != omarchyLimineConf {
		t.Errorf("limine.conf is not as setup found it:\n%s", got)
	}
	if exists(m.lim.Stage) {
		t.Error("stage directory is still there")
	}
	m.gone(t, labUnitPaths...)
	m.gone(t, "/etc/maclab", binPath, sysctlPath, watchdogCfg, filepath.Dir(watchdogCfg), journaldCfg, filepath.Dir(journaldCfg),
		gettyDropIn, filepath.Dir(gettyDropIn), sddmConf, filepath.Dir(sddmConf), workDir, "/usr/lib/modules/7.2-lab")
	m.kept(t, "/usr/lib/modules/7.1-good", "/usr/lib/modules/7.0-running", "/usr/lib/modules/6.9-arch", "/etc/sysctl.d/10-other.conf")
	want := []string{
		"systemctl disable --now lab-agent.service",
		"systemctl disable --now maclab-lab-boot-deadlines.service maclab-lab-boot-session.service maclab-lab-boot-lock.service",
		"systemctl daemon-reload",
		"systemctl daemon-reexec",
		"systemctl restart systemd-journald",
		"systemctl disable serial-getty@ttySAC0.service",
		"systemctl daemon-reload",
		"runuser -u alice -- rm -f " + m.u.path("/home/alice", stayAwake),
	}
	if !reflect.DeepEqual(m.calls, want) {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(m.calls, "\n"), strings.Join(want, "\n"))
	}
	if last := m.out[len(m.out)-1]; last != "uninstalled. labd still lists this Mac as m1air" {
		t.Errorf("last line %q", last)
	}

	// Idempotent: a second run finds nothing left to do.
	if err := m.again(false); err != nil {
		t.Fatal(err)
	}
	if m.u.acted != 0 || len(m.calls) != 0 {
		t.Errorf("second run acted %d times, ran %q:\n%s", m.u.acted, m.calls, strings.Join(m.out, "\n"))
	}
	if last := m.out[len(m.out)-1]; !strings.HasPrefix(last, "nothing to undo") {
		t.Errorf("last line %q", last)
	}
}

// A dry run changes nothing and prints exactly the actions the real run takes.
func TestUninstallDryRun(t *testing.T) {
	m := newLabMac(t)
	before := snapshot(t, m.u.root, filepath.Dir(m.lim.Conf))
	if err := m.again(true); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(t, m.u.root, filepath.Dir(m.lim.Conf)); !reflect.DeepEqual(before, after) {
		t.Error("a dry run changed files")
	}
	if len(m.calls) != 0 {
		t.Errorf("a dry run ran %q", m.calls)
	}
	dry := m.out
	if last := dry[len(dry)-1]; last != "dry run: nothing was changed" {
		t.Errorf("last line %q", last)
	}
	if err := m.again(false); err != nil {
		t.Fatal(err)
	}
	taken := m.out
	if len(dry) != len(taken) {
		t.Fatalf("dry run:\n%s\nreal run:\n%s", strings.Join(dry, "\n"), strings.Join(taken, "\n"))
	}
	for i := range len(dry) - 1 {
		if d := strings.TrimPrefix(dry[i], "would "); d != taken[i] {
			t.Errorf("dry run %q, real run %q", dry[i], taken[i])
		}
	}
}

// The dry run lists every unit setup enabled, not just lab-agent.service.
func TestUninstallDryRunListsEveryUnit(t *testing.T) {
	m := newLabMac(t)
	if err := m.again(true); err != nil {
		t.Fatal(err)
	}
	out := strings.Join(m.out, "\n")
	for _, want := range []string{
		"would run systemctl disable --now lab-agent.service",
		"would run systemctl disable --now maclab-lab-boot-deadlines.service maclab-lab-boot-session.service maclab-lab-boot-lock.service",
	} {
		if !slices.Contains(m.out, want) {
			t.Errorf("the dry run doesn't say %q:\n%s", want, out)
		}
	}
	for _, p := range labUnitPaths {
		if !slices.Contains(m.out, "would remove "+m.u.path(p)) {
			t.Errorf("the dry run doesn't remove %s:\n%s", p, out)
		}
	}
}

// Uninstall takes out the same units leave does, and setup enables: each
// name matches its unit file.
func TestUninstallAndLeaveShareTheUnits(t *testing.T) {
	l := defaultLeaveLayout()
	if !slices.Equal(l.UnitNames, labUnitNames) || !slices.Equal(l.Units, labUnitPaths) {
		t.Errorf("leave's units %v %v aren't uninstall's %v %v", l.UnitNames, l.Units, labUnitNames, labUnitPaths)
	}
	if len(labUnitNames) != len(labUnitPaths) || labUnitNames[0] != "lab-agent.service" {
		t.Fatalf("units %v, files %v", labUnitNames, labUnitPaths)
	}
	for i, name := range labUnitNames {
		if filepath.Base(labUnitPaths[i]) != name {
			t.Errorf("unit %s has file %s", name, labUnitPaths[i])
		}
	}
}

// Units left behind by an older uninstall, which took out only
// lab-agent.service, go on the next run; a Mac set up before the Lab-boot
// units existed has only the agent's to stop.
func TestUninstallLeftoverAndMissingUnits(t *testing.T) {
	m := newLabMac(t)
	os.Remove(m.u.path(unitPath))
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.calls, "systemctl disable --now maclab-lab-boot-deadlines.service maclab-lab-boot-session.service maclab-lab-boot-lock.service") ||
		slices.Contains(m.calls, "systemctl disable --now lab-agent.service") || !slices.Contains(m.calls, "systemctl daemon-reload") {
		t.Errorf("leftover units: ran\n%s", strings.Join(m.calls, "\n"))
	}
	m.gone(t, labUnitPaths...)

	m = newLabMac(t)
	for _, p := range labUnitPaths[1:] {
		os.Remove(m.u.path(p))
	}
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	if len(m.calls) < 2 || m.calls[0] != "systemctl disable --now lab-agent.service" || m.calls[1] != "systemctl daemon-reload" {
		t.Errorf("only the agent's unit: ran\n%s", strings.Join(m.calls, "\n"))
	}
	m.gone(t, unitPath)
}

// What was on before setup stays on: the getty it found enabled, and the
// user's own stay-awake.
func TestUninstallKeepsPreSetupState(t *testing.T) {
	m := newLabMac(t)
	os.WriteFile(m.u.path(workDir, gettyWasEnabled), []byte("enabled\n"), 0o644)
	os.WriteFile(m.u.path(workDir, stayAwakeWasOn), []byte("alice\n"), 0o644)
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	for _, c := range m.calls {
		if strings.Contains(c, "serial-getty") || strings.HasPrefix(c, "runuser") {
			t.Errorf("ran %q", c)
		}
	}
	m.gone(t, gettyDropIn, sddmConf)
}

// Without the lab's journald drop-in, uninstall leaves journald alone.
func TestUninstallWithoutJournaldDropIn(t *testing.T) {
	m := newLabMac(t)
	os.Remove(m.u.path(journaldCfg))
	os.WriteFile(m.u.path("/etc/systemd/journald.conf.d/50-mine.conf"), []byte("[Journal]\n"), 0o644)
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	for _, c := range append(m.calls, m.out...) {
		if strings.Contains(c, "journald") && !strings.Contains(c, "50-mine") {
			t.Errorf("%q", c)
		}
	}
	m.kept(t, "/etc/systemd/journald.conf.d/50-mine.conf")
}

func armOneShot(t *testing.T, entry string) string {
	t.Helper()
	p := efivarPath("LoaderEntryOneShot", bliGUID)
	b := binary.LittleEndian.AppendUint32(nil, efiVarNV|efiVarBS|efiVarRT)
	if err := os.WriteFile(p, append(b, utf16z(entry)...), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUninstallRefuses(t *testing.T) {
	m := newLabMac(t)
	before := snapshot(t, m.u.root, filepath.Dir(m.lim.Conf))

	m.u.cmdline = "root=UUID=x rw panic=10 maclab.job=j9"
	if err := m.u.uninstall(); err == nil || !strings.Contains(err.Error(), "lab kernel") {
		t.Errorf("on a lab kernel: %v", err)
	}
	m.u.force = true // never overrides the lab-kernel check
	if err := m.u.uninstall(); err == nil {
		t.Error("--force uninstalled on a lab kernel")
	}
	if after := snapshot(t, m.u.root, filepath.Dir(m.lim.Conf)); !reflect.DeepEqual(before, after) {
		t.Error("a refused uninstall changed files")
	}
	m.u.cmdline, m.u.force = "root=UUID=x rw", false

	// A job in flight: staged and armed.
	stageLimineEntry(t, m.lim, "j1")
	m.lim.writeEntries()
	before = snapshot(t, m.u.root, filepath.Dir(m.lim.Conf))
	v := armOneShot(t, "maclab-j1")
	err := m.u.uninstall()
	if err == nil || !strings.Contains(err.Error(), "in flight") || !strings.Contains(err.Error(), "maclab-j1 is armed") {
		t.Fatalf("with a job in flight: %v", err)
	}
	if after := snapshot(t, m.u.root, filepath.Dir(m.lim.Conf)); !reflect.DeepEqual(before, after) || !exists(v) {
		t.Error("a refused uninstall changed files")
	}

	m.u.force = true
	if err := m.again(false); err != nil {
		t.Fatal(err)
	}
	if exists(v) {
		t.Error("the lab's one-shot is still armed")
	}
	if got, _ := os.ReadFile(m.lim.Conf); string(got) != omarchyLimineConf || exists(m.lim.Stage) {
		t.Errorf("limine.conf:\n%s", got)
	}
}

// A command's work dir left by a boot that crashed or hung mid-command (the
// agent never got to clean it up) is no job in flight: uninstall removes it.
// One from this boot still is.
func TestUninstallStaleWorkDirs(t *testing.T) {
	m := newLabMac(t)
	m.u.bootTime = time.Now().Add(-10 * time.Minute)
	stale := m.u.path(workDir, "out", "c1792088777-48")
	os.MkdirAll(stale, 0o755)
	os.WriteFile(filepath.Join(stale, "log.txt"), []byte("freezing lab-agent\n"), 0o644)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(stale, old, old)

	fresh := m.u.path(workDir, "out", "c1792090000-1")
	os.MkdirAll(fresh, 0o755)
	if err := m.u.uninstall(); err == nil || !strings.Contains(err.Error(), "1 job work dirs from this boot") {
		t.Fatalf("with a work dir from this boot: %v", err)
	}
	os.RemoveAll(fresh)
	if err := m.again(false); err != nil {
		t.Fatalf("a leftover from an earlier boot blocked uninstall: %v", err)
	}
	m.gone(t, workDir)
}

// Someone else's one-shot is not the lab's to clear, and is no job in flight.
func TestUninstallLeavesOtherOneShot(t *testing.T) {
	m := newLabMac(t)
	v := armOneShot(t, "linux-aurora")
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	if !exists(v) {
		t.Error("cleared a one-shot the lab did not set")
	}
}

func TestUninstallGrub(t *testing.T) {
	const hookEnd = "# maclab: end\n"
	for _, tc := range []struct {
		name, before, edit, want string
		backupKept               bool
	}{
		{name: "restores the backup", before: "menuentry 'macOS' {\n\texit\n}\n", want: "menuentry 'macOS' {\n\texit\n}\n"},
		{name: "byte for byte", before: "set timeout=5", want: "set timeout=5"},
		{name: "removes the file setup created", before: "", want: ""},
		{name: "keeps later edits", before: "set timeout=5\n", edit: "# mine\n", want: "set timeout=5\n# mine\n", backupKept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, esp, root := t.TempDir(), t.TempDir(), t.TempDir()
			g := m1airLayout()
			g.Dir, g.EnvFile = dir, filepath.Join(esp, envName)
			custom := filepath.Join(dir, "custom.cfg")
			if tc.before != "" {
				os.WriteFile(custom, []byte(tc.before), 0o644)
			}
			os.WriteFile(g.EnvFile, nil, 0o644) // grub-editenv create
			os.MkdirAll(filepath.Join(root, defaultStage), 0o755)
			if err := g.installHook(); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(custom); !strings.HasSuffix(string(b), hookEnd) {
				t.Fatalf("custom.cfg after setup:\n%s", b)
			}
			if tc.edit != "" {
				b, _ := os.ReadFile(custom)
				os.WriteFile(custom, append(b, tc.edit...), 0o644)
			}

			var out []string
			u := &uninstaller{root: root, boot: g, say: func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) },
				cmd: func(string, ...string) error { return nil }}
			if err := u.uninstall(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(custom)
			if tc.want == "" && !os.IsNotExist(err) {
				t.Errorf("custom.cfg is still there:\n%s", got)
			} else if string(got) != tc.want {
				t.Errorf("custom.cfg:\n%q\nwant:\n%q", got, tc.want)
			}
			if exists(custom+".pre-maclab") != tc.backupKept {
				t.Errorf("backup kept: %v, want %v", !tc.backupKept, tc.backupKept)
			}
			for _, p := range []string{filepath.Join(dir, maclabCfg), g.EnvFile, filepath.Join(root, defaultStage)} {
				if exists(p) {
					t.Errorf("%s is still there", p)
				}
			}

			u.acted, out = 0, nil
			if err := u.uninstall(); err != nil || u.acted != 0 {
				t.Errorf("second run: %v, %d actions:\n%s", err, u.acted, strings.Join(out, "\n"))
			}

			// The Mac died after restoring custom.cfg, before the backup went:
			// a backup that holds just what custom.cfg does goes on the next run.
			if !tc.backupKept && tc.before != "" {
				os.WriteFile(custom+".pre-maclab", []byte(tc.want), 0o644)
				if err := u.uninstall(); err != nil || exists(custom+".pre-maclab") {
					t.Errorf("orphaned backup: %v, still there %v", err, exists(custom+".pre-maclab"))
				}
				if got, _ := os.ReadFile(custom); string(got) != tc.want {
					t.Errorf("custom.cfg after the orphan went:\n%q", got)
				}
			}
		})
	}
}

func TestStripHook(t *testing.T) {
	g := m1airLayout()
	if _, ok := stripHook([]byte("x\n\n" + strings.TrimSuffix(g.hookText(), "# maclab: end\n"))); ok {
		t.Error("a hook without its end marker was stripped")
	}
	if got, ok := stripHook([]byte("x\n")); !ok || string(got) != "x\n" {
		t.Errorf("no hook: %q %v", got, ok)
	}
}

// With Limine config enrollment on, taking the maclab block out of
// limine.conf would stop the Mac booting: uninstall refuses before changing
// anything, dry run or not, --force or not, and says how to turn it off.
func TestUninstallRefusesLimineEnrollment(t *testing.T) {
	m := newLabMac(t)
	tools := filepath.Join(m.lim.ESP.Target, "EFI/limine/limine_aa64.efi")
	os.MkdirAll(filepath.Dir(tools), 0o755)
	os.MkdirAll(m.u.path("/etc/default"), 0o755)
	for _, c := range []struct {
		name, defaults string
		loader, tools  string // the checksum enrolled in each binary; "" for none
		want           string
	}{
		// none enrolled yet, but any Limine update could enroll one mid-uninstall
		{"on, none enrolled yet", "ENABLE_ENROLL_LIMINE_CONFIG=yes\n", "", "", "To turn it off, set ENABLE_ENROLL_LIMINE_CONFIG=no in /etc/default/limine;"},
		{"enrolled in the loader", "", limineEnrolledSum, "", "To turn it off, run `sudo limine enroll-config --reset " + m.lim.Loader + "`;"},
		{"turned off, still enrolled in the tools' copy", "ENABLE_ENROLL_LIMINE_CONFIG=no\n", "", limineEnrolledSum,
			"To turn it off, run `sudo limine enroll-config --reset " + tools + "`;"},
	} {
		os.WriteFile(m.u.path("/etc/default/limine"), []byte(c.defaults), 0o644)
		os.WriteFile(m.lim.Loader, limineBinary(c.loader), 0o644)
		os.WriteFile(tools, limineBinary(c.tools), 0o644)
		before := snapshot(t, m.u.root, m.lim.ESP.Target)
		for _, dry := range []bool{true, false} {
			m.u.force = !dry
			err := m.again(dry)
			if err == nil || !strings.Contains(err.Error(), "Limine config enrollment is on") || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s, dry run %v: %v", c.name, dry, err)
			}
			if len(m.calls)+m.u.acted > 0 {
				t.Errorf("%s, dry run %v: acted %d times, ran %q", c.name, dry, m.u.acted, m.calls)
			}
		}
		if after := snapshot(t, m.u.root, m.lim.ESP.Target); !reflect.DeepEqual(before, after) {
			t.Errorf("%s: a refused uninstall changed files", c.name)
		}
	}

	// Turned off: uninstall goes ahead. Once the block is gone, enrollment
	// is none of its business.
	m.u.force = false
	os.WriteFile(m.u.path("/etc/default/limine"), nil, 0o644)
	os.WriteFile(m.lim.Loader, limineBinary(""), 0o644)
	os.WriteFile(tools, limineBinary(""), 0o644)
	if err := m.again(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(m.lim.Conf); string(got) != omarchyLimineConf {
		t.Errorf("limine.conf:\n%s", got)
	}
	os.WriteFile(m.u.path("/etc/default/limine"), []byte("ENABLE_ENROLL_LIMINE_CONFIG=yes\n"), 0o644)
	os.WriteFile(m.lim.Loader, limineBinary(limineEnrolledSum), 0o644)
	if err := m.again(false); err != nil || m.u.acted != 0 {
		t.Errorf("enrollment on again after uninstall: %v, %d actions", err, m.u.acted)
	}
}

// If lab-agent.service won't stop, the agent may still be running: uninstall
// changes nothing else, so the agent can't arm a one-shot or rewrite
// limine.conf under it.
func TestUninstallStopsWhenTheAgentWontStop(t *testing.T) {
	m := newLabMac(t)
	record := m.u.cmd
	m.u.cmd = func(name string, args ...string) error {
		record(name, args...)
		if strings.Join(args, " ") == "disable --now lab-agent.service" {
			return errors.New("exit status 1: Job for lab-agent.service canceled")
		}
		return nil
	}
	before := snapshot(t, m.u.root, m.lim.ESP.Target)
	if err := m.u.uninstall(); err == nil || !strings.Contains(err.Error(), "uninstall stopped there") {
		t.Fatalf("the agent didn't stop: %v", err)
	}
	if after := snapshot(t, m.u.root, m.lim.ESP.Target); !reflect.DeepEqual(before, after) || len(m.calls) != 1 {
		t.Errorf("changed more than the agent: ran %q", m.calls)
	}
	m.u.cmd = record
	if err := m.again(false); err != nil {
		t.Fatal(err)
	}
	m.gone(t, unitPath, workDir)
}

// An autologin user deleted since setup has no stay-awake left to turn off:
// the SDDM file still goes, and a second run has nothing to do. Any other
// failure to look the user up stops that step, to be retried.
func TestUninstallAutologinUserGone(t *testing.T) {
	m := newLabMac(t)
	m.u.home = func(string) (string, error) { return "", errors.New("nss: connection refused") }
	if err := m.u.uninstall(); err == nil || !strings.Contains(err.Error(), "autologin user alice") {
		t.Fatalf("lookup failed: %v", err)
	}
	m.kept(t, sddmConf, workDir)

	m.u.home = func(user string) (string, error) { return "", osuser.UnknownUserError(user) }
	if err := m.again(false); err != nil {
		t.Fatal(err)
	}
	m.gone(t, sddmConf, workDir)
	for _, c := range m.calls {
		if strings.HasPrefix(c, "runuser") {
			t.Errorf("ran %q", c)
		}
	}
	if err := m.again(false); err != nil || m.u.acted != 0 {
		t.Errorf("second run: %v, %d actions", err, m.u.acted)
	}
}

// writeSynced's limine.conf.tmp, left by a write the Mac died during, goes
// too, even once nothing else of the lab's is left.
func TestUninstallStaleLimineTmp(t *testing.T) {
	m := newLabMac(t)
	tmp := m.lim.Conf + ".tmp"
	os.WriteFile(tmp, []byte("half a limine.conf"), 0o644)
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	if exists(tmp) {
		t.Error("limine.conf.tmp is still there")
	}
	os.WriteFile(tmp, []byte("half a limine.conf"), 0o644)
	if err := m.again(false); err != nil || exists(tmp) || m.u.acted != 1 {
		t.Errorf("after uninstall: %v, %d actions, tmp still there %v", err, m.u.acted, exists(tmp))
	}
}

// A maclab block that lost its end line can't come out safely: its entries
// name the staged UKIs, so those stay, and the records too, with an error.
func TestUninstallLimineBlockWithoutEnd(t *testing.T) {
	m := newLabMac(t)
	stageLimineEntry(t, m.lim, "j1")
	m.lim.writeEntries()
	conf, _ := os.ReadFile(m.lim.Conf)
	broken := strings.Replace(string(conf), limineEnd+"\n", "", 1)
	os.WriteFile(m.lim.Conf, []byte(broken), 0o644)
	m.u.force = true // the staged job is in flight otherwise
	err := m.u.uninstall()
	if err == nil || !strings.Contains(err.Error(), `has no "# maclab: end" line`) {
		t.Fatalf("a block without its end: %v", err)
	}
	if got, _ := os.ReadFile(m.lim.Conf); string(got) != broken {
		t.Errorf("limine.conf changed:\n%s", got)
	}
	if !exists(filepath.Join(m.lim.Stage, "j1", limineEntry)) {
		t.Error("removed the staged job its entry names")
	}
	m.kept(t, workDir)
	if last := m.out[len(m.out)-1]; strings.HasPrefix(last, "uninstalled") {
		t.Errorf("last line %q", last)
	}
}

// --force with the bootloader not found leaves the bootloader alone, so a
// lab one-shot may still be armed into the stage in /var/lib/maclab: the
// records stay, and the run fails.
func TestUninstallForceWithoutBootloader(t *testing.T) {
	m := newLabMac(t)
	m.u.boot, m.u.bootErr, m.u.force = nil, errors.New("no FAT ESP mounted at /boot/efi, /efi or /boot"), true
	os.MkdirAll(m.u.path(altStage, "j1"), 0o755)
	if err := m.u.uninstall(); err == nil || !strings.Contains(err.Error(), "no FAT ESP") {
		t.Fatalf("bootloader not found: %v", err)
	}
	m.kept(t, workDir, altStage+"/j1")
	m.gone(t, sysctlPath, unitPath) // everything else went
}

// fakeLabd answers /api/agent/leave the way labd does, and notes when the
// call came: it must come before uninstall stops the agent.
type fakeLabd struct {
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []api.LeaveRequest
	auth    []string
	stopped atomic.Bool // lab-agent.service was stopped
	early   bool        // a call came before that
	old     bool        // an older labd, which takes an undo for a leave
}

func newFakeLabd(t *testing.T) *fakeLabd {
	f := &fakeLabd{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/agent/leave" {
			http.NotFound(w, r)
			return
		}
		var req api.LeaveRequest
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.reqs, f.auth = append(f.reqs, req), append(f.auth, r.Header.Get("Authorization"))
		f.early = !f.stopped.Load()
		f.mu.Unlock()
		json.NewEncoder(w).Encode(api.LeaveResponse{Name: "m1air", Canceled: req.Jobs, Back: req.Undo && !f.old})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// labMacFor is a lab Mac whose agent config points at server, telling labd
// for real (Leave), with job j1 staged and its one-shot armed.
func labMacFor(t *testing.T, server string, stopped *atomic.Bool) *labMac {
	m := newLabMac(t)
	cfg := `{"server":"` + server + `","name":"m1air","secret":"s3cret"}`
	if err := os.WriteFile(m.u.path(ConfigPath), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	m.u.leave = Leave
	record := m.u.cmd
	m.u.cmd = func(name string, args ...string) error {
		if stopped != nil && strings.Join(args, " ") == "disable --now lab-agent.service" {
			stopped.Store(true)
		}
		return record(name, args...)
	}
	stageLimineEntry(t, m.lim, "j1")
	m.lim.writeEntries()
	armOneShot(t, "maclab-j1")
	m.u.force = true
	return m
}

// uninstall --force mid-job tells labd first, with the job in flight, so labd
// cancels it instead of resetting the Mac once the agent goes quiet.
func TestUninstallTellsLabd(t *testing.T) {
	f := newFakeLabd(t)
	m := labMacFor(t, f.srv.URL, &f.stopped)

	// a dry run only says it would
	if err := m.again(true); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	n := len(f.reqs)
	f.mu.Unlock()
	if n != 0 || !slices.Contains(m.out, "would tell labd at "+f.srv.URL+" that m1air is leaving the lab") {
		t.Fatalf("dry run: %d calls\n%s", n, strings.Join(m.out, "\n"))
	}

	if err := m.again(false); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 1 || f.auth[0] != "Bearer s3cret" || !f.early {
		t.Fatalf("calls %+v auth %q, before the agent stopped: %v", f.reqs, f.auth, f.early)
	}
	if r := f.reqs[0]; r.Reason != "lab-agent uninstall --force with j1 in flight" || !reflect.DeepEqual(r.Jobs, []string{"j1"}) {
		t.Fatalf("told labd %+v", r)
	}
	if !slices.Contains(m.out, "told labd at "+f.srv.URL+" that m1air is leaving the lab; it canceled j1") {
		t.Errorf("output:\n%s", strings.Join(m.out, "\n"))
	}
	if last := m.out[len(m.out)-1]; last != "uninstalled. labd lists this Mac as m1air, left: `lab forget m1air` takes it off the list" {
		t.Errorf("last line %q", last)
	}
	m.gone(t, workDir, ConfigPath)
}

// With labd unreachable, uninstall still goes ahead, and says labd wasn't
// told and what to run on the controller instead.
func TestUninstallLabdUnreachable(t *testing.T) {
	f := newFakeLabd(t)
	url := f.srv.URL
	f.srv.Close()
	m := labMacFor(t, url, nil)
	if err := m.u.uninstall(); err != nil {
		t.Fatal(err)
	}
	m.gone(t, workDir, ConfigPath, unitPath)
	todo := "`lab cancel j1`, then `lab forget m1air`"
	said := slices.ContainsFunc(m.out, func(l string) bool {
		return strings.HasPrefix(l, "labd at "+url+" was not told that m1air is leaving the lab (") && strings.HasSuffix(l, "On the controller, run "+todo)
	})
	if !said {
		t.Errorf("output:\n%s", strings.Join(m.out, "\n"))
	}
	if last := m.out[len(m.out)-1]; last != "uninstalled, but labd wasn't told: on the controller, run "+todo {
		t.Errorf("last line %q", last)
	}
}

// With labd unreachable and the agent stopped by a disable --now whose
// systemctl died, there is nothing to take back: uninstall says what to run
// on the controller.
func TestUninstallStopFailedLabdUnreachable(t *testing.T) {
	f := newFakeLabd(t)
	url := f.srv.URL
	f.srv.Close()
	m := labMacFor(t, url, nil)
	record := m.u.cmd
	m.u.cmd = func(name string, args ...string) error {
		record(name, args...)
		switch strings.Join(args, " ") {
		case "disable --now lab-agent.service":
			return errors.New("signal: interrupt")
		case "is-active --quiet lab-agent.service", "is-enabled --quiet lab-agent.service":
			return errors.New("exit status 3")
		}
		return nil
	}
	if err := m.u.uninstall(); err == nil || !strings.Contains(err.Error(), "uninstall stopped there") {
		t.Fatalf("uninstall: %v", err)
	}
	said := "systemctl failed (run systemctl disable --now lab-agent.service: signal: interrupt), but lab-agent.service is no longer active or enabled, " +
		"and labd at " + url + " wasn't told that m1air is leaving the lab. Run uninstall again to finish, and on the controller run `lab cancel j1`, then `lab forget m1air`"
	if !slices.Contains(m.out, said) {
		t.Errorf("didn't say %q:\n%s", said, strings.Join(m.out, "\n"))
	}
	m.kept(t, ConfigPath, workDir)
}

// If uninstall stops after telling labd but before the agent is stopped (the
// agent won't stop, or the person interrupts it), the agent runs on: uninstall
// takes the leave back, so labd doesn't refuse its jobs for good. Once the
// agent is stopped, a later failure leaves the Mac as left. So does a
// systemctl disable --now interrupted (Ctrl-C) while PID 1 went on to stop
// the agent: taking the leave back would leave labd a silent Mac to recover.
func TestUninstallTakesBackItsLeave(t *testing.T) {
	const (
		stop     = "disable --now lab-agent.service"
		active   = "is-active --quiet lab-agent.service"
		enabled  = "is-enabled --quiet lab-agent.service"
		failed   = "run systemctl disable --now lab-agent.service: exit status 1: Failed"
		killed   = "run systemctl disable --now lab-agent.service: signal: interrupt"
		stayed   = "told labd at <url> that m1air stays in the lab after all"
		leftNote = "but lab-agent.service is no longer active or enabled: labd at <url> keeps m1air as left, as it should with no agent. " +
			"Run uninstall again to finish, then `lab forget m1air` on the controller"
	)
	for _, c := range []struct {
		name        string
		fail        string   // the systemctl command that fails
		killed      bool     // ... by Ctrl-C
		off         []string // systemctl checks that find the agent stopped or disabled
		interrupted bool
		old         bool // an older labd
		undo        bool // took the leave back
		err, said   string
	}{
		{"the agent won't stop", stop, false, nil, false, false, true,
			"uninstall stopped there", stayed},
		{"interrupted", "", false, nil, true, false, true,
			"interrupted before lab-agent.service was stopped", stayed},
		{"an older labd", stop, false, nil, false, true, true,
			"uninstall stopped there", "labd at <url> may still list m1air as left, refusing its jobs (this labd can't take a leave back): on the controller, run `lab reset m1air`"},
		{"the agent stopped, then a step failed", "daemon-reload", false, nil, false, false, false,
			"uninstall stopped there", "told labd at <url> that m1air is leaving the lab; it canceled j1"},
		{"Ctrl-C killed systemctl, PID 1 stopped the agent", stop, true, []string{active, enabled}, true, false, false,
			"uninstall stopped there", "systemctl failed (" + killed + "), " + leftNote},
		{"systemctl failed, the agent stopped and disabled", stop, false, []string{active, enabled}, false, false, false,
			"uninstall stopped there", "systemctl failed (" + failed + "), " + leftNote},
		{"Ctrl-C killed systemctl, the agent still runs", stop, true, []string{enabled}, true, false, true,
			"uninstall stopped there", stayed},
		{"Ctrl-C killed systemctl, the agent stopped but starts at boot", stop, true, []string{active}, true, false, true,
			"uninstall stopped there", stayed},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeLabd(t)
			f.old = c.old
			m := labMacFor(t, f.srv.URL, &f.stopped)
			record := m.u.cmd
			ctx, cancel := context.WithCancel(context.Background())
			m.u.cmd = func(name string, args ...string) error {
				if err := record(name, args...); err != nil {
					return err
				}
				switch a := strings.Join(args, " "); {
				case a == c.fail && c.killed:
					cancel() // the person's Ctrl-C: uninstall's and systemctl's
					return errors.New("signal: interrupt")
				case a == c.fail:
					return errors.New("exit status 1: Failed")
				case slices.Contains(c.off, a):
					return errors.New("exit status 3")
				}
				return nil
			}
			if c.interrupted && !c.killed {
				cancel()
			}
			defer cancel()
			m.u.ctx = ctx
			before := snapshot(t, m.lim.ESP.Target)
			err := m.u.uninstall()
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("uninstall: %v, want %q", err, c.err)
			}
			f.mu.Lock()
			reqs := f.reqs
			f.mu.Unlock()
			if len(reqs) == 0 || reqs[0].Undo {
				t.Fatalf("told labd %+v; want the leave first", reqs)
			}
			if undone := len(reqs) == 2 && reqs[1].Undo; undone != c.undo || len(reqs) > 2 {
				t.Errorf("told labd %+v; want the leave taken back: %v", reqs, c.undo)
			}
			if said := strings.ReplaceAll(c.said, "<url>", f.srv.URL); !slices.Contains(m.out, said) {
				t.Errorf("didn't say %q:\n%s", said, strings.Join(m.out, "\n"))
			}
			// nothing past the agent changed
			if after := snapshot(t, m.lim.ESP.Target); !reflect.DeepEqual(before, after) {
				t.Error("changed the ESP")
			}
			m.kept(t, ConfigPath, workDir)
		})
	}
}

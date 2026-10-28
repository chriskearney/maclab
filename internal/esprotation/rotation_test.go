package esprotation

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func ukiBytes(kernel string) []byte {
	var b bytes.Buffer
	dos := make([]byte, 128)
	dos[0] = 'M'
	dos[1] = 'Z'
	binary.LittleEndian.PutUint32(dos[0x3c:], 128)
	b.Write(dos)
	b.Write([]byte{'P', 'E', 0, 0})
	opt := pe.OptionalHeader64{Magic: 0x20b, Subsystem: pe.IMAGE_SUBSYSTEM_EFI_APPLICATION, NumberOfRvaAndSizes: 16}
	binary.Write(&b, binary.LittleEndian, pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_ARM64, NumberOfSections: 1, SizeOfOptionalHeader: uint16(binary.Size(opt))})
	binary.Write(&b, binary.LittleEndian, opt)
	h := pe.SectionHeader32{VirtualSize: uint32(len(kernel) + 1), SizeOfRawData: 512, PointerToRawData: 512}
	copy(h.Name[:], ".uname")
	binary.Write(&b, binary.LittleEndian, h)
	b.Write(make([]byte, 512-b.Len()))
	b.WriteString(kernel)
	b.WriteByte(0)
	b.Write(make([]byte, 1024-b.Len()))
	return b.Bytes()
}

type fixture struct {
	p                          Plan
	e                          Env
	r                          Retention
	trust, archive, controller string
	free                       uint64
	cur                        Snapshot
	locked                     bool
}

func fx(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	root := t.TempDir()
	esp := filepath.Join(root, "esp")
	os.Mkdir(esp, 0700)
	before := []byte("timeout: 3\ndefault_entry: Working\n/Working\n protocol: efi\n path: boot():/working.efi\n/Retired\n protocol: efi\n path: boot():/retired.efi\n/Other\n protocol: efi\n path: boot():/other.efi\n")
	after, err := PrepareMenu(before, "/Retired")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(esp, "retired.efi")
	os.WriteFile(file, ukiBytes("old-release"), 0600)
	os.WriteFile(filepath.Join(esp, "limine.conf"), before, 0600)
	h, _ := HashFile(file, MaxUKI)
	f.p = Plan{Version: Version, Kind: "uki-leaf", Transaction: "txn1", ESP: esp, Menu: filepath.Join(esp, "limine.conf"), Entry: "/Retired", UKI: file, Kernel: "old-release", File: h, Before: before, After: after, NextUKIBytes: 8192, NextESPTemporaryCopies: 1, Created: time.Unix(100, 0)}
	f.cur = Snapshot{Machine: "target", Boot: "boot-A", Kernel: "working-release", ESPDevice: 1, Files: map[string]string{"other": "pin", "BLI": "selected-working"}}
	f.p.Snapshot = f.cur
	f.archive = filepath.Join(root, "local")
	f.controller = filepath.Join(root, "controller")
	f.free = Reserve + Metadata + 1<<20
	f.e = Env{Observe: func(Plan) (Snapshot, error) { return f.cur, nil }, Space: func(p string) (Space, error) {
		if strings.HasPrefix(p, esp) {
			return Space{f.free, 4096, 1}, nil
		}
		return Space{1 << 30, 4096, 2}, nil
	}, Lock: func() (func(), error) {
		if f.locked {
			t.Fatal("nested lock")
		}
		f.locked = true
		return func() { f.locked = false }, nil
	}, Now: func() time.Time { return time.Unix(200, 0) }}
	f.r, err = RetainController(f.p, file, f.controller, "controller", f.e)
	if err != nil {
		t.Fatal(err)
	}
	f.trust = Digest(JSON(f.r))
	return f
}
func TestRoundPeak(t *testing.T) {
	for _, v := range []struct{ s, u, c, w uint64 }{{4097, 4096, 1, Reserve + Metadata + 8192}, {4097, 4096, 2, Reserve + Metadata + 16384}, {63985152, 4096, 1, 190865408}} {
		got, e := Required(v.s, v.u, v.c)
		if e != nil || got != v.w {
			t.Fatalf("%+v got%d %v", v, got, e)
		}
	}
	for _, v := range [][3]uint64{{0, 1, 1}, {1, 0, 1}, {1, 4096, 0}, {1, 4096, 3}, {^uint64(0), 4096, 1}} {
		if _, e := Required(v[0], v[1], v[2]); e == nil {
			t.Fatal(v)
		}
	}
	n, _ := Required(63985152, 4096, 1)
	if uint64(132947968) >= n {
		t.Fatal("actual M3 insufficient space incorrectly admitted")
	}
}
func TestRoundTrip(t *testing.T) {
	f := fx(t)
	if e := Apply(f.p, f.r, f.trust, f.archive, f.e); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(f.p.UKI); !os.IsNotExist(e) {
		t.Fatal("not retired")
	}
	b, _ := os.ReadFile(f.p.Menu)
	if !bytes.Equal(b, f.p.After) {
		t.Fatal("menu bytes")
	}
	if e := Restore(f.p, f.archive, f.e); e != nil {
		t.Fatal(e)
	}
	if e := Restore(f.p, f.archive, f.e); e != nil {
		t.Fatal("idempotent restore", e)
	}
	b, _ = os.ReadFile(f.p.Menu)
	if !bytes.Equal(b, f.p.Before) {
		t.Fatal("original bytes not restored")
	}
	h, _ := HashFile(f.p.UKI, MaxUKI)
	if h != f.p.File {
		t.Fatal(h)
	}
}
func TestApplyStopsAndRestoreAfterEveryInterruption(t *testing.T) {
	for _, phase := range []string{"prepared", "menu-retired", "file-retired"} {
		t.Run(phase, func(t *testing.T) {
			f := fx(t)
			f.e.Fault = func(s string) error {
				if s == phase {
					return errors.New("simulated power loss")
				}
				return nil
			}
			if e := Apply(f.p, f.r, f.trust, f.archive, f.e); e == nil {
				t.Fatal("fault ignored")
			}
			f.e.Fault = nil
			if e := Restore(f.p, f.archive, f.e); e != nil {
				t.Fatal(e)
			}
			b, _ := os.ReadFile(f.p.Menu)
			if !bytes.Equal(b, f.p.Before) {
				t.Fatal("menu not restored")
			}
		})
	}
}
func TestRetirementRefusals(t *testing.T) {
	for _, which := range []string{"default", "running", "shared", "parent", "normalized-ID-collision", "numeric-default", "bad-after", "traversal", "managed", "unknown-controller", "wrong-receipt", "stale-receipt", "future-receipt", "same-machine", "menu-drift", "identity-drift", "file-drift", "same-filesystem", "capacity", "kernel-name-drift", "no-copy"} {
		t.Run(which, func(t *testing.T) {
			f := fx(t)
			originalUKI := f.p.UKI
			switch which {
			case "default":
				f.p.Before = bytes.Replace(f.p.Before, []byte("default_entry: Working"), []byte("default_entry: Retired"), 1)
			case "running":
				f.p.Kernel = f.cur.Kernel
			case "shared":
				f.p.Before = bytes.Replace(f.p.Before, []byte("other.efi"), []byte("retired.efi"), 1)
			case "parent":
				f.p.Before = bytes.Replace(f.p.Before, []byte("/Other\n"), []byte("//Other\n"), 1)
			case "normalized-ID-collision":
				f.p.Before = append(f.p.Before, []byte("/Retire?\n/Retire!\n")...)
			case "numeric-default":
				f.p.Before = bytes.Replace(f.p.Before, []byte("default_entry: Working"), []byte("default_entry: 1"), 1)
			case "bad-after":
				f.p.After = append(f.p.After, 'x')
			case "traversal":
				f.p.UKI = filepath.Join(f.p.ESP, "..", "evil")
			case "managed":
				f.p.Entry = "/maclab-job"
				f.p.Before = bytes.Replace(f.p.Before, []byte("/Retired"), []byte(f.p.Entry), 1)
			case "unknown-controller":
				f.r.Controller = ""
			case "wrong-receipt":
				f.trust = strings.Repeat("0", 64)
			case "stale-receipt":
				f.r.Verified = time.Unix(-500, 0)
			case "future-receipt":
				f.r.Verified = time.Unix(300, 0)
			case "same-machine":
				f.r.Controller = f.cur.Machine
			case "menu-drift":
				os.WriteFile(f.p.Menu, append(f.p.Before, '#'), 0600)
			case "identity-drift":
				f.cur.Boot = "new-boot"
			case "file-drift":
				os.WriteFile(f.p.UKI, ukiBytes("other-release"), 0600)
			case "same-filesystem":
				f.e.Space = func(string) (Space, error) { return Space{1 << 30, 4096, 1}, nil }
			case "capacity":
				f.free = Reserve - 1
			case "kernel-name-drift":
				f.p.Kernel = "invented"
			case "no-copy":
				os.Remove(filepath.Join(f.controller, f.p.File.SHA256+".efi"))
				f.r.File.Size++
			}
			if which != "wrong-receipt" {
				f.trust = Digest(JSON(f.r))
			}
			if e := Apply(f.p, f.r, f.trust, f.archive, f.e); e == nil {
				t.Fatal("unsafe retirement accepted")
			}
			if _, e := os.Stat(originalUKI); e != nil {
				t.Fatal("UKI deleted", e)
			}
		})
	}
}
func TestRestoreCASAndReserve(t *testing.T) {
	for _, which := range []string{"menu-drift", "existing-different", "copy-corrupt", "low-reserve", "identity-drift", "destination-symlink"} {
		t.Run(which, func(t *testing.T) {
			f := fx(t)
			if e := Apply(f.p, f.r, f.trust, f.archive, f.e); e != nil {
				t.Fatal(e)
			}
			switch which {
			case "menu-drift":
				os.WriteFile(f.p.Menu, []byte("foreign"), 0600)
			case "existing-different":
				os.WriteFile(f.p.UKI, []byte("other"), 0600)
			case "copy-corrupt":
				os.WriteFile(filepath.Join(f.archive, "txn1", "uki.efi"), []byte("bad"), 0600)
			case "low-reserve":
				f.free = Reserve
			case "identity-drift":
				f.cur.Kernel = "foreign"
			case "destination-symlink":
				os.Symlink(filepath.Join(f.archive, "txn1", "uki.efi"), f.p.UKI)
			}
			if e := Restore(f.p, f.archive, f.e); e == nil {
				t.Fatal("unsafe restore accepted")
			}
		})
	}
}
func TestNoNonRegularOrAlias(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "p")
	if e := syscallMkfifo(path); e != nil {
		t.Fatal(e)
	}
	if _, e := HashFile(path, 1<<20); e == nil {
		t.Fatal("FIFO accepted")
	}
	os.Remove(path)
	os.Symlink("/etc/passwd", path)
	if _, e := HashFile(path, 1<<20); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := HashFile("/dev/null", 1<<20); e == nil {
		t.Fatal("device accepted")
	}
}

func syscallMkfifo(p string) error { return syscall.Mkfifo(p, 0600) }
func TestBackupRetirementAndProtectedNames(t *testing.T) {
	for _, which := range []string{"valid", "live", "old", "root-copy", "other-directory", "empty-suffix", "referenced", "alter-menu"} {
		t.Run(which, func(t *testing.T) {
			f := fx(t)
			f.p.Kind = "unreferenced-m1n1-backup"
			f.p.Entry = ""
			f.p.Kernel = ""
			f.p.After = append([]byte{}, f.p.Before...)
			f.p.UKI = filepath.Join(f.p.ESP, "m1n1", "boot.bin.pre-omacom-50fb")
			os.Mkdir(filepath.Dir(f.p.UKI), 0700)
			os.WriteFile(f.p.UKI, []byte("exact retired m1n1 backup bytes"), 0600)
			f.p.File, _ = HashFile(f.p.UKI, MaxUKI)
			switch which {
			case "live":
				f.p.UKI = filepath.Join(f.p.ESP, "m1n1", "boot.bin")
			case "old":
				f.p.UKI = filepath.Join(f.p.ESP, "m1n1", "boot.bin.old")
			case "root-copy":
				f.p.UKI = filepath.Join(f.p.ESP, "boot.bin")
			case "other-directory":
				f.p.UKI = filepath.Join(f.p.ESP, "EFI", "boot.bin.pre-x")
			case "empty-suffix":
				f.p.UKI = filepath.Join(f.p.ESP, "m1n1", "boot.bin.pre-")
			case "referenced":
				f.p.Before = append(f.p.Before, []byte("/Backup\n protocol: efi\n path: boot():/m1n1/boot.bin.pre-omacom-50fb\n")...)
				f.p.After = append([]byte{}, f.p.Before...)
			case "alter-menu":
				f.p.After = append(f.p.After, '#')
			}
			if which != "valid" {
				if e := validate(f.p); e == nil {
					t.Fatal("unsafe backup accepted")
				}
				return
			}
			var e error
			f.r, e = RetainController(f.p, f.p.UKI, f.controller, "controller", f.e)
			if e != nil {
				t.Fatal(e)
			}
			f.trust = Digest(JSON(f.r))
			if e = Apply(f.p, f.r, f.trust, f.archive, f.e); e != nil {
				t.Fatal(e)
			}
			if e = Restore(f.p, f.archive, f.e); e != nil {
				t.Fatal(e)
			}
			b, _ := os.ReadFile(f.p.Menu)
			if !bytes.Equal(b, f.p.Before) {
				t.Fatal("backup mode touched menu")
			}
		})
	}
}
func TestRetireOnlyDoesNotClaimStageAdmission(t *testing.T) {
	f := fx(t)
	f.p.RetireOnly = true
	f.p.NextUKIBytes = 0
	f.p.NextESPTemporaryCopies = 0
	f.free = Reserve + Metadata
	var e error
	f.r, e = RetainController(f.p, f.p.UKI, f.controller, "controller", f.e)
	if e != nil {
		t.Fatal(e)
	}
	if e = Apply(f.p, f.r, Digest(JSON(f.r)), f.archive, f.e); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(f.archive, "txn1", "capacity-admitted.json")); !os.IsNotExist(e) {
		t.Fatal("retire-only claimed stage admission")
	}
	if _, e = os.Stat(filepath.Join(f.archive, "txn1", "retire-only-not-stage-admission.json")); e != nil {
		t.Fatal(e)
	}
}
func TestRestoreNormalReturnVersusForeignProtectedDrift(t *testing.T) {
	for _, which := range []string{"new-boot", "store-churn", "loader-drift", "known-good-drift", "armed-drift"} {
		t.Run(which, func(t *testing.T) {
			f := fx(t)
			if e := Apply(f.p, f.r, f.trust, f.archive, f.e); e != nil {
				t.Fatal(e)
			}
			f.cur.Boot = "normal-return-boot"
			m := map[string]string{}
			for k, v := range f.cur.Files {
				m[k] = v
			}
			f.cur.Files = m
			switch which {
			case "store-churn":
				f.cur.Files["mutable-store:/esp/ubootefi.var"] = "new bytes"
			case "loader-drift":
				f.cur.Files["loader"] = "changed"
			case "known-good-drift":
				f.cur.Files["known-good"] = "changed"
			case "armed-drift":
				f.cur.Files["BLI"] = "armed"
			}
			e := Restore(f.p, f.archive, f.e)
			want := which == "new-boot" || which == "store-churn"
			if (e == nil) != want {
				t.Fatal(which, e)
			}
		})
	}
}
func TestControllerRetentionActuallyReopensDurableCopy(t *testing.T) {
	f := fx(t)
	dst := filepath.Join(f.controller, f.p.File.SHA256+".efi")
	os.WriteFile(dst, []byte("corrupt retained bytes"), 0600)
	if _, e := RetainController(f.p, f.p.UKI, f.controller, "controller", f.e); e == nil {
		t.Fatal("corrupt retained copy accepted")
	}
	if _, e := RetainController(f.p, f.p.UKI, f.controller, f.cur.Machine, f.e); e == nil {
		t.Fatal("same machine accepted")
	}
}
func TestRestorationAfterVerifiedTemporaryCopy(t *testing.T) {
	f := fx(t)
	if e := Apply(f.p, f.r, f.trust, f.archive, f.e); e != nil {
		t.Fatal(e)
	}
	tmp := filepath.Join(filepath.Dir(f.p.UKI), ".lab-esp-restore-"+f.p.Transaction)
	if e := copyVerified(filepath.Join(f.archive, "txn1", "uki.efi"), tmp, f.p.File); e != nil {
		t.Fatal(e)
	}
	if e := Restore(f.p, f.archive, f.e); e != nil {
		t.Fatal("interrupted temp not resumable", e)
	}
}
func TestActualMBPMenuShapeAndPeak(t *testing.T) {
	b, e := os.ReadFile("testdata/mbp-menu.conf")
	if e != nil {
		t.Fatal(e)
	}
	after, e := PrepareMenu(b, "/SiliconForest - kernel 177+182")
	if e != nil {
		t.Fatal(e)
	}
	f := fx(t)
	f.p.ESP = "/boot/efi"
	f.p.Menu = "/boot/efi/limine.conf"
	f.p.Entry = "/SiliconForest - kernel 177+182"
	f.p.UKI = "/boot/efi/EFI/Linux/siliconforest-normal-205f5e8b20fc.efi"
	f.p.Before = b
	f.p.After = after
	if e = validate(f.p); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(after, []byte("default_entry: Omarchy/linux-aurora")) || !bytes.Contains(after, []byte("///2 │")) || !bytes.Contains(after, []byte("# maclab: end")) {
		t.Fatal("unrelated menu bytes lost")
	}
	need, e := Required(64421888, 4096, 1)
	if e != nil {
		t.Fatal(e)
	}
	free := uint64(182812672 + 59273216 + 9580544 - 60219392)
	if free < need || uint64(182812672+59273216-60219392) >= need {
		t.Fatalf("wrong exact packet capacity free=%d need=%d", free, need)
	}
}
func TestNonRegularNeverDataOpened(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{fifo, "/dev/null"} {
		calls := 0
		_, e := regularWithOpen(p, func(string, int, os.FileMode) (*os.File, error) {
			calls++
			return nil, errors.New("data open attempted")
		})
		if e == nil || calls != 0 {
			t.Fatalf("%s data opened %d err%v", p, calls, e)
		}
	}
}
func TestRegularReopenRefusesPathSwap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "source")
	os.WriteFile(p, []byte("trusted"), 0600)
	f, e := regularWithOpen(p, func(proc string, flags int, mode os.FileMode) (*os.File, error) {
		os.Rename(p, p+".old")
		os.WriteFile(p, []byte("foreign"), 0600)
		return os.OpenFile(proc, flags, mode)
	})
	if f != nil {
		f.Close()
	}
	if e == nil {
		t.Fatal("path swap accepted")
	}
}
func TestExactDistinctMBPPeak(t *testing.T) {
	p := Plan{NextUKIBytes: 64413696, NextESPTemporaryCopies: 1, AdditionalESPBytes: 60215808}
	need, e := RequiredPlan(p, 4096)
	if e != nil || need != 251510784 {
		t.Fatal(need, e)
	}
	free := uint64(182812672 + 59273216 + 9580544)
	if free < need || free-need != 155648 {
		t.Fatal("wrong exact post-retirement admission", free, need)
	}
	if uint64(182812672+59273216) >= need {
		t.Fatal("SF alone incorrectly fits")
	}
}
func TestReadOnlyPlanRequiresActualUKIKernelAndPinnedBytes(t *testing.T) {
	f := fx(t)
	if _, e := NewPlan(f.p, f.e); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(f.p.Menu); !bytes.Equal(b, f.p.Before) {
		t.Fatal("plan changed menu")
	}
	f.p.Kernel = "invented"
	if _, e := NewPlan(f.p, f.e); e == nil {
		t.Fatal("invented UKI name accepted")
	}
}
func TestCapacityDriftStopsBeforeMenuMutation(t *testing.T) {
	f := fx(t)
	old := f.e.Space
	calls := 0
	f.e.Space = func(p string) (Space, error) {
		sp, e := old(p)
		if p == f.p.ESP {
			calls++
			if calls >= 2 {
				sp.Available = Reserve - 1
			}
		}
		return sp, e
	}
	if e := Apply(f.p, f.r, f.trust, f.archive, f.e); e == nil {
		t.Fatal("capacity drift ignored")
	}
	b, _ := os.ReadFile(f.p.Menu)
	if !bytes.Equal(b, f.p.Before) {
		t.Fatal("menu changed despite lost reserve")
	}
	if _, e := os.Stat(f.p.UKI); e != nil {
		t.Fatal("original artifact removed", e)
	}
}
func TestCTimeDriftCannotHideBehindRestoredMTime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file")
	os.WriteFile(p, []byte("before"), 0600)
	before, _ := os.Stat(p)
	os.WriteFile(p, []byte("after!"), 0600)
	os.Chtimes(p, before.ModTime(), before.ModTime())
	after, _ := os.Stat(p)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("fixture did not restore mtime")
	}
	if stableInfo(before, after) {
		t.Fatal("ctime change ignored")
	}
}

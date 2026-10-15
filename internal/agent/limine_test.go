package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// The head of Omarchy's Apple Silicon limine.conf, as limine-update writes it.
const omarchyLimineConf = `default_entry: 2
interface_branding: Omarchy Bootloader
timeout: 3

/+Omarchy
comment: Omarchy
comment: machine-id=0123456789abcdef0123456789abcdef order-priority=50
  //linux-aurora
  comment: 7.1.12-2-11.6-sep-ARCH
  protocol: efi
  path: boot():/EFI/Linux/omarchy_linux-aurora.efi
`

func testLimine(t *testing.T) *limineLayout {
	t.Helper()
	dir := t.TempDir()
	l := &limineLayout{Conf: filepath.Join(dir, "limine.conf"), Stage: filepath.Join(dir, "maclab")}
	if err := os.WriteFile(l.Conf, []byte(omarchyLimineConf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(l.Stage, 0o755); err != nil {
		t.Fatal(err)
	}
	return l
}

func stageLimineEntry(t *testing.T, l *limineLayout, job string) {
	t.Helper()
	d := filepath.Join(l.Stage, job)
	os.MkdirAll(d, 0o755)
	if err := os.WriteFile(filepath.Join(d, limineEntry), []byte(l.entryText(job, "maclab "+job+": 7.1.12-lab")), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLimineEntries(t *testing.T) {
	l := testLimine(t)
	stageLimineEntry(t, l, "j1001-120000-abcd")
	if err := l.writeEntries(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(l.Conf)
	want := omarchyLimineConf + "\n" + limineBegin + "\n" +
		"/maclab-j1001-120000-abcd\n    comment: maclab j1001-120000-abcd: 7.1.12-lab\n    protocol: efi\n    path: boot():/maclab/j1001-120000-abcd/uki.efi\n" +
		limineEnd + "\n"
	if string(got) != want {
		t.Fatalf("limine.conf:\n%s\nwant:\n%s", got, want)
	}

	// Idempotent, and a second job lands in the same block.
	stageLimineEntry(t, l, "j1001-130000-ef01")
	l.writeEntries()
	l.writeEntries()
	got, _ = os.ReadFile(l.Conf)
	if n := strings.Count(string(got), limineBegin); n != 1 {
		t.Fatalf("%d maclab blocks", n)
	}
	if !strings.Contains(string(got), "\n/maclab-j1001-130000-ef01\n") || !strings.HasPrefix(string(got), omarchyLimineConf) {
		t.Fatalf("limine.conf:\n%s", got)
	}

	// Cleaning up every job leaves an empty block and Omarchy's menu as it was.
	os.RemoveAll(filepath.Join(l.Stage, "j1001-120000-abcd"))
	os.RemoveAll(filepath.Join(l.Stage, "j1001-130000-ef01"))
	l.writeEntries()
	got, _ = os.ReadFile(l.Conf)
	if want := omarchyLimineConf + "\n" + limineBegin + "\n" + limineEnd + "\n"; string(got) != want {
		t.Fatalf("limine.conf:\n%s", got)
	}
}

// limine-update rewrites the menu on a kernel update and may move or drop the
// block; the next writeEntries puts exactly one back at the end.
func TestLimineEntriesAfterRewrite(t *testing.T) {
	l := testLimine(t)
	stageLimineEntry(t, l, "j1")
	l.writeEntries()
	conf, _ := os.ReadFile(l.Conf)
	moved := strings.Replace(string(conf), "/+Omarchy", "/+Omarchy\n  //linux-aurora-fallback\n  protocol: efi\n  path: boot():/EFI/Linux/omarchy_linux-aurora-fallback.efi", 1)
	os.WriteFile(l.Conf, []byte(moved), 0o644)
	l.writeEntries()
	got, _ := os.ReadFile(l.Conf)
	if n := strings.Count(string(got), limineBegin); n != 1 || !strings.HasSuffix(string(got), limineEnd+"\n") {
		t.Fatalf("limine.conf:\n%s", got)
	}
	if !strings.Contains(string(got), "linux-aurora-fallback") {
		t.Fatal("lost limine-update's own entries")
	}
}

func TestUTF16z(t *testing.T) {
	b := utf16z("maclab-j1")
	if len(b) != 2*len("maclab-j1")+2 || b[0] != 'm' || b[1] != 0 || b[len(b)-1] != 0 || b[len(b)-2] != 0 {
		t.Fatalf("% x", b)
	}
	if got := fromUTF16z(b); got != "maclab-j1" {
		t.Fatal(got)
	}
}

// Staging an installed entry checks the UKI's SHA256 and that the path's #pin
// is its BLAKE2b-512: on these Macs Limine only warns on a mismatch.
func TestStageInstalledChecksBlake2bPin(t *testing.T) {
	l := testLimine(t)
	esp := filepath.Dir(l.Conf)
	l.ESP = mount{Target: esp}
	os.MkdirAll(filepath.Join(esp, "EFI/Linux"), 0o755)
	os.WriteFile(filepath.Join(esp, "EFI/Linux/x.efi"), []byte("abc"), 0o644)
	sum := sha256.Sum256([]byte("abc"))
	// BLAKE2b-512("abc"), RFC 7693 appendix A
	const abc = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
	if got, _ := fileBlake2b(filepath.Join(esp, "EFI/Linux/x.efi")); got != abc {
		t.Fatalf("fileBlake2b: %s", got)
	}
	locks := t.TempDir()
	bootPartitionLocks = []string{filepath.Join(locks, "boot-partition.lock"), filepath.Join(locks, "limine-global.lock")}
	stage := func(pin string) error {
		_, err := (&Linux{}).stageInstalled("j1", &api.InstalledStage{Path: "boot():/EFI/Linux/x.efi#" + pin, UKISHA256: hex.EncodeToString(sum[:]),
			Cmdline: "root=UUID=x rw maclab.job=j1 panic=10", Release: "12.0"}, l, t.TempDir())
		return err
	}
	if err := stage(strings.Repeat("0", 128)); err == nil || !strings.Contains(err.Error(), "pins") {
		t.Fatalf("a wrong pin: %v", err)
	}
	if err := stage(abc); err != nil {
		t.Fatalf("the right pin: %v", err)
	}
}

// limineEnrolledSum is what `limine enroll-config` wrote on the m1air for a
// limine.conf of "timeout: 3\n".
const limineEnrolledSum = "fc00642323e1400a27f8a4401f2fcb329824d37b25545eb1475900d097c3323405d5b1ddceb98dd34f042d9da87dece9b86870a6f4cf1326c73596c90940e788"

// limineBinary is a Limine EFI binary in miniature with sum in its checksum
// slot, or the 128 '0's it ships with for "".
func limineBinary(sum string) []byte {
	if sum == "" {
		sum = strings.Repeat("0", 128)
	}
	return []byte("MZ\x00limine.conf\x00" + limineChecksumSlot + sum + "\x00")
}

// `limine enroll-config` writes limine.conf's BLAKE2B after the signature in
// Limine's EFI binary, and --reset puts the 128 '0's back.
func TestLimineConfigEnrolled(t *testing.T) {
	zeros := strings.Repeat("0", 128)
	for _, c := range []struct {
		name     string
		bin      []byte
		enrolled bool
	}{
		{"as shipped", limineBinary(""), false},
		{"enrolled", limineBinary(limineEnrolledSum), true},
		{"no slot: not Limine, or too old to enroll", []byte("limine.conf\x00" + zeros), false},
		{"cut short", []byte(limineChecksumSlot + limineEnrolledSum[:64]), false},
		{"only the first slot counts", []byte(limineChecksumSlot + zeros + limineChecksumSlot + limineEnrolledSum), false},
	} {
		if got := limineConfigEnrolled(c.bin); got != c.enrolled {
			t.Errorf("%s: enrolled %v", c.name, got)
		}
	}
}

// Each case is what Limine's own load_key_value_config made of it on the
// m1air (limine-mkinitcpio-hook 1.39.0).
func TestLimineEnrollsConfig(t *testing.T) {
	for _, c := range []struct {
		defaults string
		on       bool
	}{
		{"", false},
		{"ENABLE_ENROLL_LIMINE_CONFIG=yes\n", true},
		{`ENABLE_ENROLL_LIMINE_CONFIG="yes"`, true},
		{"  ENABLE_ENROLL_LIMINE_CONFIG = \"yes\"\n", true},
		{"ENABLE_ENROLL_LIMINE_CONFIG=\tyes\n", true},
		{"ENABLE_ENROLL_LIMINE_CONFIG=\"yes\n", true},
		{"ENABLE_ENROLL_LIMINE_CONFIG=YES\n", false},
		{"ENABLE_ENROLL_LIMINE_CONFIG='yes'\n", false},
		{"ENABLE_ENROLL_LIMINE_CONFIG=yes # on\n", false},
		{"ENABLE_ENROLL_LIMINE_CONFIG=yes \n", false},
		{"ENABLE_ENROLL_LIMINE_CONFIG=yes\r\n", false},
		{"#ENABLE_ENROLL_LIMINE_CONFIG=yes\n", false},
		{"export ENABLE_ENROLL_LIMINE_CONFIG=yes\n", false},
		{"enable_enroll_limine_config=yes\n", false},
		{"ENABLE_ENROLL_LIMINE_CONFIG=yes\nENABLE_ENROLL_LIMINE_CONFIG=no\n", false},
		{"ENABLE_ENROLL_LIMINE_CONFIG=no\nENABLE_ENROLL_LIMINE_CONFIG=yes\n", true},
	} {
		p := filepath.Join(t.TempDir(), "limine")
		if err := os.WriteFile(p, []byte(c.defaults), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := limineEnrollsConfig(p); got != c.on {
			t.Errorf("%q: on %v", c.defaults, got)
		}
	}
	if limineEnrollsConfig(filepath.Join(t.TempDir(), "limine")) {
		t.Error("no /etc/default/limine: on")
	}
}

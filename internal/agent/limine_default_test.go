package agent

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type defaultFixture struct {
	l                   *Linux
	b                   *limineLayout
	o                   LimineDefaultOptions
	cur                 defaultObservation
	conf                []byte
	modules, uki, image string
}

func newDefaultFixture(t *testing.T) *defaultFixture {
	t.Helper()
	root := t.TempDir()
	esp := filepath.Join(root, "esp")
	modules := filepath.Join(root, "modules")
	kernel := "7.2-current-custom"
	image := []byte("real kernel bytes for matching UKI and module-side vmlinuz")
	uki := filepath.Join(esp, "EFI/Linux/current.efi")
	os.MkdirAll(filepath.Dir(uki), 0755)
	os.MkdirAll(filepath.Join(modules, kernel), 0755)
	os.WriteFile(filepath.Join(modules, kernel, "vmlinuz"), image, 0644)
	cmd := "root=UUID=test rw quiet"
	os.WriteFile(uki, miniDefaultUKI(t, kernel, cmd, image), 0644)
	pin, _ := fileBlake2b(uki)
	sum, _ := fileSHA256(uki)
	conf := []byte("# preserve formatting and every entry byte\n  default_entry: Old recovery  \ntimeout: 3\n\n/+Operating System\n  //stock\n  protocol: efi\n  path: boot():/EFI/Linux/stock.efi\n\n/Old recovery\n    protocol: efi\n    path: boot():/EFI/Linux/old.efi\n\n/Current recovery\n    comment: don't regenerate this entry\n    protocol: efi\n    path: boot():/EFI/Linux/current.efi#" + pin + "\n\n" + limineBegin + "\n" + limineEnd + "\n")
	menu := filepath.Join(esp, "limine.conf")
	os.WriteFile(menu, conf, 0644)
	return &defaultFixture{l: &Linux{WorkDir: filepath.Join(root, "agent")}, b: &limineLayout{Conf: menu, ESP: mount{Target: esp}, Stage: filepath.Join(esp, "maclab")}, o: LimineDefaultOptions{ExpectedMenuSHA256: digest(conf), ExpectedDefault: "Old recovery", Entry: "Current recovery", ExpectedUKISHA256: sum, ExpectedKernel: kernel, Transaction: "t1"}, cur: defaultObservation{BootID: "boot1", Kernel: kernel, Cmdline: cmd, Selected: "Current-recovery"}, conf: conf, modules: modules, uki: uki, image: filepath.Join(modules, kernel, "vmlinuz")}
}
func miniDefaultUKI(t *testing.T, kernel, cmd string, image []byte) []byte {
	t.Helper()
	type sec struct {
		name string
		data []byte
	}
	sections := []sec{{".uname", []byte(kernel + "\x00")}, {".cmdline", []byte(cmd + "\x00")}, {".linux", image}, {".initrd", []byte("initrd")}}
	var buf bytes.Buffer
	dos := make([]byte, 128)
	dos[0], dos[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(dos[0x3c:], 128)
	buf.Write(dos)
	buf.Write([]byte{'P', 'E', 0, 0})
	opt := pe.OptionalHeader64{Magic: 0x20b, Subsystem: pe.IMAGE_SUBSYSTEM_EFI_APPLICATION, NumberOfRvaAndSizes: 16}
	fh := pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_ARM64, NumberOfSections: uint16(len(sections)), SizeOfOptionalHeader: uint16(binary.Size(opt))}
	binary.Write(&buf, binary.LittleEndian, fh)
	binary.Write(&buf, binary.LittleEndian, opt)
	headerSize := buf.Len() + len(sections)*40
	offset := (headerSize + 511) / 512 * 512
	for i, s := range sections {
		h := pe.SectionHeader32{VirtualSize: uint32(len(s.data)), SizeOfRawData: 512, PointerToRawData: uint32(offset + i*512)}
		copy(h.Name[:], s.name)
		binary.Write(&buf, binary.LittleEndian, h)
	}
	buf.Write(make([]byte, offset-buf.Len()))
	for _, s := range sections {
		buf.Write(s.data)
		buf.Write(make([]byte, 512-len(s.data)))
	}
	return buf.Bytes()
}
func (f *defaultFixture) observe() (defaultObservation, error) { return f.cur, nil }
func (f *defaultFixture) run() (*LimineDefaultResult, error) {
	return f.l.setLimineDefault(f.b, f.o, f.modules, f.observe, writeSynced)
}

func TestLimineDefaultDryRunAndApply(t *testing.T) {
	f := newDefaultFixture(t)
	f.o.DryRun = true
	r, err := f.run()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.b.Conf)
	if !bytes.Equal(got, f.conf) || r.Verified || r.Receipt != "" {
		t.Fatalf("dry run mutated or claimed apply: %+v", r)
	}
	if _, err := os.Stat(f.l.WorkDir); !os.IsNotExist(err) {
		t.Fatal("dry run wrote work directory")
	}
	f.o.DryRun = false
	r, err = f.run()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Replace(f.conf, []byte("default_entry: Old recovery"), []byte("default_entry: Current recovery"), 1)
	got, _ = os.ReadFile(f.b.Conf)
	if !bytes.Equal(got, want) || !r.Verified || r.AfterSHA256 != digest(got) {
		t.Fatalf("changed more than default or bad receipt: %+v", r)
	}
	var receipt struct {
		OriginalMenu []byte `json:"original_menu"`
	}
	b, _ := os.ReadFile(r.Receipt)
	if json.Unmarshal(b, &receipt) != nil || !bytes.Equal(receipt.OriginalMenu, f.conf) {
		t.Fatal("original bytes not preserved")
	}
	if st, _ := os.Stat(r.Receipt); st.Mode().Perm() != 0600 {
		t.Fatal("receipt not private")
	}
	if _, err = f.run(); err == nil {
		t.Fatal("stale CAS unexpectedly applied twice")
	}
}
func TestLimineDefaultRefusesInvalidTargets(t *testing.T) {
	cases := []struct {
		name   string
		change func(*defaultFixture)
	}{
		{"wrong menu hash", func(f *defaultFixture) { f.o.ExpectedMenuSHA256 = strings.Repeat("0", 64) }},
		{"wrong old default", func(f *defaultFixture) { f.o.ExpectedDefault = "stock" }},
		{"wrong UKI hash", func(f *defaultFixture) { f.o.ExpectedUKISHA256 = strings.Repeat("0", 64) }},
		{"wrong kernel", func(f *defaultFixture) { f.o.ExpectedKernel = "other" }},
		{"different selected entry", func(f *defaultFixture) { f.cur.Selected = "Old-recovery" }},
		{"lab boot", func(f *defaultFixture) { f.cur.Cmdline += " maclab.job=j1" }},
		{"module image mismatch", func(f *defaultFixture) { os.WriteFile(f.image, []byte("wrong"), 0644) }},
		{"missing module image", func(f *defaultFixture) { os.Remove(f.image) }},
		{"UKI uname mismatch", func(f *defaultFixture) {
			b := miniDefaultUKI(t, "other", f.cur.Cmdline, []byte("other"))
			os.WriteFile(f.uki, b, 0644)
			f.repin()
		}},
		{"UKI cmdline mismatch", func(f *defaultFixture) {
			b := miniDefaultUKI(t, f.cur.Kernel, "root=other", []byte("other"))
			os.WriteFile(f.uki, b, 0644)
			f.repin()
		}},
		{"UKI symlink", func(f *defaultFixture) { other := f.uki + ".real"; os.Rename(f.uki, other); os.Symlink(other, f.uki) }},
		{"menu symlink", func(f *defaultFixture) {
			other := f.b.Conf + ".real"
			os.Rename(f.b.Conf, other)
			os.Symlink(other, f.b.Conf)
		}},
		{"transaction traversal", func(f *defaultFixture) { f.o.Transaction = "../escape" }},
		{"entry cmdline override", func(f *defaultFixture) {
			f.editMenu("# preserve formatting", "# preserve formatting")
			f.conf = append(f.conf, []byte("cmdline: root=other\n")...)
			f.saveMenu()
		}},
		{"duplicate ID", func(f *defaultFixture) {
			f.conf = append(f.conf, []byte("/Current-recovery\nprotocol: efi\npath: boot():/other\n")...)
			f.saveMenu()
		}},
		{"duplicate default", func(f *defaultFixture) { f.conf = append([]byte("default_entry: Other\n"), f.conf...); f.saveMenu() }},
		{"resource traversal", func(f *defaultFixture) { f.editMenu("boot():/EFI/Linux/current.efi#", "boot():/../current.efi#") }},
		{"wrong resource pin", func(f *defaultFixture) { pin, _ := fileBlake2b(f.uki); f.editMenu(pin, strings.Repeat("0", 128)) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDefaultFixture(t)
			c.change(f)
			before, _ := os.ReadFile(f.b.Conf)
			if _, err := f.run(); err == nil {
				t.Fatal("unsafe target accepted")
			}
			after, _ := os.ReadFile(f.b.Conf)
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed menu")
			}
			if _, err := os.Stat(f.l.WorkDir); !os.IsNotExist(err) {
				t.Fatal("validation failure wrote receipt")
			}
		})
	}
}
func (f *defaultFixture) saveMenu() {
	os.WriteFile(f.b.Conf, f.conf, 0644)
	f.o.ExpectedMenuSHA256 = digest(f.conf)
}
func (f *defaultFixture) editMenu(from, to string) {
	f.conf = bytes.ReplaceAll(f.conf, []byte(from), []byte(to))
	f.saveMenu()
}
func (f *defaultFixture) repin() {
	pin, _ := fileBlake2b(f.uki)
	oldPin := strings.Split(strings.Split(string(f.conf), "current.efi#")[1], "\n")[0]
	f.editMenu(oldPin, pin)
	f.o.ExpectedUKISHA256, _ = fileSHA256(f.uki)
}

func TestLimineDefaultDriftAndFailure(t *testing.T) {
	for _, kind := range []string{"menu", "boot", "UKI", "write", "readback"} {
		t.Run(kind, func(t *testing.T) {
			f := newDefaultFixture(t)
			calls := 0
			observe := func() (defaultObservation, error) {
				calls++
				if calls == 2 {
					switch kind {
					case "menu":
						os.WriteFile(f.b.Conf, append(f.conf, []byte("# other writer\n")...), 0644)
					case "boot":
						f.cur.BootID = "boot2"
					case "UKI":
						os.WriteFile(f.uki, []byte("bad UKI"), 0644)
					}
				}
				return f.cur, nil
			}
			writes := 0
			write := func(p string, b []byte) error {
				writes++
				if kind == "write" {
					return errors.New("injected write failure")
				}
				if kind == "readback" {
					return os.WriteFile(p, []byte("tampered output"), 0644)
				}
				return writeSynced(p, b)
			}
			if _, err := f.l.setLimineDefault(f.b, f.o, f.modules, observe, write); err == nil {
				t.Fatal("drift/failure accepted")
			}
			if kind != "write" && kind != "readback" && writes != 0 {
				t.Fatal("wrote after drift")
			}
			b, err := os.ReadFile(filepath.Join(f.l.WorkDir, "default-transactions/t1.json"))
			if err != nil || !bytes.Contains(b, []byte("original_menu")) {
				t.Fatal("lost original after failure")
			}
		})
	}
}
func TestLimineDefaultReceiptCollision(t *testing.T) {
	f := newDefaultFixture(t)
	dir := filepath.Join(f.l.WorkDir, "default-transactions")
	os.MkdirAll(dir, 0700)
	receipt := filepath.Join(dir, "t1.json")
	os.WriteFile(receipt, []byte("original existing receipt"), 0600)
	if _, err := f.run(); err == nil {
		t.Fatal("overwrote existing receipt")
	}
	b, _ := os.ReadFile(receipt)
	if string(b) != "original existing receipt" {
		t.Fatal("receipt clobbered")
	}
	b, _ = os.ReadFile(f.b.Conf)
	if !bytes.Equal(b, f.conf) {
		t.Fatal("menu changed")
	}
}
func TestLimineDefaultCRLFAndIDs(t *testing.T) {
	f := newDefaultFixture(t)
	f.conf = bytes.ReplaceAll(f.conf, []byte("\n"), []byte("\r\n"))
	f.saveMenu()
	r, err := f.run()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.b.Conf)
	want := bytes.Replace(f.conf, []byte("default_entry: Old recovery"), []byte("default_entry: Current recovery"), 1)
	if !bytes.Equal(got, want) || !r.Verified {
		t.Fatal("CRLF or entry bytes changed")
	}
	for in, want := range map[string]string{"/Omacom Edge - aurora6 M3 GPU": "Omacom-Edge---aurora6-M3-GPU", "/OS/Child": "OS.Child", "/a:b": "a-b", "/.": ".-"} {
		if got := limineBaseID(in); got != want {
			t.Fatal(fmt.Sprint(in, got, want))
		}
	}
	if len(limineBaseID("/"+strings.Repeat("a", 300))) != 232 {
		t.Fatal("wrong Limine truncation")
	}
}
func TestLimineDefaultRootOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root wrapper check")
	}
	if _, err := (&Linux{}).SetLimineDefault(LimineDefaultOptions{DryRun: true}); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatal(err)
	}
}

func TestLimineDefaultRejectsConfigEnrollment(t *testing.T) {
	root := t.TempDir()
	defaults := filepath.Join(root, "defaults")
	loader := filepath.Join(root, "loader")
	plain := []byte("header++CONFIG_B2SUM_SIGNATURE++" + strings.Repeat("0", 128))
	for _, c := range []struct {
		name, config string
		binary       []byte
		want         bool
	}{
		{"unenrolled", "ENABLE_ENROLL_LIMINE_CONFIG=no\n", plain, true},
		{"flag enabled", "ENABLE_ENROLL_LIMINE_CONFIG=\"yes\"\n", plain, false},
		{"last config wins", "ENABLE_ENROLL_LIMINE_CONFIG=yes\nENABLE_ENROLL_LIMINE_CONFIG=no\n", plain, true},
		{"binary enrolled", "", append([]byte("header++CONFIG_B2SUM_SIGNATURE++1"), bytes.Repeat([]byte("0"), 127)...), false},
		{"unknown binary slot", "", []byte("not a verified loader"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			os.WriteFile(defaults, []byte(c.config), 0644)
			os.WriteFile(loader, c.binary, 0644)
			err := defaultCASEnrollmentSafe(defaults, []string{loader, filepath.Join(root, "optional absent copy")})
			if (err == nil) != c.want {
				t.Fatal(err)
			}
		})
	}
}

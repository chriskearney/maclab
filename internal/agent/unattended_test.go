package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The m1air's root: btrfs subvolume @ on a plain (unencrypted) partition.
const m1airRootSource = "/dev/nvme0n1p6[/@]"

func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if strings.HasSuffix(p, "/") {
			os.MkdirAll(full, 0o755)
			continue
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A Mac like the m1air: nothing in the way.
func m1airRoot() map[string]string {
	return map[string]string{
		"etc/default/limine":                     "ENABLE_UKI=yes\n#ENABLE_ENROLL_LIMINE_CONFIG=no\nESP_PATH=\"/boot/efi\"\n",
		"boot/efi/EFI/BOOT/BOOTAA64.EFI":         string(limineBinary("")),
		"etc/systemd/journald.conf":              "[Journal]\n#Storage=persistent\n",
		"proc/cmdline":                           "root=UUID=4f4d5801 rw rootflags=subvol=@ rootfstype=btrfs panic=10 quiet splash\n",
		"sys/class/block/nvme0n1p6/partition":    "6\n",
		"var/log/journal/":                       "",
		"etc/crypttab":                           "# <name> <device> <password> <options>\n",
		"usr/lib/systemd/journald.conf.d/x.conf": "[Journal]\nSystemMaxUse=1G\n",
	}
}

// m1airLimine is the m1air's Limine under root: U-Boot boots the ESP's
// EFI/BOOT/BOOTAA64.EFI.
func m1airLimine(root string) *limineLayout {
	esp := filepath.Join(root, "boot/efi")
	return &limineLayout{ESP: mount{Target: esp}, Loader: filepath.Join(esp, "EFI/BOOT/BOOTAA64.EFI")}
}

func TestUnattendedClean(t *testing.T) {
	root := fakeRoot(t, m1airRoot())
	hard, warnings := unattendedProblems(root, m1airLimine(root), m1airRootSource, m1airRootSource)
	if len(hard)+len(warnings) > 0 {
		t.Fatalf("hard %q warnings %q", hard, warnings)
	}
	// GRUB too, /boot on its own partition or not
	for _, boot := range []string{m1airRootSource, "/dev/nvme0n1p5"} {
		if hard, warnings := unattendedProblems(root, &grubLayout{}, m1airRootSource, boot); len(hard)+len(warnings) > 0 {
			t.Fatalf("GRUB, /boot on %s: hard %q warnings %q", boot, hard, warnings)
		}
	}
}

// Limine config enrollment, turned on in /etc/default/limine or already in a
// Limine binary on the ESP, is a hard problem that says how to turn it off.
func TestUnattendedLimineEnroll(t *testing.T) {
	for _, c := range []struct {
		name          string
		defaults      string
		loader, tools string   // the checksum enrolled in U-Boot's loader and in the tools' copy; "" for none
		want          []string // in the problem, <esp> for the ESP; none for no problem
	}{
		{"off", "ENABLE_ENROLL_LIMINE_CONFIG=no\n", "", "", nil},
		{"on: the next Limine update enrolls it", "ENABLE_ENROLL_LIMINE_CONFIG=yes\n", "", "",
			[]string{"(ENABLE_ENROLL_LIMINE_CONFIG=yes in /etc/default/limine,", "CHECKSUM MISMATCH", "To turn it off, set ENABLE_ENROLL_LIMINE_CONFIG=no in /etc/default/limine"}},
		{"not as Limine's tools read it", "ENABLE_ENROLL_LIMINE_CONFIG=YES\n", "", "", nil},
		// turned off without a reset: Limine still checks what the last update enrolled
		{"off, still enrolled", "ENABLE_ENROLL_LIMINE_CONFIG=no\n", "", limineEnrolledSum,
			[]string{"(<esp>/EFI/limine/limine_aa64.efi has it enrolled)", "To turn it off, run `sudo limine enroll-config --reset <esp>/EFI/limine/limine_aa64.efi`"}},
		{"enrolled by hand", "", limineEnrolledSum, "",
			[]string{"(<esp>/EFI/BOOT/BOOTAA64.EFI has it enrolled)", "run `sudo limine enroll-config --reset <esp>/EFI/BOOT/BOOTAA64.EFI`"}},
		{"on and enrolled", "ENABLE_ENROLL_LIMINE_CONFIG=yes\n", "", limineEnrolledSum,
			[]string{"set ENABLE_ENROLL_LIMINE_CONFIG=no in /etc/default/limine, then run `sudo limine enroll-config --reset <esp>/EFI/limine/limine_aa64.efi`"}},
	} {
		files := m1airRoot()
		files["etc/default/limine"] = "ENABLE_UKI=yes\n" + c.defaults
		files["boot/efi/EFI/BOOT/BOOTAA64.EFI"] = string(limineBinary(c.loader))
		files["boot/efi/EFI/limine/limine_aa64.efi"] = string(limineBinary(c.tools))
		root := fakeRoot(t, files)
		l := m1airLimine(root)
		hard, _ := unattendedProblems(root, l, m1airRootSource, m1airRootSource)
		if len(c.want) == 0 && len(hard) > 0 || len(c.want) > 0 && len(hard) != 1 {
			t.Errorf("%s: %q", c.name, hard)
			continue
		}
		for _, w := range c.want {
			if w = strings.ReplaceAll(w, "<esp>", l.ESP.Target); !strings.Contains(hard[0], w) {
				t.Errorf("%s: %q\nlacks %q", c.name, hard[0], w)
			}
		}
		// GRUB Macs don't use Limine's config.
		if hard, _ := unattendedProblems(root, &grubLayout{}, m1airRootSource, m1airRootSource); len(hard) > 0 {
			t.Errorf("%s, GRUB: %q", c.name, hard)
		}
	}
}

// luksRoot is / on LUKS, opened as /dev/mapper/root.
func luksRoot(more map[string]string) map[string]string {
	files := map[string]string{"dev/dm-0": "", "sys/class/block/dm-0/dm/uuid": "CRYPT-LUKS2-0123456789abcdef-root\n",
		"sys/class/block/dm-0/dm/name": "root\n", "sys/class/block/dm-0/slaves/nvme0n1p6/": ""}
	for p, b := range more {
		files[p] = b
	}
	return files
}

// An encrypted disk is refused only when booting it would wait for a
// passphrase: a key file, from crypttab or the cmdline, unlocks it alone.
func TestUnattendedEncryptedRoot(t *testing.T) {
	const luks = "/dev/mapper/root[/@]"
	for _, c := range []struct {
		name   string
		files  map[string]string
		source string
		boot   string // /boot's source; the same as /'s if empty
		grub   bool
		want   string
	}{
		{"LUKS root", map[string]string{"dev/dm-0": "", "sys/class/block/dm-0/dm/uuid": "CRYPT-LUKS2-0123456789abcdef-root\n"}, "/dev/mapper/root[/@]", "", false, "/ is on dm-crypt"},
		{"LVM on LUKS", map[string]string{"dev/dm-1": "", "sys/class/block/dm-1/dm/uuid": "LVM-abc\n",
			"sys/class/block/dm-1/slaves/dm-0/": "", "sys/class/block/dm-0/dm/uuid": "CRYPT-LUKS2-0123-cryptlvm\n"}, "/dev/mapper/vg-root", "", false, "/ is on dm-crypt"},
		{"plain LVM", map[string]string{"dev/dm-1": "", "sys/class/block/dm-1/dm/uuid": "LVM-abc\n", "sys/class/block/dm-1/slaves/nvme0n1p6/": ""}, "/dev/mapper/vg-root", "", false, ""},
		{"dm-verity root", map[string]string{"dev/dm-0": "", "sys/class/block/dm-0/dm/uuid": "CRYPT-VERITY-0123456789abcdef-root\n",
			"sys/class/block/dm-0/slaves/nvme0n1p6/": ""}, "/dev/mapper/root", "", false, ""},
		{"dm-integrity under LVM", map[string]string{"dev/dm-1": "", "sys/class/block/dm-1/dm/uuid": "LVM-abc\n",
			"sys/class/block/dm-1/slaves/dm-0/": "", "sys/class/block/dm-0/dm/uuid": "CRYPT-INTEGRITY-pv\n"}, "/dev/mapper/vg-root", "", false, ""},
		{"rd.luks cmdline", map[string]string{"proc/cmdline": "rd.luks.name=0123=root root=/dev/mapper/root rw\n"}, m1airRootSource, "", false, "rd.luks.name="},
		{"encrypt hook cmdline", map[string]string{"proc/cmdline": "cryptdevice=UUID=0123:root root=/dev/mapper/root rw\n"}, m1airRootSource, "", false, "cryptdevice="},
		{"crypttab", map[string]string{"etc/crypttab": "# comment\nhome UUID=0123 none luks\n"}, m1airRootSource, "", false, "unlocks home"},
		{"crypttab.initramfs", map[string]string{"etc/crypttab.initramfs": "root UUID=0123\n"}, m1airRootSource, "", false, "unlocks root"},
		{"swap with a random key", map[string]string{"etc/crypttab": "swap /dev/nvme0n1p7 /dev/urandom swap,cipher=aes-xts-plain64\n"}, m1airRootSource, "", false, ""},
		{"crypttab noauto", map[string]string{"etc/crypttab": "backup UUID=0123 none luks,noauto\n"}, m1airRootSource, "", false, ""},

		// a key file unlocks / with no one there
		{"LUKS root, key file in crypttab.initramfs", luksRoot(map[string]string{"etc/crypttab.initramfs": "root UUID=0123 /etc/cryptsetup-keys.d/root.key luks\n"}), luks, "", false, ""},
		{"LUKS root, key file in crypttab", luksRoot(map[string]string{"etc/crypttab": "root UUID=0123 /root.key luks,discard\n"}), luks, "", false, ""},
		{"LUKS root, cryptsetup-keys.d", luksRoot(map[string]string{"etc/crypttab.initramfs": "root UUID=0123 none luks\n",
			"etc/cryptsetup-keys.d/root.key": "k"}), luks, "", false, ""},
		{"LUKS root, crypttab keys another volume", luksRoot(map[string]string{"etc/crypttab.initramfs": "data UUID=0456 /data.key luks\n"}), luks, "", false,
			"/ is on dm-crypt: root unlocks with a passphrase"},
		{"LUKS root, rd.luks.key for every volume", luksRoot(map[string]string{"proc/cmdline": "rd.luks.name=0123=root rd.luks.key=/etc/root.key root=/dev/mapper/root rw\n"}), luks, "", false, ""},
		{"LUKS root, rd.luks.key for its UUID", luksRoot(map[string]string{"proc/cmdline": "rd.luks.name=0123=root rd.luks.key=0123=/root.key:UUID=4567 root=/dev/mapper/root\n"}), luks, "", false, ""},
		{"LUKS root, rd.luks.key for another UUID", luksRoot(map[string]string{"proc/cmdline": "rd.luks.name=0123=root rd.luks.key=0456=/data.key root=/dev/mapper/root\n"}), luks, "", false,
			"/ is on dm-crypt: root unlocks with a passphrase"},
		{"rd.luks.uuid keyed in crypttab.initramfs", map[string]string{"proc/cmdline": "rd.luks.uuid=luks-0123 root=/dev/mapper/root\n",
			"etc/crypttab.initramfs": "root UUID=0123 /root.key\n"}, m1airRootSource, "", false, ""},
		{"LUKS root, encrypt hook with cryptkey", luksRoot(map[string]string{"proc/cmdline": "cryptdevice=UUID=0123:root cryptkey=rootfs:/root.key root=/dev/mapper/root\n"}), luks, "", false, ""},
		{"LVM on LUKS, key file", map[string]string{"dev/dm-1": "", "sys/class/block/dm-1/dm/uuid": "LVM-abc\n", "sys/class/block/dm-1/slaves/dm-0/": "",
			"sys/class/block/dm-0/dm/uuid": "CRYPT-LUKS2-0123-cryptlvm\n", "sys/class/block/dm-0/dm/name": "cryptlvm\n",
			"etc/crypttab.initramfs": "cryptlvm UUID=0123 /crypto_keyfile.bin luks\n"}, "/dev/mapper/vg-root", "", false, ""},

		// nofail: boot goes on without it, unless / or /boot needs it
		{"nofail passphrase volume", map[string]string{"etc/crypttab": "home UUID=0123 none luks,nofail\n"}, m1airRootSource, "", false, ""},
		{"nofail passphrase volume, initramfs", map[string]string{"etc/crypttab.initramfs": "data UUID=0123 - nofail\n"}, m1airRootSource, "", false, ""},
		{"nofail passphrase volume holding /", luksRoot(map[string]string{"etc/crypttab": "root UUID=0123 none luks,nofail\n"}), luks, "", false,
			"/ is on dm-crypt: root unlocks with a passphrase"},
		{"nofail passphrase volume holding /boot", map[string]string{"dev/dm-2": "", "sys/class/block/dm-2/dm/uuid": "CRYPT-LUKS2-0789-boot\n",
			"sys/class/block/dm-2/dm/name": "boot\n", "etc/crypttab": "boot UUID=0789 none luks,nofail\n"}, m1airRootSource, "/dev/mapper/boot", false,
			"/boot is on dm-crypt: boot unlocks with a passphrase"},

		// GRUB unlocks /boot itself, key file or not
		{"GRUB, /boot on keyed LUKS", luksRoot(map[string]string{"etc/crypttab.initramfs": "root UUID=0123 /root.key luks\n"}), luks, "", true,
			"GRUB reads the kernels from /boot, which is on dm-crypt"},
		{"GRUB, keyed LUKS root, plain /boot", luksRoot(map[string]string{"etc/crypttab.initramfs": "root UUID=0123 /root.key luks\n"}), luks, "/dev/nvme0n1p5", true, ""},
	} {
		files := m1airRoot()
		for p, b := range c.files {
			files[p] = b
		}
		root := fakeRoot(t, files)
		// udev's /dev/mapper links are relative
		os.MkdirAll(filepath.Join(root, "dev/mapper"), 0o755)
		os.Symlink("../dm-0", filepath.Join(root, "dev/mapper/root"))
		os.Symlink("../dm-1", filepath.Join(root, "dev/mapper/vg-root"))
		os.Symlink("../dm-2", filepath.Join(root, "dev/mapper/boot"))
		var b bootloader = m1airLimine(root)
		if c.grub {
			b = &grubLayout{}
		}
		boot := c.boot
		if boot == "" {
			boot = c.source
		}
		hard, _ := unattendedProblems(root, b, c.source, boot)
		switch {
		case c.want == "" && len(hard) > 0:
			t.Errorf("%s: %q", c.name, hard)
		case c.want != "" && (len(hard) != 1 || !strings.Contains(hard[0], c.want) || !strings.Contains(hard[0], "passphrase")):
			t.Errorf("%s: %q, want %q", c.name, hard, c.want)
		}
	}
}

func TestUnattendedJournal(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		gone  []string // removed from the m1air's files
		want  string
	}{
		{"no /var/log/journal", nil, []string{"var/log/journal/"}, "no /var/log/journal"},
		{"Storage=persistent creates it", map[string]string{"etc/systemd/journald.conf": "[Journal]\nStorage=persistent\n"}, []string{"var/log/journal/"}, ""},
		{"Storage=volatile", map[string]string{"etc/systemd/journald.conf": "[Journal]\nStorage=volatile\n"}, nil, "Storage=volatile in /etc/systemd/journald.conf"},
		{"/usr/lib's journald.conf where /etc has none", map[string]string{"usr/lib/systemd/journald.conf": "[Journal]\nStorage=volatile\n"},
			[]string{"etc/systemd/journald.conf"}, "Storage=volatile in /usr/lib/systemd/journald.conf"},
		{"/etc's journald.conf hides /usr/lib's", map[string]string{"usr/lib/systemd/journald.conf": "[Journal]\nStorage=volatile\n"}, nil, ""},
		{"drop-in", map[string]string{"etc/systemd/journald.conf.d/50-ram.conf": "[Journal]\nStorage=none\n"}, nil, "Storage=none in /etc/systemd/journald.conf.d/50-ram.conf"},
		{"/usr/local/lib drop-in", map[string]string{"usr/local/lib/systemd/journald.conf.d/50-ram.conf": "[Journal]\nStorage=volatile\n"}, nil,
			"Storage=volatile in /usr/local/lib/systemd/journald.conf.d/50-ram.conf"},
		{"later drop-in wins", map[string]string{"usr/lib/systemd/journald.conf.d/10-ram.conf": "[Journal]\nStorage=volatile\n",
			"etc/systemd/journald.conf.d/20-disk.conf": "[Journal]\nStorage=persistent\n"}, nil, ""},
		{"/etc masks /usr/lib", map[string]string{"usr/lib/systemd/journald.conf.d/10-ram.conf": "[Journal]\nStorage=volatile\n",
			"etc/systemd/journald.conf.d/10-ram.conf": "[Journal]\n"}, nil, ""},
		{"an empty value resets it", map[string]string{"usr/lib/systemd/journald.conf.d/10-ram.conf": "[Journal]\nStorage=volatile\n",
			"etc/systemd/journald.conf.d/20-reset.conf": "[Journal]\nStorage=\n"}, nil, ""},
		{"a value journald doesn't know", map[string]string{"etc/systemd/journald.conf": "[Journal]\nStorage=Volatile\n"}, nil, ""},
		{"other section", map[string]string{"etc/systemd/journald.conf": "[Other]\nStorage=volatile\n"}, nil, ""},
	} {
		files := m1airRoot()
		for _, p := range c.gone {
			delete(files, p)
		}
		for p, b := range c.files {
			files[p] = b
		}
		root := fakeRoot(t, files)
		hard, warnings := unattendedProblems(root, m1airLimine(root), m1airRootSource, m1airRootSource)
		if len(hard) > 0 {
			t.Errorf("%s: hard %q", c.name, hard)
		}
		switch {
		case c.want == "" && len(warnings) > 0:
			t.Errorf("%s: %q", c.name, warnings)
		case c.want != "" && (len(warnings) != 1 || !strings.Contains(warnings[0], c.want) || !strings.Contains(warnings[0], "no logs")):
			t.Errorf("%s: %q, want %q", c.name, warnings, c.want)
		}
	}
}

func TestPersistJournal(t *testing.T) {
	const runtime = "run/log/journal/873f3249bd1a4ef38712b0fa73800436/system.journal"
	volatile := func() map[string]string {
		files := m1airRoot()
		delete(files, "var/log/journal/")
		files["etc/machine-id"] = "873f3249bd1a4ef38712b0fa73800436\n"
		files[runtime] = "" // this boot's journal, in /run
		return files
	}
	root := fakeRoot(t, volatile())
	if move, err := persistJournal(root, true); move || err != nil {
		t.Fatalf("--volatile-journal: move %v, %v", move, err)
	}
	if _, err := os.Stat(filepath.Join(root, journalCfg)); err == nil {
		t.Fatal("--volatile-journal wrote a drop-in")
	}
	if move, err := persistJournal(root, false); !move || err != nil {
		t.Fatalf("move %v, %v", move, err)
	}
	if _, warnings := unattendedProblems(root, m1airLimine(root), m1airRootSource, m1airRootSource); len(warnings) > 0 {
		t.Fatalf("after setup: %q", warnings)
	}
	conf, _ := os.ReadFile(filepath.Join(root, journalCfg))
	// Restarting journald failed: this boot's journal is still in /run, so
	// setup run again tries again.
	if move, err := persistJournal(root, false); !move || err != nil {
		t.Fatalf("again, journal still in /run: move %v, %v", move, err)
	}
	// It worked: journald moved the journal to /var/log/journal.
	os.Remove(filepath.Join(root, runtime))
	if move, err := persistJournal(root, false); move || err != nil {
		t.Fatalf("again, journal on disk: move %v, %v", move, err)
	}
	if again, _ := os.ReadFile(filepath.Join(root, journalCfg)); string(again) != string(conf) || !strings.Contains(string(conf), "\nStorage=persistent\n") {
		t.Fatalf("drop-in:\n%s", again)
	}

	// Already on disk: setup leaves journald alone, even before it moved
	// this boot's journal there.
	for _, files := range []map[string]string{m1airRoot(), {"etc/systemd/journald.conf": "[Journal]\nStorage=persistent\n"}} {
		files["etc/machine-id"] = "873f3249bd1a4ef38712b0fa73800436\n"
		files[runtime] = ""
		root := fakeRoot(t, files)
		if move, err := persistJournal(root, false); move || err != nil {
			t.Fatalf("persistent: move %v, %v", move, err)
		}
		if _, err := os.Stat(filepath.Join(root, journalCfg)); err == nil {
			t.Fatal("wrote a drop-in for a persistent journal")
		}
	}

	// A drop-in that sorts after the lab's still wins: say so.
	files := volatile()
	files["etc/systemd/journald.conf.d/99-ram.conf"] = "[Journal]\nStorage=volatile\n"
	if move, err := persistJournal(fakeRoot(t, files), false); move || err == nil || !strings.Contains(err.Error(), "99-ram.conf") {
		t.Fatalf("overridden: move %v, %v", move, err)
	}
}

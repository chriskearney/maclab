package agent

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// unattended lists what stops this Mac from rebooting into a lab kernel and
// back with no one at it. Setup refuses a Mac with any hard problem; the
// warnings lose evidence, not the Mac.
func unattended(b bootloader) (hard, warnings []string) {
	l, _ := b.(*limineLayout)
	m, _ := findMount("/")
	return unattendedProblems("/", l, m.Source)
}

// unattendedProblems reads everything under root ("/" except in tests), and
// on a Limine Mac (l set) Limine's binaries on the ESP. rootSource is
// findmnt's SOURCE for /, such as /dev/nvme0n1p6[/@].
func unattendedProblems(root string, l *limineLayout, rootSource string) (hard, warnings []string) {
	if l != nil {
		if why := l.enrollment(filepath.Join(root, "etc/default/limine")); why != "" {
			hard = append(hard, why)
		}
	}
	if why := encryptedRoot(root, rootSource); why != "" {
		hard = append(hard, "the disk is encrypted ("+why+"): every lab reboot would stop at the passphrase prompt")
	}
	if why := volatileJournal(root); why != "" {
		warnings = append(warnings, "the journal is not kept across reboots ("+why+"): a lab boot that fails takes its journal with it, "+
			"so labd collects no logs from it. lab-agent setup keeps it on disk unless given --volatile-journal")
	}
	return hard, warnings
}

// encryptedRoot says why booting needs a passphrase, or "" when it doesn't.
func encryptedRoot(root, rootSource string) string {
	if dev := strings.TrimSpace(reSubvol.ReplaceAllString(rootSource, "")); strings.HasPrefix(dev, "/dev/") {
		name := filepath.Base(dev)
		// /dev/mapper/<name> links to ../dm-N, the name sysfs knows it by
		if t, err := filepath.EvalSymlinks(filepath.Join(root, dev)); err == nil {
			name = filepath.Base(t)
		}
		if dmCrypt(filepath.Join(root, "sys/class/block"), name, 0) {
			return "/ is on dm-crypt"
		}
	}
	for _, f := range strings.Fields(readTrim(filepath.Join(root, "proc/cmdline"))) {
		for _, p := range []string{"cryptdevice=", "rd.luks.uuid=", "rd.luks.name=", "luks.uuid=", "luks.name="} {
			if strings.HasPrefix(f, p) {
				return f + " on the kernel cmdline"
			}
		}
	}
	for _, tab := range []string{"etc/crypttab", "etc/crypttab.initramfs"} {
		b, _ := os.ReadFile(filepath.Join(root, tab))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			// noauto: nothing unlocks it at boot
			if len(f) > 3 && slices.Contains(strings.Split(f[3], ","), "noauto") {
				continue
			}
			// a key file (/dev/urandom for swap, say) unlocks without anyone
			if len(f) < 3 || f[2] == "none" || f[2] == "-" {
				return "/" + tab + " unlocks " + f[0] + " with a passphrase"
			}
		}
	}
	return ""
}

// dmCrypt says whether block device name is, or sits on (LVM on LUKS), a
// dm-crypt mapping. cryptsetup's dm-verity and dm-integrity mappings carry
// the same CRYPT- prefix but take no key.
func dmCrypt(sysBlock, name string, depth int) bool {
	if depth > 8 {
		return false
	}
	uuid := readTrim(filepath.Join(sysBlock, name, "dm/uuid"))
	if strings.HasPrefix(uuid, "CRYPT-") && !strings.HasPrefix(uuid, "CRYPT-VERITY-") && !strings.HasPrefix(uuid, "CRYPT-INTEGRITY-") {
		return true
	}
	slaves, _ := os.ReadDir(filepath.Join(sysBlock, name, "slaves"))
	for _, s := range slaves {
		if dmCrypt(sysBlock, s.Name(), depth+1) {
			return true
		}
	}
	return false
}

// volatileJournal says why journald keeps nothing across a reboot, or "" when
// it does. Storage= comes from the first journald.conf found, then the drop-ins
// in name order, each name from the first directory that has it, as
// journald.conf(5) lists them.
func volatileJournal(root string) string {
	var confs []string
	for _, d := range []string{"etc", "run", "usr/local/lib", "usr/lib"} {
		c := filepath.Join(d, "systemd/journald.conf")
		if _, err := os.Stat(filepath.Join(root, c)); err == nil {
			confs = append(confs, c)
			break
		}
	}
	dropins := map[string]string{}
	for _, d := range []string{"usr/lib", "usr/local/lib", "run", "etc"} {
		files, _ := filepath.Glob(filepath.Join(root, d, "systemd/journald.conf.d/*.conf"))
		for _, f := range files {
			dropins[filepath.Base(f)] = filepath.Join(d, "systemd/journald.conf.d", filepath.Base(f))
		}
	}
	names := make([]string, 0, len(dropins))
	for n := range dropins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		confs = append(confs, dropins[n])
	}
	storage, from := "auto", ""
	for _, c := range confs {
		b, err := os.ReadFile(filepath.Join(root, c))
		if err != nil {
			continue
		}
		section := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || section != "[Journal]" || strings.TrimSpace(k) != "Storage" {
				continue
			}
			// journald ignores a value it doesn't know; an empty one resets it
			switch v = strings.TrimSpace(v); v {
			case "":
				storage, from = "auto", "/"+c
			case "auto", "volatile", "persistent", "none":
				storage, from = v, "/"+c
			}
		}
	}
	switch storage {
	case "volatile", "none":
		return "Storage=" + storage + " in " + from
	case "persistent":
		return ""
	}
	if st, err := os.Stat(filepath.Join(root, "var/log/journal")); err != nil || !st.IsDir() {
		return "no /var/log/journal"
	}
	return ""
}

// journalInRun says whether journald still keeps this boot's journal in
// /run/log/journal, as it does until it moves it to /var/log/journal.
func journalInRun(root string) bool {
	id := readTrim(filepath.Join(root, "etc/machine-id"))
	if id == "" {
		return false
	}
	files, _ := filepath.Glob(filepath.Join(root, "run/log/journal", id, "*.journal"))
	return len(files) > 0
}

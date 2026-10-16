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
	m, _ := findMount("/")
	bm, _ := findMount("/boot")
	return unattendedProblems("/", b, m.Source, bm.Source)
}

// unattendedProblems reads everything under root ("/" except in tests), and
// on a Limine Mac Limine's binaries on the ESP. rootSource and bootSource are
// findmnt's SOURCE for / and /boot, such as /dev/nvme0n1p6[/@].
func unattendedProblems(root string, b bootloader, rootSource, bootSource string) (hard, warnings []string) {
	if l, ok := b.(*limineLayout); ok {
		if why := l.enrollment(filepath.Join(root, "etc/default/limine")); why != "" {
			hard = append(hard, why)
		}
	}
	_, grub := b.(*grubLayout)
	if why := encryptedRoot(root, rootSource, bootSource, grub); why != "" {
		hard = append(hard, "the disk is encrypted ("+why+"): every lab reboot would stop at the passphrase prompt")
	}
	if why := volatileJournal(root); why != "" {
		warnings = append(warnings, "the journal is not kept across reboots ("+why+"): a lab boot that fails takes its journal with it, "+
			"so labd collects no logs from it. lab-agent setup keeps it on disk unless given --volatile-journal")
	}
	return hard, warnings
}

// cryptVolume is an encrypted volume the boot unlocks, as one place sets it up.
type cryptVolume struct {
	name    string // its /dev/mapper name; "" if unknown
	uuid    string // its LUKS UUID, lower case, if that place names one
	from    string // where: a crypttab, or a cmdline parameter
	cmdline bool   // the cmdline sets it up: the initramfs waits for it
	// initramfs: the initramfs sets it up, before / is mounted: the cmdline
	// names it, or crypttab.initramfs does. It never reads /etc/crypttab.
	initramfs bool
	encrypt   bool // the encrypt hook's cryptdevice=, which reads no crypttab
	keyed     bool // a key file unlocks it, with no one at the keyboard
	// early: a key file the initramfs can read before / is unlocked unlocks
	// it: crypttab.initramfs's, rd.luks.key='s or cryptkey='s, unless it is
	// on the encrypted / or /boot itself. Only such a key unlocks the volume
	// under / or /boot.
	early bool
	late  string // why the key file it has isn't such a key, if it isn't
	// nofail: boot carries on without it (crypttab's nofail)
	nofail bool
}

// encryptedRoot says why booting needs a passphrase, or "" when it doesn't.
// An encrypted volume that unlocks with a key file needs none. For the
// volume under / or /boot, the key file must be one the initramfs reads
// before / is unlocked: one its crypttab.initramfs line names, or
// rd.luks.key= or cryptkey= on the cmdline, and not on the encrypted / or
// /boot itself. /etc/crypttab's and /etc/cryptsetup-keys.d's are on / and
// read only once it is unlocked, and the initramfs reads neither, so they
// count only for other volumes. What waits for a passphrase is a volume the
// boot can't do without: /'s or /boot's, one the cmdline names, or one
// crypttab unlocks without nofail. Under GRUB, a /boot on dm-crypt needs one
// whatever unlocks it later: GRUB itself asks for it to read the kernel.
func encryptedRoot(root, rootSource, bootSource string, grub bool) string {
	sysBlock := filepath.Join(root, "sys/class/block")
	type under struct{ path, mapping string }
	var held []under            // the dm-crypt mappings / and /boot sit on
	needed := map[string]bool{} // their names
	for _, m := range []struct{ path, source string }{{"/", rootSource}, {"/boot", bootSource}} {
		dev := strings.TrimSpace(reSubvol.ReplaceAllString(m.source, ""))
		if !strings.HasPrefix(dev, "/dev/") {
			continue
		}
		maps := dmCrypt(sysBlock, blockName(root, dev), 0)
		if len(maps) > 0 && grub && m.path == "/boot" {
			return "GRUB reads the kernels from /boot, which is on dm-crypt, and asks for its passphrase itself"
		}
		for _, mapping := range maps {
			held = append(held, under{m.path, mapping})
			needed[mapping] = true
		}
	}
	vols := cryptVolumes(root, func(dev string) string {
		if dev == "" {
			return ""
		}
		if len(held) > 0 && held[0].path == "/" && dev == cmdlineValue(root, "root") {
			return held[0].mapping
		}
		for _, m := range dmCrypt(sysBlock, blockName(root, devPath(dev)), 0) {
			if needed[m] {
				return m
			}
		}
		return ""
	})
	// One volume may be set up in two places. sd-encrypt reads the cmdline's
	// rd.luks.* and crypttab.initramfs together, so either may give it its
	// key file; and an /etc/crypttab line for a volume the initramfs has
	// unlocked already needs nothing more. The initramfs never reads
	// /etc/crypttab, and the encrypt hook's cryptdevice= no crypttab at all.
	for i, c := range vols {
		for _, o := range vols {
			same := c.name != "" && o.name == c.name || c.uuid != "" && o.uuid == c.uuid
			if !same || c.initramfs && (c.encrypt || o.encrypt || !o.initramfs) {
				continue
			}
			vols[i].keyed = vols[i].keyed || o.keyed
			vols[i].early = vols[i].early || o.early
		}
	}
	for _, h := range held {
		if slices.ContainsFunc(vols, func(c cryptVolume) bool { return c.early && c.name == h.mapping }) {
			continue
		}
		why := h.path + " is on dm-crypt: " + h.mapping + " unlocks with a passphrase"
		if i := slices.IndexFunc(vols, func(c cryptVolume) bool { return c.late != "" && c.name == h.mapping }); i >= 0 {
			why += "; " + vols[i].late
		}
		return why
	}
	for _, c := range vols {
		if c.keyed || c.nofail && !c.cmdline && !needed[c.name] {
			continue
		}
		return c.from + " unlocks " + orUnknown(c.name) + " with a passphrase"
	}
	return ""
}

func orUnknown(name string) string {
	if name == "" {
		return "a volume"
	}
	return name
}

// blockName is sysfs's name for block device dev under root: /dev/mapper/<name>
// and /dev/disk/by-*/ link to ../dm-N, say.
func blockName(root, dev string) string {
	if t, err := filepath.EvalSymlinks(filepath.Join(root, dev)); err == nil {
		return filepath.Base(t)
	}
	return filepath.Base(dev)
}

// devPath is the /dev path of a device as fstab names it (UUID=, LABEL=,
// PARTUUID=, PARTLABEL= or a path).
func devPath(dev string) string {
	for _, by := range [][2]string{{"UUID=", "by-uuid"}, {"LABEL=", "by-label"}, {"PARTUUID=", "by-partuuid"}, {"PARTLABEL=", "by-partlabel"}} {
		if v, ok := strings.CutPrefix(dev, by[0]); ok {
			return "/dev/disk/" + by[1] + "/" + v
		}
	}
	return dev
}

// cmdlineValue is the value of the kernel cmdline's last key= under root.
func cmdlineValue(root, key string) string {
	v := ""
	for _, f := range strings.Fields(readTrim(filepath.Join(root, "proc/cmdline"))) {
		if val, ok := strings.CutPrefix(f, key+"="); ok {
			v = val
		}
	}
	return v
}

// cmdlineKey is a key file the cmdline gives: set, and the device it is on,
// "" for a file in the initramfs itself.
type cmdlineKey struct {
	set bool
	dev string
}

// cryptVolumes lists the encrypted volumes the cmdline and the crypttabs set
// up at boot, and whether a key file unlocks each. locked names the volume
// under / or /boot that dev ("" for the initramfs's own files) is on, so
// that a key file there can only be read once it is unlocked; "" if none.
func cryptVolumes(root string, locked func(dev string) string) []cryptVolume {
	cmdline := strings.Fields(readTrim(filepath.Join(root, "proc/cmdline")))
	// rd.luks.key=[<uuid>=]<file>[:<device>] gives one volume a key file, or
	// with no UUID every rd.luks.uuid/rd.luks.name one; cryptkey=<device>:...
	// (rootfs:<file> for the initramfs) gives the encrypt hook's cryptdevice=
	// one.
	var all, cryptkey cmdlineKey
	byUUID := map[string]cmdlineKey{}
	for _, f := range cmdline {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "rd.luks.key", "luks.key":
			if u, file, ok := strings.Cut(v, "="); ok && !strings.HasPrefix(v, "/") && file != "" {
				_, dev, _ := strings.Cut(file, ":")
				byUUID[luksUUID(u)] = cmdlineKey{true, dev}
			} else if v != "" {
				_, dev, _ := strings.Cut(v, ":")
				all = cmdlineKey{true, dev}
			}
		case "cryptkey":
			if dev, _, _ := strings.Cut(v, ":"); v != "" {
				if dev == "rootfs" {
					dev = ""
				}
				cryptkey = cmdlineKey{true, dev}
			}
		}
	}
	keyed := func(c *cryptVolume, k cmdlineKey, from string) {
		c.keyed = k.set
		if on := locked(k.dev); k.set && on != "" {
			c.late = from + "'s key file is on " + k.dev + ", which can't be read before " + on + " is unlocked"
		} else {
			c.early = k.set
		}
	}
	var vols []cryptVolume
	for _, f := range cmdline {
		k, v, _ := strings.Cut(f, "=")
		c := cryptVolume{from: f + " on the kernel cmdline", cmdline: true, initramfs: true}
		switch k {
		case "rd.luks.uuid", "luks.uuid":
			c.uuid = luksUUID(v)
			c.name = "luks-" + c.uuid
		case "rd.luks.name", "luks.name":
			u, name, _ := strings.Cut(v, "=")
			c.uuid, c.name = luksUUID(u), name
		case "cryptdevice": // <device>:<name>[:<options>]
			if _, rest, ok := strings.Cut(v, ":"); ok {
				c.name, _, _ = strings.Cut(rest, ":")
			}
			c.encrypt = true
			keyed(&c, cryptkey, "cryptkey=")
			vols = append(vols, c)
			continue
		default:
			continue
		}
		key, ok := byUUID[c.uuid]
		if !ok {
			key = all
		}
		keyed(&c, key, "rd.luks.key=")
		vols = append(vols, c)
	}
	for _, tab := range []string{"etc/crypttab", "etc/crypttab.initramfs"} {
		initramfs := tab == "etc/crypttab.initramfs"
		b, _ := os.ReadFile(filepath.Join(root, tab))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			var opts []string
			if len(f) > 3 {
				opts = strings.Split(f[3], ",")
			}
			// noauto: nothing unlocks it at boot
			if slices.Contains(opts, "noauto") {
				continue
			}
			c := cryptVolume{name: f[0], from: "/" + tab, initramfs: initramfs, nofail: slices.Contains(opts, "nofail")}
			if u, ok := strings.CutPrefix(f[1], "UUID="); ok {
				c.uuid = luksUUID(u)
			}
			// a key file (/dev/urandom for swap, say) unlocks without anyone,
			// from the initramfs when crypttab.initramfs names it; a
			// <file>:<device> one is on that device
			if len(f) > 2 && f[2] != "none" && f[2] != "-" {
				_, dev, _ := strings.Cut(f[2], ":")
				if initramfs {
					keyed(&c, cmdlineKey{true, dev}, "/"+tab)
				} else {
					c.keyed, c.late = true, "/etc/crypttab's key file counts only once / is unlocked, and the initramfs reads /etc/crypttab.initramfs"
				}
			}
			// without one, crypttab(5) looks for <name>.key in
			// cryptsetup-keys.d: the running system's, on / or in /run
			for _, d := range []string{"etc/cryptsetup-keys.d", "run/cryptsetup-keys.d"} {
				if !c.keyed && exists(filepath.Join(root, d, f[0]+".key")) {
					c.keyed, c.late = true, "/"+d+"/"+f[0]+".key counts only once / is unlocked: name a key file the initramfs holds in /etc/crypttab.initramfs"
				}
			}
			vols = append(vols, c)
		}
	}
	return vols
}

// luksUUID is a LUKS UUID as the cmdline or crypttab gives it, made comparable.
func luksUUID(u string) string {
	return strings.ToLower(strings.TrimPrefix(u, "luks-"))
}

// dmCrypt lists the dm-crypt mappings block device name is, or sits on (LVM
// on LUKS), by their /dev/mapper names (sysfs's dm-N where it has none).
// cryptsetup's dm-verity and dm-integrity mappings carry the same CRYPT-
// prefix but take no key.
func dmCrypt(sysBlock, name string, depth int) []string {
	if depth > 8 {
		return nil
	}
	uuid := readTrim(filepath.Join(sysBlock, name, "dm/uuid"))
	if strings.HasPrefix(uuid, "CRYPT-") && !strings.HasPrefix(uuid, "CRYPT-VERITY-") && !strings.HasPrefix(uuid, "CRYPT-INTEGRITY-") {
		if n := readTrim(filepath.Join(sysBlock, name, "dm/name")); n != "" {
			return []string{n}
		}
		return []string{name}
	}
	var maps []string
	slaves, _ := os.ReadDir(filepath.Join(sysBlock, name, "slaves"))
	for _, s := range slaves {
		maps = append(maps, dmCrypt(sysBlock, s.Name(), depth+1)...)
	}
	return maps
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

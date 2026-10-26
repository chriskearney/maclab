package esprotation

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

const bliGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// LiveEnv never enrolls, writes EFI variables, changes a default or probes a
// device. It uses the same two boot-partition locks and fixed order as agent.
func LiveEnv(work string) Env {
	return Env{Observe: func(p Plan) (Snapshot, error) { return observeLive(p, work) }, Space: StatSpace, Lock: bootLocks}
}
func bootLocks() (func(), error) {
	var held []*os.File
	unlock := func() {
		for i := len(held) - 1; i >= 0; i-- {
			syscall.Flock(int(held[i].Fd()), syscall.LOCK_UN)
			held[i].Close()
		}
	}
	deadline := time.Now().Add(time.Minute)
	for _, p := range []string{"/run/lock/boot-partition.lock", "/tmp/limine-global.lock"} {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0644)
		if err != nil {
			unlock()
			return nil, err
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			f.Close()
			unlock()
			return nil, errors.New("unsafe boot lock")
		}
		for {
			err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				break
			}
			if err != syscall.EWOULDBLOCK || time.Now().After(deadline) {
				f.Close()
				unlock()
				return nil, errors.New("boot lock timeout")
			}
			time.Sleep(200 * time.Millisecond)
		}
		held = append(held, f)
	}
	return unlock, nil
}
func efiRead(name string) ([]byte, error) {
	b, err := os.ReadFile("/sys/firmware/efi/efivars/" + name + "-" + bliGUID)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) < 4 || len(b) > 8192 {
		return nil, errors.New("invalid BLI variable")
	}
	return b, nil
}
func efiText(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	var u []uint16
	for i := 4; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
func observeLive(p Plan, work string) (Snapshot, error) {
	var s Snapshot
	s.Files = map[string]string{}
	if os.Geteuid() != 0 {
		return s, errors.New("lab-esp requires root")
	}
	if !filepath.IsAbs(p.ESP) || filepath.Clean(p.ESP) != p.ESP || !filepath.IsAbs(work) {
		return s, errors.New("unclean ESP/work path")
	}
	cfgBytes, err := ReadFile("/etc/maclab/agent.json", 1<<20)
	if err != nil {
		return s, err
	}
	var cfg struct {
		WorkDir string `json:"work_dir"`
	}
	if err = json.Unmarshal(cfgBytes, &cfg); err != nil {
		return s, err
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = "/var/lib/maclab"
	}
	if work != cfg.WorkDir {
		return s, errors.New("work-dir must match actual installed agent configuration")
	}
	s.Files["/etc/maclab/agent.json"] = Digest(cfgBytes)
	if p.Menu != filepath.Join(p.ESP, "limine.conf") && p.Menu != filepath.Join(p.ESP, "EFI/BOOT/limine.conf") && p.Menu != filepath.Join(p.ESP, "boot/limine/limine.conf") && p.Menu != filepath.Join(p.ESP, "boot/limine.conf") && p.Menu != filepath.Join(p.ESP, "limine/limine.conf") {
		return s, errors.New("unsupported menu location")
	}
	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return s, err
	}
	found := false
	mountSource := ""
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[1] == p.ESP && f[2] == "vfat" && !strings.Contains(f[3], "ro,") {
			found = true
			mountSource = f[0]
			s.Files["mount"] = Digest([]byte(line))
		}
	}
	if !found {
		return s, errors.New("ESP must be a directly mounted writable vfat filesystem")
	}
	part, err := efiRead("LoaderDevicePartUUID")
	if err != nil {
		return s, err
	}
	uuid := efiText(part)
	if len(uuid) != 36 || strings.ContainsAny(uuid, "/\\\x00") {
		return s, errors.New("booted ESP partition UUID required")
	}
	bootDevice, err := filepath.EvalSymlinks(filepath.Join("/dev/disk/by-partuuid", uuid))
	if err != nil {
		return s, err
	}
	mountedDevice, err := filepath.EvalSymlinks(mountSource)
	if err != nil || bootDevice != mountedDevice {
		return s, errors.New("mounted ESP is not BLI boot-device partition")
	}
	s.Files["BLI:LoaderDevicePartUUID"] = Digest(part)
	activeMenu := ""
	for _, rel := range []string{"EFI/BOOT/limine.conf", "boot/limine/limine.conf", "boot/limine.conf", "limine/limine.conf", "limine.conf"} {
		path := filepath.Join(p.ESP, rel)
		if _, e := os.Lstat(path); e == nil {
			activeMenu = path
			break
		} else if !os.IsNotExist(e) {
			return s, e
		}
	}
	if activeMenu != p.Menu {
		return s, errors.New("provided menu is not first Limine config location")
	}
	sp, err := StatSpace(p.ESP)
	if err != nil {
		return s, err
	}
	s.ESPDevice = sp.Device
	for path, dst := range map[string]*string{"/etc/machine-id": &s.Machine, "/proc/sys/kernel/random/boot_id": &s.Boot, "/proc/sys/kernel/osrelease": &s.Kernel} {
		b, e := os.ReadFile(path)
		if e != nil {
			return s, e
		}
		*dst = strings.TrimSpace(string(b))
		if *dst == "" {
			return s, errors.New("missing live identity")
		}
	}
	cmd, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return s, err
	}
	for _, v := range strings.Fields(string(cmd)) {
		if strings.HasPrefix(v, "maclab.job=") {
			return s, errors.New("lab boot is protected; no rotation during a job")
		}
	}
	s.Files["/proc/cmdline"] = Digest(cmd)
	info, err := efiRead("LoaderInfo")
	if err != nil {
		return s, err
	}
	version := efiText(info)
	if version != "Limine 12.9.0" && version != "Limine 12.9.3" {
		return s, errors.New("unreviewed Limine BLI ID contract")
	}
	s.Files["BLI:LoaderInfo"] = Digest(info)
	for _, name := range []string{"LoaderEntrySelected", "LoaderEntryDefault", "LoaderEntryOneShot"} {
		b, e := efiRead(name)
		if e != nil {
			return s, e
		}
		s.Files["BLI:"+name] = Digest(b)
		if name == "LoaderEntryOneShot" && efiText(b) != "" {
			return s, errors.New("armed one-shot protected")
		}
		if name == "LoaderEntryDefault" && efiText(b) == entryID(p.Entry) {
			return s, errors.New("BLI default entry is protected")
		}
		if name == "LoaderEntrySelected" {
			if efiText(b) == "" {
				return s, errors.New("selected BLI entry required")
			}
			if efiText(b) == entryID(p.Entry) {
				return s, errors.New("current selected entry is protected")
			}
		}
	}
	// Any local pending job workspace is conservatively active. Never use a
	// stale controller list as permission to retire a possible in-flight entry.
	jobs, err := os.ReadDir(filepath.Join(work, "jobs"))
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	if len(jobs) > 0 {
		return s, errors.New("local job workspace exists; finish supported cleanup before rotation")
	}
	for _, name := range []string{"known-good.json", "known-good.json.prev"} {
		path := filepath.Join(work, name)
		b, e := ReadFile(path, 1<<20)
		if os.IsNotExist(e) && name == "known-good.json.prev" {
			s.Files[path] = "absent"
			continue
		}
		if e != nil {
			return s, e
		}
		var kg struct {
			Kernel string `json:"kernel"`
		}
		if e = json.Unmarshal(b, &kg); e != nil || kg.Kernel == "" {
			return s, errors.New("invalid known-good record")
		}
		if p.Kind == "uki-leaf" && kg.Kernel == p.Kernel {
			return s, fmt.Errorf("%s kernel is protected", name)
		}
		s.Files[path] = Digest(b)
	}
	for _, path := range []string{filepath.Join(p.ESP, "EFI/BOOT/BOOTAA64.EFI"), filepath.Join(p.ESP, "EFI/limine/limine_aa64.efi"), "/etc/default/limine"} {
		b, e := ReadFile(path, 16<<20)
		if os.IsNotExist(e) && strings.Contains(path, "limine_aa64") {
			s.Files[path] = "absent"
			continue
		}
		if e != nil {
			return s, e
		}
		s.Files[path] = Digest(b)
		marker := []byte("++CONFIG_B2SUM_SIGNATURE++")
		if path != "/etc/default/limine" && !bytes.Contains(b, marker) {
			return s, errors.New("unknown loader checksum contract")
		}
		if i := bytes.Index(b, marker); i >= 0 {
			off := i + len(marker)
			if len(b) < off+128 || !bytes.Equal(b[off:off+128], bytes.Repeat([]byte("0"), 128)) {
				return s, errors.New("enrolled menu checksum prevents retirement")
			}
		}
		if path == "/etc/default/limine" {
			for _, line := range strings.Split(string(b), "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
				if ok && strings.TrimSpace(k) == "ENABLE_ENROLL_LIMINE_CONFIG" && strings.Trim(strings.TrimSpace(v), "\"") != "no" {
					return s, errors.New("Limine enrollment setting must explicitly be no or absent")
				}
			}
		}
	}
	// Protect the running boot payload and all explicit fallback copies. The only
	// permitted backup retirement name is disjoint from these protected names.
	for _, rel := range []string{"m1n1/boot.bin", "m1n1/boot.bin.old", "boot.bin"} {
		path := filepath.Join(p.ESP, rel)
		h, e := HashFile(path, MaxUKI)
		if os.IsNotExist(e) && rel != "m1n1/boot.bin" {
			s.Files[path] = "absent"
			continue
		}
		if e != nil {
			return s, e
		}
		s.Files[path] = h.SHA256
	}
	// Reopen every OTHER live menu resource, protect all of them byte-for-byte.
	// The retired target is guarded separately and is absent during restore.
	entries, def, err := parseMenu(p.Before)
	if err != nil {
		return s, err
	}
	defaultFound := false
	for _, ent := range entries {
		if strings.TrimPrefix(ent.Name, "/") == def || ent.ID == def {
			defaultFound = true
		}
		if ent.Resource == "" {
			continue
		}
		path, e := resourcePath(p.ESP, ent.Resource)
		if e != nil {
			return s, e
		}
		if path == p.UKI {
			continue
		}
		h, e := HashFile(path, MaxUKI)
		if e != nil {
			return s, e
		}
		s.Files[path] = h.SHA256
	}
	if !defaultFound {
		return s, errors.New("named default must resolve uniquely")
	}
	// Preserve mutable U-Boot store by exact bytes while applying; restore
	// observes but never rolls back legitimate post-boot variable state.
	for _, name := range []string{"ubootefi.var", "EFI/BOOT/ubootefi.var"} {
		path := filepath.Join(p.ESP, name)
		b, e := ReadFile(path, 4<<20)
		if os.IsNotExist(e) {
			s.Files["mutable-store:"+path] = "absent"
			continue
		}
		if e != nil {
			return s, e
		}
		s.Files["mutable-store:"+path] = Digest(b)
	}
	return s, nil
}

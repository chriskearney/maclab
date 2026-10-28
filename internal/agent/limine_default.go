package agent

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// LimineDefaultOptions is an explicit CAS on an existing, currently booted UKI.
// It neither installs a kernel nor changes the lab's qualification references.
type LimineDefaultOptions struct {
	ExpectedMenuSHA256 string
	ExpectedDefault    string
	Entry              string
	ExpectedUKISHA256  string
	ExpectedKernel     string
	Transaction        string // required for apply; original menu receipt is create-only
	DryRun             bool
}

type LimineDefaultResult struct {
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256"`
	Kernel       string `json:"kernel"`
	Entry        string `json:"entry"`
	EntryID      string `json:"entry_id"`
	UKISHA256    string `json:"uki_sha256"`
	Receipt      string `json:"receipt,omitempty"`
	DryRun       bool   `json:"dry_run"`
	Verified     bool   `json:"verified"`
}

type defaultObservation struct{ BootID, Kernel, Cmdline, Selected string }
type defaultEntry struct {
	name, canonical, protocol, resource, cmdline string
	depth                                        int
}

// SetLimineDefault changes only the named global default option. Apply takes
// the same two locks as staging, retains original bytes durably, then rereads
// identity, UKI and menu before writing. Dry-run changes no files or EFI vars;
// it is only an observation and apply always revalidates under the locks.
func (l *Linux) SetLimineDefault(o LimineDefaultOptions) (*LimineDefaultResult, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("setting the Limine default requires root, including dry-run")
	}
	b, err := detectLimine()
	if err != nil {
		return nil, err
	}
	observe := func() (defaultObservation, error) {
		boot, k, cmd := l.Identity()
		_, data, err := readEfivar("LoaderEntrySelected", bliGUID)
		if err != nil {
			return defaultObservation{}, fmt.Errorf("selected entry: %w", err)
		}
		return defaultObservation{boot, k, cmd, fromUTF16z(data)}, nil
	}
	if !o.DryRun {
		unlock, err := lockBootPartition(time.Minute)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}
	if err := defaultCASEnrollmentSafe("/etc/default/limine", []string{b.Loader, filepath.Join(b.ESP.Target, "EFI/limine/limine_aa64.efi")}); err != nil {
		return nil, err
	}
	return l.setLimineDefault(b, o, "/usr/lib/modules", observe, writeSynced)
}

func (l *Linux) setLimineDefault(b *limineLayout, o LimineDefaultOptions, moduleRoot string, observe func() (defaultObservation, error), write func(string, []byte) error) (*LimineDefaultResult, error) {
	if !lowerHex(o.ExpectedMenuSHA256, 64) || !lowerHex(o.ExpectedUKISHA256, 64) || o.ExpectedKernel == "" || strings.ContainsAny(o.ExpectedKernel, "/\x00\r\n") {
		return nil, errors.New("exact lowercase menu/UKI SHA256 and kernel release are required")
	}
	if !o.DryRun && (o.Transaction == "" || strings.ContainsAny(o.Transaction, "/. \\:\x00\r\n")) {
		return nil, errors.New("apply needs a unique plain transaction name")
	}
	before, err := readRegular(b.Conf)
	if err != nil {
		return nil, err
	}
	current, err := observe()
	if err != nil {
		return nil, err
	}
	out, result, err := planLimineDefault(before, b.ESP.Target, moduleRoot, o, current)
	if err != nil {
		return nil, err
	}
	if o.DryRun {
		return result, nil
	}
	dir := filepath.Join(l.WorkDir, "default-transactions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if _, err := noSymlinkPath(dir); err != nil {
		return nil, err
	}
	receipt := filepath.Join(dir, o.Transaction+".json")
	payload, _ := json.MarshalIndent(struct {
		State        string               `json:"state"`
		OriginalMenu []byte               `json:"original_menu"`
		Result       *LimineDefaultResult `json:"planned_change"`
	}{"prepared; verify menu readback before assuming committed", before, result}, "", "  ")
	if err := writeDefaultReceipt(receipt, payload); err != nil {
		return nil, fmt.Errorf("preserve original menu: %w", err)
	}
	result.Receipt = receipt
	// The receipt is not permission to write stale state. Recheck immediately
	// before mutation even though cooperative boot writers are locked out.
	again, err := readRegular(b.Conf)
	if err != nil {
		return nil, err
	}
	now, err := observe()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(before, again) || now != current {
		return nil, fmt.Errorf("menu or running boot changed; original retained at %s", receipt)
	}
	checked, _, err := planLimineDefault(again, b.ESP.Target, moduleRoot, o, now)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(checked, out) {
		return nil, errors.New("default plan changed")
	}
	final, err := readRegular(b.Conf)
	if err != nil {
		return nil, err
	}
	last, err := observe()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(final, before) || last != current {
		return nil, fmt.Errorf("menu or boot drifted before write; original at %s", receipt)
	}
	if err := write(b.Conf, out); err != nil {
		return nil, fmt.Errorf("default write not confirmed; inspect menu before retry; original at %s: %w", receipt, err)
	}
	got, err := readRegular(b.Conf)
	if err != nil || !bytes.Equal(got, out) {
		return nil, fmt.Errorf("default readback failed; do not retry blindly; original at %s", receipt)
	}
	result.Verified = true
	return result, nil
}

func writeDefaultReceipt(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return syncFile(filepath.Dir(p))
}
func lowerHex(s string, n int) bool { return len(s) == n && strings.Trim(s, "0123456789abcdef") == "" }
func digest(b []byte) string        { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func noSymlinkPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if real != abs {
		return "", fmt.Errorf("refusing symlink in %s", p)
	}
	return abs, nil
}
func readRegular(p string) ([]byte, error) {
	if _, err := noSymlinkPath(p); err != nil {
		return nil, err
	}
	s, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !s.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not regular", p)
	}
	return os.ReadFile(p)
}

func planLimineDefault(conf []byte, esp, moduleRoot string, o LimineDefaultOptions, cur defaultObservation) ([]byte, *LimineDefaultResult, error) {
	if digest(conf) != o.ExpectedMenuSHA256 {
		return nil, nil, errors.New("menu SHA256 changed")
	}
	if cur.Kernel != o.ExpectedKernel || cur.BootID == "" || jobTag(cur.Cmdline) != "" {
		return nil, nil, errors.New("target must be the expected currently running non-lab boot")
	}
	entries, start, end, old, err := parseDefaultMenu(conf)
	if err != nil {
		return nil, nil, err
	}
	if old != o.ExpectedDefault {
		return nil, nil, errors.New("default entry changed")
	}
	var target *defaultEntry
	for i := range entries {
		e := &entries[i]
		if e.depth == 1 && e.name == o.Entry {
			target = e
		}
	}
	if target == nil || strings.HasPrefix(target.name, entryPrefix) || target.protocol != "efi" || target.cmdline != "" {
		return nil, nil, errors.New("target must be an existing top-level non-lab EFI entry without a cmdline override")
	}
	id := limineBaseID(target.canonical)
	if cur.Selected != id {
		return nil, nil, fmt.Errorf("selected entry %q is not target %q", cur.Selected, id)
	}
	file, pin, err := defaultUKIPath(esp, target.resource)
	if err != nil {
		return nil, nil, err
	}
	if _, err := noSymlinkPath(file); err != nil {
		return nil, nil, err
	}
	st, err := os.Lstat(file)
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, errors.New("UKI must be a regular file")
	}
	sum, err := fileSHA256(file)
	if err != nil {
		return nil, nil, err
	}
	if sum != o.ExpectedUKISHA256 {
		return nil, nil, errors.New("UKI SHA256 changed")
	}
	b2, err := fileBlake2b(file)
	if err != nil {
		return nil, nil, err
	}
	if b2 != pin {
		return nil, nil, errors.New("UKI does not match the entry's BLAKE2b pin")
	}
	if err := currentUKI(file, moduleRoot, cur); err != nil {
		return nil, nil, err
	}
	out := append([]byte(nil), conf[:start]...)
	out = append(out, o.Entry...)
	out = append(out, conf[end:]...)
	result := &LimineDefaultResult{BeforeSHA256: digest(conf), AfterSHA256: digest(out), Kernel: cur.Kernel, Entry: o.Entry, EntryID: id, UKISHA256: sum, DryRun: o.DryRun}
	return out, result, nil
}

// This deliberately supports one literal global named default and existing
// menu entries only. Reject ambiguity instead of reproducing a full loader.
func parseDefaultMenu(conf []byte) (entries []defaultEntry, start, end int, old string, err error) {
	if bytes.IndexByte(conf, 0) >= 0 {
		return nil, 0, 0, "", errors.New("NUL in menu")
	}
	defaults := 0
	offset := 0
	seenEntry := false
	stack := []string{}
	ids := map[string]bool{}
	for _, raw := range bytes.SplitAfter(conf, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if strings.HasPrefix(line, "/") {
			seenEntry = true
			depth := len(line) - len(strings.TrimLeft(line, "/"))
			name := strings.TrimLeft(strings.TrimLeft(line, "/"), "+")
			name = strings.TrimLeft(name, " ")
			if name == "" || strings.ContainsAny(name, "\r\n") || depth > len(stack)+1 {
				return nil, 0, 0, "", errors.New("unsupported menu hierarchy")
			}
			stack = append(stack[:depth-1], name)
			canonical := "/" + strings.Join(stack, "/")
			id := limineBaseID(canonical)
			if ids[id] {
				return nil, 0, 0, "", fmt.Errorf("ambiguous normalized entry ID %q", id)
			}
			ids[id] = true
			entries = append(entries, defaultEntry{name: name, canonical: canonical, depth: depth})
		} else if line != "" && !strings.HasPrefix(line, "#") {
			key, val, ok := strings.Cut(line, ":")
			key = strings.ToLower(strings.TrimSpace(key))
			val = strings.TrimSpace(val)
			if ok && key == "default_entry" {
				defaults++
				if seenEntry || defaults != 1 || val == "" || strings.ContainsAny(val, "\x00\r\n#/") {
					return nil, 0, 0, "", errors.New("need exactly one literal global named default_entry")
				}
				colon := bytes.IndexByte(raw, ':')
				s := colon + 1
				for s < len(raw) && (raw[s] == ' ' || raw[s] == '\t') {
					s++
				}
				e := len(raw)
				for e > s && strings.ContainsRune(" \t\r\n", rune(raw[e-1])) {
					e--
				}
				start, end, old = offset+s, offset+e, val
			} else if ok && len(entries) > 0 {
				e := &entries[len(entries)-1]
				switch key {
				case "protocol":
					if e.protocol != "" {
						return nil, 0, 0, "", errors.New("duplicate protocol")
					}
					e.protocol = val
				case "path":
					if e.resource != "" {
						return nil, 0, 0, "", errors.New("duplicate path")
					}
					e.resource = val
				case "cmdline":
					if e.cmdline != "" {
						return nil, 0, 0, "", errors.New("duplicate cmdline")
					}
					e.cmdline = val
				}
			}
		}
		offset += len(raw)
	}
	if defaults != 1 {
		return nil, 0, 0, "", errors.New("need one explicit default_entry")
	}
	return
}

// Limine v12.9.3 common/menu.c: BLI_ID_MAX=256, 24 reserved for suffix;
// slash becomes '.', other bytes outside [a-zA-Z0-9+_.@-] become '-'. We
// reject base-ID collisions rather than rely on menu-order duplicate suffixes.
func limineBaseID(canonical string) string {
	b := []byte(strings.TrimPrefix(canonical, "/"))
	out := make([]byte, 0, 232)
	for _, c := range b {
		if len(out) == 232 {
			break
		}
		switch {
		case c == '/':
			out = append(out, '.')
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+_.@-", rune(c)):
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	s := string(out)
	if s == "" || s == "." || s == ".." {
		s += "-"
	}
	return s
}
func defaultUKIPath(esp, resource string) (string, string, error) {
	p, pin, ok := strings.Cut(resource, "#")
	if !ok || !lowerHex(pin, 128) || !strings.HasPrefix(p, "boot():/") {
		return "", "", errors.New("target requires a pinned boot(): UKI resource")
	}
	rel := strings.TrimPrefix(p, "boot():/")
	if rel == "" || strings.ContainsAny(rel, "\\\x00\r\n:#") || path.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return "", "", errors.New("unsafe UKI resource path")
	}
	return filepath.Join(esp, filepath.FromSlash(rel)), pin, nil
}
func currentUKI(file, moduleRoot string, cur defaultObservation) error {
	p, err := pe.Open(file)
	if err != nil {
		return fmt.Errorf("UKI PE: %w", err)
	}
	defer p.Close()
	h, ok := p.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || p.Machine != pe.IMAGE_FILE_MACHINE_ARM64 || h.Subsystem != pe.IMAGE_SUBSYSTEM_EFI_APPLICATION {
		return errors.New("target is not an ARM64 EFI UKI")
	}
	sections := map[string]*pe.Section{}
	for _, s := range p.Sections {
		if _, found := sections[s.Name]; found {
			return errors.New("duplicate UKI section")
		}
		sections[s.Name] = s
	}
	text := func(name string) (string, error) {
		s := sections[name]
		if s == nil || s.VirtualSize == 0 || s.VirtualSize > 1<<20 || s.VirtualSize > s.Size {
			return "", fmt.Errorf("invalid %s section", name)
		}
		b, err := io.ReadAll(io.LimitReader(s.Open(), int64(s.VirtualSize)))
		return strings.TrimRight(string(b), "\x00\r\n"), err
	}
	uname, err := text(".uname")
	if err != nil {
		return err
	}
	if uname != cur.Kernel {
		return errors.New("UKI .uname does not match running kernel")
	}
	cmd, err := text(".cmdline")
	if err != nil {
		return err
	}
	if jobTag(cmd) != "" || strings.Join(strings.Fields(cmd), " ") != strings.Join(strings.Fields(cur.Cmdline), " ") {
		return errors.New("UKI command line does not match running non-lab boot")
	}
	linux := sections[".linux"]
	initrd := sections[".initrd"]
	if linux == nil || initrd == nil || linux.VirtualSize == 0 || linux.VirtualSize > linux.Size || initrd.VirtualSize == 0 || initrd.VirtualSize > initrd.Size {
		return errors.New("UKI lacks valid kernel/initrd sections")
	}
	image := filepath.Join(moduleRoot, cur.Kernel, "vmlinuz")
	// A recovery image must have usable module-side kernel bytes too. The
	// caller's UKI/selected identity check is not a package promotion.
	if _, err := noSymlinkPath(image); err != nil {
		return err
	}
	expected, err := fileSHA256(image)
	if err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, linux.Open(), int64(linux.VirtualSize)); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("UKI .linux differs from running kernel's vmlinuz")
	}
	return nil
}

// Keep this check local to the additive command so it also layers onto the
// deployed older agent source. It never resets/enrolls a loader. A config
// checksum enrollment would make a default-only menu change unbootable.
func defaultCASEnrollmentSafe(defaults string, loaders []string) error {
	data, err := os.ReadFile(defaults)
	if err != nil {
		return err
	}
	enabled := false
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "ENABLE_ENROLL_LIMINE_CONFIG" {
			value = strings.TrimSpace(value)
			value = strings.TrimPrefix(strings.TrimSuffix(value, "\""), "\"")
			enabled = value == "yes"
		}
	}
	if enabled {
		return errors.New("config enrollment enabled; refusing to change default")
	}
	const signature = "++CONFIG_B2SUM_SIGNATURE++"
	for i, file := range loaders {
		bin, err := os.ReadFile(file)
		if os.IsNotExist(err) && i > 0 {
			continue
		}
		if err != nil {
			return err
		}
		slot := bytes.Index(bin, []byte(signature))
		if slot < 0 || len(bin) < slot+len(signature)+128 {
			return fmt.Errorf("cannot verify config enrollment slot in %s", file)
		}
		if !bytes.Equal(bin[slot+len(signature):slot+len(signature)+128], bytes.Repeat([]byte("0"), 128)) {
			return fmt.Errorf("%s has an enrolled config checksum; refusing default change", file)
		}
	}
	return nil
}

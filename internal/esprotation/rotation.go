// Package esprotation implements explicit, reversible UKI retirement. It never
// discovers deletion candidates, promotes a kernel, changes a default or boots.
package esprotation

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const Reserve uint64 = 120 << 20
const Metadata uint64 = 1 << 20
const MaxUKI int64 = 512 << 20
const Version = 1

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var plain = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`)

type File struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Snapshot struct {
	Machine   string            `json:"machine"`
	Boot      string            `json:"boot"`
	Kernel    string            `json:"kernel"`
	ESPDevice uint64            `json:"esp_device"`
	Files     map[string]string `json:"files"`
}
type Plan struct {
	Version                int       `json:"version"`
	Kind                   string    `json:"kind"`
	RetireOnly             bool      `json:"retire_only"`
	Transaction            string    `json:"transaction"`
	ESP                    string    `json:"esp"`
	Menu                   string    `json:"menu"`
	Entry                  string    `json:"entry"`
	UKI                    string    `json:"uki"`
	Kernel                 string    `json:"kernel"`
	File                   File      `json:"file"`
	Before                 []byte    `json:"before_menu"`
	After                  []byte    `json:"after_menu"`
	Snapshot               Snapshot  `json:"snapshot"`
	AdditionalESPBytes     uint64    `json:"additional_esp_bytes"`
	NextUKIBytes           uint64    `json:"next_uki_bytes"`
	NextESPTemporaryCopies uint64    `json:"next_esp_temporary_copies"`
	Created                time.Time `json:"created"`
}
type Retention struct {
	Version    int       `json:"version"`
	PlanSHA256 string    `json:"plan_sha256"`
	Controller string    `json:"controller"`
	File       File      `json:"file"`
	Path       string    `json:"path"`
	Verified   time.Time `json:"verified"`
}
type Space struct{ Available, Unit, Device uint64 }
type Env struct {
	Observe func(Plan) (Snapshot, error)
	Space   func(string) (Space, error)
	Lock    func() (func(), error)
	Now     func() time.Time
	// Fault is used by deterministic interruption tests; production leaves nil.
	Fault func(string) error
}

func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func JSON(v any) []byte {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		panic(e)
	}
	return append(b, '\n')
}
func PlanHash(p Plan) string { return Digest(JSON(p)) }
func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}
func (e Env) fault(s string) error {
	if e.Fault != nil {
		return e.Fault(s)
	}
	return nil
}
func sameInode(a, b os.FileInfo) bool {
	aa, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	bb, ok := b.Sys().(*syscall.Stat_t)
	return ok && aa.Dev == bb.Dev && aa.Ino == bb.Ino && a.Mode().IsRegular() && b.Mode().IsRegular()
}
func stableInfo(a, b os.FileInfo) bool {
	if !sameInode(a, b) {
		return false
	}
	aa := a.Sys().(*syscall.Stat_t)
	bb := b.Sys().(*syscall.Stat_t)
	return aa.Size == bb.Size && aa.Mtim == bb.Mtim && aa.Ctim == bb.Ctim && aa.Mode == bb.Mode
}
func regular(path string) (*os.File, error) { return regularWithOpen(path, os.OpenFile) }

// O_PATH obtains a typed reference WITHOUT opening a device/FIFO for data.
// Only after REG admission do we reopen that exact held inode via procfs.
func regularWithOpen(path string, dataOpen func(string, int, os.FileMode) (*os.File, error)) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("need clean absolute file path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	at := "/"
	for i, p := range parts {
		at = filepath.Join(at, p)
		st, err := os.Lstat(at)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink refused: %s", at)
		}
		if i < len(parts)-1 && !st.IsDir() {
			return nil, errors.New("non-directory ancestor")
		}
	}
	held, err := os.OpenFile(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer held.Close()
	typed, err := held.Stat()
	if err != nil || !typed.Mode().IsRegular() {
		return nil, errors.New("not a regular file; no data-open attempted")
	}
	f, err := dataOpen(fmt.Sprintf("/proc/self/fd/%d", held.Fd()), os.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	named, pe := os.Lstat(path)
	if err != nil || pe != nil || !stableInfo(typed, opened) || !stableInfo(opened, named) {
		f.Close()
		return nil, errors.New("regular path/inode changed before read")
	}
	return f, nil
}

func HashFile(path string, max int64) (File, error) {
	f, err := regular(path)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || before.Size() < 0 || before.Size() > max {
		return File{}, errors.New("file size refused")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, max+1))
	if err != nil {
		return File{}, err
	}
	after, err := f.Stat()
	named, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || n != before.Size() || after.Size() != n || !stableInfo(before, after) || !stableInfo(after, named) {
		return File{}, errors.New("file changed during read")
	}
	return File{hex.EncodeToString(h.Sum(nil)), n}, nil
}
func ReadFile(path string, max int64) ([]byte, error) {
	f, err := regular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("oversize file")
	}
	return b, err
}
func StatSpace(path string) (Space, error) {
	var fs syscall.Statfs_t
	var st syscall.Stat_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return Space{}, err
	}
	if err := syscall.Stat(path, &st); err != nil {
		return Space{}, err
	}
	if fs.Bsize <= 0 {
		return Space{}, errors.New("bad allocation unit")
	}
	return Space{uint64(fs.Bavail) * uint64(fs.Bsize), uint64(fs.Bsize), uint64(st.Dev)}, nil
}

// copies counts simultaneous NEW ESP UKI allocations. Replacing an existing UKI
// still needs a full new temp. Root-private build then one temp => 1, whereas a
// separate staged copy plus generator .tmp => 2. Existing files are never credit.
func Required(size, unit, copies uint64) (uint64, error) {
	max := ^uint64(0)
	if size == 0 || size > uint64(MaxUKI) || unit == 0 || copies < 1 || copies > 2 || size > max-(unit-1) {
		return 0, errors.New("invalid UKI peak")
	}
	rounded := (size + unit - 1) / unit * unit
	if rounded > (max-Reserve-Metadata)/copies {
		return 0, errors.New("capacity overflow")
	}
	return Reserve + Metadata + rounded*copies, nil
}

// RequiredPlan includes distinct extra live allocations (for example an old6
// fallback) separately rather than multiplying differently sized UKIs.
func RequiredPlan(p Plan, unit uint64) (uint64, error) {
	n, err := Required(p.NextUKIBytes, unit, p.NextESPTemporaryCopies)
	if err != nil {
		return 0, err
	}
	if p.AdditionalESPBytes == 0 {
		return n, nil
	}
	if p.AdditionalESPBytes > uint64(MaxUKI)*2 || unit == 0 || p.AdditionalESPBytes > ^uint64(0)-(unit-1) {
		return 0, errors.New("invalid additional ESP budget")
	}
	extra := (p.AdditionalESPBytes + unit - 1) / unit * unit
	if n > ^uint64(0)-extra {
		return 0, errors.New("combined peak overflow")
	}
	return n + extra, nil
}

func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func privateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid private directory")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	at := "/"
	for _, p := range parts {
		at = filepath.Join(at, p)
		s, e := os.Lstat(at)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe archive directory")
		}
	}
	s, e := os.Stat(path)
	if e != nil {
		return e
	}
	st := s.Sys().(*syscall.Stat_t)
	if st.Uid != uint32(os.Geteuid()) || s.Mode().Perm()&0077 != 0 {
		return errors.New("archive directory must be private and owned by invoking uid")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return err
	}
	if uint64(fs.Type) == 0x01021994 || uint64(fs.Type) == 0x858458f6 {
		return errors.New("recovery archives must not be on tmpfs/ramfs")
	}
	for dir := path; ; dir = filepath.Dir(dir) {
		if err := syncDir(dir); err != nil {
			return err
		}
		if dir == "/" {
			break
		}
	}
	return nil
}
func exclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func atomic(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".lab-esp-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func copyVerified(src, dst string, want File) error {
	f, e := regular(src)
	if e != nil {
		return e
	}
	defer f.Close()
	out, e := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(f, want.Size+1))
	if e == nil && (n != want.Size || hex.EncodeToString(h.Sum(nil)) != want.SHA256) {
		e = errors.New("source changed during copy")
	}
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = syncDir(filepath.Dir(dst)); e != nil {
		return e
	}
	got, e := HashFile(dst, MaxUKI)
	if e != nil || got != want {
		return errors.New("retained copy readback mismatch")
	}
	return nil
}
func UKIKernel(path string) (string, error) {
	f, e := regular(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	p, e := pe.NewFile(f)
	if e != nil {
		return "", e
	}
	defer p.Close()
	h, ok := p.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || p.Machine != pe.IMAGE_FILE_MACHINE_ARM64 || h.Subsystem != pe.IMAGE_SUBSYSTEM_EFI_APPLICATION {
		return "", errors.New("not ARM64 EFI UKI")
	}
	var name string
	for _, s := range p.Sections {
		if s.Name == ".uname" {
			if name != "" || s.VirtualSize == 0 || s.VirtualSize > 4096 || s.Size > 8192 || s.VirtualSize > s.Size {
				return "", errors.New("invalid .uname")
			}
			b, e := s.Data()
			if e != nil {
				return "", e
			}
			name = strings.TrimRight(string(b[:s.VirtualSize]), "\x00\n")
		}
	}
	if name == "" || strings.ContainsAny(name, "/\x00\r\n") {
		return "", errors.New("invalid UKI kernel")
	}
	return name, nil
}

type entry struct {
	Name, ID, Resource string
	Start, End, Depth  int
}

func entryID(path string) string {
	var b strings.Builder
	for _, c := range []byte(strings.TrimPrefix(path, "/")) {
		if b.Len() == 232 {
			break
		}
		if c == '/' {
			b.WriteByte('.')
		} else if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("+_.@-", rune(c)) {
			b.WriteByte(c)
		} else {
			b.WriteByte('-')
		}
	}
	s := b.String()
	if s == "" || s == "." || s == ".." {
		s += "-"
	}
	return s
}
func parseMenu(b []byte) ([]entry, string, error) {
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, "", errors.New("NUL menu")
	}
	var entries []entry
	def := ""
	offset := 0
	stack := []string{}
	ids := map[string]bool{}
	for _, raw := range bytes.SplitAfter(b, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if strings.HasPrefix(line, "/") {
			d := len(line) - len(strings.TrimLeft(line, "/"))
			n := strings.TrimSpace(strings.TrimLeft(line[d:], "+"))
			if n == "" || d > len(stack)+1 {
				return nil, "", errors.New("ambiguous menu hierarchy")
			}
			stack = append(stack[:d-1], n)
			canonical := "/" + strings.Join(stack, "/")
			id := entryID(canonical)
			if ids[id] {
				return nil, "", errors.New("duplicate normalized menu ID")
			}
			ids[id] = true
			if len(entries) > 0 {
				entries[len(entries)-1].End = offset
			}
			entries = append(entries, entry{canonical, id, "", offset, len(b), d})
		} else if line != "" && !strings.HasPrefix(line, "#") {
			key, val, ok := strings.Cut(line, ":")
			key = strings.ToLower(strings.TrimSpace(key))
			val = strings.TrimSpace(val)
			if !ok {
				return nil, "", errors.New("unparsed menu directive")
			}
			if key == "default_entry" {
				if def != "" || len(entries) > 0 || val == "" {
					return nil, "", errors.New("ambiguous default")
				}
				def = val
			} else if key == "path" || key == "kernel_path" {
				if len(entries) == 0 || entries[len(entries)-1].Resource != "" {
					return nil, "", errors.New("ambiguous boot resource")
				}
				entries[len(entries)-1].Resource = val
			} else if key == "module_path" || key == "initrd_path" {
				return nil, "", errors.New("external module resources unsupported for retirement")
			}
		}
		offset += len(raw)
	}
	if def == "" {
		return nil, "", errors.New("explicit named default required")
	}
	return entries, def, nil
}
func resourcePath(esp, res string) (string, error) {
	s, _, _ := strings.Cut(res, "#")
	if !strings.HasPrefix(s, "boot():/") {
		return "", errors.New("only boot(): resources supported")
	}
	s = strings.TrimPrefix(s, "boot():/")
	if s == "" || filepath.Clean(s) != s || strings.ContainsAny(s, "\\:\x00\r\n") || strings.HasPrefix(s, "/") || s == ".." || strings.HasPrefix(s, "../") {
		return "", errors.New("unsafe UKI resource")
	}
	return filepath.Join(esp, s), nil
}
func validate(p Plan) error {
	if len(p.Before) > 256<<10 || len(p.After) > 256<<10 {
		return errors.New("menu exceeds bounded metadata allowance")
	}
	if p.Version != Version || !plain.MatchString(p.Transaction) || p.ESP == "" || !hex64.MatchString(p.File.SHA256) || p.File.Size <= 0 || p.File.Size > MaxUKI || p.Snapshot.Machine == "" || p.Snapshot.Boot == "" || p.Snapshot.Kernel == "" {
		return errors.New("incomplete plan identity")
	}
	if p.Kind != "uki-leaf" && p.Kind != "unreferenced-m1n1-backup" {
		return errors.New("unknown artifact kind")
	}
	if p.Kind == "uki-leaf" && p.Kernel == "" {
		return errors.New("UKI kernel required")
	}
	if p.Kernel == p.Snapshot.Kernel {
		return errors.New("running kernel is protected")
	}
	if !p.RetireOnly {
		if _, e := RequiredPlan(p, 4096); e != nil {
			return e
		}
	} else if p.NextUKIBytes != 0 || p.NextESPTemporaryCopies != 0 || p.AdditionalESPBytes != 0 {
		return errors.New("retire-only plan must not claim a staging budget")
	}
	entries, def, e := parseMenu(p.Before)
	if e != nil {
		return e
	}
	if p.Kind == "unreferenced-m1n1-backup" {
		base := filepath.Base(p.UKI)
		if filepath.Dir(p.UKI) != filepath.Join(p.ESP, "m1n1") || !strings.HasPrefix(base, "boot.bin.pre-") || !plain.MatchString(strings.TrimPrefix(base, "boot.bin.pre-")) || p.Entry != "" || p.Kernel != "" || !bytes.Equal(p.Before, p.After) {
			return errors.New("backup retirement limited to explicit unreferenced m1n1/boot.bin.pre-<plain> bytes")
		}
		for _, ent := range entries {
			if ent.Resource == "" {
				continue
			}
			r, err := resourcePath(p.ESP, ent.Resource)
			if err != nil {
				return err
			}
			if r == p.UKI {
				return errors.New("referenced backup is protected")
			}
		}
		return nil
	}
	var target *entry
	for i := range entries {
		ent := &entries[i]
		if ent.Name == p.Entry {
			target = ent
		}
		if ent.Resource != "" {
			r, e := resourcePath(p.ESP, ent.Resource)
			if e != nil {
				return e
			}
			if r == p.UKI && ent.Name != p.Entry {
				return errors.New("shared UKI resource is protected")
			}
		}
	}
	if target != nil && (bytes.Contains(p.Before[target.Start:target.End], []byte("# maclab:")) || strings.HasPrefix(target.Name, "/maclab-")) {
		return errors.New("managed lab entries require normal supported job cleanup; not generic retirement")
	}
	if target == nil || target.Depth != 1 || target.Resource == "" {
		return errors.New("target must be an existing top-level leaf UKI entry")
	}
	for _, ent := range entries {
		if ent.Start > target.Start && ent.Depth > target.Depth && ent.Start == target.End {
			return errors.New("target is a parent")
		}
	}
	if def == strings.TrimPrefix(target.Name, "/") || def == target.ID || strings.HasPrefix(def, "/") || regexp.MustCompile(`^[0-9]+$`).MatchString(def) {
		return errors.New("target default or numeric/ambiguous default protected")
	}
	r, e := resourcePath(p.ESP, target.Resource)
	if e != nil || r != p.UKI {
		return errors.New("UKI entry mismatch")
	}
	expected := append(append([]byte{}, p.Before[:target.Start]...), p.Before[target.End:]...)
	if !bytes.Equal(expected, p.After) {
		return errors.New("after menu is not exact single leaf removal")
	}
	if _, _, e = parseMenu(p.After); e != nil {
		return e
	}
	return nil
}
func NewPlan(p Plan, e Env) (Plan, error) {
	if p.Created.IsZero() {
		p.Created = e.now()
	}
	s, err := e.Observe(p)
	if err != nil {
		return p, err
	}
	p.Snapshot = s
	if err = validate(p); err != nil {
		return p, err
	}
	got, err := HashFile(p.UKI, MaxUKI)
	if err != nil || got != p.File {
		return p, errors.New("UKI bytes do not match explicit pin")
	}
	if p.Kind == "uki-leaf" {
		k, err := UKIKernel(p.UKI)
		if err != nil || k != p.Kernel {
			return p, errors.New("UKI .uname does not match explicit pin")
		}
	}
	return p, nil
}

// PrepareMenu is pure: no device/file mutation. Unknown syntax is refused.
func PrepareMenu(before []byte, target string) ([]byte, error) {
	es, _, e := parseMenu(before)
	if e != nil {
		return nil, e
	}
	for _, ent := range es {
		if ent.Name == target {
			return append(append([]byte{}, before[:ent.Start]...), before[ent.End:]...), nil
		}
	}
	return nil, errors.New("entry not found")
}
func sameSnapshot(a, b Snapshot) bool { return bytes.Equal(JSON(a), JSON(b)) }

// Restore after a normal test return must not replay old EFI state or demand
// an old boot ID. All other guards (including current kernel/selected/default,
// no armed/pending job and every nonretired UKI) remain exact. Differences are
// retained in restored receipt; apply never uses this normalization.
func sameRestorationSnapshot(a, b Snapshot) bool {
	copySnapshot := func(s Snapshot) Snapshot {
		s.Boot = ""
		m := map[string]string{}
		for k, v := range s.Files {
			if !strings.HasPrefix(k, "mutable-store:") {
				m[k] = v
			}
		}
		s.Files = m
		return s
	}
	return sameSnapshot(copySnapshot(a), copySnapshot(b))
}
func checkState(p Plan, e Env, menu []byte) error {
	s, err := e.Observe(p)
	if err != nil {
		return err
	}
	if !sameSnapshot(s, p.Snapshot) {
		return errors.New("live identity/protected state drift")
	}
	b, err := ReadFile(p.Menu, 4<<20)
	if err != nil || !bytes.Equal(b, menu) {
		return errors.New("menu CAS drift")
	}
	return nil
}

// RetainController runs on the controller, outside its GC-controlled artifacts
// directory. No success proof is emitted until the durable independent copy is
// re-read. A repeat invocation re-verifies bytes and emits a fresh receipt.
func RetainController(p Plan, source, root, machine string, e Env) (Retention, error) {
	var r Retention
	if err := validate(p); err != nil {
		return r, err
	}
	if machine == "" || machine == p.Snapshot.Machine {
		return r, errors.New("controller must be a different machine")
	}
	for _, part := range strings.Split(root, string(os.PathSeparator)) {
		if part == "artifacts" {
			return r, errors.New("archive root must be outside controller CAS/GC directory")
		}
	}
	if err := privateDir(root); err != nil {
		return r, err
	}
	dst := filepath.Join(root, p.File.SHA256+".efi")
	if _, err := os.Lstat(dst); os.IsNotExist(err) {
		if err = copyVerified(source, dst, p.File); err != nil {
			return r, err
		}
	}
	got, err := HashFile(dst, MaxUKI)
	if err != nil || got != p.File {
		return r, errors.New("controller retained-copy mismatch")
	}
	retained, err := regular(dst)
	if err != nil {
		return r, err
	}
	err = retained.Sync()
	retained.Close()
	if err != nil {
		return r, err
	}
	if err = syncDir(root); err != nil {
		return r, err
	}
	got, err = HashFile(dst, MaxUKI)
	if err != nil || got != p.File {
		return r, errors.New("controller post-fsync readback mismatch")
	}
	r = Retention{Version: Version, PlanSHA256: PlanHash(p), Controller: machine, File: p.File, Path: dst, Verified: e.now()}
	if err = exclusive(filepath.Join(root, p.Transaction+"-"+PlanHash(p)[:12]+"-"+fmt.Sprint(e.now().UnixNano())+".receipt.json"), JSON(r)); err != nil {
		return r, err
	}
	return r, nil
}

// The trusted receipt hash comes from a reviewer over the existing authenticated
// lab channel. It is an explicit attestation of RetainController readback, not a
// caller-provided success boolean or a new signing/trust service.
func verifyRetention(p Plan, r Retention, trusted string, now time.Time) error {
	if !hex64.MatchString(trusted) || Digest(JSON(r)) != trusted {
		return errors.New("controller retention receipt hash mismatch")
	}
	age := now.Sub(r.Verified)
	if r.Version != Version || r.PlanSHA256 != PlanHash(p) || r.File != p.File || r.Controller == "" || r.Controller == p.Snapshot.Machine || r.Path == "" || age < 0 || age > 5*time.Minute {
		return errors.New("stale or mismatched controller retention proof")
	}
	return nil
}

func record(dir, phase string, p Plan, extra any) error {
	if b, e := ReadFile(filepath.Join(dir, phase+".json"), 1<<20); e == nil {
		var prior struct {
			Phase      string `json:"phase"`
			PlanSHA256 string `json:"plan_sha256"`
		}
		if json.Unmarshal(b, &prior) == nil && prior.Phase == phase && prior.PlanSHA256 == PlanHash(p) {
			return nil
		}
		return errors.New("receipt phase drift")
	} else if !os.IsNotExist(e) {
		return e
	}
	return exclusive(filepath.Join(dir, phase+".json"), JSON(struct {
		Phase      string    `json:"phase"`
		PlanSHA256 string    `json:"plan_sha256"`
		Time       time.Time `json:"time"`
		Evidence   any       `json:"evidence"`
	}{phase, PlanHash(p), time.Now().UTC(), extra}))
}
func Apply(p Plan, r Retention, trusted, archive string, e Env) error {
	if err := validate(p); err != nil {
		return err
	}
	if err := verifyRetention(p, r, trusted, e.now()); err != nil {
		return err
	}
	unlock, err := e.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err = checkState(p, e, p.Before); err != nil {
		return err
	}
	got, err := HashFile(p.UKI, MaxUKI)
	if err != nil || got != p.File {
		return errors.New("retirement file CAS drift")
	}
	if p.Kind == "uki-leaf" {
		k, err := UKIKernel(p.UKI)
		if err != nil || k != p.Kernel {
			return errors.New("live UKI kernel changed")
		}
	}
	spESP, err := e.Space(p.ESP)
	if err != nil {
		return err
	}
	need := Reserve + Metadata
	if !p.RetireOnly {
		need, err = RequiredPlan(p, spESP.Unit)
		if err != nil {
			return err
		}
	}
	st, err := os.Stat(p.UKI)
	if err != nil {
		return err
	}
	allocated := uint64(st.Sys().(*syscall.Stat_t).Blocks) * 512
	if spESP.Available < Reserve+Metadata || spESP.Available > ^uint64(0)-allocated || spESP.Available+allocated < need {
		return fmt.Errorf("retirement cannot safely admit planned peak: free=%d reclaim=%d need=%d", spESP.Available, allocated, need)
	}
	if err = privateDir(archive); err != nil {
		return err
	}
	sp, err := e.Space(archive)
	if err != nil || sp.Device == p.Snapshot.ESPDevice {
		return errors.New("local archive must be outside ESP")
	}
	dir := filepath.Join(archive, p.Transaction)
	if err = os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("transaction already exists; inspect receipts, do not retry blindly: %w", err)
	}
	if err = syncDir(archive); err != nil {
		return err
	}
	if err = exclusive(filepath.Join(dir, "plan.json"), JSON(p)); err != nil {
		return err
	}
	if err = exclusive(filepath.Join(dir, "controller-retention.json"), JSON(r)); err != nil {
		return err
	}
	if err = copyVerified(p.UKI, filepath.Join(dir, "uki.efi"), p.File); err != nil {
		return err
	}
	if err = record(dir, "prepared", p, r); err != nil {
		return err
	}
	if err = e.fault("prepared"); err != nil {
		return err
	}
	if err = checkState(p, e, p.Before); err != nil {
		return err
	}
	got, err = HashFile(p.UKI, MaxUKI)
	if err != nil || got != p.File {
		return errors.New("retirement file drift after archive")
	}
	if err = verifyRetention(p, r, trusted, e.now()); err != nil {
		return err
	}
	spESP, err = e.Space(p.ESP)
	if err != nil {
		return err
	}
	if spESP.Available < Reserve+Metadata || spESP.Available > ^uint64(0)-allocated || spESP.Available+allocated < need {
		return errors.New("ESP capacity drift before retirement commit")
	}
	if !bytes.Equal(p.Before, p.After) {
		if err = atomic(p.Menu, p.After); err != nil {
			return err
		}
	}
	if err = record(dir, "menu-retired", p, nil); err != nil {
		return err
	}
	if err = e.fault("menu-retired"); err != nil {
		return err
	}
	got, err = HashFile(p.UKI, MaxUKI)
	if err != nil || got != p.File {
		return errors.New("retirement file drift before unlink")
	}
	if err = os.Remove(p.UKI); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(p.UKI)); err != nil {
		return err
	}
	if err = e.fault("file-retired"); err != nil {
		return err
	}
	if err = record(dir, "retired", p, nil); err != nil {
		return err
	}
	sp, err = e.Space(p.ESP)
	if err != nil {
		return err
	}
	if p.RetireOnly {
		return record(dir, "retire-only-not-stage-admission", p, sp)
	}
	needed, err := RequiredPlan(p, sp.Unit)
	if err != nil {
		return err
	}
	if sp.Available < needed {
		return fmt.Errorf("retired safely but next operation NOT ADMITTED: need %d, available %d", needed, sp.Available)
	}
	return record(dir, "capacity-admitted", p, sp)
}

// Restore is CAS-safe and usable after interruption in every apply phase. It
// restores bytes before the entry; it never overwrites different existing bytes.
func Restore(p Plan, archive string, e Env) error {
	if err := validate(p); err != nil {
		return err
	}
	unlock, err := e.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	s, err := e.Observe(p)
	if err != nil {
		return err
	}
	if !sameRestorationSnapshot(s, p.Snapshot) {
		return errors.New("live protected-state drift")
	}
	dir := filepath.Join(archive, p.Transaction)
	saved, err := ReadFile(filepath.Join(dir, "plan.json"), 16<<20)
	if err != nil || !bytes.Equal(saved, JSON(p)) {
		return errors.New("missing exact transaction plan")
	}
	b, err := ReadFile(p.Menu, 4<<20)
	if err != nil || (!bytes.Equal(b, p.Before) && !bytes.Equal(b, p.After)) {
		return errors.New("restore menu CAS drift")
	}
	src := filepath.Join(dir, "uki.efi")
	got, err := HashFile(src, MaxUKI)
	if err != nil || got != p.File {
		return errors.New("local retained-copy mismatch; recover verified controller copy explicitly")
	}
	got, err = HashFile(p.UKI, MaxUKI)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && got != p.File {
		return errors.New("restore destination exists with different bytes")
	}
	if os.IsNotExist(err) {
		sp, e2 := e.Space(p.ESP)
		if e2 != nil {
			return e2
		}
		need, e2 := Required(uint64(p.File.Size), sp.Unit, 1)
		if e2 != nil {
			return e2
		}
		if sp.Available < need {
			return fmt.Errorf("restore reserve: need %d free, available %d; remove only the separately-owned completed test artifact first", need, sp.Available)
		}
		tmp := filepath.Join(filepath.Dir(p.UKI), ".lab-esp-restore-"+p.Transaction)
		if prior, er := HashFile(tmp, MaxUKI); er == nil {
			if prior != p.File {
				return errors.New("interrupted restore temp has different bytes")
			}
		} else if os.IsNotExist(er) {
			if err = copyVerified(src, tmp, p.File); err != nil {
				return err
			}
		} else {
			return er
		}
		sp, e2 = e.Space(p.ESP)
		if e2 != nil || sp.Available < Reserve+Metadata {
			return errors.New("restore reserve lost after copy")
		}
		if _, e2 = os.Lstat(p.UKI); !os.IsNotExist(e2) {
			return errors.New("restore destination appeared")
		}
		if err = os.Rename(tmp, p.UKI); err != nil {
			return err
		}
		if err = syncDir(filepath.Dir(p.UKI)); err != nil {
			return err
		}
	}
	got, err = HashFile(p.UKI, MaxUKI)
	if err != nil || got != p.File {
		return errors.New("restored UKI readback failed")
	}
	if err = e.fault("restore-file"); err != nil {
		return err
	}
	current, err := e.Observe(p)
	if err != nil {
		return err
	}
	if !sameRestorationSnapshot(current, p.Snapshot) {
		return errors.New("protected state changed during restoration")
	}
	again, err := ReadFile(p.Menu, 4<<20)
	if err != nil || !bytes.Equal(again, b) {
		return errors.New("menu changed before restoring entry")
	}
	if !bytes.Equal(b, p.Before) {
		if err = atomic(p.Menu, p.Before); err != nil {
			return err
		}
	}
	return record(dir, "restored", p, struct {
		File     File     `json:"file"`
		Observed Snapshot `json:"observed"`
	}{got, s})
}

package mesa

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/iconidentify/maclab/internal/api"
	"golang.org/x/sys/unix"
)

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var jobRE = regexp.MustCompile(`^j[0-9]{4}-[0-9]{6}-[0-9a-f]{4}$`)
var nameRE = regexp.MustCompile(`^(mesa|mesa-[a-z0-9+_.-]{1,60}|vulkan-[a-z0-9+_.-]{1,60}|opencl-[a-z0-9+_.-]{1,60})$`)

type Fetch func(context.Context, string, string) error

func Sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func JSON(v any) []byte   { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }
func OpenRegular(p string) (*os.File, error) {
	f, e := os.OpenFile(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !a.Mode().IsRegular() {
		return nil, errors.New("nonregular: no data-open")
	}
	r, e := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), os.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	b, e := r.Stat()
	c, ce := os.Lstat(p)
	if e != nil || ce != nil || !stable(a, b) || !stable(b, c) {
		r.Close()
		return nil, errors.New("regular inode/path changed")
	}
	return r, nil
}
func stable(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	return ok && a.Mode().IsRegular() && b.Mode().IsRegular() && x.Dev == y.Dev && x.Ino == y.Ino && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func Hash(p string, max int64) (string, error) {
	f, e := OpenRegular(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || a.Size() > max {
		return "", errors.New("oversize file")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, max+1))
	if e != nil {
		return "", e
	}
	b, e := f.Stat()
	c, ce := os.Lstat(p)
	if e != nil || ce != nil || n > max || n != a.Size() || !stable(a, b) || !stable(b, c) {
		return "", errors.New("file changed during hash")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func Read(p string, max int64) ([]byte, error) {
	f, e := OpenRegular(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("oversize file")
	}
	return b, e
}
func cleanName(p string) (string, error) {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimSuffix(p, "/")
	if p == "" || p == "." {
		return "", nil
	}
	if path.IsAbs(p) || path.Clean(p) != p || strings.HasPrefix(p, "../") || p == ".." || strings.ContainsAny(p, "\\\x00\r\n") {
		return "", errors.New("unsafe archive path")
	}
	return p, nil
}
func checkDirs(p string) error {
	abs, e := filepath.Abs(p)
	if e != nil || abs != p {
		return errors.New("absolute prefix required")
	}
	at := "/"
	for _, c := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		at = filepath.Join(at, c)
		s, e := os.Lstat(at)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe prefix ancestor")
		}
		owner := s.Sys().(*syscall.Stat_t).Uid
		stickyRoot := owner == 0 && s.Mode()&os.ModeSticky != 0
		if (owner != 0 && owner != uint32(os.Geteuid())) || (s.Mode().Perm()&0022 != 0 && !stickyRoot) {
			return errors.New("prefix ancestor writable by another account")
		}
	}
	return nil
}
func writeNew(p string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, mode)
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
	return e
}
func syncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func pkgInfo(b []byte, expected string) (Package, error) {
	v := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
			continue
		}
		k, s, ok := strings.Cut(l, " = ")
		if !ok {
			return Package{}, errors.New("invalid PKGINFO")
		}
		switch k {
		case "pkgname", "pkgbase", "pkgver", "arch":
			if v[k] != "" {
				return Package{}, errors.New("duplicate PKGINFO identity")
			}
			v[k] = s
		}
	}
	if v["pkgname"] != expected || !nameRE.MatchString(v["pkgbase"]) || !regexp.MustCompile(`^[0-9A-Za-z:+_.~]+-[0-9]+(?:\.[0-9]+)*$`).MatchString(v["pkgver"]) || v["arch"] != "aarch64" {
		return Package{}, errors.New("PKGINFO name/base/version/aarch64 mismatch")
	}
	return Package{MesaPackage: api.MesaPackage{Name: expected}, PkgBase: v["pkgbase"], Version: v["pkgver"], Arch: v["arch"], PKGInfoSHA256: Sum(b)}, nil
}

type unpacker struct {
	m       *Manifest
	entries int
	bytes   int64
	links   map[string]string
}

func (u *unpacker) unpack(r io.Reader, pkg api.MesaPackage) error {
	tr := tar.NewReader(r)
	var info []byte
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		u.entries++
		if u.entries > MaxEntries {
			return errors.New("archive entry budget")
		}
		n, e := cleanName(h.Name)
		if e != nil {
			return e
		}
		if n == "" {
			continue
		}
		if h.Mode&06000 != 0 {
			return errors.New("setuid/setgid archive member")
		}
		if h.Size < 0 || h.Size > MaxFile || u.bytes > MaxExpanded-h.Size {
			return errors.New("expanded archive budget")
		}
		u.bytes += h.Size
		if strings.HasPrefix(n, ".") {
			if n != ".PKGINFO" && n != ".BUILDINFO" && n != ".MTREE" && n != ".INSTALL" {
				return errors.New("unknown package metadata")
			}
			if h.Typeflag != tar.TypeReg {
				return errors.New("nonregular metadata")
			}
			if n == ".PKGINFO" {
				if info != nil || h.Size > 1<<20 {
					return errors.New("duplicate/oversize PKGINFO")
				}
				info, e = io.ReadAll(tr)
				if e != nil {
					return e
				}
			}
			continue
		}
		if !strings.HasPrefix(n, "usr/") && !strings.HasPrefix(n, "etc/") && n != "usr" && n != "etc" {
			return errors.New("package path outside staged usr/etc")
		}
		dst := filepath.Join(u.m.Root, filepath.FromSlash(n))
		if h.Typeflag == tar.TypeDir {
			if _, exists := u.m.Files[n]; exists {
				return errors.New("directory overlaps file")
			}
			if e = os.MkdirAll(dst, 0755); e != nil {
				return e
			}
			continue
		}
		if _, exists := u.m.Files[n]; exists {
			return errors.New("split-package file collision")
		}
		if e = os.MkdirAll(filepath.Dir(dst), 0755); e != nil {
			return e
		}
		if e = checkDirs(filepath.Dir(dst)); e != nil {
			return e
		}
		switch h.Typeflag {
		case tar.TypeReg:
			f, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0644)
			if e != nil {
				return e
			}
			hash := sha256.New()
			size, e := io.Copy(io.MultiWriter(f, hash), tr)
			if e == nil && size != h.Size {
				e = errors.New("short member")
			}
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
			u.m.Files[n] = File{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size, Package: pkg.Name}
		case tar.TypeSymlink:
			if h.Size != 0 || h.Linkname == "" || path.IsAbs(h.Linkname) || strings.ContainsAny(h.Linkname, "\\\x00\r\n") {
				return errors.New("unsafe package link")
			}
			target := path.Clean(path.Join(path.Dir(n), h.Linkname))
			if target == ".." || strings.HasPrefix(target, "../") || path.IsAbs(target) {
				return errors.New("escaping package link")
			}
			u.links[n] = h.Linkname
			u.m.Files[n] = File{Link: h.Linkname, Package: pkg.Name}
		default:
			return errors.New("nonregular archive member (hardlinks/devices/FIFOs refused)")
		}
	}
	if info == nil {
		return errors.New("missing PKGINFO")
	}
	p, e := pkgInfo(info, pkg.Name)
	if e != nil {
		return e
	}
	p.SHA256 = pkg.SHA256
	if len(u.m.Packages) > 0 {
		prior := u.m.Packages[0]
		if p.PkgBase != prior.PkgBase || p.Version != prior.Version || p.Arch != prior.Arch {
			return errors.New("split package base/version/arch mismatch")
		}
	}
	u.m.Packages = append(u.m.Packages, p)
	return nil
}
func resolve(m Manifest, n string) (string, error) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		f, ok := m.Files[n]
		if !ok {
			return "", errors.New("link/provider target missing")
		}
		if f.Link == "" {
			if f.SHA256 == "" {
				return "", errors.New("unhashed provider")
			}
			return n, nil
		}
		if seen[n] {
			return "", errors.New("package link cycle")
		}
		seen[n] = true
		n = path.Clean(path.Join(path.Dir(n), f.Link))
		if n == ".." || strings.HasPrefix(n, "../") {
			return "", errors.New("link escape")
		}
	}
	return "", errors.New("link depth")
}
func provider(m Manifest, base string) (string, error) {
	var found string
	for n, f := range m.Files {
		b := path.Base(n)
		if path.Dir(n) != "usr/lib" {
			continue
		}
		if b == base || strings.HasPrefix(b, base+".") {
			if f.Link != "" {
				continue
			}
			if found != "" {
				return "", errors.New("ambiguous provider")
			}
			found = n
		}
	}
	if found == "" {
		return "", fmt.Errorf("missing staged provider %s", base)
	}
	return resolve(m, found)
}
func finalize(m *Manifest, links map[string]string) error {
	for n, l := range links {
		if _, e := resolve(*m, n); e != nil {
			return e
		}
		if e := os.Symlink(l, filepath.Join(m.Root, filepath.FromSlash(n))); e != nil {
			return e
		}
	}
	var e error
	m.Providers = map[string]string{}
	m.Providers["egl"], e = provider(*m, "libEGL_mesa.so")
	if e != nil {
		return e
	}
	m.Providers["vulkan"], e = provider(*m, "libvulkan_asahi.so")
	if e != nil {
		return e
	}
	for n, f := range m.Files {
		if path.Dir(n) == "usr/lib" && f.Link == "" && (strings.HasPrefix(path.Base(n), "libgallium-") || path.Base(n) == "libgallium.so") {
			if m.Providers["gallium"] != "" {
				return errors.New("ambiguous gallium")
			}
			m.Providers["gallium"] = n
		}
	}
	if m.Providers["gallium"] == "" {
		return errors.New("missing staged gallium")
	}
	// Original package descriptors must exist and name the actual native roles.
	// Relocation changes only library_path in derived copies; it does not invent
	// missing packaging or silently repair a mismatched ICD/provider split.
	descriptors := []struct{ rel, role string }{{"usr/share/vulkan/icd.d/asahi_icd.aarch64.json", "vulkan"}, {"usr/share/glvnd/egl_vendor.d/50_mesa.json", "egl"}}
	parsed := map[string]map[string]any{}
	for _, d := range descriptors {
		f, ok := m.Files[d.rel]
		if !ok || f.Link != "" || f.Size > 65536 {
			return errors.New("missing/nonregular package vendor descriptor")
		}
		b, err := Read(filepath.Join(m.Root, d.rel), 65536)
		if err != nil {
			return err
		}
		var doc map[string]any
		if err = json.Unmarshal(b, &doc); err != nil {
			return err
		}
		icd, ok := doc["ICD"].(map[string]any)
		if !ok {
			return errors.New("vendor descriptor ICD missing")
		}
		lib, ok := icd["library_path"].(string)
		if !ok || lib == "" {
			return errors.New("vendor descriptor library missing")
		}
		if strings.Contains(lib, "/") {
			if !strings.HasPrefix(lib, "/usr/lib/") || path.Clean(lib) != lib {
				return errors.New("unsupported vendor provider path")
			}
			lib = strings.TrimPrefix(lib, "/")
		} else {
			lib = "usr/lib/" + lib
		}
		resolved, err := resolve(*m, lib)
		if err != nil || resolved != m.Providers[d.role] {
			return errors.New("vendor descriptor does not name staged native provider")
		}
		if d.role == "vulkan" {
			v, ok := icd["api_version"].(string)
			if !ok || !regexp.MustCompile(`^1\.[2-9]\.[0-9]+$`).MatchString(v) {
				return errors.New("Vulkan descriptor does not provide required API>=1.2")
			}
		}
		icd["library_path"] = filepath.Join(m.Root, m.Providers[d.role])
		parsed[d.role] = doc
	}
	// Derived vendor descriptors name only the canonical staged provider. Original
	// archive bytes and file hashes remain in the manifest, never overwritten.
	m.VulkanJSON = filepath.Join(m.Prefix, "vulkan.json")
	m.EGLJSON = filepath.Join(m.Prefix, "egl.json")
	vk := parsed["vulkan"]
	egl := parsed["egl"]
	m.VulkanJSONSHA256 = Sum(JSON(vk))
	m.EGLJSONSHA256 = Sum(JSON(egl))
	if e = writeNew(m.VulkanJSON, JSON(vk), 0644); e != nil {
		return e
	}
	return writeNew(m.EGLJSON, JSON(egl), 0644)
}

// Stage creates one brand-new owned prefix. Errors retain a failed ownership
// record for explicit cleanup; they never sweep another job or mutate /usr.
func Stage(ctx context.Context, parent, job string, spec api.MesaSpec, fetch Fetch) (Manifest, error) {
	return stageWith(ctx, parent, job, spec, fetch, map[string]string{"gl": GLProbeSHA, "vulkan": VKProbeSHA})
}
func stageWith(ctx context.Context, parent, job string, spec api.MesaSpec, fetch Fetch, tools map[string]string) (Manifest, error) {
	var m Manifest
	ctx, cancel := context.WithTimeout(ctx, stageTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return m, err
	}
	if !jobRE.MatchString(job) || spec.Mode != api.MesaStaged || len(spec.Packages) < 1 || len(spec.Packages) > 8 {
		return m, errors.New("invalid staged Mesa request")
	}
	if e := checkDirs(parent); e != nil {
		return m, e
	}
	prefix := filepath.Join(parent, job)
	if e := os.Mkdir(prefix, 0700); e != nil {
		return m, fmt.Errorf("prefix exists or cannot create: %w", e)
	}
	m = Manifest{Schema: Schema, Job: job, Prefix: prefix, Root: filepath.Join(prefix, "root"), Files: map[string]File{}, Probes: map[string]Tool{}}
	if e := writeNew(filepath.Join(prefix, "owner.json"), JSON(map[string]any{"schema": Schema, "job": job, "kind": "mesa-staged"}), 0600); e != nil {
		return m, e
	}
	for _, n := range []string{"root", "downloads", "tools"} {
		if e := os.Mkdir(filepath.Join(prefix, n), 0755); e != nil {
			return m, e
		}
	}
	u := unpacker{m: &m, links: map[string]string{}}
	names := map[string]bool{}
	hashes := map[string]bool{}
	for _, p := range spec.Packages {
		if !nameRE.MatchString(p.Name) || !hashRE.MatchString(p.SHA256) || names[p.Name] || hashes[p.SHA256] {
			return m, errors.New("invalid/duplicate split package identity")
		}
		names[p.Name] = true
		hashes[p.SHA256] = true
		archive := filepath.Join(prefix, "downloads", p.Name+".pkg.tar.zst")
		if e := fetch(ctx, p.SHA256, archive); e != nil {
			return m, e
		}
		got, e := Hash(archive, MaxCompressed)
		if e != nil || got != p.SHA256 {
			return m, errors.New("downloaded package hash/size mismatch")
		}
		if e := decodePackage(ctx, archive, &u, p); e != nil {
			return m, e
		}
	}
	if e := finalize(&m, u.links); e != nil {
		return m, e
	}
	for _, apiName := range []string{"gl", "vulkan"} {
		sha := tools[apiName]
		if !hashRE.MatchString(sha) {
			return m, errors.New("probe not pinned")
		}
		dst := filepath.Join(prefix, "tools", apiName+"-render-check")
		if e := fetch(ctx, sha, dst); e != nil {
			return m, e
		}
		got, e := Hash(dst, MaxFile)
		if e != nil || got != sha {
			return m, errors.New("probe artifact integrity mismatch")
		}
		if e = os.Chmod(dst, 0755); e != nil {
			return m, e
		}
		m.Probes[apiName] = Tool{dst, sha}
	}
	if e := writeNew(filepath.Join(prefix, "manifest.json"), JSON(m), 0600); e != nil {
		return m, e
	}
	if e := syncDir(prefix); e != nil {
		return m, e
	}
	return m, nil
}

type limitedWriter struct {
	W         io.Writer
	N         int
	Truncated bool
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	n := len(b)
	if len(b) > w.N {
		w.Truncated = true
	}
	if w.N > 0 {
		take := min(w.N, len(b))
		_, e := w.W.Write(b[:take])
		w.N -= take
		if e != nil {
			return 0, e
		}
	}
	return n, nil
}

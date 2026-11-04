package mesa

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"github.com/iconidentify/maclab/internal/api"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type member struct {
	name, body, link string
	kind             byte
	mode             int64
	size             int64
}

func archive(t *testing.T, name, base, version, arch string, entries []member) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	meta := fmt.Sprintf("pkgname = %s\npkgbase = %s\npkgver = %s\narch = %s\n", name, base, version, arch)
	entries = append([]member{{name: ".PKGINFO", body: meta}}, entries...)
	for _, v := range entries {
		kind := v.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		mode := v.mode
		if mode == 0 {
			mode = 0644
		}
		size := int64(len(v.body))
		if v.size > 0 {
			size = v.size
		}
		h := &tar.Header{Name: v.name, Mode: mode, Size: size, Typeflag: kind, Linkname: v.link}
		if e := w.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if v.body != "" {
			w.Write([]byte(v.body))
		}
	}
	w.Close()
	cmd := exec.Command("zstd", "-q", "-c")
	cmd.Stdin = bytes.NewReader(b.Bytes())
	out, e := cmd.Output()
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func fixture(t *testing.T) (string, api.MesaSpec, Fetch, map[string]string, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	a := archive(t, "mesa-aurora", "mesa-aurora", "1:26.3.0_devel.231095.abc-1", "aarch64", []member{{name: "usr/lib/libEGL_mesa.so.0.0.0", body: "EGL staged library"}, {name: "usr/lib/libgallium-26-devel.so", body: "Gallium staged library"}, {name: "usr/lib/libEGL_mesa.so.0", kind: tar.TypeSymlink, link: "libEGL_mesa.so.0.0.0"}, {name: "usr/share/glvnd/egl_vendor.d/50_mesa.json", body: `{"file_format_version":"1.0.0","ICD":{"library_path":"libEGL_mesa.so.0"}}`}})
	b := archive(t, "vulkan-aurora", "mesa-aurora", "1:26.3.0_devel.231095.abc-1", "aarch64", []member{{name: "usr/lib/libvulkan_asahi.so", body: "VK staged library"}, {name: "usr/share/vulkan/icd.d/asahi_icd.aarch64.json", body: `{"file_format_version":"1.0.1","ICD":{"library_path":"/usr/lib/libvulkan_asahi.so","api_version":"1.4.363"}}`}})
	store := map[string][]byte{Sum(a): a, Sum(b): b}
	spec := api.MesaSpec{Mode: api.MesaStaged, Packages: []api.MesaPackage{{Name: "mesa-aurora", SHA256: Sum(a)}, {Name: "vulkan-aurora", SHA256: Sum(b)}}}
	tools := map[string]string{}
	for _, apiName := range []string{"gl", "vulkan"} {
		data := []byte("host parser fixture only: " + apiName)
		tools[apiName] = Sum(data)
		store[Sum(data)] = data
	}
	fetch := func(ctx context.Context, sha, dst string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		b, ok := store[sha]
		if !ok {
			return fmt.Errorf("missing fixture")
		}
		return os.WriteFile(dst, b, 0600)
	}
	return root, spec, fetch, tools, store
}
func TestStageCoherentPrefix(t *testing.T) {
	root, spec, fetch, tools, _ := fixture(t)
	m, e := stageWith(context.Background(), root, "j1026-010203-abcd", spec, fetch, tools)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Packages) != 2 || len(m.Probes) != 2 || len(m.Providers) != 3 {
		t.Fatalf("incomplete manifest %+v", m)
	}
	if _, e = os.Lstat(filepath.Join(m.Root, "usr/lib/libEGL_mesa.so.0")); e != nil {
		t.Fatal(e)
	}
	for n, f := range m.Files {
		if f.Link == "" {
			got, e := Hash(filepath.Join(m.Root, n), MaxFile)
			if e != nil || got != f.SHA256 {
				t.Fatal(n, got, e)
			}
		}
	}
	if _, e = stageWith(context.Background(), root, m.Job, spec, fetch, tools); e == nil {
		t.Fatal("overwrote existing prefix")
	}
	if len(m.Packages[0].PKGInfoSHA256) != 64 {
		t.Fatal("metadata provenance omitted")
	}
}
func TestHostileArchivesAndSplitIdentity(t *testing.T) {
	for _, which := range []string{"traversal", "absolute", "device", "fifo", "hardlink", "setuid", "escape-link", "link-cycle", "collision", "wrong-name", "wrong-base", "wrong-version", "wrong-arch", "missing-provider", "oversize", "duplicate-metadata"} {
		t.Run(which, func(t *testing.T) {
			root, spec, fetch, tools, store := fixture(t)
			name, base, version, arch := "vulkan-aurora", "mesa-aurora", "1:26.3.0_devel.231095.abc-1", "aarch64"
			entries := []member{{name: "usr/lib/libvulkan_asahi.so", body: "VK"}, {name: "usr/share/vulkan/icd.d/asahi_icd.aarch64.json", body: `{"file_format_version":"1.0.1","ICD":{"library_path":"/usr/lib/libvulkan_asahi.so","api_version":"1.4.363"}}`}}
			switch which {
			case "traversal":
				entries = append(entries, member{name: "../escape", body: "bad"})
			case "absolute":
				entries = append(entries, member{name: "/etc/shadow", body: "bad"})
			case "device":
				entries = append(entries, member{name: "usr/lib/device", kind: tar.TypeChar})
			case "fifo":
				entries = append(entries, member{name: "usr/lib/fifo", kind: tar.TypeFifo})
			case "hardlink":
				entries = append(entries, member{name: "usr/lib/hard", kind: tar.TypeLink, link: "usr/lib/libvulkan_asahi.so"})
			case "setuid":
				entries[0].mode = 04755
			case "escape-link":
				entries = append(entries, member{name: "usr/lib/alias", kind: tar.TypeSymlink, link: "../../../etc/shadow"})
			case "link-cycle":
				entries = append(entries, member{name: "usr/lib/a", kind: tar.TypeSymlink, link: "b"}, member{name: "usr/lib/b", kind: tar.TypeSymlink, link: "a"})
			case "collision":
				entries = append(entries, member{name: "usr/lib/libEGL_mesa.so.0.0.0", body: "different"})
			case "wrong-name":
				name = "vulkan-different"
			case "wrong-base":
				base = "mesa-other"
			case "wrong-version":
				version = "99-1"
			case "wrong-arch":
				arch = "x86_64"
			case "missing-provider":
				entries = []member{{name: "usr/lib/irrelevant.so", body: "none"}}
			case "oversize":
				entries = []member{{name: "usr/lib/libvulkan_asahi.so", size: MaxFile + 1}}
			case "duplicate-metadata":
				entries = append(entries, member{name: ".PKGINFO", body: "pkgname = forged\n"})
			}
			data := archive(t, name, base, version, arch, entries)
			spec.Packages[1].SHA256 = Sum(data)
			store[Sum(data)] = data
			if _, e := stageWith(context.Background(), root, "j1026-010203-abcd", spec, fetch, tools); e == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, e := os.Stat(filepath.Join(filepath.Dir(root), "escape")); !os.IsNotExist(e) {
				t.Fatal("path escaped")
			}
		})
	}
}
func TestStageIntegrityAndCancellation(t *testing.T) {
	for _, which := range []string{"hash", "tool-hash", "same-archive", "installed", "cancel"} {
		t.Run(which, func(t *testing.T) {
			root, spec, fetch, tools, store := fixture(t)
			ctx := context.Background()
			switch which {
			case "hash":
				store[spec.Packages[0].SHA256] = []byte("corrupt")
			case "tool-hash":
				store[tools["gl"]] = []byte("wrong helper")
			case "same-archive":
				spec.Packages[1].SHA256 = spec.Packages[0].SHA256
			case "installed":
				spec.Mode = api.MesaInstalled
			case "cancel":
				c, stop := context.WithCancel(ctx)
				stop()
				ctx = c
			}
			if _, e := stageWith(ctx, root, "j1026-010203-abcd", spec, fetch, tools); e == nil {
				t.Fatal("bad request accepted")
			}
		})
	}
}
func TestHashRegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("staged\n"), 0o644)
	if got, e := Hash(p, 1<<20); e != nil || got != Sum([]byte("staged\n")) {
		t.Fatalf("Hash = %q, %v", got, e)
	}
}

func TestSafeHashNoDataOpenForSpecialFiles(t *testing.T) {
	for _, p := range []string{"/dev/null", t.TempDir()} {
		if _, e := Hash(p, 1<<20); e == nil {
			t.Fatal("nonregular accepted")
		}
	}
	root := t.TempDir()
	p := filepath.Join(root, "symlink")
	os.Symlink("/etc/passwd", p)
	if _, e := Hash(p, 1<<20); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := cleanName("usr/../escape"); e == nil {
		t.Fatal("unclean path")
	}
	if _, e := pkgInfo([]byte("pkgname = mesa\npkgbase = x\npkgver = 1\narch = aarch64\npkgname = mesa\n"), "mesa"); e == nil {
		t.Fatal("duplicate metadata")
	}
	if strings.TrimSpace(Semantics) == "" {
		t.Fatal("missing semantics")
	}
}

func TestOfficialArchiveStagesOnlyExactReviewedCASBytes(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint("bad=", bad), func(t *testing.T) {
			root, spec, fetch, tools, store := fixture(t)
			spec.OfficialGPU = true
			data, err := os.ReadFile("testdata/official-archive.tar.gz")
			if err != nil {
				t.Fatal(err)
			}
			if Sum(data) != OfficialArchiveSHA || int64(len(data)) != OfficialArchiveBytes {
				t.Fatal("fixture is not the qualified archive")
			}
			if bad {
				data = append([]byte(nil), data...)
				data[0] ^= 1
			}
			store[OfficialArchiveSHA] = data
			m, err := stageWith(context.Background(), root, "j1026-010203-abcd", spec, fetch, tools)
			if bad {
				if err == nil {
					t.Fatal("tampered official archive admitted")
				}
				return
			}
			if err != nil || m.OfficialArchive == nil || m.OfficialArchive.SHA256 != OfficialArchiveSHA {
				t.Fatal(m, err)
			}
			got, err := Hash(m.OfficialArchive.Path, OfficialArchiveBytes)
			if err != nil || got != OfficialArchiveSHA {
				t.Fatal(got, err)
			}
		})
	}
}

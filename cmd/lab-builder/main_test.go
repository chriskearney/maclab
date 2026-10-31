package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
)

func TestBuilderToken(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("bldr_abc\n"), 0o600)
	open := filepath.Join(dir, "open")
	os.WriteFile(open, []byte("bldr_abc"), 0o644)
	os.Chmod(open, 0o644)
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	for _, c := range []struct {
		name, flag, file, env, want string
		err                         bool
	}{
		{name: "file", file: good, flag: "ignored", env: "ignored", want: "bldr_abc"},
		{name: "readable by others", file: open, err: true},
		{name: "empty file", file: empty, err: true},
		{name: "missing file", file: filepath.Join(dir, "none"), err: true},
		{name: "flag", flag: "bldr_flag", env: "ignored", want: "bldr_flag"},
		{name: "env", env: " bldr_env\n", want: "bldr_env"},
	} {
		got, err := builderToken(c.flag, c.file, c.env)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
		if err != nil && strings.Contains(err.Error(), "bldr_abc") {
			t.Errorf("%s: the error shows the token: %v", c.name, err)
		}
	}
}

// Nothing lab-builder starts gets a MACLAB_ variable, the token among them.
func TestChildEnvDropsMaclabVariables(t *testing.T) {
	env := childEnv([]string{"HOME=/var/root", "MACLAB_BUILDER_TOKEN=bldr_x", "MACLAB_URL=https://x", "PATH=/usr/bin"})
	if strings.Join(env, " ") != "HOME=/var/root PATH=/usr/bin" {
		t.Fatalf("env %q", env)
	}
	t.Setenv("MACLAB_BUILDER_TOKEN", "bldr_secret")
	cmd := (&builder{}).container(context.Background(), "list")
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "MACLAB_") || strings.Contains(e, "bldr_secret") {
			t.Fatalf("container command env has %q", e)
		}
	}
}

func TestContainerPrefix(t *testing.T) {
	for p, ok := range map[string]bool{"maclab": true, "maclabhttps": true, "lab.2_x": true, "": false, "-x": false,
		"a b": false, "x/y": false, strings.Repeat("a", 33): false} {
		if rePrefix.MatchString(p) != ok {
			t.Errorf("%q: %v", p, !ok)
		}
	}
}

// A build VM shares the scratch dir and may leave links to files of this
// host there: none is ever read or uploaded, wherever it points.
func TestOutputsReadNoLinks(t *testing.T) {
	host := t.TempDir()
	secret := filepath.Join(host, "builder.token")
	os.WriteFile(secret, []byte("bldr_host_secret"), 0o600)
	os.Mkdir(filepath.Join(host, "dir"), 0o700)
	os.WriteFile(filepath.Join(host, "dir", "x.pkg.tar.zst"), []byte("host file"), 0o600)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "kernel.tar.zst"), []byte("kernel"), 0o644)
	os.WriteFile(filepath.Join(dir, "inside"), []byte("in"), 0o644)
	os.Mkdir(filepath.Join(dir, "out"), 0o755)
	os.WriteFile(filepath.Join(dir, "out", "linux-x-1-1-aarch64.pkg.tar.zst"), []byte("pkg"), 0o644)
	os.Symlink(secret, filepath.Join(dir, "release"))                             // to a host file
	os.Symlink(secret, filepath.Join(dir, "out", "evil-1-1-aarch64.pkg.tar.zst")) // listed output, to a host file
	os.Symlink("inside", filepath.Join(dir, "kernel"))                            // a link that stays inside
	os.Symlink(filepath.Join(host, "dir"), filepath.Join(dir, "outlink"))         // an outputs dir that is a link
	os.WriteFile(filepath.Join(dir, "big"), make([]byte, 5000), 0o644)

	o, err := openOutputs(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if f, st, err := o.regular("kernel.tar.zst"); err != nil || st.Size() != 6 {
		t.Fatalf("regular file: %v", err)
	} else {
		f.Close()
	}
	if f, _, err := o.regular("out/linux-x-1-1-aarch64.pkg.tar.zst"); err != nil {
		t.Fatalf("regular package: %v", err)
	} else {
		f.Close()
	}
	for _, name := range []string{"release", "out/evil-1-1-aarch64.pkg.tar.zst", "kernel", "outlink/x.pkg.tar.zst"} {
		if f, _, err := o.regular(name); err == nil {
			f.Close()
			t.Errorf("%s: read through a link", name)
		}
		if s, err := o.small(name); err == nil || strings.Contains(s, "secret") {
			t.Errorf("%s: small read %q %v", name, s, err)
		}
	}
	if _, err := o.list("outlink"); err == nil {
		t.Error("listed a linked outputs dir")
	}
	ents, err := o.list("out")
	if err != nil || len(ents) != 2 {
		t.Fatalf("list out: %v %v", ents, err)
	}
	if _, err := o.small("big"); err == nil {
		t.Error("an oversized short output was read")
	}
	// A second name for the same file is refused too.
	os.Link(filepath.Join(dir, "kernel.tar.zst"), filepath.Join(dir, "hardlink"))
	if f, _, err := o.regular("hardlink"); err == nil {
		f.Close()
		t.Error("read a hard-linked output")
	}
}

// fakeLabd records every upload a builder makes.
type fakeLabd struct {
	mu   sync.Mutex
	got  [][]byte
	srv  *httptest.Server
	path []string
}

func newFakeLabd(t *testing.T) *fakeLabd {
	f := &fakeLabd{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got = append(f.got, body)
		f.path = append(f.path, r.URL.Path+"?"+r.URL.RawQuery)
		f.mu.Unlock()
		sum := sha256.Sum256(body)
		json.NewEncoder(w).Encode(map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(body)})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLabd) builder() *builder {
	rt := f.srv.Client().Transport
	return &builder{server: f.srv.URL, token: "t", rt: rt, http: labhttp.Client(rt, time.Minute)}
}

func (f *fakeLabd) uploaded(content string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, g := range f.got {
		if bytes.Contains(g, []byte(content)) {
			return true
		}
	}
	return false
}

// collect is what run does once a build ends: these are its callers' cases.
func TestCollect(t *testing.T) {
	host := t.TempDir()
	marker := filepath.Join(host, "token")
	os.WriteFile(marker, []byte("HOST-ONLY-MARKER"), 0o600)
	scratch := func(files map[string]string, links map[string]string) string {
		d := t.TempDir()
		for name, content := range files {
			os.MkdirAll(filepath.Dir(filepath.Join(d, name)), 0o755)
			os.WriteFile(filepath.Join(d, name), []byte(content), 0o644)
		}
		for name, target := range links {
			os.MkdirAll(filepath.Dir(filepath.Join(d, name)), 0o755)
			os.Symlink(target, filepath.Join(d, name))
		}
		return d
	}
	bd := api.Build{ID: "b1031-120000-abcd", Kind: api.BuildPackage}
	push := func(string) {}

	// A Mesa package build: no release, no kernel, two packages and the PKGBUILD.
	f := newFakeLabd(t)
	var res api.BuildResult
	f.builder().collect(context.Background(), bd, scratch(map[string]string{
		"out/mesa-aurora-1:26.3.0-1-aarch64.pkg.tar.zst":   "mesa",
		"out/vulkan-aurora-1:26.3.0-1-aarch64.pkg.tar.zst": "vulkan",
		"out/PKGBUILD": "pkgbuild",
	}, nil), true, &res, push)
	if res.Error != "" || res.Release != "" || res.Artifact != "" || len(res.Files) != 3 {
		t.Fatalf("Mesa package build: %+v", res)
	}
	for _, p := range f.path {
		if p != "/api/builder/artifacts?build="+bd.ID {
			t.Errorf("upload %s", p)
		}
	}

	// A kernel package build: release and kernel name, the kernel package is the artifact.
	f = newFakeLabd(t)
	res = api.BuildResult{}
	f.builder().collect(context.Background(), bd, scratch(map[string]string{
		"release": "7.2.11-6-2-ARCH\n", "kernel": "linux-aurora-7.2.11-2-aarch64.pkg.tar.zst\n",
		"out/linux-aurora-7.2.11-2-aarch64.pkg.tar.zst": "kernel pkg",
	}, nil), true, &res, push)
	if res.Error != "" || res.Release != "7.2.11-6-2-ARCH" || res.Artifact == "" || len(res.Files) != 1 {
		t.Fatalf("kernel package build: %+v", res)
	}

	// A kernel-kind build needs its release.
	f = newFakeLabd(t)
	res = api.BuildResult{}
	f.builder().collect(context.Background(), api.Build{ID: bd.ID}, scratch(map[string]string{"kernel.tar.zst": "k"}, nil), false, &res, push)
	if res.Error == "" || len(f.got) != 0 {
		t.Fatalf("kernel build without a release: %+v, %d uploads", res, len(f.got))
	}
	f = newFakeLabd(t)
	res = api.BuildResult{}
	f.builder().collect(context.Background(), api.Build{ID: bd.ID}, scratch(map[string]string{"kernel.tar.zst": "k", "release": "7.2.11-lab1-ab12"}, nil), false, &res, push)
	if res.Error != "" || res.Release != "7.2.11-lab1-ab12" || res.Artifact == "" {
		t.Fatalf("kernel build: %+v", res)
	}

	// Links to a host file, anywhere among the outputs, fail the build and upload nothing of it.
	for name, c := range map[string]struct {
		pkg   bool
		files map[string]string
		links map[string]string
	}{
		"package leaf":     {true, map[string]string{"out/a-1-1-aarch64.pkg.tar.zst": "a"}, map[string]string{"out/z-1-1-aarch64.pkg.tar.zst": marker}},
		"package release":  {true, map[string]string{"out/a-1-1-aarch64.pkg.tar.zst": "a"}, map[string]string{"release": marker}},
		"package kernel":   {true, map[string]string{"out/a-1-1-aarch64.pkg.tar.zst": "a"}, map[string]string{"kernel": marker}},
		"package out dir":  {true, nil, map[string]string{"out": host}},
		"kernel tarball":   {false, map[string]string{"release": "r"}, map[string]string{"kernel.tar.zst": marker}},
		"kernel release":   {false, map[string]string{"kernel.tar.zst": "k"}, map[string]string{"release": marker}},
		"dangling release": {true, map[string]string{"out/a-1-1-aarch64.pkg.tar.zst": "a"}, map[string]string{"release": filepath.Join(host, "none")}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeLabd(t)
			var res api.BuildResult
			f.builder().collect(context.Background(), bd, scratch(c.files, c.links), c.pkg, &res, push)
			if res.Error == "" {
				t.Errorf("no error: %+v", res)
			}
			if f.uploaded("HOST-ONLY-MARKER") || strings.Contains(res.Release, "MARKER") {
				t.Error("the host marker left the host")
			}
		})
	}
}

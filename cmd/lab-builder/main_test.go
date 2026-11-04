package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

func TestPackageJobs(t *testing.T) {
	for _, c := range []struct{ flag, cpus, want string }{
		{"", "10", "10"}, {"", "4", "4"}, {"4", "10", "4"}, {"007", "10", "7"}, {"1024", "10", "1024"},
	} {
		if got, err := packageJobs(c.flag, c.cpus); err != nil || got != c.want {
			t.Errorf("packageJobs(%q, %q) = %q, %v; want %q", c.flag, c.cpus, got, err, c.want)
		}
	}
	for _, c := range []struct{ flag, cpus string }{{"0", "10"}, {"-1", "10"}, {"x", "10"}, {"1025", "10"}, {"", "x"}, {"4 5", "10"}} {
		if got, err := packageJobs(c.flag, c.cpus); err == nil {
			t.Errorf("packageJobs(%q, %q) = %q, want an error", c.flag, c.cpus, got)
		}
	}
}

// Only package builds get the job count; neither kind gets anything of lab-builder's own.
func TestBuildEnv(t *testing.T) {
	b := &builder{pkgJobs: "4"}
	src := api.Source{Repo: "https://example.invalid/r", SHA: strings.Repeat("a", 40)}
	pkg := strings.Join(b.buildEnv(api.Build{Kind: api.BuildPackage, Source: src, Pkgrel: "2"}, ""), " ")
	if pkg != "SRC_REPO=https://example.invalid/r SRC_SHA="+src.SHA+" PKGREL=2 OMARCHY_BUILD_JOBS=4" {
		t.Errorf("package env %q", pkg)
	}
	kern := strings.Join(b.buildEnv(api.Build{Source: src}, "-lab1-ab12"), " ")
	if kern != "URL=https://example.invalid/r SHA="+src.SHA+" LABVER=-lab1-ab12" {
		t.Errorf("kernel env %q", kern)
	}
	if strings.Contains(pkg+kern, "MACLAB_") || strings.Contains(pkg+kern, "bldr_") {
		t.Error("a build env carries lab-builder's own settings")
	}
}

// pkgbuild runs makepkg through sudo, which resets the environment: the job
// count reaches makepkg only because as_build passes it on.
func TestPkgbuildForwardsJobs(t *testing.T) {
	raw, err := os.ReadFile("../../builder/pkg/pkgbuild")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "[[ -z ${OMARCHY_BUILD_JOBS")
	j := strings.Index(s[max(i, 0):], "\n}\n")
	if i < 0 || j < 0 {
		t.Fatal("pkgbuild has no job-count check and as_build")
	}
	part := s[i : i+j+3]
	dir := t.TempDir()
	// The image's sudo: the command after "-u build", in a reset environment.
	os.WriteFile(filepath.Join(dir, "sudo"), []byte("#!/bin/bash\n[ \"$1\" = -u ] && shift 2\nexec /usr/bin/env -i \"$@\"\n"), 0o755)
	run := func(jobs *string) (string, error) {
		script := "set -euo pipefail\nC=/c W=/w\nfail() { echo \"error: $*\"; exit 1; }\n" + part +
			"\nas_build printenv OMARCHY_BUILD_JOBS || echo '<unset>'\n"
		cmd := exec.Command("/bin/bash", "-c", script)
		cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
		if jobs != nil {
			cmd.Env = append(cmd.Env, "OMARCHY_BUILD_JOBS="+*jobs)
		}
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	four, zero, bad := "4", "0", "4;id"
	if out, err := run(&four); err != nil || out != "4" {
		t.Errorf("jobs 4: makepkg saw %q (%v)", out, err)
	}
	if out, err := run(nil); err != nil || out != "" {
		t.Errorf("no jobs: makepkg saw %q (%v); want empty, so the recipe keeps its default", out, err)
	}
	for _, v := range []*string{&zero, &bad} {
		if out, err := run(v); err == nil || !strings.Contains(out, "is not a job count") {
			t.Errorf("jobs %q: %q %v", *v, out, err)
		}
	}
}

// bash parses a script one command at a time as it runs it, so a syntax error
// late in pkgbuild fails every package build at that line, and the test above,
// which runs only one part, never sees it. 7de96c65's jobs line did this: in
// bash (not in POSIX mode), an apostrophe inside "${X:-...}" opens a quote.
// The whole file must parse, and the check must catch that line.
func TestPkgbuildParses(t *testing.T) {
	const file = "../../builder/pkg/pkgbuild"
	ver, err := exec.Command("/bin/bash", "-c", `echo "$BASH_VERSION"`).Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bash %s", strings.TrimSpace(string(ver)))
	parse := func(path string) (string, error) {
		out, err := exec.Command("/bin/bash", "-n", path).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if out, err := parse(file); err != nil || out != "" {
		t.Errorf("bash -n pkgbuild: %v %s", err, out)
	}

	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines, n := strings.Split(string(raw), "\n"), 0
	for i, l := range lines {
		if strings.HasPrefix(l, `echo "jobs: `) {
			lines[i] = `echo "jobs: OMARCHY_BUILD_JOBS=${OMARCHY_BUILD_JOBS:-(unset: the recipe's default)}"`
			n++
		}
	}
	if n != 1 {
		t.Fatalf("pkgbuild has %d jobs lines, want 1", n)
	}
	old := filepath.Join(t.TempDir(), "pkgbuild")
	if err := os.WriteFile(old, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := parse(old); err == nil || !strings.Contains(out, "unexpected EOF") {
		t.Errorf("bash -n passed pkgbuild with 7de96c65's jobs line: %v %q", err, out)
	}
}

// fakeDocker is a docker CLI that logs each call and keeps one container's
// /io in a directory: cp copies in and out of it, and start runs a pretend
// kbuild there, which fails when the config says "fail".
const fakeDocker = `#!/bin/sh
state=$(dirname "$0")/state
echo "$*" >> "$state/calls"
[ "$1" = --context ] && shift 2
case "$1" in
create) mkdir -p "$state/io" ;;
cp)
  case "$2" in
  *:/io/.) cp -R "$state/io/." "$3" ;;
  *) cp -R "$2" "$state/io-in" && cp -R "$state/io-in/." "$state/io" ;;
  esac ;;
start)
  echo "kbuild: building"
  grep -q fail "$state/io/config" && { echo "kbuild: failed" >&2; exit 3; }
  echo 7.2.0-lab-x > "$state/io/release"
  echo kernel > "$state/io/kernel.tar.zst" ;;
esac
`

func dockerBuilder(t *testing.T) (*builder, string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.Mkdir(filepath.Join(bin, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(bin, "docker")
	if err := os.WriteFile(p, []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	return &builder{runtime: "docker", docker: p, dockerContext: "colima", cpus: "12", mem: "24G"}, filepath.Join(bin, "state")
}

func calls(t *testing.T, state string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(state, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// With --runtime docker, /io is copied into the container and back out, never
// bind-mounted: Colima shares only $HOME into its VM, and a bind mount of
// anything else is silently empty (malik-na/maclab#45).
func TestDockerBuildCopiesIOInAndOut(t *testing.T) {
	b, state := dockerBuilder(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config"), []byte("CONFIG_ARM64=y\n"), 0o644)
	var out bytes.Buffer
	if err := b.buildVM(context.Background(), "maclab-b1", "maclab-kbuild:1", "maclab-cache", dir, []string{"URL=u", "SHA=s"}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if rel, _ := os.ReadFile(filepath.Join(dir, "release")); strings.TrimSpace(string(rel)) != "7.2.0-lab-x" {
		t.Fatalf("release %q not copied out", rel)
	}
	if _, err := os.Stat(filepath.Join(dir, "kernel.tar.zst")); err != nil {
		t.Fatal("artifact not copied out:", err)
	}
	if !strings.Contains(out.String(), "kbuild: building") {
		t.Fatalf("build output not streamed: %q", out.String())
	}
	want := []string{
		"--context colima create --name maclab-b1 --cpus 12 --memory 24G -v maclab-cache:/cache -e URL=u -e SHA=s maclab-kbuild:1",
		"--context colima cp " + dir + "/. maclab-b1:/io",
		"--context colima start --attach maclab-b1",
		"--context colima cp maclab-b1:/io/. " + dir,
		"--context colima rm --force maclab-b1",
	}
	if got := calls(t, state); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("docker calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A kbuild that fails is kbuild's error, and the container is removed anyway.
func TestDockerBuildFailureRemovesTheContainer(t *testing.T) {
	b, state := dockerBuilder(t)
	b.dockerContext = ""
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config"), []byte("fail\n"), 0o644)
	var out bytes.Buffer
	err := b.buildVM(context.Background(), "maclab-b2", "maclab-kbuild:1", "maclab-cache", dir, nil, &out)
	if !errors.As(err, new(*exec.ExitError)) {
		t.Fatalf("err %v, want kbuild's exit status", err)
	}
	if !strings.Contains(out.String(), "kbuild: failed") {
		t.Fatalf("kbuild's error not streamed: %q", out.String())
	}
	got := calls(t, state)
	if last := got[len(got)-1]; last != "rm --force maclab-b2" {
		t.Fatalf("last docker call %q, want the container removed", last)
	}
	for _, c := range got {
		if strings.HasPrefix(c, "cp maclab-b2:") {
			t.Fatalf("copied the outputs of a failed build: %q", c)
		}
	}
}

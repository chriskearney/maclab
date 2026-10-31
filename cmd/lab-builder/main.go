// Command lab-builder builds kernels for the lab on a controller Mac. Each
// build runs `kbuild` in an Apple `container` micro-VM; the only state it
// keeps is one size-capped cache volume.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"errors"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
	"io/fs"
)

type builder struct {
	server, token, host string
	prefix              string // build VMs are named <prefix>-<build id>
	image, volume       string
	pkgImage, pkgVolume string // package builds (makepkg on Arch Linux ARM); empty image: kernel builds only
	cpus, mem           string
	io                  string
	githubToken         string // file holding a GitHub token for private repos
	asUser              *user.User
	http                *http.Client
	rt                  http.RoundTripper // every request to labd, with labhttp's policy
}

func main() {
	home, _ := os.UserHomeDir()
	hostname, _ := os.Hostname()
	b := &builder{}
	flag.StringVar(&b.server, "server", os.Getenv("MACLAB_URL"), "labd URL, e.g. https://labd.example.com/maclab")
	caFile := flag.String("ca-file", os.Getenv("MACLAB_CA_FILE"), "PEM file of CA certificates for labd's https certificate, when the system doesn't trust it")
	plain := flag.Bool("allow-plain-http", os.Getenv("MACLAB_ALLOW_PLAIN_HTTP") == "1", "allow an http:// labd on another machine: the builder token then crosses the network unencrypted")
	flag.StringVar(&b.token, "token", "", "builder token; it shows in ps, so prefer --token-file (or MACLAB_BUILDER_TOKEN)")
	tokenFile := flag.String("token-file", "", "file holding the builder token (from lab builder add -o, or labd's builder.token); readable by its owner only")
	flag.StringVar(&b.host, "name", strings.Split(hostname, ".")[0], "name shown in the lab when using the shared builder.token (a named builder's name comes from labd)")
	flag.StringVar(&b.prefix, "container-prefix", "maclab", "build VMs are named <prefix>-<build id>; give a second lab-builder on this Mac its own")
	flag.StringVar(&b.image, "image", "maclab-kbuild:1", "builder image")
	flag.StringVar(&b.volume, "volume", "maclab-cache", "cache volume (create with: container volume create -s 40G maclab-cache)")
	flag.StringVar(&b.pkgImage, "pkg-image", "maclab-pkgbuild:1", "package builder image (builder/pkg); empty to take kernel builds only")
	flag.StringVar(&b.pkgVolume, "pkg-volume", "maclab-pkgcache", "package build volume; needs room for a whole kernel tree (create with: container volume create -s 120G maclab-pkgcache)")
	flag.StringVar(&b.cpus, "cpus", "10", "")
	flag.StringVar(&b.mem, "memory", "16G", "")
	flag.StringVar(&b.io, "io", "", "scratch dir for inputs and the artifact; emptied after each build (default ~/maclab/io of the container user)")
	flag.StringVar(&b.githubToken, "github-token-file", "", "GitHub token for cloning private github.com repos (default ~/.config/maclab/github-token of the container user)")
	as := flag.String("as-user", "", "run container as this user, in their login session. Lets lab-builder run as a root daemon, which macOS Local Network privacy does not block")
	flag.Parse()
	tok, err := builderToken(b.token, *tokenFile, os.Getenv("MACLAB_BUILDER_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	b.token = tok
	os.Unsetenv("MACLAB_BUILDER_TOKEN") // so nothing started from here inherits it
	if !rePrefix.MatchString(b.prefix) {
		log.Fatalf("--container-prefix %q: letters, digits, dots, dashes and underscores, up to 32", b.prefix)
	}
	b.server = strings.TrimRight(b.server, "/")
	if err := labhttp.CheckServer(b.server, *plain); err != nil {
		log.Fatal(err)
	}
	pol := labhttp.Policy{AllowPlainHTTP: *plain}
	if *caFile != "" {
		ca, err := labhttp.ReadCAFile(*caFile)
		if err != nil {
			log.Fatal(err)
		}
		pol.CAPEM = ca
	}
	rt, err := pol.Transport()
	if err != nil {
		log.Fatal(err)
	}
	b.rt, b.http = rt, labhttp.Client(rt, 60*time.Second)
	if *as != "" {
		u, err := user.Lookup(*as)
		if err != nil {
			log.Fatal(err)
		}
		b.asUser, home = u, u.HomeDir
	}
	if b.io == "" {
		b.io = filepath.Join(home, "maclab", "io")
	}
	if b.githubToken == "" {
		b.githubToken = filepath.Join(home, ".config", "maclab", "github-token")
	}
	if b.server == "" || b.token == "" {
		log.Fatal("need --server and a token (--token-file)")
	}
	b.server = strings.TrimRight(b.server, "/")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	b.whoami(ctx)
	log.Printf("lab-builder %s: image %s, volume %s, %s cpus, %s, build VMs %s-*", b.host, b.image, b.volume, b.cpus, b.mem, b.prefix)
	kinds := "kernel"
	if b.pkgImage != "" {
		kinds += ",package"
		log.Printf("package builds: image %s, volume %s", b.pkgImage, b.pkgVolume)
	}
	for ctx.Err() == nil {
		var a api.BuildAssignment
		code, err := b.call(ctx, "POST", "/api/builder/poll?host="+b.host+"&kinds="+kinds, nil, &a)
		if err != nil {
			log.Printf("poll: %v", err)
			sleep(ctx, 10*time.Second)
			continue
		}
		if code == 204 {
			continue
		}
		b.run(ctx, a)
	}
}

// container runs the container CLI, in the configured user's session if any.
func (b *builder) container(ctx context.Context, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if b.asUser == nil {
		cmd = exec.CommandContext(ctx, "/usr/local/bin/container", args...)
	} else {
		full := append([]string{"asuser", b.asUser.Uid, "sudo", "-n", "-u", b.asUser.Username, "/usr/local/bin/container"}, args...)
		cmd = exec.CommandContext(ctx, "/bin/launchctl", full...)
	}
	cmd.Env = childEnv(os.Environ())
	return cmd
}

var rePrefix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)

// builderToken picks the builder token: --token-file, else --token, else
// MACLAB_BUILDER_TOKEN. A token file must be readable by its owner only.
func builderToken(flagTok, file, env string) (string, error) {
	if file != "" {
		st, err := os.Stat(file)
		if err != nil {
			return "", err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("%s can be read by others than its owner (mode %o): chmod 600 it", file, st.Mode().Perm())
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return "", fmt.Errorf("%s holds no token", file)
		}
		return tok, nil
	}
	if flagTok != "" {
		log.Printf("warning: a token in --token shows in ps; use --token-file")
		return flagTok, nil
	}
	return strings.TrimSpace(env), nil
}

// childEnv is the environment for what lab-builder starts: its own, without
// any MACLAB_ variable (the builder token among them).
func childEnv(env []string) []string {
	var out []string
	for _, e := range env {
		if !strings.HasPrefix(e, "MACLAB_") {
			out = append(out, e)
		}
	}
	return out
}

// whoami asks labd who it takes this builder for, and stops if labd refuses
// the token. A labd that can't be reached now is tried again by the poll loop.
func (b *builder) whoami(ctx context.Context) {
	var me api.BuilderSelf
	code, err := b.call(ctx, "GET", "/api/builder/self", nil, &me)
	switch {
	case code == 401 || code == 403:
		log.Fatalf("labd at %s refused this builder's token: %v", b.server, err)
	case err != nil:
		log.Printf("labd at %s: %v (polling anyway)", b.server, err)
	case me.Shared:
		log.Printf("labd at %s takes this builder for its own (the shared builder.token), as %s", b.server, b.host)
	default:
		b.host = me.Name
		log.Printf("labd at %s knows this builder as %s (%s)", b.server, me.Name, strings.Join(me.Kinds, ","))
	}
}

func (b *builder) chown(path string) {
	if b.asUser != nil {
		uid, _ := strconv.Atoi(b.asUser.Uid)
		gid, _ := strconv.Atoi(b.asUser.Gid)
		os.Chown(path, uid, gid)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (b *builder) call(ctx context.Context, method, path string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequestWithContext(ctx, method, b.server+path, rd)
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return resp.StatusCode, json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

func (b *builder) download(ctx context.Context, sha, dst string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", b.server+"/api/builder/artifacts/"+sha, nil)
	req.Header.Set("Authorization", "Bearer "+b.token)
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("config %s: %s", sha, resp.Status)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func (b *builder) upload(ctx context.Context, build string, f *os.File) (string, error) {
	defer f.Close()
	req, _ := http.NewRequestWithContext(ctx, "POST", b.server+"/api/builder/artifacts?build="+url.QueryEscape(build), f)
	req.Header.Set("Authorization", "Bearer "+b.token)
	resp, err := labhttp.Client(b.rt, 30*time.Minute).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct{ SHA256 string }
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("upload: %s", strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.SHA256, nil
}

// run executes one build and always reports back, success or not.
func (b *builder) run(ctx context.Context, a api.BuildAssignment) {
	bd := a.Build
	log.Printf("build %s (%s): %s %s", bd.ID, orStr(bd.Kind, "kernel"), bd.Source.Repo, bd.Source.SHA)
	t0 := time.Now()
	dir := filepath.Join(b.io, bd.ID)
	os.RemoveAll(dir)
	os.MkdirAll(dir, 0o755)
	defer os.RemoveAll(dir) // nothing accumulates on the host
	b.chown(dir)

	// Lines go to labd in batches; a cancel from labd stops the container.
	var mu sync.Mutex
	var pending []string
	push := func(l string) { mu.Lock(); pending = append(pending, l); mu.Unlock() }
	bctx, cancel := context.WithCancel(ctx)
	defer cancel()
	flushed := make(chan struct{})
	flush := func() {
		mu.Lock()
		lines := pending
		pending = nil
		mu.Unlock()
		var r struct{ Cancel bool }
		if _, err := b.call(ctx, "POST", "/api/builder/builds/"+bd.ID+"/progress", api.BuildProgress{Lines: lines}, &r); err != nil {
			log.Printf("progress: %v", err)
			mu.Lock()
			pending = append(lines, pending...)
			mu.Unlock()
		}
		if r.Cancel {
			cancel()
		}
	}
	go func() {
		defer close(flushed)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-bctx.Done():
				return
			case <-t.C:
				flush()
			}
		}
	}()

	result := api.BuildResult{}
	defer func() {
		cancel()
		<-flushed
		flush()
		result.Seconds = time.Since(t0).Seconds()
		if _, err := b.call(ctx, "POST", "/api/builder/builds/"+bd.ID+"/done", result, nil); err != nil {
			log.Printf("done: %v", err)
		}
		log.Printf("build %s finished in %s: %s%s", bd.ID, time.Since(t0).Round(time.Second), result.Release, result.Error)
	}()

	pkg := bd.Kind == api.BuildPackage
	image, volume := b.image, b.volume
	env := []string{"URL=" + bd.Source.Repo, "SHA=" + bd.Source.SHA, "LABVER=" + a.LabVer}
	input, inputSHA := "config", bd.ConfigSHA
	if pkg {
		image, volume = b.pkgImage, b.pkgVolume
		env = []string{"SRC_REPO=" + bd.Source.Repo, "SRC_SHA=" + bd.Source.SHA, "PKGREL=" + bd.Pkgrel}
		input, inputSHA = "recipe.tar", bd.Recipe
		line := fmt.Sprintf("builder %s: packages from %s", b.host, orStr(bd.RecipeDir, "recipe "+bd.Recipe[:12]))
		if bd.Source.SHA != "" {
			line += fmt.Sprintf(" at %s @ %s", bd.Source.Repo, bd.Source.SHA)
		}
		push(line)
	} else {
		push(fmt.Sprintf("builder %s: %s @ %s", b.host, bd.Source.Repo, bd.Source.SHA))
	}
	if err := b.download(ctx, inputSHA, filepath.Join(dir, input)); err != nil {
		result.Error = err.Error()
		return
	}
	b.chown(filepath.Join(dir, input))
	// Private GitHub repos: the token goes into this build's scratch dir only
	// (never onto a command line) and kbuild deletes it right after fetching.
	if strings.HasPrefix(bd.Source.Repo, "https://github.com/") {
		if tok, err := os.ReadFile(b.githubToken); err == nil && len(strings.TrimSpace(string(tok))) > 0 {
			p := filepath.Join(dir, "github-token")
			if err := os.WriteFile(p, []byte(strings.TrimSpace(string(tok))), 0o600); err == nil {
				b.chown(p)
			}
		}
	}
	vm := b.prefix + "-" + bd.ID
	args := []string{"run", "--rm", "--name", vm, "--cpus", b.cpus, "--memory", b.mem,
		"-v", volume + ":/cache", "-v", dir + ":/io"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	cmd := b.container(bctx, append(args, image)...)
	cmd.WaitDelay = 10 * time.Second
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		result.Error = "starting the build VM: " + err.Error()
		return
	}
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			l := sc.Text()
			if strings.HasPrefix(l, "[") && strings.Contains(l, "/6]") {
				continue // container's own image-pull progress
			}
			push(l)
		}
	}()
	err := cmd.Wait()
	pw.Close()
	if bctx.Err() != nil {
		b.container(context.Background(), "stop", vm).Run()
		b.container(context.Background(), "delete", "--force", vm).Run()
		result.Error = "canceled"
		return
	}
	if err != nil {
		result.Error = "kbuild: " + err.Error()
		return
	}
	b.collect(ctx, bd, dir, pkg, &result, push)
}

// collect reads what a finished build left in its scratch dir and uploads
// it. kbuild always writes the release; pkgbuild writes one only when a
// package holds a kernel, so a package build without one (Mesa, m1n1)
// reports none.
func (b *builder) collect(ctx context.Context, bd api.Build, dir string, pkg bool, result *api.BuildResult, push func(string)) {
	out, err := openOutputs(dir)
	if err != nil {
		result.Error = err.Error()
		return
	}
	defer out.Close()
	rel, err := out.small("release")
	switch {
	case err == nil:
		result.Release = rel
	case pkg && errors.Is(err, fs.ErrNotExist):
	default:
		result.Error = err.Error()
		return
	}
	push("@@stage upload")
	if pkg {
		b.uploadPackages(ctx, bd, out, result, push)
		return
	}
	f, _, err := out.regular("kernel.tar.zst")
	if err != nil {
		result.Error = err.Error()
		return
	}
	sha, err := b.upload(ctx, bd.ID, f)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Artifact = sha
}

// uploadPackages uploads everything pkgbuild left in out/. The package that
// holds a vmlinuz becomes the build's artifact, so `lab run` can boot it.
func (b *builder) uploadPackages(ctx context.Context, bd api.Build, out *outputs, result *api.BuildResult, push func(string)) {
	kernel, err := out.small("kernel")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		result.Error = err.Error()
		return
	}
	ents, err := out.list("out")
	if err != nil {
		result.Error = "no outputs: " + err.Error()
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		f, st, err := out.regular("out/" + e.Name())
		if err != nil {
			result.Error = err.Error()
			return
		}
		sha, err := b.upload(ctx, bd.ID, f)
		if err != nil {
			result.Error = err.Error()
			return
		}
		push(fmt.Sprintf("uploaded %s sha256 %s", e.Name(), sha))
		result.Files = append(result.Files, api.BuildFile{Name: e.Name(), SHA256: sha, Size: st.Size()})
		if e.Name() == kernel {
			result.Artifact = sha
		}
	}
	if len(result.Files) == 0 {
		result.Error = "makepkg made no packages"
	}
}

// outputs is a build's scratch dir as lab-builder reads what the build left
// there. The build VM shares that dir, so any name in it may be a link the VM
// made to a file of this host: every output is resolved inside the dir
// (os.Root), never through a symlink, and only as a regular file.
type outputs struct{ root *os.Root }

func openOutputs(dir string) (*outputs, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &outputs{r}, nil
}

func (o *outputs) Close() error { return o.root.Close() }

// regular opens name for reading if it is a regular file, reached through no
// symlink at all.
func (o *outputs) regular(name string) (*os.File, fs.FileInfo, error) {
	if err := o.noLinks(name); err != nil {
		return nil, nil, err
	}
	st, err := o.root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("build output %s is not a regular file (%s)", name, st.Mode().Type())
	}
	f, err := o.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	fst, err := f.Stat()
	if err != nil || !fst.Mode().IsRegular() || !os.SameFile(st, fst) {
		f.Close()
		return nil, nil, fmt.Errorf("build output %s changed while it was opened", name)
	}
	if n, ok := links(fst); !ok || n != 1 {
		f.Close()
		return nil, nil, fmt.Errorf("build output %s has %d links; an output is one file of its own", name, n)
	}
	return f, fst, nil
}

// links is a file's hard-link count.
func links(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}

// noLinks refuses a name any of whose directories is a symlink.
func (o *outputs) noLinks(name string) error {
	dir := filepath.Dir(filepath.Clean(name))
	for dir != "." && dir != "/" {
		st, err := o.root.Lstat(dir)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return fmt.Errorf("build output dir %s is not a directory (%s)", dir, st.Mode().Type())
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

// small reads a short text output (release, kernel), trimmed.
func (o *outputs) small(name string) (string, error) {
	f, _, err := o.regular(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(b) > 4096 {
		return "", fmt.Errorf("build output %s is longer than 4096 bytes", name)
	}
	return strings.TrimSpace(string(b)), nil
}

// list lists a directory of outputs, which must itself be a directory and
// not a link.
func (o *outputs) list(name string) ([]fs.DirEntry, error) {
	st, err := o.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("build output %s is not a directory (%s)", name, st.Mode().Type())
	}
	if err := o.noLinks(name + "/x"); err != nil {
		return nil, err
	}
	d, err := o.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.ReadDir(-1)
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

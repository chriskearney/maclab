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
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
)

type builder struct {
	server, token, host string
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
	flag.StringVar(&b.token, "token", os.Getenv("MACLAB_BUILDER_TOKEN"), "builder token (labd data dir: builder.token)")
	flag.StringVar(&b.host, "name", strings.Split(hostname, ".")[0], "name shown in the lab")
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
		log.Fatal("need --server and --token")
	}
	b.server = strings.TrimRight(b.server, "/")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("lab-builder %s: image %s, volume %s, %s cpus, %s", b.host, b.image, b.volume, b.cpus, b.mem)
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
	if b.asUser == nil {
		return exec.CommandContext(ctx, "/usr/local/bin/container", args...)
	}
	full := append([]string{"asuser", b.asUser.Uid, "sudo", "-n", "-u", b.asUser.Username, "/usr/local/bin/container"}, args...)
	return exec.CommandContext(ctx, "/bin/launchctl", full...)
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

func (b *builder) upload(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	req, _ := http.NewRequestWithContext(ctx, "POST", b.server+"/api/builder/artifacts", f)
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
	args := []string{"run", "--rm", "--name", "maclab-" + bd.ID, "--cpus", b.cpus, "--memory", b.mem,
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
		b.container(context.Background(), "stop", "maclab-"+bd.ID).Run()
		b.container(context.Background(), "delete", "--force", "maclab-"+bd.ID).Run()
		result.Error = "canceled"
		return
	}
	if err != nil {
		result.Error = "kbuild: " + err.Error()
		return
	}
	rel, _ := os.ReadFile(filepath.Join(dir, "release"))
	result.Release = strings.TrimSpace(string(rel))
	push("@@stage upload")
	b.uploadPackages(ctx, dir, &result, push)
}

// uploadPackages uploads packaged outputs from out/. The file named in kernel
// becomes the boot artifact; the other files remain named build outputs.
func (b *builder) uploadPackages(ctx context.Context, dir string, result *api.BuildResult, push func(string)) {
	kernel, _ := os.ReadFile(filepath.Join(dir, "kernel"))
	ents, err := os.ReadDir(filepath.Join(dir, "out"))
	if err != nil {
		result.Error = "no outputs: " + err.Error()
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, "out", e.Name())
		st, err := os.Stat(p)
		if err != nil {
			result.Error = err.Error()
			return
		}
		sha, err := b.upload(ctx, p)
		if err != nil {
			result.Error = err.Error()
			return
		}
		push(fmt.Sprintf("uploaded %s sha256 %s", e.Name(), sha))
		result.Files = append(result.Files, api.BuildFile{Name: e.Name(), SHA256: sha, Size: st.Size()})
		if e.Name() == strings.TrimSpace(string(kernel)) {
			result.Artifact = sha
		}
	}
	if len(result.Files) == 0 {
		result.Error = "build made no outputs"
	}
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

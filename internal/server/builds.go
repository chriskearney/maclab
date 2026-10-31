package server

// Kernel builds from source. A builder host (lab-builder on the controller
// Mac) long-polls for work, streams its log here, and uploads the artifact.
// Builds are keyed by what determines the kernel, so the same commit and
// config is only ever built once.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// recipe changes whenever kbuild changes what it produces, so old artifacts
// stop matching; pkgRecipe does the same for the package builder.
const (
	recipe    = "kbuild-1"
	pkgRecipe = "pkgbuild-1"
)

type buildMgr struct {
	s        *Server
	mu       sync.Mutex
	changed  chan struct{}
	builders map[string]time.Time // host -> last poll
	cancel   map[string]bool
	beat     map[string]time.Time // build id -> last progress
}

func newBuildMgr(s *Server) *buildMgr {
	return &buildMgr{s: s, changed: make(chan struct{}), builders: map[string]time.Time{}, cancel: map[string]bool{}, beat: map[string]time.Time{}}
}

func (m *buildMgr) bump() {
	m.mu.Lock()
	close(m.changed)
	m.changed = make(chan struct{})
	m.mu.Unlock()
}

func (m *buildMgr) wait(ctx context.Context, d time.Duration) {
	m.mu.Lock()
	ch := m.changed
	m.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-ch:
	case <-m.s.clock().After(d):
	}
}

func (s *Server) buildDir(id string) string { return filepath.Join(s.cfg.DataDir, "builds", id) }

func (s *Server) getBuild(id string) (*api.Build, error) {
	l, err := s.store.builds(`id=?`, id)
	if err != nil {
		return nil, err
	}
	if len(l) == 0 {
		return nil, fmt.Errorf("no build %s", id)
	}
	return l[0], nil
}

func (s *Server) saveBuild(b *api.Build) {
	b.Updated = s.now()
	if err := s.store.saveBuild(b); err != nil {
		s.log.Printf("save build %s: %v", b.ID, err)
	}
	s.hub.publish("build", "", b)
	s.builds.bump()
}

// deviceConfig returns the artifact sha of a Mac's running kernel config,
// fetching it from the agent the first time for each kernel release.
func (s *Server) deviceConfig(ctx context.Context, name string) (string, error) {
	v := s.dev(name)
	if v == nil {
		return "", fmt.Errorf("no device %q", name)
	}
	d := v.snapshot()
	kernel := d.KnownGood
	if kernel == "" {
		kernel = d.Kernel
	}
	if sha := s.store.configFor(name, kernel); sha != "" {
		if _, err := os.Stat(s.artifactPath(sha)); err == nil {
			return sha, nil
		}
	}
	if d.Kernel != kernel || d.Health.JobTag != "" {
		return "", fmt.Errorf("%s is not on its known-good kernel right now, so its config can't be read; try again when it's back", name)
	}
	var text string
	if err := v.call(ctx, api.CmdConfig, "", nil, time.Minute, &text); err != nil {
		return "", fmt.Errorf("reading %s's kernel config: %w", name, err)
	}
	sha, _, err := s.storeArtifact(strings.NewReader(text))
	if err != nil {
		return "", err
	}
	s.store.setConfig(name, kernel, sha)
	return sha, nil
}

func buildKey(src api.Source, configSHA string) string {
	h := sha256.Sum256([]byte(src.Repo + "\n" + src.SHA + "\n" + configSHA + "\n" + recipe))
	return hex.EncodeToString(h[:])
}

func packageKey(src api.Source, recipeSHA, pkgrel string) string {
	h := sha256.Sum256([]byte("package\n" + recipeSHA + "\n" + src.Repo + "\n" + src.SHA + "\n" + pkgrel + "\n" + pkgRecipe))
	return hex.EncodeToString(h[:])
}

// EnsureBuild resolves the source and returns a build of it: an existing one
// with the same key when there is one, otherwise a newly queued build.
func (s *Server) EnsureBuild(ctx context.Context, req api.BuildRequest) (*api.Build, error) {
	if req.Recipe != "" {
		return s.ensurePackageBuild(ctx, req)
	}
	src, err := parseSource(req.Source)
	if err != nil {
		return nil, err
	}
	if src, err = resolve(ctx, src); err != nil {
		return nil, err
	}
	cfg := req.Config
	switch {
	case cfg != "":
		if _, err := os.Stat(s.artifactPath(cfg)); err != nil {
			return nil, fmt.Errorf("config artifact %s not uploaded", cfg)
		}
	case req.Device != "":
		if cfg, err = s.deviceConfig(ctx, req.Device); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("say whose config to build with: a device, or a config artifact")
	}
	now := s.now()
	b := &api.Build{ID: "b" + now.Format("0102-150405") + "-" + randHex(2), Key: buildKey(src, cfg), Source: src,
		Device: req.Device, ConfigSHA: cfg, State: api.BuildQueued, Created: now, Updated: now}
	if req.Config != "" {
		b.Device, b.ConfigName = "", req.ConfigName // built with the uploaded config, not a Mac's
	}
	return s.queueBuild(b, req.Force)
}

// ensurePackageBuild queues a makepkg run of an uploaded recipe, optionally
// pointed at another commit and pkgrel.
func (s *Server) ensurePackageBuild(ctx context.Context, req api.BuildRequest) (*api.Build, error) {
	if !reSHA.MatchString(req.Recipe) {
		return nil, errors.New("recipe must be an artifact sha256 (upload the recipe tarball first)")
	}
	if _, err := os.Stat(s.artifactPath(req.Recipe)); err != nil {
		return nil, fmt.Errorf("recipe artifact %s not uploaded", req.Recipe)
	}
	if req.Device != "" || req.Config != "" {
		return nil, errors.New("package builds use the recipe's own config; drop the device and config")
	}
	if req.Pkgrel != "" && !rePkgrel.MatchString(req.Pkgrel) {
		return nil, fmt.Errorf("pkgrel %q is not a number like 3 or 11.14", req.Pkgrel)
	}
	var src api.Source
	if req.Source != "" {
		var err error
		if src, err = parseSource(req.Source); err != nil {
			return nil, err
		}
		if src, err = resolve(ctx, src); err != nil {
			return nil, err
		}
	}
	now := s.now()
	return s.queueBuild(&api.Build{ID: "b" + now.Format("0102-150405") + "-" + randHex(2), Kind: api.BuildPackage,
		Key: packageKey(src, req.Recipe, req.Pkgrel), Source: src, Recipe: req.Recipe, RecipeDir: req.RecipeDir,
		Pkgrel: req.Pkgrel, State: api.BuildQueued, Created: now, Updated: now}, req.Force)
}

var rePkgrel = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// queueBuild returns an earlier build with the same key when there is a
// usable one, and otherwise queues b.
func (s *Server) queueBuild(b *api.Build, force bool) (*api.Build, error) {
	key := b.Key
	s.builds.mu.Lock()
	defer s.builds.mu.Unlock()
	if !force {
		prior, _ := s.store.builds(`key=? ORDER BY created DESC LIMIT 5`, key)
		for _, b := range prior {
			switch b.State {
			case api.BuildQueued, api.BuildRunning:
				return b, nil
			case api.BuildDone:
				if s.outputsKept(b) {
					return b, nil
				}
			}
		}
	}
	os.MkdirAll(s.buildDir(b.ID), 0o755)
	if err := s.store.saveBuild(b); err != nil {
		return nil, err
	}
	s.log.Printf("build %s queued: %s", b.ID, buildWhat(b))
	s.hub.publish("build", "", b)
	go s.builds.bump()
	return b, nil
}

// outputsKept says whether all of a finished build's outputs are still stored.
func (s *Server) outputsKept(b *api.Build) bool {
	shas := []string{b.Artifact}
	for _, f := range b.Files {
		shas = append(shas, f.SHA256)
	}
	for _, sha := range shas {
		if sha == "" {
			continue
		}
		if _, err := os.Stat(s.artifactPath(sha)); err != nil {
			return false
		}
	}
	return b.Artifact != "" || len(b.Files) > 0
}

// buildWhat describes a build in one line, for logs.
func buildWhat(b *api.Build) string {
	var w string
	if b.Kind == api.BuildPackage {
		w = "packages from " + orStr(b.RecipeDir, "recipe "+b.Recipe[:12])
		if b.Pkgrel != "" {
			w += " pkgrel " + b.Pkgrel
		}
		if b.Source.SHA == "" {
			return w
		}
		w += " at "
	}
	return w + fmt.Sprintf("%s@%s (%s)", shortRepo(b.Source.Repo), b.Source.Ref, b.Source.SHA[:12])
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// waitBuild blocks until a build finishes, calling onChange with every update.
func (s *Server) waitBuild(ctx context.Context, id string, onChange func(*api.Build)) (*api.Build, error) {
	var last string
	for {
		b, err := s.getBuild(id)
		if err != nil {
			return nil, err
		}
		if sig := string(b.State) + b.Stage; sig != last {
			last = sig
			if onChange != nil {
				onChange(b)
			}
		}
		switch b.State {
		case api.BuildDone, api.BuildFailed, api.BuildCanceled:
			return b, nil
		}
		s.builds.wait(ctx, 5*time.Second)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
}

// estimate is how long builds like this one have taken, from recent history:
// same kind, and the same config (kernels) or recipe (packages) when possible.
func (s *Server) estimate(like *api.Build) float64 {
	l, _ := s.store.builds(`state='done' ORDER BY created DESC LIMIT 40`)
	var sum, n float64
	for _, b := range l {
		if b.Kind != like.Kind || b.Seconds <= 0 {
			continue
		}
		if (b.ConfigSHA == like.ConfigSHA && b.RecipeDir == like.RecipeDir) || n == 0 {
			sum += b.Seconds
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / n
}

// ---- builder host API ----

func (s *Server) builderAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.BuilderToken == "" || subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.BuilderToken)) != 1 {
			httpErr(w, 401, "bad builder token")
			return
		}
		h(w, r)
	}
}

// hBuilderPoll hands the oldest queued build to a builder, long-polling up to
// 25s. Builders say which kinds they can run (?kinds=kernel,package); one that
// doesn't say only gets kernel builds.
func (s *Server) hBuilderPoll(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "builder"
	}
	kinds := `json_extract(data, '$.kind') IS NULL`
	if strings.Contains(r.URL.Query().Get("kinds"), "package") {
		kinds = `1=1`
	}
	deadline := s.now().Add(25 * time.Second)
	for {
		s.builds.mu.Lock()
		s.builds.builders[host] = s.now()
		s.builds.mu.Unlock()
		q, _ := s.store.builds(`state='queued' AND (` + kinds + `) ORDER BY created ASC LIMIT 1`)
		if len(q) > 0 {
			b := q[0]
			b.State, b.Builder, b.Started, b.Stage = api.BuildRunning, host, s.now(), "starting"
			b.ETA = s.estimate(b)
			s.builds.mu.Lock()
			s.builds.beat[b.ID] = s.now()
			s.builds.mu.Unlock()
			s.saveBuild(b)
			s.log.Printf("build %s started on %s", b.ID, host)
			a := api.BuildAssignment{Build: *b}
			if b.Kind == api.BuildKernel {
				a.LabVer = "-lab" + b.Source.SHA[:8] + "-" + b.Key[:4]
			}
			writeJSON(w, a)
			return
		}
		if s.now().After(deadline) || r.Context().Err() != nil {
			w.WriteHeader(204)
			return
		}
		s.builds.wait(r.Context(), deadline.Sub(s.now()))
	}
}

// hBuilderProgress takes a batch of log lines. kbuild's "@@stage x" and
// "@@progress n total" lines update the build instead of the log.
func (s *Server) hBuilderProgress(w http.ResponseWriter, r *http.Request) {
	b, err := s.getBuild(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	var p api.BuildProgress
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	f, _ := os.OpenFile(filepath.Join(s.buildDir(b.ID), "build.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	var shown []string
	for _, l := range p.Lines {
		switch {
		case strings.HasPrefix(l, "@@stage "):
			b.Stage = strings.TrimPrefix(l, "@@stage ")
		case strings.HasPrefix(l, "@@progress "):
			if f := strings.Fields(l); len(f) == 3 {
				n, _ := strconv.ParseFloat(f[1], 64)
				t, _ := strconv.ParseFloat(f[2], 64)
				if t > 0 {
					b.Progress = min(n/t, 1)
				}
			}
		default:
			shown = append(shown, l)
			if f != nil {
				fmt.Fprintln(f, l)
			}
		}
	}
	if f != nil {
		f.Close()
	}
	if p.Stage != "" {
		b.Stage = p.Stage
	}
	b.LogLines += len(shown)
	if est := s.estimate(b); est > 0 {
		b.ETA = max(0, est-s.since(b.Started).Seconds())
	}
	s.builds.mu.Lock()
	s.builds.beat[b.ID] = s.now()
	cancel := s.builds.cancel[b.ID]
	s.builds.mu.Unlock()
	s.saveBuild(b)
	if len(shown) > 0 {
		s.hub.publish("buildlog", "", map[string]any{"id": b.ID, "lines": shown})
	}
	writeJSON(w, map[string]bool{"cancel": cancel})
}

func (s *Server) hBuilderArtifact(w http.ResponseWriter, r *http.Request) {
	sha, n, err := s.storeArtifact(r.Body)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	writeJSON(w, map[string]any{"sha256": sha, "size": n})
}

func (s *Server) hBuilderDone(w http.ResponseWriter, r *http.Request) {
	b, err := s.getBuild(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	var d api.BuildResult
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	b.Seconds = d.Seconds
	b.ETA = 0
	s.builds.mu.Lock()
	canceled := s.builds.cancel[b.ID]
	delete(s.builds.cancel, b.ID)
	delete(s.builds.beat, b.ID)
	s.builds.mu.Unlock()
	switch {
	case canceled:
		b.State, b.Error = api.BuildCanceled, "canceled"
	case d.Error != "":
		b.State, b.Error = api.BuildFailed, d.Error
	default:
		var size int64
		missing := false
		for _, f := range d.Files {
			if _, err := os.Stat(s.artifactPath(f.SHA256)); err != nil {
				missing = true
			}
		}
		if d.Artifact != "" {
			st, err := os.Stat(s.artifactPath(d.Artifact))
			if err != nil {
				missing = true
			} else {
				size = st.Size()
			}
		}
		if missing || (d.Artifact == "" && len(d.Files) == 0) {
			b.State, b.Error = api.BuildFailed, "builder reported outputs that were never uploaded"
			break
		}
		b.State, b.Release, b.Artifact, b.Size, b.Files, b.Progress, b.Stage = api.BuildDone, d.Release, d.Artifact, size, d.Files, 1, "done"
	}
	s.saveBuild(b)
	s.log.Printf("build %s %s in %.0fs: %s%s", b.ID, b.State, b.Seconds, b.Release, b.Error)
	go s.gcArtifacts()
	w.WriteHeader(204)
}

// ---- Maintainer API ----

func (s *Server) hCreateBuild(w http.ResponseWriter, r *http.Request) {
	var req api.BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	b, err := s.EnsureBuild(r.Context(), req)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	writeJSON(w, b)
}

// hBuildFile serves one output of a package build under its file name.
func (s *Server) hBuildFile(w http.ResponseWriter, r *http.Request) {
	b, err := s.getBuild(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	name := r.PathValue("name")
	for _, f := range b.Files {
		if f.Name == name {
			w.Header().Set("Content-Disposition", `attachment; filename="`+f.Name+`"`)
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeFile(w, r, s.artifactPath(f.SHA256))
			return
		}
	}
	if name == api.RecipeFile && b.Recipe != "" {
		if _, err := os.Stat(s.artifactPath(b.Recipe)); err != nil {
			httpErr(w, 404, "build %s: its recipe %s is no longer stored", b.ID, b.Recipe[:12])
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+api.RecipeFile+`"`)
		w.Header().Set("Content-Type", "application/x-tar")
		http.ServeFile(w, r, s.artifactPath(b.Recipe))
		return
	}
	httpErr(w, 404, "build %s has no file %q", b.ID, name)
}

func (s *Server) hBuilds(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 500 {
		n = 30
	}
	l, err := s.store.builds(`1=1 ORDER BY created DESC LIMIT ?`, n)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if l == nil {
		l = []*api.Build{}
	}
	writeJSON(w, l)
}

func (s *Server) hBuild(w http.ResponseWriter, r *http.Request) {
	b, err := s.getBuild(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	writeJSON(w, b)
}

// hBuildLog serves the build log; ?follow=1 keeps streaming until the build ends.
func (s *Server) hBuildLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.getBuild(id); err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // a reverse proxy passes it on as it comes
	path := filepath.Join(s.buildDir(id), "build.log")
	if r.URL.Query().Get("follow") != "1" {
		http.ServeFile(w, r, path)
		return
	}
	fl, _ := w.(http.Flusher)
	var off int64
	for {
		if f, err := os.Open(path); err == nil {
			f.Seek(off, io.SeekStart)
			n, _ := io.Copy(w, f)
			off += n
			f.Close()
			if fl != nil {
				fl.Flush()
			}
		}
		b, err := s.getBuild(id)
		if err != nil || (b.State != api.BuildQueued && b.State != api.BuildRunning) {
			return
		}
		s.builds.wait(r.Context(), 2*time.Second)
		if r.Context().Err() != nil {
			return
		}
	}
}

func (s *Server) hCancelBuild(w http.ResponseWriter, r *http.Request) {
	b, err := s.getBuild(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	switch b.State {
	case api.BuildQueued:
		b.State, b.Error = api.BuildCanceled, "canceled before it started"
		s.saveBuild(b)
	case api.BuildRunning:
		s.builds.mu.Lock()
		s.builds.cancel[b.ID] = true
		s.builds.mu.Unlock()
	}
	w.Write([]byte("canceling\n"))
}

func (s *Server) hBuilders(w http.ResponseWriter, r *http.Request) {
	s.builds.mu.Lock()
	out := []map[string]any{}
	for host, t := range s.builds.builders {
		out = append(out, map[string]any{"host": host, "last_seen": t, "alive": s.since(t) < time.Minute})
	}
	s.builds.mu.Unlock()
	writeJSON(w, out)
}

// buildMonitor fails builds whose builder went silent, and on start fails
// builds that were running when labd stopped.
func (s *Server) buildMonitor() {
	// A build that was running when labd stopped is usually still running on its
	// builder, which keeps reporting to the new labd. Give it the same silence
	// window as any build instead of failing it at once.
	running, _ := s.store.builds(`state='running'`)
	s.builds.mu.Lock()
	for _, b := range running {
		s.builds.beat[b.ID] = s.now()
	}
	s.builds.mu.Unlock()
	t := s.clock().NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C():
		}
		s.builds.mu.Lock()
		var lost []string
		for id, at := range s.builds.beat {
			if s.since(at) > 10*time.Minute {
				lost = append(lost, id)
				delete(s.builds.beat, id)
			}
		}
		s.builds.mu.Unlock()
		for _, id := range lost {
			if b, err := s.getBuild(id); err == nil && b.State == api.BuildRunning {
				b.State, b.Error = api.BuildFailed, "the builder stopped reporting for 10 minutes"
				s.saveBuild(b)
			}
		}
	}
}

// lastLines returns the tail of a build log, for failure summaries.
func (s *Server) buildLogTail(id string, n int) []string {
	f, err := os.Open(filepath.Join(s.buildDir(id), "build.log"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines
}

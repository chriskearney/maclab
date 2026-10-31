package server

// Builders build kernels and packages for the lab (lab-builder). A builder
// proves who it is with one of two kinds of token.
//
// The data directory's builder.token is the controller's own builder. It is
// trusted with every builder right (any build, any artifact) and is never
// handed out.
//
// Any other builder is added by a Maintainer (lab builder add) and gets a
// token of its own, shown once. With it a builder may only build: take
// queued builds of the kinds it was given, and for the builds it took, read
// their inputs, report progress, upload outputs and finish them. Each token is
// one generation of its name. Removing the builder ends its open requests,
// fails what it was building and drops its claims; adding the name again makes
// a new generation that inherits nothing. Claims are kept in memory, so a labd
// restart fails a named builder's running builds rather than trusting a claim
// it can no longer check.
//
// A builder's kernels boot as root on lab Macs. Adding one trusts whoever runs
// it, for that, as much as a Maintainer.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"

	"github.com/iconidentify/maclab/internal/api"
)

// builderCred is who a builder request comes from: a named builder's
// generation, or (gen "") the shared builder.token.
type builderCred struct {
	name  string
	gen   string
	kinds []string
}

func (c builderCred) shared() bool { return c.gen == "" }

type builderCredKey struct{}

func builderCredOf(r *http.Request) builderCred {
	c, _ := r.Context().Value(builderCredKey{}).(builderCred)
	return c
}

// claim is a named builder's hold on a build it took: which generation took
// it, and what it has uploaded for it.
type claim struct {
	gen     string
	uploads map[string]bool
}

// uploadedAll says whether every output d names was uploaded for this claim.
func (cl *claim) uploadedAll(d api.BuildResult) bool {
	if cl == nil || (d.Artifact != "" && !cl.uploads[d.Artifact]) {
		return false
	}
	for _, f := range d.Files {
		if !cl.uploads[f.SHA256] {
			return false
		}
	}
	return true
}

func newBuilderToken() string { return "bldr_" + randHex(20) }

// builderReportMax caps a builder's progress or done report.
const builderReportMax = 16 << 20

// builderUploadMax caps one upload by a named builder. A kernel package is a
// few hundred MB.
var builderUploadMax int64 = 4 << 30

var errBuilderRemoved = errors.New("this builder was removed")

// builderAuth admits a builder: a named builder by its token (its request
// ends when it is removed), or the shared builder.token.
func (s *Server) builderAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		var c builderCred
		if b, gen, err := s.store.builderByToken(hashSecret(tok)); tok != "" && err == nil {
			c = builderCred{name: b.Name, gen: gen, kinds: b.Kinds}
		} else if s.cfg.BuilderToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.BuilderToken)) != 1 {
			httpErr(w, 401, "bad builder token")
			return
		}
		ctx, cancel := context.WithCancel(context.WithValue(r.Context(), builderCredKey{}, c))
		if c.shared() {
			defer cancel()
		} else {
			defer s.bconns.add(c.gen, cancel)()
			// Removed between the lookup and registering this request.
			if !s.store.builderGenCurrent(c.gen) {
				httpErr(w, 401, "bad builder token")
				return
			}
		}
		h(w, r.WithContext(ctx))
	}
}

// ownsLocked says whether c may act on build b: always for the shared token;
// for a named builder, only while b runs on the claim its current generation
// made. Callers hold s.builds.state.
func (s *Server) ownsLocked(c builderCred, b *api.Build) error {
	if c.shared() {
		return nil
	}
	if !s.store.builderGenCurrent(c.gen) {
		return errBuilderRemoved
	}
	cl := s.builds.claims[b.ID]
	if cl == nil || cl.gen != c.gen || b.State != api.BuildRunning || b.Builder != c.name {
		return fmt.Errorf("build %s isn't running on builder %s", b.ID, c.name)
	}
	return nil
}

// kindsWhere is the SQL condition for the queued builds c may take, given the
// kinds its lab-builder asked for (?kinds=kernel,package; none: kernel only).
func kindsWhere(c builderCred, asked string) string {
	askedPkg := slices.Contains(splitList(asked), api.BuilderPackage)
	kernel, pkg := true, askedPkg
	if !c.shared() {
		kernel = slices.Contains(c.kinds, api.BuilderKernel)
		pkg = askedPkg && slices.Contains(c.kinds, api.BuilderPackage)
	}
	switch {
	case kernel && pkg:
		return `1=1`
	case kernel:
		return `json_extract(data, '$.kind') IS NULL`
	case pkg:
		return `json_extract(data, '$.kind') = '` + api.BuildPackage + `'`
	}
	return `0=1`
}

// claimBuild records that a builder polled and hands it the oldest queued
// build matching where, under the state lock: two builders never take the
// same build, and a removed named builder takes none and isn't seen again.
func (s *Server) claimBuild(c builderCred, host, where string) (*api.Build, error) {
	s.builds.state.Lock()
	defer s.builds.state.Unlock()
	if !c.shared() && !s.store.builderGenCurrent(c.gen) {
		return nil, errBuilderRemoved
	}
	s.builds.mu.Lock()
	s.builds.builders[host] = s.now()
	s.builds.mu.Unlock()
	q, err := s.store.builds(`state='queued' AND (` + where + `) ORDER BY created ASC LIMIT 1`)
	if err != nil || len(q) == 0 {
		return nil, err
	}
	b := q[0]
	b.State, b.Builder, b.Started, b.Stage = api.BuildRunning, host, s.now(), "starting"
	b.ETA = s.estimate(b)
	s.builds.mu.Lock()
	s.builds.beat[b.ID] = s.now()
	s.builds.mu.Unlock()
	if c.shared() {
		delete(s.builds.claims, b.ID)
	} else {
		s.builds.claims[b.ID] = &claim{gen: c.gen, uploads: map[string]bool{}}
	}
	s.saveBuild(b)
	return b, nil
}

func (s *Server) hBuilderSelf(w http.ResponseWriter, r *http.Request) {
	c := builderCredOf(r)
	if c.shared() {
		writeJSON(w, api.BuilderSelf{Shared: true})
		return
	}
	writeJSON(w, api.BuilderSelf{Name: c.name, Kinds: c.kinds})
}

// hBuilderGetArtifact serves a builder an artifact: the shared token any; a
// named builder only an input (config or recipe) of a build it runs now.
func (s *Server) hBuilderGetArtifact(w http.ResponseWriter, r *http.Request) {
	if c := builderCredOf(r); !c.shared() {
		sha := r.PathValue("sha")
		s.builds.state.Lock()
		ok := false
		for id, cl := range s.builds.claims {
			if cl.gen != c.gen {
				continue
			}
			if b, err := s.getBuild(id); err == nil && s.ownsLocked(c, b) == nil && sha != "" &&
				(b.ConfigSHA == sha || b.Recipe == sha) {
				ok = true
				break
			}
		}
		s.builds.state.Unlock()
		if !ok {
			httpErr(w, 404, "no artifact %s for this builder now", short(sha))
			return
		}
	}
	s.hBuilderFetch(w, r)
}

// ctxReader stops reading once ctx ends: a removed builder's upload stops
// mid-body.
type ctxReader struct {
	ctx context.Context
	io.ReadCloser
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.ReadCloser.Read(p)
}

// namedUpload stores a named builder's upload for the build it names
// (?build=), capped while it streams, and records it for that build only if
// the builder still holds the build once the body is in.
func (s *Server) namedUpload(w http.ResponseWriter, r *http.Request, c builderCred) {
	id := r.URL.Query().Get("build")
	s.builds.state.Lock()
	b, err := s.getBuild(id)
	if err == nil {
		err = s.ownsLocked(c, b)
	}
	s.builds.state.Unlock()
	if err != nil {
		httpErr(w, 403, "an upload must name a build this builder is running (?build=): %v", err)
		return
	}
	sha, n, err := s.storeArtifact(http.MaxBytesReader(w, ctxReader{r.Context(), r.Body}, builderUploadMax))
	switch {
	case errors.As(err, new(*http.MaxBytesError)):
		httpErr(w, 413, "an upload is limited to %d bytes", builderUploadMax)
		return
	case err != nil && r.Context().Err() != nil:
		httpErr(w, 403, "%v", errBuilderRemoved)
		return
	case err != nil:
		httpErr(w, 500, "%v", err)
		return
	}
	s.builds.state.Lock()
	defer s.builds.state.Unlock()
	b, err = s.getBuild(id)
	if err == nil {
		err = s.ownsLocked(c, b)
	}
	if err != nil {
		httpErr(w, 403, "not recorded: %v", err)
		return
	}
	s.builds.claims[id].uploads[sha] = true
	writeJSON(w, map[string]any{"sha256": sha, "size": n})
}

// ---- Maintainer API ----

// builderKinds checks and orders the kinds a builder is given; none is kernel.
func builderKinds(kinds []string) ([]string, error) {
	if len(kinds) == 0 {
		return []string{api.BuilderKernel}, nil
	}
	var out []string
	for _, k := range []string{api.BuilderKernel, api.BuilderPackage} {
		if slices.Contains(kinds, k) {
			out = append(out, k)
		}
	}
	for _, k := range kinds {
		if k != api.BuilderKernel && k != api.BuilderPackage {
			return nil, fmt.Errorf("a builder's kinds are %s and %s, not %q", api.BuilderKernel, api.BuilderPackage, k)
		}
	}
	return out, nil
}

func (s *Server) hAddBuilder(w http.ResponseWriter, r *http.Request) {
	var req api.BuilderRequest
	if !decodeBody(w, r, 4<<10, &req) {
		return
	}
	if !reMaintainer.MatchString(req.Name) {
		httpErr(w, 400, "a builder's name is letters, digits, dots, dashes and underscores")
		return
	}
	kinds, err := builderKinds(req.Kinds)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	nb := api.NewBuilder{Builder: api.Builder{Name: req.Name, Kinds: kinds, Added: s.now(), AddedBy: maintainerName(r)}, Token: newBuilderToken()}
	if err := s.store.addBuilder(nb.Builder, randHex(16), hashSecret(nb.Token)); err != nil {
		if s.store.hasBuilder(req.Name) {
			httpErr(w, 409, "there is already a builder named %s", req.Name)
			return
		}
		httpErr(w, 500, "%v", err)
		return
	}
	s.log.Printf("builder %s (%s) added by %s", nb.Name, joinList(kinds), nb.AddedBy)
	writeJSON(w, nb)
}

// hRemoveBuilder removes a named builder: its token stops working, its open
// requests end, and the builds it was running fail.
func (s *Server) hRemoveBuilder(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	by := maintainerName(r)
	s.builds.state.Lock()
	gen, ok, err := s.store.removeBuilder(name)
	if err != nil || !ok {
		s.builds.state.Unlock()
		if err != nil {
			httpErr(w, 500, "%v", err)
		} else {
			httpErr(w, 404, "no builder %s", name)
		}
		return
	}
	s.bconns.end(gen)
	failed := []string{}
	for id, cl := range s.builds.claims {
		if cl.gen != gen {
			continue
		}
		delete(s.builds.claims, id)
		b, err := s.getBuild(id)
		if err != nil || b.State != api.BuildRunning {
			continue
		}
		b.State, b.Error, b.ETA = api.BuildFailed, fmt.Sprintf("builder %s was removed by %s", name, by), 0
		s.builds.mu.Lock()
		delete(s.builds.beat, id)
		delete(s.builds.cancel, id)
		s.builds.mu.Unlock()
		s.saveBuild(b)
		failed = append(failed, id)
	}
	s.builds.state.Unlock()
	s.builds.mu.Lock()
	delete(s.builds.builders, name)
	s.builds.mu.Unlock()
	sort.Strings(failed)
	s.log.Printf("builder %s removed by %s; failed builds: %v", name, by, failed)
	writeJSON(w, api.RemovedBuilder{Removed: name, FailedBuilds: failed})
}

// hBuilders lists the named builders, and the hosts that polled with the
// shared builder.token, with the build each is running.
func (s *Server) hBuilders(w http.ResponseWriter, r *http.Request) {
	named, err := s.store.builders()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	running, _ := s.store.builds(`state='running'`)
	on := map[string]string{}
	for _, b := range running {
		on[b.Builder] = b.ID
	}
	s.builds.mu.Lock()
	seen := map[string]bool{}
	out := []api.BuilderStatus{}
	for _, b := range named {
		st := api.BuilderStatus{Host: b.Name, Registered: true, Kinds: b.Kinds, Added: b.Added, AddedBy: b.AddedBy, Build: on[b.Name]}
		if t, ok := s.builds.builders[b.Name]; ok {
			st.LastSeen, st.Alive = t, s.since(t) < time1Minute
		}
		seen[b.Name] = true
		out = append(out, st)
	}
	for host, t := range s.builds.builders {
		if !seen[host] {
			out = append(out, api.BuilderStatus{Host: host, Shared: true, LastSeen: t, Alive: s.since(t) < time1Minute, Build: on[host]})
		}
	}
	s.builds.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	writeJSON(w, out)
}

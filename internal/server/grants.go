package server

// What a Mac may take from labd and add to it, by its device secret. A Mac on
// the internet is told apart by its secret alone, so its reach is kept to
// the enrollment that secret belongs to and the job that enrollment is
// running:
//
//   - It fetches an artifact only if a command for its active job named it
//     (a kernel to stage, a test script, Mesa packages and the lab's probes,
//     a Release's packages), and only until that job ends, whether or not
//     another job follows; or if a Maintainer granted it that artifact
//     explicitly, until that grant's expiry (artifact-grants).
//   - It adds files only to its active job, and only to a job submitted for
//     its own enrollment.
//
// Grants are kept in memory, on the Mac's live record: an enrollment that
// ends, enrolls again or outlives a labd restart has none. Job grants are
// adapted from Naeem Malik's artifact grants (maclab PR #53, 8affa064),
// bound here to the enrollment and the active job.

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// fetchGrant is a Maintainer's explicit grant: the Mac may fetch shas until
// expires, while deviceID is still its enrollment.
type fetchGrant struct {
	shas     map[string]bool
	expires  time.Time
	deviceID string
	by       string
}

// grantLocked lets the Mac fetch the artifacts command c names, for c's job:
// the grants of any other job go. Caller holds v.mu.
func (v *dev) grantLocked(c api.Command) {
	shas := artifactsIn(c)
	if c.JobID == "" || len(shas) == 0 {
		return
	}
	for sha, job := range v.grants {
		if job != c.JobID {
			delete(v.grants, sha)
		}
	}
	if v.grants == nil {
		v.grants = map[string]string{}
	}
	for _, sha := range shas {
		v.grants[sha] = c.JobID
	}
}

// artifactsIn names the artifacts in labd's store that command c has the
// Mac fetch.
func artifactsIn(c api.Command) []string {
	var shas []string
	switch c.Kind {
	case api.CmdStage:
		var a api.StageArgs
		json.Unmarshal(c.Args, &a)
		shas = append(shas, a.Artifact)
	case api.CmdRunTest:
		var t api.TestSpec
		json.Unmarshal(c.Args, &t)
		shas = append(shas, t.Script)
	case api.CmdBootOnce:
		var a api.BootOnceArgs
		json.Unmarshal(c.Args, &a)
		for _, t := range a.Tests {
			shas = append(shas, t.Script)
		}
	case api.CmdInstall:
		var a api.InstallArgs
		json.Unmarshal(c.Args, &a)
		for _, p := range a.Packages {
			shas = append(shas, p.SHA256)
		}
	case api.CmdMesaStage:
		var a api.MesaStageArgs
		json.Unmarshal(c.Args, &a)
		shas = append(shas, mesaRefs(api.JobSpec{Mesa: &a.Spec})...)
	}
	return slices.DeleteFunc(shas, func(sha string) bool { return !reSHA.MatchString(sha) })
}

// endJobLocked ends the Mac's authority over job: it is no longer the Mac's
// active job, and its grants go. Despite the name it takes v.mu itself; it
// is the lock under which the job stops being the Mac's.
func (v *dev) endJobLocked(job string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.d.ActiveJob == job {
		v.d.ActiveJob = ""
	}
	for sha, j := range v.grants {
		if j == job {
			delete(v.grants, sha)
		}
	}
}

// mayFetchLocked is whether the Mac may fetch sha now. Caller holds v.mu.
func (v *dev) mayFetchLocked(sha string, now time.Time) bool {
	if v.forgotten {
		return false
	}
	if job := v.grants[sha]; job != "" && job == v.d.ActiveJob {
		return true
	}
	g := v.fetchGrant
	return g != nil && g.deviceID == v.d.ID && now.Before(g.expires) && g.shas[sha]
}

// hAgentArtifact serves a Mac an artifact it may fetch (see mayFetchLocked);
// any other answers 404, as if it weren't there.
func (s *Server) hAgentArtifact(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	if !reSHA.MatchString(sha) {
		httpErr(w, 400, "bad sha256")
		return
	}
	v := agentDev(r)
	v.mu.Lock()
	ok := v.mayFetchLocked(sha, s.now())
	v.mu.Unlock()
	if !ok {
		httpErr(w, 404, "no artifact %s for this Mac now", short(sha))
		return
	}
	s.hBuilderFetch(w, r)
}

// hBuilderFetch serves any artifact: to the builder, by its own token; to a
// Mac, once hAgentArtifact let it.
func (s *Server) hBuilderFetch(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	if !reSHA.MatchString(sha) {
		httpErr(w, 400, "bad sha256")
		return
	}
	http.ServeFile(w, r, s.artifactPath(sha))
}

// Explicit grants: a Maintainer lets a Mac fetch named artifacts for a
// while, outside any job. bt2's preflight on the Mac, run through lab exec
// under the Maintainer's lease, fetches its packages this way. It is
// deliberate authority that outlives jobs until it expires; it does nothing
// else (no uploads, no reports).
const (
	maxGrantArtifacts = 256
	maxGrantTTL       = 12 * time.Hour
	defaultGrantTTL   = time.Hour
	grantBodyMax      = 64 << 10
)

type artifactGrantRequest struct {
	Artifacts []string `json:"artifacts"`
	TTLSec    int      `json:"ttl_sec,omitempty"`
}

type artifactGrantResponse struct {
	Device    string    `json:"device"`
	Artifacts []string  `json:"artifacts"`
	Expires   time.Time `json:"expires,omitzero"`
}

// hArtifactGrants sets a Mac's explicit grant to exactly the artifacts named,
// replacing the one it had; an empty list revokes it. A request labd refuses
// leaves the grant as it was.
func (s *Server) hArtifactGrants(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	var req artifactGrantRequest
	if !decodeBody(w, r, grantBodyMax, &req) {
		return
	}
	ttl := time.Duration(req.TTLSec) * time.Second
	switch {
	case req.TTLSec == 0:
		ttl = defaultGrantTTL
	case req.TTLSec < 0 || ttl > maxGrantTTL:
		httpErr(w, 400, "ttl_sec: 1 to %d", int(maxGrantTTL.Seconds()))
		return
	}
	if len(req.Artifacts) > maxGrantArtifacts {
		httpErr(w, 400, "at most %d artifacts in one grant", maxGrantArtifacts)
		return
	}
	shas := map[string]bool{}
	for _, sha := range req.Artifacts {
		if !reSHA.MatchString(sha) {
			httpErr(w, 400, "bad sha256 %q", sha)
			return
		}
		if st, err := os.Stat(s.artifactPath(sha)); err != nil || !st.Mode().IsRegular() {
			httpErr(w, 404, "no artifact %s in labd's store", short(sha))
			return
		}
		shas[sha] = true
	}
	by := maintainerName(r)
	resp := artifactGrantResponse{Artifacts: []string{}}
	v.mu.Lock()
	resp.Device = v.d.Name
	if v.forgotten {
		v.mu.Unlock()
		httpErr(w, 404, "no device %q", resp.Device)
		return
	}
	if len(shas) == 0 {
		v.fetchGrant = nil
	} else {
		g := &fetchGrant{shas: shas, expires: s.now().Add(ttl), deviceID: v.d.ID, by: by}
		v.fetchGrant = g
		resp.Expires = g.expires
		for sha := range shas {
			resp.Artifacts = append(resp.Artifacts, sha)
		}
		slices.Sort(resp.Artifacts)
	}
	v.mu.Unlock()
	if len(shas) == 0 {
		s.log.Printf("Maintainer %s revoked %s's artifact grant", by, resp.Device)
	} else {
		s.log.Printf("Maintainer %s granted %s %d artifact(s) until %s", by, resp.Device, len(shas), resp.Expires.Format(time.RFC3339))
	}
	writeJSON(w, resp)
}

// uploadMax caps one file a Mac adds to a job; tests lower it.
var uploadMax int64 = 1 << 30

// hUpload stores a file a Mac adds to its active job (see the top of this
// file). The body goes to a temporary file first; it replaces the job's file
// only if it was whole and under uploadMax, and the job is still the Mac's.
func (s *Server) hUpload(w http.ResponseWriter, r *http.Request) {
	job := r.URL.Query().Get("job")
	name, ok := cleanName(r.URL.Query().Get("name"))
	if !ok || strings.ContainsAny(job, "/.") || job == "" {
		httpErr(w, 400, "bad job or name")
		return
	}
	v := agentDev(r)
	j, err := s.store.job(job)
	if err != nil || !v.ownsActiveJob(j) {
		httpErr(w, 404, "no such job for this device")
		return
	}
	p := filepath.Join(s.jobDir(job), name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".upload-*")
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	tmp := f.Name()
	_, err = io.Copy(f, http.MaxBytesReader(w, r.Body, uploadMax))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		if _, ok := err.(*http.MaxBytesError); ok {
			httpErr(w, 413, "a job file over %d bytes", uploadMax)
			return
		}
		httpErr(w, 500, "%v", err)
		return
	}
	// The job may have ended, or the enrollment, while the body arrived: the
	// file takes its place only if the job is still the Mac's, decided under
	// the lock its end is.
	v.mu.Lock()
	ok = v.ownsActiveJobLocked(j)
	if ok {
		err = os.Rename(tmp, p)
	}
	v.mu.Unlock()
	if !ok || err != nil {
		os.Remove(tmp)
		if !ok {
			httpErr(w, 404, "no such job for this device")
		} else {
			httpErr(w, 500, "%v", err)
		}
		return
	}
	w.Write([]byte("ok"))
}

// ownsActiveJob is whether j was submitted for v's enrollment and is the job
// v runs now. A job from before labd kept enrollments is no Mac's.
func (v *dev) ownsActiveJob(j *api.Job) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.ownsActiveJobLocked(j)
}

// ownsActiveJobLocked is ownsActiveJob for a caller holding v.mu.
func (v *dev) ownsActiveJobLocked(j *api.Job) bool {
	return !v.forgotten && j.DeviceID != "" && j.DeviceID == v.d.ID && j.Spec.Device == v.d.Name && v.d.ActiveJob == j.ID
}

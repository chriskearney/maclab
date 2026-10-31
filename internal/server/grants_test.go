package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/mesa"
)

// A Mac fetches only what a command for its active job named, and only while
// that job is its active one: not after the job ends, whether another job
// follows or not, and not another job's. None of this needs an explicit grant.
// (Job grants after Naeem Malik's maclab PR #53, 8affa064.)
func TestJobGrantsLastOnlyWhileTheJobIsActive(t *testing.T) {
	s := &Server{devs: map[string]*dev{}}
	sha := func(c byte) string { return strings.Repeat(string(c), 64) }
	m := &dev{s: s, d: api.Device{ID: "d-m", Name: "m", ActiveJob: "j1"}}
	other := &dev{s: s, d: api.Device{ID: "d-o", Name: "other", ActiveJob: "j2"}}
	cmd := func(kind, job string, args any) api.Command {
		b, _ := json.Marshal(args)
		return api.Command{Kind: kind, JobID: job, Args: b}
	}
	for _, c := range []api.Command{
		cmd(api.CmdStage, "j1", api.StageArgs{Artifact: sha('a')}),
		cmd(api.CmdRunTest, "j1", api.TestSpec{Name: "t", Script: sha('b')}),
		cmd(api.CmdBootOnce, "j1", api.BootOnceArgs{Tests: []api.TestSpec{{Name: "u", Script: sha('c')}}}),
		cmd(api.CmdInstall, "j1", api.InstallArgs{Packages: []api.InstallPackage{{Name: "linux", SHA256: sha('d')}}}),
		cmd(api.CmdMesaStage, "j1", api.MesaStageArgs{Spec: api.MesaSpec{Packages: []api.MesaPackage{{Name: "mesa", SHA256: sha('e')}}}}),
		cmd(api.CmdExec, "", api.ExecArgs{Command: sha('f')}),
		cmd(api.CmdStage, "", api.StageArgs{Artifact: sha('g')}), // no job: no grant
	} {
		m.grantLocked(c)
	}
	now := time.Now()
	may := func(v *dev, s string) bool { return v.mayFetchLocked(s, now) }
	for _, c := range []byte("abcde") {
		if !may(m, sha(c)) {
			t.Errorf("its job's artifact %c", c)
		}
	}
	for _, p := range []string{mesa.GLProbeSHA, mesa.VKProbeSHA} {
		if !may(m, p) {
			t.Errorf("a Mesa job's probe %s", short(p))
		}
	}
	for name, c := range map[string]string{"never sent": sha('9'), "a word in an exec": sha('f'), "sent with no job": sha('g')} {
		if may(m, c) {
			t.Errorf("%s: fetchable", name)
		}
	}
	if may(other, sha('a')) {
		t.Error("another Mac fetches this Mac's kernel")
	}
	// The job ends and no other starts: nothing is fetchable any more.
	m.d.ActiveJob = ""
	for _, c := range []byte("abcde") {
		if may(m, sha(c)) {
			t.Errorf("the ended job's artifact %c, with no job running", c)
		}
	}
	// The next job's grants are its own.
	m.d.ActiveJob = "j3"
	if may(m, sha('a')) {
		t.Error("an earlier job's kernel, during the next job")
	}
	m.grantLocked(cmd(api.CmdStage, "j3", api.StageArgs{Artifact: sha('1')}))
	if !may(m, sha('1')) || may(m, sha('b')) {
		t.Error("the next job's grants")
	}
	// A forgotten Mac fetches nothing.
	m.forgotten = true
	if may(m, sha('1')) {
		t.Error("a forgotten Mac fetches")
	}
}

// A real job over the wire: the Mac downloads its kernel through the grant
// check while the job runs, and once the job is over, without any later job,
// the same request is refused. No explicit grant is involved.
func TestAFinishedJobsKernelIsNoLongerFetchable(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	kernel := l.artifact("krel=7.2-grant behavior=ok")
	j := l.run(api.JobSpec{Kernel: kernel})
	l.expect(j, api.OutcomePass)
	if resp, _ := l.agentGet(l.secret, kernel, ""); resp.StatusCode != 404 {
		t.Fatalf("the finished job's kernel: %s", resp.Status)
	}
	if resp, _ := l.agentGet(l.secret, kernel, "bytes=5-"); resp.StatusCode != 404 {
		t.Fatalf("the finished job's kernel, from an offset: %s", resp.Status)
	}
}

func (l *lab) grant(token string, body any) (*http.Response, string) {
	l.t.Helper()
	return l.as(token, "POST", "/api/devices/"+l.name+"/artifact-grants", body)
}

// A Maintainer's explicit grant: exactly the artifacts named, for a while;
// replaced as a whole by the next grant, revoked by an empty one, left as it
// was by a refused one; gone when it expires, when labd restarts and when the
// Mac enrolls again. Only a Maintainer gives one, and it lets the Mac fetch,
// nothing else.
func TestExplicitArtifactGrant(t *testing.T) {
	clock := agent.NewFakeClock(time.Now())
	l := newLabWith(t, labConfig{clock: clock})
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	a, b := l.artifact("package a "+strings.Repeat("a", 4000)), l.artifact("package b")
	fetch := func(sha, rng string) int {
		resp, _ := l.agentGet(l.secret, sha, rng)
		return resp.StatusCode
	}
	if fetch(a, "") != 404 {
		t.Fatal("fetchable before any grant")
	}
	resp, body := l.grant(harnessToken, map[string]any{"artifacts": []string{a}, "ttl_sec": 60})
	var g struct {
		Artifacts []string
		Expires   time.Time
	}
	if json.Unmarshal([]byte(body), &g); resp.StatusCode != 200 || len(g.Artifacts) != 1 || g.Expires.IsZero() {
		t.Fatalf("grant: %s %s", resp.Status, body)
	}
	if fetch(a, "") != 200 || fetch(a, "bytes=100-") != 206 || fetch(b, "") != 404 {
		t.Fatal("the granted artifact, by range too, and only it")
	}
	req, _ := http.NewRequest("HEAD", l.url+"/api/agent/artifacts/"+a, nil)
	req.Header.Set("Authorization", "Bearer "+l.secret)
	if r, err := l.client().Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("HEAD of the granted artifact: %v %v", r, err)
	}
	// Refused grants change nothing.
	for name, bad := range map[string]any{
		"a bad sha":       map[string]any{"artifacts": []string{"nope"}},
		"an unknown sha":  map[string]any{"artifacts": []string{strings.Repeat("e", 64)}},
		"too long":        map[string]any{"artifacts": []string{b}, "ttl_sec": 43201},
		"a negative TTL":  map[string]any{"artifacts": []string{b}, "ttl_sec": -1},
		"too many shas":   map[string]any{"artifacts": make([]string, 257)},
		"not JSON at all": "{",
	} {
		if resp, body := l.grant(harnessToken, bad); resp.StatusCode == 200 {
			t.Errorf("%s: %s %s", name, resp.Status, body)
		}
	}
	if fetch(a, "") != 200 || fetch(b, "") != 404 {
		t.Fatal("a refused grant changed the grant")
	}
	// Only a Maintainer grants.
	for who, tok := range map[string]string{"the Mac itself": l.secret, "the builder": "bld", "nobody": ""} {
		if resp, _ := l.grant(tok, map[string]any{"artifacts": []string{b}}); resp.StatusCode != 401 {
			t.Errorf("%s granted: %s", who, resp.Status)
		}
	}
	// A new grant replaces the old one as a whole.
	l.grant(harnessToken, map[string]any{"artifacts": []string{b}, "ttl_sec": 60})
	if fetch(a, "") != 404 || fetch(b, "") != 200 {
		t.Fatal("the replaced grant")
	}
	// It expires.
	clock.Advance(61 * time.Second)
	if fetch(b, "") != 404 {
		t.Fatal("an expired grant")
	}
	// An empty grant revokes.
	l.grant(harnessToken, map[string]any{"artifacts": []string{a}})
	if resp, _ := l.grant(harnessToken, map[string]any{"artifacts": []string{}}); resp.StatusCode != 200 || fetch(a, "") != 404 {
		t.Fatal("an empty grant didn't revoke")
	}
	// An explicit grant lets the Mac fetch, nothing more: no upload outside its job.
	l.grant(harnessToken, map[string]any{"artifacts": []string{a}})
	up, _ := http.NewRequest("POST", l.url+"/api/agent/upload?job=j-none&name=x", strings.NewReader("x"))
	up.Header.Set("Authorization", "Bearer "+l.secret)
	if r, err := l.client().Do(up); err != nil || r.StatusCode != 404 {
		t.Fatalf("an upload with only an explicit grant: %v %v", r, err)
	}
	// labd restarts: grants live in memory, so there are none.
	ctx2, cancel2 := context.WithCancel(l.ctx)
	defer cancel2()
	s2, err := New(ctx2, l.s.cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	v2 := s2.dev(l.name)
	v2.mu.Lock()
	ok := v2.mayFetchLocked(a, clock.Now())
	v2.mu.Unlock()
	if ok {
		t.Fatal("a grant outlived labd's restart")
	}
}

// Enrolling again (the same activation, before the first check-in) leaves
// the Mac no grant, and a Mac that took a freed name gets none of the old
// one's.
func TestGrantsDontSurviveEnrollingAgainOrAReusedName(t *testing.T) {
	j := newJoinLab(t)
	tok := j.invite("regrant").Token
	_, first := j.enroll(tok, keyA, termsSum())
	art, _ := putArtifactForTest(j.s, "a package")
	if code, body := j.do("POST", "/api/devices/regrant/artifact-grants", "adm_secret", `{"artifacts":["`+art+`"]}`); code != 200 {
		t.Fatalf("grant: %d %s", code, body)
	}
	if code, _ := j.do("GET", "/api/agent/artifacts/"+art, first.Secret, ""); code != 200 {
		t.Fatalf("granted fetch: %d", code)
	}
	_, again := j.enroll(tok, keyA, termsSum())
	if code, _ := j.do("GET", "/api/agent/artifacts/"+art, again.Secret, ""); code != 404 {
		t.Errorf("after enrolling again: %d, want 404", code)
	}
	// The Mac is forgotten and another enrolls under its name.
	j.do("POST", "/api/devices/regrant/artifact-grants", "adm_secret", `{"artifacts":["`+art+`"]}`)
	if code, body := j.do("DELETE", "/api/devices/regrant?force=true", "adm_secret", ""); code != 200 {
		t.Fatalf("forget: %d %s", code, body)
	}
	_, next := j.enroll(j.invite("regrant").Token, keyB, termsSum())
	if next.DeviceID == first.DeviceID || next.Secret == "" {
		t.Fatalf("the new enrollment: %+v", next)
	}
	if code, _ := j.do("GET", "/api/agent/artifacts/"+art, next.Secret, ""); code != 404 {
		t.Errorf("the reused name inherited the grant: %d", code)
	}
}

// A Mac adds files only to the job it runs now, submitted for its own
// enrollment: not a finished job, not a job from before labd recorded
// enrollments, not a job of an earlier Mac by the same name.
func TestUploadsAreBoundToTheEnrollmentAndTheActiveJob(t *testing.T) {
	j := newJoinLab(t)
	_, old := j.enroll(j.invite("reused").Token, keyA, termsSum())
	save := func(job *api.Job) {
		if err := j.s.store.saveJob(job); err != nil {
			t.Fatal(err)
		}
	}
	setActive := func(name, id string) {
		v := j.s.dev(name)
		v.mu.Lock()
		v.d.ActiveJob = id
		v.mu.Unlock()
	}
	upload := func(secret, job, name, body string) (int, string) {
		return j.do("POST", "/api/agent/upload?job="+job+"&name="+name, secret, body)
	}
	save(&api.Job{ID: "j-old", Spec: api.JobSpec{Device: "reused"}, DeviceID: old.DeviceID, State: api.JobTesting})
	setActive("reused", "j-old")
	if code, body := upload(old.Secret, "j-old", "journal", "its own journal"); code != 200 {
		t.Fatalf("the Mac's own active job: %d %s", code, body)
	}
	setActive("reused", "")
	if code, _ := upload(old.Secret, "j-old", "journal", "rewritten later"); code != 404 {
		t.Errorf("a finished job: %d, want 404", code)
	}
	save(&api.Job{ID: "j-legacy", Spec: api.JobSpec{Device: "reused"}, State: api.JobTesting})
	setActive("reused", "j-legacy")
	if code, _ := upload(old.Secret, "j-legacy", "journal", "x"); code != 404 {
		t.Errorf("a job without an enrollment: %d, want 404", code)
	}
	// The Mac is forgotten; another takes its name and even has a job whose
	// ID it could guess. The old job stays the old Mac's.
	setActive("reused", "")
	save(&api.Job{ID: "j-old", Spec: api.JobSpec{Device: "reused"}, DeviceID: old.DeviceID, State: api.JobDone})
	save(&api.Job{ID: "j-legacy", Spec: api.JobSpec{Device: "reused"}, State: api.JobDone})
	if code, body := j.do("DELETE", "/api/devices/reused?force=true", "adm_secret", ""); code != 200 {
		t.Fatalf("forget: %d %s", code, body)
	}
	_, next := j.enroll(j.invite("reused").Token, keyB, termsSum())
	setActive("reused", "j-old")
	if code, _ := upload(next.Secret, "j-old", "journal", "TAMPERED"); code != 404 {
		t.Errorf("the reused name wrote into the old Mac's job: %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(j.s.jobDir("j-old"), "journal")); string(b) != "its own journal" {
		t.Errorf("the old job's journal: %q", b)
	}
}

// An upload over the cap is refused and leaves nothing behind; a failed one
// doesn't replace the file it was for.
func TestUploadCapLeavesNoPartialFile(t *testing.T) {
	old := uploadMax
	uploadMax = 1024
	defer func() { uploadMax = old }()
	j := newJoinLab(t)
	_, e := j.enroll(j.invite("capped").Token, keyA, termsSum())
	j.s.store.saveJob(&api.Job{ID: "j-cap", Spec: api.JobSpec{Device: "capped"}, DeviceID: e.DeviceID, State: api.JobTesting})
	v := j.s.dev("capped")
	v.mu.Lock()
	v.d.ActiveJob = "j-cap"
	v.mu.Unlock()
	if code, _ := j.do("POST", "/api/agent/upload?job=j-cap&name=boot0/journal", e.Secret, "small"); code != 200 {
		t.Fatalf("a small upload: %d", code)
	}
	if code, _ := j.do("POST", "/api/agent/upload?job=j-cap&name=boot0/journal", e.Secret, strings.Repeat("x", 2048)); code != 413 {
		t.Fatalf("an upload over the cap: %d", code)
	}
	dir := filepath.Join(j.s.jobDir("j-cap"), "boot0")
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "journal" {
		t.Errorf("left in the job: %v", ents)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "journal")); string(b) != "small" {
		t.Errorf("the refused upload replaced the file: %q", b)
	}
}

// A job runs only on the enrollment it was submitted for. One from before
// labd recorded enrollments, or one for an earlier Mac by the same name, is
// never dispatched: it ends canceled, and creates no grant.
func TestJobsRunOnlyOnTheirOwnEnrollment(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	kernel := l.artifact("krel=7.2-legacy behavior=ok")
	v := l.s.dev(l.name)
	for id, deviceID := range map[string]string{"jlegacy-0001": "", "jearlier-0001": "d-an-earlier-one"} {
		job := &api.Job{ID: id, Spec: api.JobSpec{Device: l.name, Kernel: kernel}, DeviceID: deviceID, State: api.JobQueued, Created: time.Now()}
		if err := l.s.store.saveJob(job); err != nil {
			t.Fatal(err)
		}
		v.queue <- id
		got := l.waitJob(id, func(j *api.Job) bool { return j.State == api.JobDone })
		if got.Outcome != api.OutcomeCanceled || !strings.Contains(got.Summary, "submit it again") {
			t.Errorf("%s: %s %q", id, got.Outcome, got.Summary)
		}
		if resp, _ := l.agentGet(l.secret, kernel, ""); resp.StatusCode != 404 {
			t.Errorf("%s granted its kernel: %s", id, resp.Status)
		}
	}
}

// waitJob waits for job id to meet cond.
func (l *lab) waitJob(id string, cond func(*api.Job) bool) *api.Job {
	l.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if j, err := l.s.store.job(id); err == nil && cond(j) {
			return j
		}
	}
	l.t.Fatalf("job %s: timed out", id)
	return nil
}

// The Mac's authority over a job ends before anyone can see the job done:
// whoever learns it is done (the stream, a wait) finds its grants gone and
// its files closed. An explicit grant is separate and stays until it expires.
func TestJobAuthorityEndsBeforeTheJobIsSeenDone(t *testing.T) {
	j := newJoinLab(t)
	_, e := j.enroll(j.invite("ending").Token, keyA, termsSum())
	kernel, _ := putArtifactForTest(j.s, "the job's kernel")
	pkg, _ := putArtifactForTest(j.s, "a granted package")
	if code, _ := j.do("POST", "/api/devices/ending/artifact-grants", "adm_secret", `{"artifacts":["`+pkg+`"]}`); code != 200 {
		t.Fatal("grant")
	}
	job := &api.Job{ID: "j-ending", Spec: api.JobSpec{Device: "ending", Kernel: kernel}, DeviceID: e.DeviceID, State: api.JobTesting}
	j.s.store.saveJob(job)
	v := j.s.dev("ending")
	args, _ := json.Marshal(api.StageArgs{Artifact: kernel})
	v.mu.Lock()
	v.d.ActiveJob = job.ID
	v.grantLocked(api.Command{Kind: api.CmdStage, JobID: job.ID, Args: args})
	v.mu.Unlock()
	if code, _ := j.do("GET", "/api/agent/artifacts/"+kernel, e.Secret, ""); code != 200 {
		t.Fatal("the running job's kernel")
	}
	sb := j.s.hub.subscribe("ending")
	defer j.s.hub.unsubscribe(sb)
	(&jobRun{s: j.s, v: v, j: job}).finish(api.OutcomePass, "done")
	for ev := range sb.ch {
		if ev.kind != "job" || !strings.Contains(string(ev.data), `"state":"done"`) {
			continue
		}
		if code, _ := j.do("GET", "/api/agent/artifacts/"+kernel, e.Secret, ""); code != 404 {
			t.Errorf("the job's kernel once it is seen done: %d", code)
		}
		if code, _ := j.do("POST", "/api/agent/upload?job=j-ending&name=late", e.Secret, "late"); code != 404 {
			t.Errorf("an upload once the job is seen done: %d", code)
		}
		if code, _ := j.do("GET", "/api/agent/artifacts/"+pkg, e.Secret, ""); code != 200 {
			t.Errorf("the explicit grant ended with the job: %d", code)
		}
		return
	}
}

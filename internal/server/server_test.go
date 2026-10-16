package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/oob"
)

// fakeOOB is a Central-Scrutinizer-shaped controller wired to a simulated Mac.
type fakeOOB struct {
	sim    *agent.Sim
	lines  chan string
	resets int
	mu     sync.Mutex
}

func (f *fakeOOB) Name() string { return "fake-oob" }
func (f *fakeOOB) Reset(ctx context.Context) error {
	f.mu.Lock()
	f.resets++
	f.mu.Unlock()
	f.sim.PowerCycle()
	return nil
}
func (f *fakeOOB) Raw(ctx context.Context, w io.Writer) error     { <-ctx.Done(); return nil }
func (f *fakeOOB) Write(ctx context.Context, b []byte) error      { return nil }
func (f *fakeOOB) Arm(ctx context.Context, d time.Duration) error { return nil }
func (f *fakeOOB) Status(ctx context.Context) (string, error)     { return "Connection: Sink", nil }
func (f *fakeOOB) Serial(ctx context.Context, fn func(string)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case l := <-f.lines:
			fn(l)
		}
	}
}

type lab struct {
	t      *testing.T
	s      *Server
	sim    *agent.Sim
	oob    *fakeOOB
	notes  []Notification
	mu     sync.Mutex
	cancel context.CancelFunc
	url    string
	name   string // the simulated Mac
}

func newLab(t *testing.T, withOOB bool) *lab { return newLabNamed(t, withOOB, "sim-mac") }

// testKnobs shortens labd's timings for the tests. They're set once: an
// earlier test's labd can still be reading them while the next test starts.
var testKnobs sync.Once

func newLabNamed(t *testing.T, withOOB bool, name string) *lab {
	testKnobs.Do(func() {
		aliveWindow = 1500 * time.Millisecond
		panicGrace = 2 * time.Second
		serialStall = 3 * time.Second
		quietGrace = 3 * time.Second
	})
	ctx, cancel := context.WithCancel(context.Background())
	l := &lab{t: t, cancel: cancel, name: name}
	sim := agent.NewSim(t.TempDir())
	sim.RebootDelay = 300 * time.Millisecond
	l.sim = sim
	l.oob = &fakeOOB{sim: sim, lines: make(chan string, 1000)}
	sim.Serial = func(line string) {
		select {
		case l.oob.lines <- line:
		default:
		}
	}
	quiet := log.New(io.Discard, "", 0)
	if os.Getenv("MACLAB_TEST_LOG") != "" {
		quiet = log.New(os.Stderr, "labd: ", log.Ltime|log.Lmicroseconds)
	}
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "admin", Interval: 200 * time.Millisecond,
		BootTimeout: 4 * time.Second, OfflineAfter: time.Hour, BuilderToken: "bld",
		OOBFactory: func(*api.Device) (oob.Controller, error) { return l.oob, nil }}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	l.s = s
	s.OnNotify(func(n Notification) { l.mu.Lock(); l.notes = append(l.notes, n); l.mu.Unlock() })
	hs := httptest.NewServer(s.Handler())
	l.url = hs.URL
	t.Cleanup(func() { cancel(); hs.Close() })

	// Enroll the simulated Mac exactly as lab-agent setup would.
	tok, _ := s.store.addTokenForTest(name)
	resp, err := agent.Enroll(ctx, hs.URL, tok, sim.Facts())
	if err != nil {
		t.Fatal(err)
	}
	a := agent.New(&agent.Config{Server: hs.URL, DeviceID: resp.DeviceID, Name: resp.Name, Secret: resp.Secret, WorkDir: t.TempDir()}, sim, quiet)
	go a.Run(ctx)
	if withOOB {
		v := s.dev(name)
		v.mu.Lock()
		v.d.OOB = &api.OOBConfig{Driver: "fake"}
		v.mu.Unlock()
		s.attachOOB(v)
	}
	return l
}

func (st *store) addTokenForTest(name string) (string, error) {
	tok := "enr_test_" + name
	return tok, st.addToken(hashSecret(tok), api.EnrollTokenRequest{Name: name, Model: api.ModelLaptop}, time.Now().Add(time.Hour))
}

func (l *lab) artifact(content string) string {
	l.t.Helper()
	sha, err := putArtifactForTest(l.s, content)
	if err != nil {
		l.t.Fatal(err)
	}
	return sha
}

func putArtifactForTest(s *Server, content string) (string, error) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/artifacts", strings.NewReader(content))
	s.hPutArtifact(rec, req)
	var sha string
	body := rec.Body.String()
	if i := strings.Index(body, `"sha256":"`); i >= 0 {
		sha = body[i+10 : i+74]
	}
	return sha, nil
}

func (l *lab) run(spec api.JobSpec) *api.Job {
	l.t.Helper()
	spec.Device = l.name
	j, _, err := l.s.Submit(spec)
	if err != nil {
		l.t.Fatal(err)
	}
	return l.wait(j.ID, 60*time.Second)
}

func (l *lab) wait(id string, d time.Duration) *api.Job {
	l.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		j, err := l.s.store.job(id)
		if err == nil && j.State == api.JobDone {
			return j
		}
		time.Sleep(50 * time.Millisecond)
	}
	j, _ := l.s.store.job(id)
	l.t.Fatalf("job %s did not finish: state %s events %v", id, j.State, j.Events)
	return nil
}

func (l *lab) baseline() {
	l.t.Helper()
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	j := l.run(api.JobSpec{Baseline: true})
	if j.Outcome != api.OutcomePass {
		l.t.Fatalf("baseline: %s: %s\n%v", j.Outcome, j.Summary, j.Events)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
}

func (l *lab) waitDevice(cond func(api.Device) bool) api.Device {
	l.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		d := l.s.dev(l.name).snapshot()
		if cond(d) {
			return d
		}
		time.Sleep(50 * time.Millisecond)
	}
	d := l.s.dev(l.name).snapshot()
	l.t.Fatalf("device condition not met: state=%s reason=%s kernel=%s", d.State, d.StateReason, d.Kernel)
	return d
}

func (l *lab) expect(j *api.Job, outcome string) {
	l.t.Helper()
	if j.Outcome != outcome {
		var ev []string
		for _, e := range j.Events {
			ev = append(ev, e.Msg)
		}
		l.t.Fatalf("outcome %s (%s), want %s\nevents:\n  %s", j.Outcome, j.Summary, outcome, strings.Join(ev, "\n  "))
	}
}

func TestBaselineAndGoodKernel(t *testing.T) {
	l := newLab(t, true)
	if _, _, err := l.s.Submit(api.JobSpec{Device: "sim-mac", Kernel: l.artifact("krel=x")}); err == nil {
		t.Fatal("job accepted before baseline")
	}
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-rc1 behavior=ok"), Tests: []api.TestSpec{{Name: "gui-smoke", Builtin: "gui-smoke"}}})
	l.expect(j, api.OutcomePass)
	if !j.Result.Booted || j.Result.BootKernel != "7.2-rc1" || len(j.Result.Tests) != 2 {
		t.Fatalf("result: %+v", j.Result)
	}
	if len(j.Result.NewErrorLines) != 1 || !strings.Contains(j.Result.NewErrorLines[0], "regression") {
		t.Fatalf("baseline diff: %v", j.Result.NewErrorLines)
	}
	d := l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	if d.Kernel != agent.SimKnownGood || d.Health.JobTag != "" {
		t.Fatalf("not restored: kernel %s tag %q", d.Kernel, d.Health.JobTag)
	}
}

func TestPanicAtBootFallsBack(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-bad behavior=panic")})
	l.expect(j, api.OutcomePanicked)
	if !j.Result.FellBack || l.oob.resets != 0 {
		t.Fatalf("fellback=%v resets=%d", j.Result.FellBack, l.oob.resets)
	}
	if !strings.Contains(j.Summary, "VFS: Unable to mount root fs") {
		t.Fatalf("summary lacks the panic line: %s", j.Summary)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
}

func TestHangRecoveredByHardReset(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-hang behavior=hang")})
	l.expect(j, api.OutcomeHung)
	if l.oob.resets == 0 {
		t.Fatal("expected a hard reset")
	}
	if !strings.Contains(j.Summary, "rcu_sched") {
		t.Fatalf("summary: %s", j.Summary)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
}

func TestSilentHangDetectedFromSerial(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	start := time.Now()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-silent behavior=silent"), BootTimeoutSec: 30})
	l.expect(j, api.OutcomeHung)
	if time.Since(start) > 20*time.Second {
		t.Fatalf("took %s: serial stall should beat the 30s boot timeout", time.Since(start))
	}
	if !strings.Contains(strings.Join(j.Result.Recovery, "|"), "serial console silent") {
		t.Fatalf("recovery: %v", j.Result.Recovery)
	}
}

func TestNoOOBAsksHumanThenResumes(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-hang behavior=hang")})
	l.expect(j, api.OutcomeHung)
	d := l.waitDevice(func(d api.Device) bool { return d.State == api.StateNeedsHands })
	if d.Action == nil || !strings.Contains(d.Action.Text(), "Hold the power button") {
		t.Fatalf("action: %+v", d.Action)
	}
	l.mu.Lock()
	var urgent int
	for _, n := range l.notes {
		if n.Priority == "urgent" {
			urgent++
		}
	}
	l.mu.Unlock()
	if urgent != 1 {
		t.Fatalf("urgent notifications: %d", urgent)
	}

	// A job queued now waits for the human.
	next, _, err := l.s.Submit(api.JobSpec{Device: "sim-mac", Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if j, _ := l.s.store.job(next.ID); j.State != api.JobQueued {
		t.Fatalf("job started while the Mac needed hands: %s", j.State)
	}
	l.sim.PowerCycle() // the human
	l.expect(l.wait(next.ID, 60*time.Second), api.OutcomePass)
}

func TestCrashDuringTest(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-oops behavior=crash-in-test")})
	l.expect(j, api.OutcomePanicked)
	if !strings.Contains(j.Summary, "during test boot-health") {
		t.Fatalf("summary: %s", j.Summary)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
}

func TestCrashTestSelfRecovers(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Crash: "panic"})
	l.expect(j, api.OutcomePass)
	if !strings.Contains(j.Summary, "recovered by itself") {
		t.Fatalf("summary: %s", j.Summary)
	}
}

func TestFailingTest(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok"), Tests: []api.TestSpec{{Name: "will-fail", Builtin: "x"}}})
	l.expect(j, api.OutcomeTestsFailed)
}

func (l *lab) get(method, path string) (*http.Response, string) {
	l.t.Helper()
	req, _ := http.NewRequest(method, l.url+path, nil)
	req.Header.Set("Authorization", "Bearer admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestLiveStreamScreenAndLogs(t *testing.T) {
	l := newLab(t, true)
	l.baseline()

	// The stream carries job, device and serial events while a job runs.
	req, _ := http.NewRequest("GET", l.url+"/api/stream", nil)
	req.Header.Set("Authorization", "Bearer admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	kinds := make(chan string, 1000)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if k, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				kinds <- k
			}
		}
	}()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-live behavior=ok")})
	l.expect(j, api.OutcomePass)
	seen := map[string]bool{}
	for len(kinds) > 0 {
		seen[<-kinds] = true
	}
	for _, k := range []string{"job", "device", "serial", "screen"} {
		if !seen[k] {
			t.Errorf("stream never sent a %q event (saw %v)", k, seen)
		}
	}
	// Jobs capture the screen after boot and after tests.
	var shots int
	for _, f := range j.Result.Logs {
		if strings.HasPrefix(f, "screen/") {
			shots++
		}
	}
	if shots != 2 {
		t.Errorf("job screenshots: %v", j.Result.Logs)
	}

	// Capture now, then fetch the latest image.
	if r, body := l.get("POST", "/api/devices/sim-mac/screenshot"); r.StatusCode != 200 {
		t.Fatalf("screenshot: %s %s", r.Status, body)
	}
	r, body := l.get("GET", "/api/devices/sim-mac/screen")
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/jpeg" || len(body) < 1000 {
		t.Fatalf("screen: %s %s %d bytes", r.Status, r.Header.Get("Content-Type"), len(body))
	}
	if r, body := l.get("GET", "/api/devices/sim-mac/logs?source=kernel&lines=10"); r.StatusCode != 200 || !strings.Contains(body, "sim kernel") {
		t.Fatalf("logs: %s %q", r.Status, body)
	}
}

func TestScreenAtRestoredOnStart(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	quiet := log.New(io.Discard, "", 0)
	s, err := New(ctx, Config{DataDir: dir, AdminToken: "a"}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	d := api.Device{ID: "d1", Name: "mac", State: api.StateReady}
	s.store.saveDevice(&d, "h")
	os.MkdirAll(s.screenDir("mac"), 0o755)
	os.WriteFile(filepath.Join(s.screenDir("mac"), "1790753481823.jpg"), []byte("x"), 0o644)
	s2, err := New(ctx, Config{DataDir: dir, AdminToken: "a"}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.view(s2.dev("mac")).ScreenAt; got.UnixMilli() != 1790753481823 {
		t.Fatalf("screen_at %v", got)
	}
}

// fakeBuilder plays lab-builder: it takes builds and "builds" a sim kernel.
func (l *lab) fakeBuilder(ctx context.Context, builds *int) {
	post := func(path string, body io.Reader, out any) int {
		req, _ := http.NewRequestWithContext(ctx, "POST", l.url+path, body)
		req.Header.Set("Authorization", "Bearer bld")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		if out != nil {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	for ctx.Err() == nil {
		var a api.BuildAssignment
		if post("/api/builder/poll?host=fake", nil, &a) != 200 {
			continue
		}
		*builds++
		lines := `{"lines":["==> fetch","@@stage fetch","@@stage build","@@progress 50 100","CC some/file.o warning: x","@@progress 100 100"]}`
		post("/api/builder/builds/"+a.Build.ID+"/progress", strings.NewReader(lines), nil)
		var up struct{ SHA256 string }
		post("/api/builder/artifacts", strings.NewReader("krel=7.2-src"+a.LabVer+" behavior=ok"), &up)
		done, _ := json.Marshal(api.BuildResult{Release: "7.2-src" + a.LabVer, Artifact: up.SHA256, Seconds: 1})
		post("/api/builder/builds/"+a.Build.ID+"/done", bytes.NewReader(done), nil)
	}
}

func gitRepo(t *testing.T) string {
	dir := t.TempDir()
	run := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(dir, "Makefile"), []byte("all:\n"), 0o644)
	run("add", ".")
	run("commit", "-q", "-m", "x")
	return "file://" + dir + "@main"
}

func TestSourceBuildJobAndReuse(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	builds := 0
	go l.fakeBuilder(ctx, &builds)

	src := gitRepo(t)
	j := l.run(api.JobSpec{Source: src})
	l.expect(j, api.OutcomePass)
	if !strings.HasPrefix(j.Result.BootKernel, "7.2-src-lab") || j.Spec.Build == "" {
		t.Fatalf("booted %q build %q", j.Result.BootKernel, j.Spec.Build)
	}
	var hasLog bool
	for _, f := range j.Result.Logs {
		hasLog = hasLog || f == "build.log"
	}
	b, err := l.s.getBuild(j.Spec.Build)
	if err != nil || !hasLog || b.State != api.BuildDone || b.LogLines != 2 || b.Progress != 1 {
		t.Fatalf("build %+v log=%v err=%v", b, hasLog, err)
	}
	if r, body := l.get("GET", "/api/builds/"+b.ID+"/log"); r.StatusCode != 200 || !strings.Contains(body, "warning: x") || strings.Contains(body, "@@") {
		t.Fatalf("log: %s %q", r.Status, body)
	}

	// Same source again: no second build.
	j2 := l.run(api.JobSpec{Source: src})
	l.expect(j2, api.OutcomePass)
	if builds != 1 || j2.Spec.Build != b.ID {
		t.Fatalf("builds=%d reused=%s want %s", builds, j2.Spec.Build, b.ID)
	}
	var reused bool
	for _, e := range j2.Events {
		reused = reused || strings.HasPrefix(e.Msg, "reusing ")
	}
	if !reused {
		t.Fatal("second job did not say it reused the build")
	}
}

func TestBuildFailureFailsJob(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Source: "file:///nonexistent/repo.git@main"})
	l.expect(j, api.OutcomeBuildFailed)

	// A build that starts and fails still links the job to its build and log.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			req, _ := http.NewRequestWithContext(ctx, "POST", l.url+"/api/builder/poll?host=x", nil)
			req.Header.Set("Authorization", "Bearer bld")
			resp, err := http.DefaultClient.Do(req)
			if err != nil || resp.StatusCode != 200 {
				continue
			}
			var a api.BuildAssignment
			json.NewDecoder(resp.Body).Decode(&a)
			resp.Body.Close()
			done, _ := json.Marshal(api.BuildResult{Error: "compile error"})
			r2, _ := http.NewRequest("POST", l.url+"/api/builder/builds/"+a.Build.ID+"/done", bytes.NewReader(done))
			r2.Header.Set("Authorization", "Bearer bld")
			http.DefaultClient.Do(r2)
		}
	}()
	j = l.run(api.JobSpec{Source: gitRepo(t)})
	l.expect(j, api.OutcomeBuildFailed)
	if j.Spec.Build == "" {
		t.Fatal("failed build job has no spec.build")
	}
}

func TestPackageBuild(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recipe := l.artifact("PKGBUILD tarball")
	b, err := l.s.EnsureBuild(ctx, api.BuildRequest{Recipe: recipe, RecipeDir: "/r/linux-aurora", Pkgrel: "11.14"})
	if err != nil || b.Kind != api.BuildPackage || b.State != api.BuildQueued {
		t.Fatalf("queue: %+v %v", b, err)
	}
	if _, err := l.s.EnsureBuild(ctx, api.BuildRequest{Recipe: recipe, Pkgrel: "eleven"}); err == nil {
		t.Fatal("a bad pkgrel was accepted")
	}

	poll := func(kinds string, wait time.Duration) (api.BuildAssignment, int) {
		pctx, done := context.WithTimeout(ctx, wait)
		defer done()
		req, _ := http.NewRequestWithContext(pctx, "POST", l.url+"/api/builder/poll?host=x&kinds="+kinds, nil)
		req.Header.Set("Authorization", "Bearer bld")
		var a api.BuildAssignment
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return a, 0
		}
		defer resp.Body.Close()
		json.NewDecoder(resp.Body).Decode(&a)
		return a, resp.StatusCode
	}
	// A builder that only knows kernel builds must not get it.
	if a, code := poll("", 1500*time.Millisecond); code == 200 {
		t.Fatalf("kernel-only builder got %+v", a.Build)
	}
	a, code := poll("kernel,package", 5*time.Second)
	if code != 200 || a.Build.ID != b.ID || a.Build.Pkgrel != "11.14" || a.LabVer != "" {
		t.Fatalf("package builder got %d %+v labver %q", code, a.Build, a.LabVer)
	}
	upload := func(content string) string {
		req, _ := http.NewRequest("POST", l.url+"/api/builder/artifacts", strings.NewReader(content))
		req.Header.Set("Authorization", "Bearer bld")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var up struct{ SHA256 string }
		json.NewDecoder(resp.Body).Decode(&up)
		return up.SHA256
	}
	kpkg := upload("krel=7.1.12-2-11.14-sep-ARCH behavior=ok")
	hpkg := upload("headers")
	files := []api.BuildFile{{Name: "linux-aurora-7.1.12.aurora2-11.14-aarch64.pkg.tar.zst", SHA256: kpkg, Size: 41},
		{Name: "linux-aurora-headers-7.1.12.aurora2-11.14-aarch64.pkg.tar.zst", SHA256: hpkg, Size: 7}}
	done, _ := json.Marshal(api.BuildResult{Release: "7.1.12-2-11.14-sep-ARCH", Artifact: kpkg, Files: files, Seconds: 900})
	req, _ := http.NewRequest("POST", l.url+"/api/builder/builds/"+b.ID+"/done", bytes.NewReader(done))
	req.Header.Set("Authorization", "Bearer bld")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 204 {
		t.Fatalf("done: %v %v", resp, err)
	}
	b, _ = l.s.getBuild(b.ID)
	if b.State != api.BuildDone || len(b.Files) != 2 || b.Artifact != kpkg {
		t.Fatalf("finished build %+v", b)
	}
	if r, body := l.get("GET", "/api/builds/"+b.ID+"/files/"+files[1].Name); r.StatusCode != 200 || body != "headers" ||
		!strings.Contains(r.Header.Get("Content-Disposition"), files[1].Name) {
		t.Fatalf("file: %s %q", r.Status, body)
	}
	if r, _ := l.get("GET", "/api/builds/"+b.ID+"/files/..%2Fetc%2Fpasswd"); r.StatusCode != 404 {
		t.Fatalf("unknown file: %s", r.Status)
	}
	// The recipe it was built from is served as uploaded, and the artifact GC
	// keeps it even when it is old and the store is over budget.
	if r, body := l.get("GET", "/api/builds/"+b.ID+"/files/"+api.RecipeFile); r.StatusCode != 200 || body != "PKGBUILD tarball" {
		t.Fatalf("recipe: %s %q", r.Status, body)
	}
	month := time.Now().Add(-30 * 24 * time.Hour)
	os.Chtimes(l.s.artifactPath(recipe), month, month)
	budget := l.s.cfg.ArtifactBudget
	l.s.cfg.ArtifactBudget = 1
	l.s.gcArtifacts()
	l.s.cfg.ArtifactBudget = budget
	if _, err := os.Stat(l.s.artifactPath(recipe)); err != nil {
		t.Fatalf("the artifact GC removed the recipe: %v", err)
	}
	// The same recipe and pkgrel again is the same build.
	if again, err := l.s.EnsureBuild(ctx, api.BuildRequest{Recipe: recipe, Pkgrel: "11.14"}); err != nil || again.ID != b.ID {
		t.Fatalf("not reused: %+v %v", again, err)
	}
	// And the kernel package boots once like any kernel artifact.
	j := l.run(api.JobSpec{Kernel: b.Artifact})
	l.expect(j, api.OutcomePass)
	if j.Result.BootKernel != "7.1.12-2-11.14-sep-ARCH" {
		t.Fatalf("booted %q", j.Result.BootKernel)
	}
}

func TestSuspendDuringTestIsNotACrash(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	l.sim.SuspendFor = 6 * time.Second // well past quietGrace: only the announcement keeps it waiting
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok"),
		Tests: []api.TestSpec{{Name: "suspend-then-resume", Builtin: "x"}, {Name: "after-resume", Builtin: "x"}}})
	l.expect(j, api.OutcomePass)
	var slept, back bool
	for _, e := range j.Events {
		slept = slept || strings.Contains(e.Msg, "went to sleep")
		back = back || strings.Contains(e.Msg, "back on the same boot")
	}
	if !slept || !back || len(j.Result.Recovery) != 0 || len(j.Result.Tests) != 3 {
		t.Fatalf("slept=%v back=%v recovery=%v tests=%+v", slept, back, j.Result.Recovery, j.Result.Tests)
	}
}

func TestShortQuietSpellDuringTest(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	l.sim.SuspendFor = 2 * time.Second // past aliveWindow, within quietGrace, never announced
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok"), Tests: []api.TestSpec{{Name: "quiet-suspend-wifi-drop", Builtin: "x"}}})
	l.expect(j, api.OutcomePass)
	if len(j.Result.Recovery) != 0 {
		t.Fatalf("recovery %v", j.Result.Recovery)
	}
}

func TestOmarchyMTest(t *testing.T) {
	l := newLab(t, true)
	var posts []string
	var mu sync.Mutex
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		posts = append(posts, string(b))
		n := len(posts)
		mu.Unlock()
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"id":"r%d","report_url":"https://site/reports/r%d","deletion_url":"https://site/del/r%d?token=x","tester":false}`, n, n, n)
	}))
	defer site.Close()
	l.s.cfg.OMT, l.s.cfg.OMTSite, l.s.cfg.OMTPublish = true, site.URL, true
	l.waitDevice(func(d api.Device) bool { return d.Facts.AgentVersion != "" })

	// The baseline runs it on the known-good kernel, keeps it as the reference and publishes it.
	l.baseline()
	jobs, _ := l.s.store.jobs("sim-mac", 1, false)
	base := jobs[0]
	if o := base.Result.OMT; o == nil || !o.KnownGood || o.Pass != 3 || o.Fail != 1 || o.Skip != 1 || o.Published != "https://site/reports/r1" {
		t.Fatalf("baseline omt %+v", base.Result.OMT)
	}
	if len(posts) != 1 || !strings.Contains(posts[0], `"kernel":"`+agent.SimKnownGood+`"`) {
		t.Fatalf("site got %d posts: %v", len(posts), posts)
	}
	if _, err := os.Stat(filepath.Join(l.s.jobDir(base.ID), "omt-published.json")); err != nil {
		t.Fatal("the deletion link was not kept with the job")
	}

	// A good lab kernel: same results, nothing regressed, not published.
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.expect(j, api.OutcomePass)
	if o := j.Result.OMT; o == nil || o.KnownGood || len(o.Regressions) != 0 || len(o.LabBoot) != 1 || o.Published != "" || !strings.Contains(o.ComparedTo, base.ID) {
		t.Fatalf("good kernel omt %+v", j.Result.OMT)
	}

	// A lab kernel that breaks Wi-Fi fails the job and names the check.
	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-bad behavior=omt-regress")})
	l.expect(j, api.OutcomeTestsFailed)
	if o := j.Result.OMT; o == nil || len(o.Regressions) != 1 || o.Regressions[0].ID != "wifi.connected" {
		t.Fatalf("regressed omt %+v", j.Result.OMT)
	}
	// A kernel without the fingerprint driver, which the job says to expect, passes;
	// the same kernel with a different node unbound would still fail.
	j2 := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-tb behavior=omt-no-fingerprint"), OMTAllow: []string{"hardware.drivers:apple,mesa-fingerprint"}})
	l.expect(j2, api.OutcomePass)
	if o := j2.Result.OMT; len(o.Allowed) != 1 || len(o.Regressions) != 0 {
		t.Fatalf("allowed omt %+v", o)
	}
	j2 = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-tb2 behavior=omt-no-fingerprint"), OMTAllow: []string{"hardware.drivers:apple,other"}})
	l.expect(j2, api.OutcomeTestsFailed)

	// And it can't be published: the site would file it under the packaged kernel.
	if r, body := l.get("POST", "/api/jobs/"+j.ID+"/publish"); r.StatusCode != 409 || !strings.Contains(body, "lab kernel") {
		t.Fatalf("publish of a lab kernel run: %s %s", r.Status, body)
	}
	if len(posts) != 1 {
		t.Fatalf("site got %d posts, want 1", len(posts))
	}

	// A known-good run whose job fails keeps the old reference; a clean one replaces it.
	ref, _ := os.ReadFile(l.s.omtBaselinePath("sim-mac"))
	l.s.cfg.OMTPublish = false
	j = l.run(api.JobSpec{Tests: []api.TestSpec{{Name: "check-that-will-fail", Builtin: "x"}}})
	l.expect(j, api.OutcomeTestsFailed)
	if now, _ := os.ReadFile(l.s.omtBaselinePath("sim-mac")); !bytes.Equal(ref, now) || !strings.HasPrefix(j.Result.OMT.Reference, "kept") {
		t.Fatalf("a failed known-good job replaced the reference (%s)", j.Result.OMT.Reference)
	}
	j = l.run(api.JobSpec{})
	l.expect(j, api.OutcomePass)
	if now, _ := os.ReadFile(l.s.omtBaselinePath("sim-mac")); !strings.Contains(string(now), j.ID) || j.Result.OMT.Reference != "became the reference" {
		t.Fatalf("a clean known-good job did not become the reference (%s)", j.Result.OMT.Reference)
	}
}

// omtDriversReport is cut down from two real MacBook Air (M1) reports, where
// hardware.drivers fails on every kernel: the known-good kernel leaves the SEP
// unclaimed, and a lab kernel that lost the Neural Engine's driver leaves that
// instead. Both leave the fingerprint reader unclaimed.
func omtDriversReport(kernel string, nodes ...string) []byte {
	unclaimed := map[string][2]string{ // compatible -> inventory entry, evidence line
		"apple,mesa-fingerprint": {`{"compatible":"apple,mesa-fingerprint","count":1,"outcome":"unknown-hardware"}`,
			"unclaimed: apple,mesa-fingerprint (1 node): unknown hardware"},
		"apple,sep": {`{"compatible":"apple,sep","count":1,"outcome":"not-in-asahi","feature":"sep","layer":"asahi"}`,
			"unclaimed: apple,sep (1 node): not yet supported by Asahi (Secure enclave (SEP))"},
		"apple,t8103-ane": {`{"compatible":"apple,t8103-ane","count":1,"outcome":"not-in-asahi","feature":"neural-engine","layer":"asahi"}`,
			"unclaimed: apple,t8103-ane (1 node): not yet supported by Asahi (Neural engine)"},
	}
	var inv, ev []string
	for _, n := range nodes {
		inv, ev = append(inv, unclaimed[n][0]), append(ev, strconv.Quote(unclaimed[n][1]))
	}
	return fmt.Appendf(nil, `{"schema_version":1,"tool":{"name":"omarchy-m-test","version":"0.1.13"},"catalogue_version":14,
"machine":{"model":"Apple MacBook Air (M1, 2020)","soc":"t8103","kernel":%q},"inventory":{"unclaimed":[%s]},
"checks":[{"id":"system.identity","kind":"automatic","status":"pass","evidence":["chip: M1 (t8103)"],"classification":{"outcome":"works"}},
{"id":"hardware.drivers","kind":"automatic","status":"fail","evidence":["279 hardware nodes: %d unclaimed",%s],"classification":{"outcome":"not-in-aurora"}}]}`,
		kernel, strings.Join(inv, ","), len(nodes), strings.Join(ev, ","))
}

func TestOmarchyMTestDriverNodes(t *testing.T) {
	l := newLab(t, true)
	l.s.cfg.OMT = true
	l.sim.OMTReport = func(kernel string) []byte {
		if strings.HasPrefix(kernel, "7.2-ane") {
			return omtDriversReport(kernel, "apple,mesa-fingerprint", "apple,t8103-ane")
		}
		return omtDriversReport(kernel, "apple,mesa-fingerprint", "apple,sep")
	}
	l.waitDevice(func(d api.Device) bool { return d.Facts.AgentVersion != "" })
	l.baseline()
	var ref omtBaseline
	if b, _ := os.ReadFile(l.s.omtBaselinePath("sim-mac")); json.Unmarshal(b, &ref) != nil || strings.Join(ref.Unclaimed, " ") != "apple,mesa-fingerprint apple,sep" {
		t.Fatalf("reference %+v", ref)
	}

	// The same nodes unclaimed: nothing changed, though the check fails on both.
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.expect(j, api.OutcomePass)
	if o := j.Result.OMT; len(o.Regressions) != 0 || len(o.Fixed) != 0 {
		t.Fatalf("same nodes omt %+v", o)
	}

	// The Neural Engine lost its driver: hardware.drivers fails on both kernels,
	// but the node regressed, and the SEP gained one.
	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ane behavior=ok")})
	l.expect(j, api.OutcomeTestsFailed)
	o := j.Result.OMT
	if len(o.Regressions) != 1 || o.Regressions[0].ID != "hardware.drivers:apple,t8103-ane" || o.Regressions[0].Outcome != "not-in-asahi" ||
		!strings.Contains(o.Regressions[0].Evidence, "Neural engine") || len(o.Fixed) != 1 || o.Fixed[0].ID != "hardware.drivers:apple,sep" {
		t.Fatalf("lost driver omt %+v", o)
	}
	named := false
	for _, e := range j.Events {
		named = named || strings.Contains(e.Msg, "hardware.drivers:apple,t8103-ane regressed, hardware.drivers:apple,sep fixed")
	}
	if !named || !strings.Contains(j.Result.Tests[len(j.Result.Tests)-1].Error, "hardware.drivers:apple,t8103-ane") {
		t.Fatalf("the events don't name the node: %+v %+v", j.Events, j.Result.Tests)
	}

	// --omt-allow names the node to expect; another node's name doesn't cover it.
	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ane2 behavior=ok"), OMTAllow: []string{"hardware.drivers:apple,t8103-ane"}})
	l.expect(j, api.OutcomePass)
	if o := j.Result.OMT; len(o.Allowed) != 1 || len(o.Regressions) != 0 {
		t.Fatalf("allowed omt %+v", o)
	}
	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ane3 behavior=ok"), OMTAllow: []string{"hardware.drivers:apple,other"}})
	l.expect(j, api.OutcomeTestsFailed)

	// A reference recorded before the lab kept its unclaimed nodes compares as before.
	ref.Unclaimed = nil
	b, _ := json.Marshal(ref)
	os.WriteFile(l.s.omtBaselinePath("sim-mac"), b, 0o644)
	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ane4 behavior=ok")})
	l.expect(j, api.OutcomePass)
}

func TestCmdlineBaseAndStrip(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok"), CmdlineBase: "default", Cmdline: "extra=1"})
	l.expect(j, api.OutcomePass)
	c := j.Result.BootCmdline
	if !strings.HasPrefix(c, "root=UUID=sim rw loglevel=7 panic=10") || strings.Contains(c, "quiet") || !strings.Contains(c, "extra=1") || !strings.Contains(c, "maclab.job="+j.ID) {
		t.Fatalf("booted with %q", c)
	}
	var shown bool
	for _, e := range j.Events {
		shown = shown || strings.HasPrefix(e.Msg, "cmdline: root=UUID=sim rw")
	}
	if !shown {
		t.Fatal("the job does not show the staged cmdline")
	}
	// A strip that would leave no root= fails the stage, not the boot.
	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok2 behavior=ok"), CmdlineStrip: []string{"root"}})
	l.expect(j, api.OutcomeStageFailed)
	if _, code, err := l.s.Submit(api.JobSpec{Device: "sim-mac", Baseline: true, CmdlineBase: "default"}); err == nil || code != 400 {
		t.Fatalf("baseline with a cmdline base: %d %v", code, err)
	}
	if _, code, err := l.s.Submit(api.JobSpec{Device: "sim-mac", CmdlineStrip: []string{"[bad"}}); err == nil || code != 400 {
		t.Fatalf("bad glob: %d %v", code, err)
	}
}

// Without a serial console a test boot keeps the base's quiet and splash,
// unless the job asks for a verbose boot.
func TestQuietTestBoots(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-quiet behavior=ok"), CmdlineBase: "default"})
	l.expect(j, api.OutcomePass)
	if c := j.Result.BootCmdline; !strings.HasPrefix(c, "root=UUID=sim rw quiet splash panic=10") || strings.Contains(c, "loglevel=7") {
		t.Fatalf("quiet boot: %q", c)
	}
	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-verbose behavior=ok"), CmdlineBase: "default", VerboseBoot: true})
	l.expect(j, api.OutcomePass)
	if c := j.Result.BootCmdline; !strings.HasPrefix(c, "root=UUID=sim rw loglevel=7 panic=10") || strings.Contains(c, "quiet") {
		t.Fatalf("verbose boot: %q", c)
	}
}

func TestBuildWithUploadedConfig(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	builds := 0
	go l.fakeBuilder(ctx, &builds)
	cfg := l.artifact("CONFIG_ARM64=y\nCONFIG_APPLE_T6030_DISPLAY_GATE=y\n")
	src := gitRepo(t)
	b, err := l.s.EnsureBuild(ctx, api.BuildRequest{Source: src, Config: cfg, ConfigName: "unified.config"})
	if err != nil || b.ConfigSHA != cfg || b.ConfigName != "unified.config" || b.Device != "" {
		t.Fatalf("build %+v %v", b, err)
	}
	// A job built from the same source and config reuses that build, whatever Mac it runs on.
	j := l.run(api.JobSpec{Source: src, Config: cfg})
	l.expect(j, api.OutcomePass)
	if j.Spec.Build != b.ID || builds != 1 {
		t.Fatalf("job used build %s (want %s), %d builds", j.Spec.Build, b.ID, builds)
	}
	// The Mac's own config is a different build.
	if b2, _ := l.s.EnsureBuild(ctx, api.BuildRequest{Source: src, Device: "sim-mac"}); b2.Key == b.Key {
		t.Fatal("device config and uploaded config share a build key")
	}
	if _, code, err := l.s.Submit(api.JobSpec{Device: "sim-mac", Config: cfg}); err == nil || code != 400 {
		t.Fatalf("config without a source: %d %v", code, err)
	}
}

func TestRunningBuildSurvivesLabdRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	quiet := log.New(io.Discard, "", 0)
	s1, err := New(ctx, Config{DataDir: dir, AdminToken: "a", BuilderToken: "bld"}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b := &api.Build{ID: "b1004-000000-abcd", Key: "k", Source: api.Source{Repo: "https://github.com/x/y", SHA: strings.Repeat("a", 40)},
		ConfigSHA: "c", State: api.BuildRunning, Stage: "build", Created: now, Updated: now}
	s1.saveBuild(b)
	// labd restarts while the builder keeps compiling.
	s2, err := New(ctx, Config{DataDir: dir, AdminToken: "a", BuilderToken: "bld"}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let buildMonitor's startup pass run
	if got, _ := s2.getBuild(b.ID); got.State != api.BuildRunning {
		t.Fatalf("after restart: %s %s", got.State, got.Error)
	}
	hs := httptest.NewServer(s2.Handler())
	defer hs.Close()
	up, _ := http.NewRequest("POST", hs.URL+"/api/builder/artifacts", strings.NewReader("kernel"))
	up.Header.Set("Authorization", "Bearer bld")
	resp, err := http.DefaultClient.Do(up)
	if err != nil {
		t.Fatal(err)
	}
	var art struct{ SHA256 string }
	json.NewDecoder(resp.Body).Decode(&art)
	resp.Body.Close()
	done, _ := json.Marshal(api.BuildResult{Release: "7.2-x", Artifact: art.SHA256, Seconds: 1})
	req, _ := http.NewRequest("POST", hs.URL+"/api/builder/builds/"+b.ID+"/done", bytes.NewReader(done))
	req.Header.Set("Authorization", "Bearer bld")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 204 {
		t.Fatalf("done: %v %v", resp, err)
	}
	if got, _ := s2.getBuild(b.ID); got.State != api.BuildDone {
		t.Fatalf("after done: %s %s", got.State, got.Error)
	}
}

func TestCancelWhileBootingRestoresKnownGood(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	l.sim.RebootDelay = 2 * time.Second // long enough to cancel mid-reboot
	j, _, err := l.s.Submit(api.JobSpec{Device: "sim-mac", Kernel: l.artifact("krel=7.2-slow behavior=ok")})
	if err != nil {
		t.Fatal(err)
	}
	// Cancel the moment the one-shot is armed, while the Mac reboots into the test kernel.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		cur, _ := l.s.store.job(j.ID)
		if cur.State == api.JobBooting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r, body := l.get("POST", "/api/jobs/"+j.ID+"/cancel"); r.StatusCode != 200 {
		t.Fatalf("cancel: %s %s", r.Status, body)
	}
	j = l.wait(j.ID, 60*time.Second)
	if j.Outcome != api.OutcomeCanceled {
		t.Fatalf("outcome %s: %s", j.Outcome, j.Summary)
	}
	if d := l.s.dev("sim-mac").snapshot(); d.Kernel != agent.SimKnownGood || d.Health.JobTag != "" {
		t.Fatalf("after the cancel the Mac runs %s (lab entry %q); events %v", d.Kernel, d.Health.JobTag, j.Events)
	}
	// The next job stages the same kernel without tripping over it.
	l.sim.RebootDelay = 300 * time.Millisecond
	l.expect(l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-slow behavior=ok")}), api.OutcomePass)
}

func TestBaselinePublishesWhenKnownGoodChanges(t *testing.T) {
	l := newLab(t, true)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		fmt.Fprint(w, `{"report_url":"https://site/r/1","deletion_url":"https://site/d/1"}`)
	}))
	defer site.Close()
	l.s.cfg.OMT, l.s.cfg.OMTSite, l.s.cfg.OMTPublish = true, site.URL, true
	l.waitDevice(func(d api.Device) bool { return d.Facts.AgentVersion != "" })
	l.baseline()
	// The Mac's kernel was upgraded outside the lab; the next baseline re-records it.
	v := l.s.dev("sim-mac")
	v.mu.Lock()
	v.d.KnownGood = "7.1.12-old"
	v.mu.Unlock()
	j := l.run(api.JobSpec{Baseline: true})
	l.expect(j, api.OutcomePass)
	if o := j.Result.OMT; o == nil || o.Published != "https://site/r/1" {
		t.Fatalf("baseline after a kernel change was not published: %+v", j.Result.OMT)
	}
}

func TestResetRespectsLease(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	v := l.s.dev("sim-mac")
	v.mu.Lock()
	v.d.Lease = &api.Lease{Holder: "connor (homework)", Expires: time.Now().Add(time.Hour)}
	v.mu.Unlock()
	if r, body := l.get("POST", "/api/devices/sim-mac/reset?by=some-agent"); r.StatusCode != 409 || !strings.Contains(body, "connor (homework)") {
		t.Fatalf("reset by a non-holder: %s %s", r.Status, body)
	}
	if r, _ := l.get("POST", "/api/devices/sim-mac/reset?by="+url.QueryEscape("connor (homework)")); r.StatusCode != 200 {
		t.Fatalf("reset by the holder: %s", r.Status)
	}
}

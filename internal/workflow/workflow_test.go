package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func pinFile(t *testing.T, path string, b []byte) Pin {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return Pin{path, Hash(b), int64(len(b))}
}
func fixture(t *testing.T, phases ...Phase) *Runner {
	t.Helper()
	dir := t.TempDir()
	p := Plan{Schema: "maclab.workflow/1", ID: "fixture", Device: "testmac", Inputs: raw(map[string]any{"boot_id": "fresh-actual-boot", "kernel": strings.Repeat("a", 64)}), Phases: phases}
	b := raw(p)
	path := filepath.Join(dir, "plan.json")
	os.WriteFile(path, b, 0600)
	r, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Dir = filepath.Join(dir, "state")
	return r
}
func authFor(t *testing.T, r *Runner, until time.Time, scopes ...string) string {
	t.Helper()
	e := pinFile(t, filepath.Join(filepath.Dir(r.Dir), "actual-operator-evidence.json"), []byte(`{"fixture":"test-only explicit evidence"}`))
	a := Authorization{Schema: "maclab.workflow-authorization/1", PlanSHA256: r.PlanSHA, Device: r.Plan.Device, ApprovedBy: "CPU-test", Evidence: e, Scopes: scopes, ValidUntil: until}
	p := filepath.Join(filepath.Dir(r.Dir), "authorization.json")
	os.WriteFile(p, raw(a), 0600)
	return p
}
func bindPhase() Phase {
	return Phase{ID: "binding", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"expected_boot_id": "", "authorized": false}), Bind: map[string]Value{"/expected_boot_id": {"inputs", "/boot_id"}}}
}
func jobPhases() []Phase {
	return []Phase{{ID: "job-spec", Kind: "bind", TimeoutSec: 2, Template: raw(api.JobSpec{Device: "testmac", Kernel: strings.Repeat("a", 64), Holder: "fixture"})}, {ID: "submit", Kind: "submit", TimeoutSec: 2, Mutates: true, Scope: "boot-test", InputPhase: "job-spec"}, {ID: "wait", Kind: "wait", TimeoutSec: 2, InputPhase: "submit"}}
}

type fakeBackend struct {
	Submits, Uploads, Reads int
	Crash                   bool
	Fail                    bool
	Actual                  *api.Job
}

func (f *fakeBackend) Submit(ctx context.Context, s api.JobSpec) (*api.Job, error) {
	f.Submits++
	if f.Crash {
		panic("crash after actual submission")
	}
	if f.Fail {
		return nil, errors.New("response lost after server may accept")
	}
	f.Actual = &api.Job{ID: "real-fixture-job", Spec: s, State: api.JobDone, Outcome: api.OutcomePass}
	return f.Actual, nil
}
func (f *fakeBackend) Upload(ctx context.Context, path string) (string, error) {
	f.Uploads++
	b, e := os.ReadFile(path)
	return Hash(b), e
}
func (f *fakeBackend) Job(ctx context.Context, id string) (*api.Job, error) {
	f.Reads++
	return f.Actual, nil
}
func readState(t *testing.T, r *Runner) *State {
	t.Helper()
	l, s, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	return s
}

func TestBindingsResumeAndCanonicalEvidence(t *testing.T) {
	r := fixture(t, bindPhase())
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	s := readState(t, r)
	var b map[string]any
	json.Unmarshal(s.Records["binding"].Output, &b)
	if b["expected_boot_id"] != "fresh-actual-boot" || b["authorized"] != false {
		t.Fatalf("binding fabricated authorization or wrong boot: %v", b)
	}
	if s.Records["binding"].Attempt == "" {
		t.Fatal("missing intent")
	}
}
func TestAmbiguousSubmissionNeverRepeats(t *testing.T) {
	r := fixture(t, jobPhases()...)
	f := &fakeBackend{Fail: true}
	r.Backend = f
	a := authFor(t, r, time.Now().Add(time.Hour), "boot-test")
	if e := r.Run(context.Background(), a, false); e == nil {
		t.Fatal("expected ambiguity")
	}
	if e := r.Run(context.Background(), a, false); e == nil || !strings.Contains(e.Error(), "reconciliation") {
		t.Fatal(e)
	}
	if f.Submits != 1 || f.Reads != 0 {
		t.Fatal("duplicate submission or advanced after ambiguity")
	}
	s := readState(t, r)
	if s.Records["submit"].State != "uncertain" || s.Records["submit"].RequestSHA256 == "" {
		t.Fatal("missing exact intent")
	}
}
func TestCrashAfterSubmissionJournalSurvives(t *testing.T) {
	r := fixture(t, jobPhases()...)
	f := &fakeBackend{Crash: true}
	r.Backend = f
	a := authFor(t, r, time.Now().Add(time.Hour), "boot-test")
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no crash")
			}
		}()
		_ = r.Run(context.Background(), a, false)
	}()
	f.Crash = false
	if e := r.Run(context.Background(), a, false); e == nil {
		t.Fatal("interrupted mutation replayed")
	}
	if f.Submits != 1 {
		t.Fatal("duplicated")
	}
	s := readState(t, r)
	if s.Records["submit"].State != "running" {
		t.Fatal("crash intent lost")
	}
}
func TestReconcileActualOutputAndContinueWithoutRepeat(t *testing.T) {
	r := fixture(t, jobPhases()...)
	f := &fakeBackend{Fail: true}
	r.Backend = f
	a := authFor(t, r, time.Now().Add(time.Hour), "boot-test")
	_ = r.Run(context.Background(), a, false)
	s := readState(t, r)
	j := api.Job{ID: "actual-existing-job", Spec: api.JobSpec{Device: "testmac", Kernel: strings.Repeat("a", 64), Holder: "fixture"}, State: api.JobDone, Outcome: api.OutcomePass}
	out := pinFile(t, filepath.Join(filepath.Dir(r.Dir), "actual-job.json"), raw(j))
	evidence := pinFile(t, filepath.Join(filepath.Dir(r.Dir), "independent-job-check.json"), []byte(`{"actual_job_checked":true}`))
	proof := Reconciliation{Schema: "maclab.workflow-reconciliation/1", PlanSHA256: r.PlanSHA, Device: r.Plan.Device, Phase: "submit", Attempt: s.Records["submit"].Attempt, RequestSHA256: s.Records["submit"].RequestSHA256, ReviewedBy: "CPU-reviewer", Decision: "completed", Evidence: evidence, Output: &out}
	p := filepath.Join(filepath.Dir(r.Dir), "reconcile.json")
	b := raw(proof)
	os.WriteFile(p, b, 0600)
	if e := r.Reconcile(p, strings.Repeat("0", 64)); e == nil {
		t.Fatal("wrong receipt hash accepted")
	}
	proof.Attempt = "foreign"
	os.WriteFile(p, raw(proof), 0600)
	if e := r.Reconcile(p, Hash(raw(proof))); e == nil {
		t.Fatal("wrong attempt accepted")
	}
	proof.Attempt = s.Records["submit"].Attempt
	b = raw(proof)
	os.WriteFile(p, b, 0600)
	if e := r.Reconcile(p, Hash(b)); e != nil {
		t.Fatal(e)
	}
	f.Fail = false
	f.Actual = &j
	if e := r.Run(context.Background(), a, false); e != nil {
		t.Fatal(e)
	}
	if f.Submits != 1 || f.Reads != 1 {
		t.Fatal("not resumed at wait")
	}
}
func TestScopedAuthorizationExpiresWithoutNewAnswer(t *testing.T) {
	r := fixture(t, jobPhases()...)
	f := &fakeBackend{}
	r.Backend = f
	for _, a := range []string{authFor(t, r, time.Now().Add(-time.Second), "boot-test"), authFor(t, r, time.Now().Add(time.Hour), "other")} {
		if e := r.Run(context.Background(), a, false); e == nil {
			t.Fatal("bad scope/time admitted")
		}
	}
	if f.Submits != 0 {
		t.Fatal("side effect before authorization")
	}
	a := authFor(t, r, time.Now().Add(time.Hour), "boot-test")
	if e := r.Run(context.Background(), a, false); e != nil {
		t.Fatal(e)
	}
	if f.Submits != 1 {
		t.Fatal("no actual submission")
	}
}
func TestCacheReadbackReuseAndCorruptionRefusal(t *testing.T) {
	dir := t.TempDir()
	p := pinFile(t, filepath.Join(dir, "artifact"), []byte("actual fixture package bytes"))
	r := fixture(t, Phase{ID: "cache", Kind: "cache", TimeoutSec: 2, File: &p})
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	s := readState(t, r)
	var cached Pin
	json.Unmarshal(s.Records["cache"].Output, &cached)
	os.Remove(p.Path)
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal("cache incorrectly needs source", e)
	}
	os.WriteFile(cached.Path, []byte("corrupt"), 0600)
	if e := r.Run(context.Background(), "", false); e == nil {
		t.Fatal("corrupt retained cache accepted")
	}
}
func TestCacheRejectsNonRegularBeforeDataOpen(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	os.Symlink("/etc/passwd", link)
	for _, p := range []string{fifo, "/dev/null", link} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		e := copyPinned(ctx, Pin{p, strings.Repeat("a", 64), 1}, nil)
		cancel()
		if e == nil || time.Since(start) > time.Second/2 {
			t.Fatalf("nonregular opened/blocked %s: %v", p, e)
		}
	}
}
func TestPlanDriftAndOutputDriftRefused(t *testing.T) {
	r := fixture(t, bindPhase())
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	r.PlanSHA = strings.Repeat("b", 64)
	if _, _, e := r.Open(); e == nil {
		t.Fatal("plan drift accepted")
	}
	r.PlanSHA = Hash(raw(r.Plan))
	sraw, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	var s State
	json.Unmarshal(sraw, &s)
	s.Records["binding"].Output = raw(map[string]any{"forged": true})
	os.WriteFile(filepath.Join(r.Dir, "state.json"), raw(s), 0600)
	if _, _, e := r.Open(); e == nil {
		t.Fatal("output drift accepted")
	}
}
func TestDuplicateForwardAndOverlappingBindingsRefused(t *testing.T) {
	for _, mutate := range []func(*Plan){func(p *Plan) { p.Phases = append(p.Phases, p.Phases[0]) }, func(p *Plan) { p.Phases[0].Bind["/expected_boot_id"] = Value{"future", "/boot"} }, func(p *Plan) { p.Phases[0].Bind[""] = Value{"inputs", ""} }} {
		r := fixture(t, bindPhase())
		mutate(&r.Plan)
		if e := r.Plan.Validate(); e == nil {
			t.Fatal("bad plan accepted")
		}
	}
}
func TestExplicitRecoveryNeverAutomatic(t *testing.T) {
	p := jobPhases()
	p = append(p, Phase{ID: "rollback-metadata", Kind: "bind", TimeoutSec: 2, Recovery: true, Template: raw(map[string]any{"status": "ROLLBACK_REQUIRES_OWNER"})})
	r := fixture(t, p...)
	r.Backend = &fakeBackend{Fail: true}
	a := authFor(t, r, time.Now().Add(time.Hour), "boot-test")
	_ = r.Run(context.Background(), a, false)
	s := readState(t, r)
	if s.Records["rollback-metadata"] != nil {
		t.Fatal("rollback auto-ran")
	}
	if e := r.Run(context.Background(), a, true); e != nil {
		t.Fatal(e)
	}
	s = readState(t, r)
	if s.Records["rollback-metadata"] == nil || s.Records["submit"].State != "uncertain" {
		t.Fatal("recovery laundered failure")
	}
}
func TestCanceledOrIncompleteJobNeverPass(t *testing.T) {
	for _, j := range []api.Job{{ID: "actual", Spec: api.JobSpec{Device: "testmac"}, State: api.JobDone, Outcome: api.OutcomeCanceled, Canceled: true}, {ID: "actual", Spec: api.JobSpec{Device: "foreign"}, State: api.JobDone, Outcome: api.OutcomePass}, {ID: "actual", Spec: api.JobSpec{Device: "testmac"}, State: api.JobDone, Outcome: api.OutcomeTestsFailed}} {
		r := fixture(t, Phase{ID: "job", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]string{"id": "actual"})}, Phase{ID: "wait", Kind: "wait", TimeoutSec: 2, InputPhase: "job"})
		r.Backend = &fakeBackend{Actual: &j}
		if e := r.Run(context.Background(), "", false); e == nil {
			t.Fatal("failed/foreign job accepted")
		}
	}
}
func TestSubmissionRejectsWaiverAndNonExactSource(t *testing.T) {
	for _, s := range []api.JobSpec{{Device: "foreign", Kernel: strings.Repeat("a", 64)}, {Device: "testmac", Kernel: strings.Repeat("a", 64), Publish: true}, {Device: "testmac", Kernel: strings.Repeat("a", 64), Baseline: true}, {Device: "testmac", Kernel: strings.Repeat("a", 64), OMTAllow: []string{"waiver"}}, {Device: "testmac", Source: "mutable/main"}} {
		ph := jobPhases()
		ph[0].Template = raw(s)
		r := fixture(t, ph...)
		f := &fakeBackend{}
		r.Backend = f
		a := authFor(t, r, time.Now().Add(time.Hour), "boot-test")
		if e := r.Run(context.Background(), a, false); e == nil || f.Submits != 0 {
			t.Fatal("invalid submission dispatched")
		}
	}
}
func TestStatusReportsPhaseAndElapsedWithoutRemote(t *testing.T) {
	r := fixture(t, bindPhase())
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	b, e := r.Status()
	if e != nil {
		t.Fatal(e)
	}
	var status map[string]any
	json.Unmarshal(b, &status)
	if status["complete"] != true || status["elapsed_seconds"] == nil {
		t.Fatal(string(b))
	}
}
func TestExclusiveStateLock(t *testing.T) {
	r := fixture(t, bindPhase())
	lock, _, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if _, _, e = r.Open(); e == nil {
		t.Fatal("two active owners admitted")
	}
}
func TestRealHelperFixedProtocolNoShell(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	python, _ = filepath.EvalSymlinks(python)
	b, _ := os.ReadFile(python)
	py := Pin{python, Hash(b), int64(len(b))}
	dir := t.TempDir()
	source := pinFile(t, filepath.Join(dir, "helper.py"), []byte("import argparse,json\np=argparse.ArgumentParser();p.add_argument('--binding');a=p.parse_args();b=json.load(open(a.binding));print(json.dumps({'status':'CHECKED','value':b['literal']}))\n"))
	literal := "$(touch /tmp/workflow-must-not-evaluate); `id`"
	out, e := RunHelper(context.Background(), Helper{Python: py, Source: source}, raw(map[string]string{"literal": literal}), filepath.Join(dir, "invocation"))
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]string
	json.Unmarshal(out, &v)
	if v["value"] != literal {
		t.Fatal("literal was interpolated")
	}
}
func TestRealHelperTimeoutCannotAdvance(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	python, _ = filepath.EvalSymlinks(python)
	b, _ := os.ReadFile(python)
	py := Pin{python, Hash(b), int64(len(b))}
	dir := t.TempDir()
	source := pinFile(t, filepath.Join(dir, "sleeper.py"), []byte("import time\ntime.sleep(20)\n"))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e := RunHelper(ctx, Helper{Python: py, Source: source}, []byte(`{}`), filepath.Join(dir, "invocation"))
	if e == nil || time.Since(start) > 2*time.Second {
		t.Fatal(e)
	}
}

// The subprocess dies without running Go defers after the server-side effect.
// A restarted coordinator must still find the durable running intent.
func TestActualProcessCrashResume(t *testing.T) {
	if os.Getenv("MACLAB_WORKFLOW_CPU_CRASH") == "1" {
		r, e := LoadPlan(os.Getenv("WF_PLAN"))
		if e != nil {
			os.Exit(71)
		}
		r.Dir = os.Getenv("WF_STATE")
		r.Backend = crashFileBackend{os.Getenv("WF_COUNTER")}
		_ = r.Run(context.Background(), os.Getenv("WF_AUTH"), false)
		os.Exit(72)
	}
	r := fixture(t, jobPhases()...)
	a := authFor(t, r, time.Now().Add(time.Hour), "boot-test")
	counter := filepath.Join(filepath.Dir(r.Dir), "server-side-effect")
	cmd := exec.Command(os.Args[0], "-test.run=^TestActualProcessCrashResume$")
	cmd.Env = append(os.Environ(), "MACLAB_WORKFLOW_CPU_CRASH=1", "WF_PLAN="+filepath.Join(filepath.Dir(r.Dir), "plan.json"), "WF_STATE="+r.Dir, "WF_AUTH="+a, "WF_COUNTER="+counter)
	e := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("child did not die at intended crash: %v", e)
	}
	r.Backend = &fakeBackend{}
	if e = r.Run(context.Background(), a, false); e == nil {
		t.Fatal("crashed submission repeated")
	}
	if b, _ := os.ReadFile(counter); string(b) != "accepted-once" {
		t.Fatal("actual side effect not retained")
	}
}

type crashFileBackend struct{ path string }

func (c crashFileBackend) Submit(ctx context.Context, s api.JobSpec) (*api.Job, error) {
	f, e := os.OpenFile(c.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		panic(e)
	}
	f.WriteString("accepted-once")
	f.Sync()
	f.Close()
	os.Exit(23)
	return nil, fmt.Errorf("unreachable")
}
func (c crashFileBackend) Job(context.Context, string) (*api.Job, error)  { panic("unexpected") }
func (c crashFileBackend) Upload(context.Context, string) (string, error) { panic("unexpected") }

func TestLargeIntegerIdentityPreserved(t *testing.T) {
	r := fixture(t, Phase{ID: "binding", Kind: "bind", TimeoutSec: 2, Template: []byte(`{"mtime_ns":0}`), Bind: map[string]Value{"/mtime_ns": {"inputs", "/mtime_ns"}}, Checks: []Check{{"/mtime_ns", []byte(`1793026027181000123`)}}})
	r.Plan.Inputs = []byte(`{"mtime_ns":1793026027181000123}`)
	r.PlanSHA = Hash(raw(r.Plan))
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	s := readState(t, r)
	if !strings.Contains(string(s.Records["binding"].Output), "1793026027181000123") {
		t.Fatal("nanosecond identity rounded")
	}
}
func TestStatusDuringExclusiveActiveRun(t *testing.T) {
	r := fixture(t, bindPhase())
	lock, _, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	b, e := r.Status()
	if e != nil {
		t.Fatal("active-run status unavailable", e)
	}
	if !strings.Contains(string(b), "next_phase") {
		t.Fatal(string(b))
	}
}
func TestReturnedKernelAndPolledSpecDriftRefused(t *testing.T) {
	want := api.JobSpec{Device: "testmac", Kernel: strings.Repeat("a", 64)}
	bad := want
	bad.Kernel = strings.Repeat("b", 64)
	if e := matchSubmitted(want, bad); e == nil {
		t.Fatal("returned kernel substitution accepted")
	}
	bad = want
	bad.InstalledManifest = strings.Repeat("b", 64)
	if e := matchSubmitted(want, bad); e == nil {
		t.Fatal("manifest substitution accepted")
	}
	bad = want
	bad.Cmdline = "unreviewed"
	if e := matchSubmitted(want, bad); e == nil {
		t.Fatal("cmdline substitution accepted")
	}
}
func TestStandingAuthorityHasNoInventedExpiry(t *testing.T) {
	r := fixture(t, jobPhases()...)
	r.Backend = &fakeBackend{}
	a := authFor(t, r, time.Time{}, "boot-test")
	if e := r.Run(context.Background(), a, false); e != nil {
		t.Fatal(e)
	}
}
func TestHelperFailureRetainsGenuineLogs(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip(e)
	}
	python, _ = filepath.EvalSymlinks(python)
	b, _ := os.ReadFile(python)
	dir := t.TempDir()
	source := pinFile(t, filepath.Join(dir, "fail.py"), []byte("import sys\nprint('genuine partial stdout',flush=True)\nprint('genuine failure',file=sys.stderr,flush=True)\nsys.exit(7)\n"))
	outdir := filepath.Join(dir, "invoke")
	_, e = RunHelper(context.Background(), Helper{Python: Pin{python, Hash(b), int64(len(b))}, Source: source}, []byte(`{}`), outdir)
	if e == nil {
		t.Fatal("failed helper accepted")
	}
	for name, want := range map[string]string{"stdout.json": "genuine partial stdout", "stderr.txt": "genuine failure"} {
		got, err := os.ReadFile(filepath.Join(outdir, name))
		if err != nil || !strings.Contains(string(got), want) {
			t.Fatal("lost actual failed logs", name, err)
		}
	}
}
func TestHelperSuccessDrainsRedirectedDescendant(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip(e)
	}
	python, _ = filepath.EvalSymlinks(python)
	b, _ := os.ReadFile(python)
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")
	source := pinFile(t, filepath.Join(dir, "fork.py"), []byte("import subprocess,json,sys\np=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nopen("+fmt.Sprintf("%q", pidfile)+",'w').write(str(p.pid))\nprint(json.dumps({'status':'PASS'}),flush=True)\n"))
	_, e = RunHelper(context.Background(), Helper{Python: Pin{python, Hash(b), int64(len(b))}, Source: source}, []byte(`{}`), filepath.Join(dir, "invoke"))
	if e != nil {
		t.Fatal(e)
	}
	pidraw, _ := os.ReadFile(pidfile)
	bstat, err := os.ReadFile("/proc/" + strings.TrimSpace(string(pidraw)) + "/stat")
	if err == nil {
		end := strings.LastIndex(string(bstat), ")")
		fields := strings.Fields(string(bstat[end+1:]))
		if len(fields) > 0 && fields[0] != "Z" && fields[0] != "X" {
			t.Fatal("owned descendant survived helper success")
		}
	}
}

func TestOMTMustActuallyRunInGUIWithExactServerDefault(t *testing.T) {
	want := api.JobSpec{Device: "testmac", Kernel: strings.Repeat("a", 64), Tests: []api.TestSpec{{Name: "omarchy-m-test", Builtin: "omarchy-m-test", GUI: true}}}
	good := want
	good.Tests = []api.TestSpec{{Name: "omarchy-m-test", Builtin: "omarchy-m-test", GUI: true, TimeoutSec: 900}}
	if e := matchSubmitted(want, good); e != nil {
		t.Fatal(e)
	}
	bad := good
	bad.Tests = append([]api.TestSpec{}, good.Tests...)
	bad.Tests[0].GUI = false
	if e := matchSubmitted(want, bad); e == nil {
		t.Fatal("OMT GUI gate masked")
	}
	bad.Tests[0].GUI = true
	bad.Tests[0].TimeoutSec = 1
	if e := matchSubmitted(want, bad); e == nil {
		t.Fatal("OMT deadline changed")
	}
}

func TestAmbiguousJSONKeysRefusedEveryIdentityPath(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{"authorized":false,"authorized":true}`), []byte(`{"nest":{"boot":"actual","boot":"forged"}}`)} {
		var x any
		if e := decodeValue(b, &x); e == nil {
			t.Fatal("ambiguous value admitted")
		}
		if _, e := canonical(b); e == nil {
			t.Fatal("ambiguous evidence canonicalized")
		}
		var a Authorization
		if e := Decode(b, &a); e == nil {
			t.Fatal("ambiguous typed receipt admitted")
		}
	}
}

func TestAggregateCheckpointCannotBecomeUnreadable(t *testing.T) {
	large := strings.Repeat("x", 2200000)
	r := fixture(t, Phase{ID: "one", Kind: "bind", TimeoutSec: 3, Template: raw(map[string]string{"data": large})}, Phase{ID: "two", Kind: "bind", TimeoutSec: 3, Template: raw(map[string]string{"data": large})})
	if e := r.Run(context.Background(), "", false); e == nil {
		t.Fatal("oversized aggregate checkpoint accepted")
	}
	s := readState(t, r)
	if s.Records["one"].State != "done" || s.Records["two"].State != "running" {
		t.Fatal("previous durable intent lost")
	}
	if _, e := r.Status(); e != nil {
		t.Fatal("status irrecoverable", e)
	}
}

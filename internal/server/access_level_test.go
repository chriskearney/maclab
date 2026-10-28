package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// The Access level and Audit log (#28). A Volunteer's Mac starts at
// Qualification; `access full` lets Maintainers do everything a Lab-owned Mac
// allows. labd rejects what the level doesn't allow at submit, and lab-agent
// refuses it at run. Every Maintainer action on the Mac lands in its Audit
// log, which `log` reads on the Mac and labd keeps a copy of.

// alWire stands between labd and the Mac. It hands the Mac commands labd
// never sent, as a labd that is bypassed or holds a stale copy of the
// Access level would, and records every command result the Mac sends back.
type alWire struct {
	mu      sync.Mutex
	pending []map[string]any
	results map[string]api.CommandResult
	seq     int
}

func newALWire() *alWire { return &alWire{results: map[string]api.CommandResult{}} }

func (w *alWire) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/checkin" && r.URL.Path != "/api/agent/report" {
			next.ServeHTTP(rw, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var rep struct {
			Results []api.CommandResult `json:"results"`
		}
		json.Unmarshal(body, &rep)
		w.mu.Lock()
		for _, res := range rep.Results {
			w.results[res.ID] = res
		}
		inject := w.pending
		if r.URL.Path == "/api/agent/checkin" {
			w.pending = nil
		} else {
			inject = nil
		}
		w.mu.Unlock()
		if len(inject) == 0 {
			next.ServeHTTP(rw, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		var resp map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
			w.mu.Lock()
			w.pending = append(inject, w.pending...)
			w.mu.Unlock()
			for k, v := range rec.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(rec.Code)
			rw.Write(rec.Body.Bytes())
			return
		}
		cmds, _ := resp["commands"].([]any)
		for _, c := range inject {
			cmds = append(cmds, c)
		}
		resp["commands"] = cmds
		out, _ := json.Marshal(resp)
		for k, v := range rec.Header() {
			rw.Header()[k] = v
		}
		rw.Header().Del("Content-Length")
		rw.WriteHeader(rec.Code)
		rw.Write(out)
	})
}

// send queues a command for the Mac's next check-in answer, as coming from
// the named Maintainer for job (which may be ""), and returns its ID.
func (w *alWire) send(kind, job, maintainer string, args any) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seq++
	id := fmt.Sprintf("al-cmd-%d", w.seq)
	a, _ := json.Marshal(args)
	w.pending = append(w.pending, map[string]any{
		"id": id, "kind": kind, "job_id": job, "maintainer": maintainer, "args": json.RawMessage(a),
	})
	return id
}

// result waits for the Mac's result for command id.
func (w *alWire) result(t *testing.T, id string) api.CommandResult {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		res, ok := w.results[id]
		w.mu.Unlock()
		if ok {
			return res
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the Mac never answered command %s", id)
	return api.CommandResult{}
}

// alSetAccess sets the Mac's Access level as its Volunteer does, and gives
// check-ins time to carry it to labd.
func (l *lab) alSetAccess(level string) {
	l.t.Helper()
	l.mustVolunteer("access", level)
	time.Sleep(time.Second)
}

// alExec runs `lab exec` on the Mac through labd as the holder of token.
func (l *lab) alExec(token, command string) (*http.Response, api.ExecResult, string) {
	l.t.Helper()
	r, body := l.as(token, "POST", "/api/devices/"+l.name+"/exec", api.ExecArgs{Command: command})
	var res api.ExecResult
	json.Unmarshal([]byte(body), &res)
	return r, res, body
}

// alSubmit submits a job through labd's API and returns the answer, whatever it is.
func (l *lab) alSubmit(spec api.JobSpec) (*http.Response, string) {
	l.t.Helper()
	spec.Device = l.name
	return l.post("/api/jobs", spec)
}

func alIs4xx(r *http.Response) bool { return r.StatusCode >= 400 && r.StatusCode < 500 }

// alWatch tries a Maintainer's live screenshot and live journal read of the
// Mac, and returns labd's two answers.
func (l *lab) alWatch() (shot, journal *http.Response, bodies string) {
	l.t.Helper()
	shot, b1 := l.get("POST", "/api/devices/"+l.name+"/screenshot")
	journal, b2 := l.get("GET", "/api/devices/"+l.name+"/logs?source=journal&lines=10")
	return shot, journal, b1 + " | " + b2
}

// alWatchRefused checks labd refuses both the live screenshot and the live journal.
func (l *lab) alWatchRefused(why string) {
	l.t.Helper()
	shot, journal, bodies := l.alWatch()
	if !alIs4xx(shot) || !alIs4xx(journal) {
		l.t.Fatalf("%s, yet labd answered the screenshot %s and the live journal %s: %s", why, shot.Status, journal.Status, bodies)
	}
}

func (l *lab) alWatchAllowed(why string) {
	l.t.Helper()
	shot, journal, bodies := l.alWatch()
	if shot.StatusCode != 200 || journal.StatusCode != 200 {
		l.t.Fatalf("%s, yet labd answered the screenshot %s and the live journal %s: %s", why, shot.Status, journal.Status, bodies)
	}
}

// alStatusLevel is the Access level the `status` output shows, lower case:
// "qualification" or "full" when its Access level line names exactly one.
func alStatusLevel(out string) string {
	for _, line := range strings.Split(strings.ToLower(out), "\n") {
		if !strings.Contains(line, "access level") {
			continue
		}
		q, f := strings.Contains(line, "qualification"), strings.Contains(line, "full")
		switch {
		case q && !f:
			return "qualification"
		case f && !q:
			return "full"
		}
	}
	return ""
}

// alHasWhen is whether out names the time an entry was made: its date or
// its minute, in the Mac's local time.
func alHasWhen(out string, at time.Time) bool {
	for _, t := range []time.Time{at, at.Add(-time.Minute)} {
		if strings.Contains(out, t.Format("2006-01-02")) || strings.Contains(out, t.Format("15:04")) {
			return true
		}
	}
	return false
}

// alWaitLog waits for the Mac's `log` to show every one of want.
func (l *lab) alWaitLog(want ...string) string {
	l.t.Helper()
	var out string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		out = l.mustVolunteer("log")
		if alContainsAll(out, want...) {
			return out
		}
	}
	l.t.Fatalf("the Mac's Audit log lacks %q:\n%s", want, out)
	return ""
}

func alContainsAll(s string, want ...string) bool {
	for _, w := range want {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}

// alScriptJob is a kernel job whose one test is a Maintainer's script.
func (l *lab) alScriptJob(krel, script string, gui bool) api.JobSpec {
	return api.JobSpec{Kernel: l.artifact("krel=" + krel + " behavior=ok"),
		Tests: []api.TestSpec{{Name: "maintainer-script", Script: l.artifact(script), GUI: gui}}}
}

func TestAccessLevelIsQualificationByDefault(t *testing.T) {
	l, _, _ := windowLab(t, labConfig{})
	if out := l.mustVolunteer("status"); alStatusLevel(out) != "qualification" {
		t.Fatalf("status does not show the Access level as Qualification:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(l.deviceBody()), "qualification") {
		t.Fatalf("labd does not know the Mac is at Qualification:\n%s", l.deviceBody())
	}
	if r, _, body := l.alExec(harnessToken, "id"); !alIs4xx(r) {
		t.Fatalf("a Volunteer's Mac that never chose an Access level took lab exec: %s %s", r.Status, body)
	}
}

func TestQualificationAccessLevelRejectsExecAtLabd(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	r, res, body := l.alExec(harnessToken, "cat /etc/shadow")
	if !alIs4xx(r) || strings.Contains(res.Stdout, "sim ran") {
		t.Fatalf("lab exec on a Mac at Qualification: %s %s", r.Status, body)
	}
	if !strings.Contains(strings.ToLower(body), "access level") {
		t.Fatalf("labd's refusal does not name the Access level: %s", body)
	}
}

func TestQualificationAccessLevelRejectsScriptAndGUIScriptJobsAtSubmit(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	before := len(l.jobsOf())
	for _, c := range []struct {
		flag string
		gui  bool
	}{{"--script", false}, {"--gui-script", true}} {
		r, body := l.alSubmit(l.alScriptJob("7.2-scripted", "echo from a Maintainer", c.gui))
		if !alIs4xx(r) {
			t.Fatalf("a %s job on a Mac at Qualification: %s %s", c.flag, r.Status, body)
		}
		if !strings.Contains(strings.ToLower(body), "access level") {
			t.Fatalf("labd's refusal of a %s job does not name the Access level: %s", c.flag, body)
		}
	}
	if n := len(l.jobsOf()); n != before {
		t.Fatalf("rejected jobs were queued: %d jobs, %d before", n, before)
	}
}

func TestQualificationAccessLevelAllowsQualificationWork(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-qual behavior=ok"), Tests: []api.TestSpec{{Name: "gui-smoke", Builtin: "gui-smoke"}}})
	j := l.jobAPI(id, 60*time.Second)
	l.expect(j, api.OutcomePass)
	if j.Result.BootKernel != "7.2-qual" {
		t.Fatalf("the lab-kernel run at Qualification did not boot its kernel: %+v", j.Result)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	l.expect(l.jobAPI(l.submitJob(api.JobSpec{Crash: "panic"}), 60*time.Second), api.OutcomePass)
}

func TestFullAccessLevelAllowsExecAndScripts(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	l.alSetAccess("full")
	if out := l.mustVolunteer("status"); alStatusLevel(out) != "full" {
		t.Fatalf("status does not show the Access level as Full:\n%s", out)
	}
	r, res, body := l.alExec(harnessToken, "uname -a")
	if r.StatusCode != 200 || !strings.Contains(res.Stdout, "sim ran: uname -a") {
		t.Fatalf("lab exec on a Mac at Full: %s %s", r.Status, body)
	}
	if r, body := l.alSubmit(l.alScriptJob("7.2-gui", "echo in your session", true)); r.StatusCode != 200 {
		t.Fatalf("a --gui-script job on a Mac at Full: %s %s", r.Status, body)
	}
	r, body = l.alSubmit(l.alScriptJob("7.2-script", "echo as root", false))
	var j api.Job
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil {
		t.Fatalf("a --script job on a Mac at Full: %s %s", r.Status, body)
	}
	l.expect(l.jobAPI(j.ID, 90*time.Second), api.OutcomePass)
}

// lab-agent checks the Access level itself, whatever labd sends: a labd
// that was bypassed, or that still holds the level from before the
// Volunteer lowered it, can't get exec or a script run.
func TestLabAgentRefusesExecAndScriptsAtQualificationWhateverLabdSends(t *testing.T) {
	w := newALWire()
	l, _ := windowEndLab(t, labConfig{wrap: w.wrap})
	exec := w.send(api.CmdExec, "", "mallory", api.ExecArgs{Command: "touch /al-bypassed"})
	script := w.send(api.CmdRunTest, "al-job-bypass", "mallory", api.TestSpec{Name: "al-script", Script: l.artifact("echo bypassed")})
	gui := w.send(api.CmdRunTest, "al-job-bypass", "mallory", api.TestSpec{Name: "al-gui-script", Script: l.artifact("echo bypassed"), GUI: true})
	if res := w.result(t, exec); res.OK || strings.Contains(string(res.Output), "sim ran") {
		t.Fatalf("lab-agent at Qualification ran an exec labd should never have sent: %+v", res)
	}
	for _, id := range []string{script, gui} {
		if res := w.result(t, id); res.OK || strings.Contains(string(res.Output), "sim test") {
			t.Fatalf("lab-agent at Qualification ran a script labd should never have sent: %+v", res)
		}
	}
	out := l.alWaitLog("mallory", "touch /al-bypassed")
	if !strings.Contains(strings.ToLower(out), "refus") {
		t.Fatalf("the Audit log does not record lab-agent's refusal:\n%s", out)
	}

	// At Full, the same command runs: it is the level that refused it.
	l.mustVolunteer("access", "full")
	again := w.send(api.CmdExec, "", "mallory", api.ExecArgs{Command: "touch /al-allowed"})
	if res := w.result(t, again); !res.OK || !strings.Contains(string(res.Output), "sim ran: touch /al-allowed") {
		t.Fatalf("lab-agent at Full refused an exec: %+v", res)
	}
}

func TestLabAgentRefusesAScreenshotOrJournalReadOutsideAWindow(t *testing.T) {
	w := newALWire()
	l, _, _ := windowLab(t, labConfig{wrap: w.wrap})
	l.mustVolunteer("access", "full")
	shot := w.send(api.CmdScreen, "", "mallory", api.ScreenArgs{WaitSec: 1})
	journal := w.send(api.CmdLogs, "", "mallory", api.LogsArgs{Source: "journal", Lines: 10})
	for _, id := range []string{shot, journal} {
		if res := w.result(t, id); res.OK {
			t.Fatalf("lab-agent watched the Mac outside its window: %+v", res)
		}
	}
}

func TestAccessLevelChangesTakeEffectOnTheMacAtOnceWithLabdDown(t *testing.T) {
	sw := &labdSwitch{}
	l, _, _ := windowLab(t, labConfig{wrap: sw.wrap})
	sw.down.Store(true)
	time.Sleep(500 * time.Millisecond) // check-ins in flight
	l.mustVolunteer("access", "full")
	if out := l.mustVolunteer("status"); alStatusLevel(out) != "full" {
		t.Fatalf("access full with labd down did not change the Mac's level at once:\n%s", out)
	}
	l.mustVolunteer("access", "qualification")
	if out := l.mustVolunteer("status"); alStatusLevel(out) != "qualification" {
		t.Fatalf("access qualification with labd down did not change the Mac's level at once:\n%s", out)
	}
}

func TestLoweringTheAccessLevelEndsALeaseAtOnce(t *testing.T) {
	l, clock := windowEndLab(t, labConfig{})
	l.alSetAccess("full")
	l.takeLease("connor (homework)", time.Hour)
	l.mustVolunteer("access", "qualification")
	l.leaseEndsBy(clock.Now().Add(5*time.Second), "the Volunteer lowered the Access level")
}

func TestLoweringTheAccessLevelEndsAScriptJobIncomplete(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	l.alSetAccess("full")
	l.sim.SetTestLength(time.Minute)
	id := l.submitJob(l.alScriptJob("7.2-lowered", "sleep 60", false))
	l.waitTesting(id, "7.2-lowered")
	labBoot, _, _ := l.sim.Identity()
	l.mustVolunteer("access", "qualification")
	l.backOnItsOwnSystem(labBoot, 5*time.Second, "the Volunteer lowered the Access level below the job's script")
	l.expect(l.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
	l.waitDevice(func(d api.Device) bool {
		return d.State == api.StateReady && d.Kernel == agent.SimKnownGood && d.Health.JobTag == ""
	})
}

func TestLoweringTheAccessLevelLeavesAJobItStillAllowsRunning(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	l.alSetAccess("full")
	l.sim.SetTestLength(3 * time.Second)
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-kept behavior=ok"), Tests: []api.TestSpec{{Name: "long-work", Builtin: "x"}}})
	l.waitTesting(id, "7.2-kept")
	l.mustVolunteer("access", "qualification")
	j := l.jobAPI(id, 60*time.Second)
	l.expect(j, api.OutcomePass)
	if j.Result.BootKernel != "7.2-kept" {
		t.Fatalf("result: %+v", j.Result)
	}
}

func TestScreenshotsAndTheLiveJournalNeedALeaseInsideTheWindowAtBothLevels(t *testing.T) {
	l, clock, _ := windowLab(t, labConfig{})
	for _, level := range []string{"qualification", "full"} {
		l.alSetAccess(level)
		l.alWatchRefused("at " + level + ", outside the window")
		l.mustVolunteer("open", "--until", clock.Now().Add(2*time.Hour).Format("15:04"))
		time.Sleep(time.Second) // check-ins carry it to labd
		l.alWatchRefused("at " + level + ", inside the window but with no job or lease")
		l.takeLease("connor (homework)", time.Hour)
		l.alWatchAllowed("at " + level + ", a lease holds the Mac inside its window")
		if r, body := l.get("DELETE", "/api/devices/"+l.name+"/lease"); r.StatusCode != 200 {
			t.Fatalf("release: %s %s", r.Status, body)
		}
		l.alWatchRefused("at " + level + ", the lease was released")
		l.mustVolunteer("pause")
		time.Sleep(time.Second)
	}
}

func TestScreenshotsAndTheLiveJournalAreAllowedWhileAJobHoldsTheMac(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	l.longJob("7.2-watched")
	l.alWatchAllowed("a job holds the Mac inside its window at Qualification")
}

func TestJobCapturesStillHappenAtQualification(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	j := l.jobAPI(l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-shots behavior=ok")}), 60*time.Second)
	l.expect(j, api.OutcomePass)
	var shots int
	for _, f := range j.Result.Logs {
		if strings.HasPrefix(f, "screen/") {
			shots++
		}
	}
	if shots != 2 {
		t.Fatalf("job screenshots at Qualification: %v", j.Result.Logs)
	}
}

func TestEveryMaintainerActionIsInTheMacsAuditLog(t *testing.T) {
	l, clock := windowEndLab(t, labConfig{})
	grace := l.addMaintainer(harnessToken, "grace")
	l.alSetAccess("full")
	if r, _, body := l.alExec(harnessToken, "uname -a # al-first"); r.StatusCode != 200 {
		t.Fatalf("exec: %s %s", r.Status, body)
	}
	id := l.submitJob(l.alScriptJob("7.2-audited", "echo al-audited-script", false))
	l.expect(l.jobAPI(id, 90*time.Second), api.OutcomePass)
	if r, _, body := l.alExec(grace.Token, "ls /home # al-last"); r.StatusCode != 200 {
		t.Fatalf("exec as grace: %s %s", r.Status, body)
	}
	out := l.alWaitLog(harnessMaintainer, "grace", "uname -a # al-first", "ls /home # al-last", id, "echo al-audited-script")
	if !alHasWhen(out, clock.Now()) {
		t.Fatalf("the Audit log does not say when (%s):\n%s", clock.Now().Format(time.DateTime), out)
	}
	// Append-only: the first action is still there, before the last.
	if strings.Index(out, "al-first") > strings.Index(out, "al-last") {
		t.Fatalf("the Audit log is out of order:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "al-last") && !strings.Contains(line, "grace") {
			t.Fatalf("grace's exec is not attributed to grace: %q", line)
		}
	}
}

// lab-agent records an action before acting on it: a test still running is
// already in the log.
func TestAuditEntryIsWrittenBeforeTheActionRuns(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	id, _ := l.longJob("7.2-running")
	l.alWaitLog(harnessMaintainer, id, "long-work")
	if j, _ := l.jobNow(id); j.State != api.JobTesting {
		t.Fatalf("the job's test ended before the check: %s", j.State)
	}
}

func TestCommandsReachTheMacWithTheMaintainersNameAndJob(t *testing.T) {
	w := newALWire()
	l, _ := windowEndLab(t, labConfig{wrap: w.wrap})
	l.mustVolunteer("access", "full")
	id := w.send(api.CmdExec, "al-job-42", "mallory", api.ExecArgs{Command: "echo al-attributed"})
	if res := w.result(t, id); !res.OK {
		t.Fatalf("exec at Full: %+v", res)
	}
	out := l.alWaitLog("echo al-attributed")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "al-attributed") && (!strings.Contains(line, "mallory") || !strings.Contains(line, "al-job-42")) {
			t.Fatalf("the Audit entry lacks who or which job: %q", line)
		}
	}
}

func TestLogReadsTheAuditLogWithLabdDown(t *testing.T) {
	sw := &labdSwitch{}
	l, _ := windowEndLab(t, labConfig{wrap: sw.wrap})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-offline-log behavior=ok")})
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
	l.alWaitLog(id)
	sw.down.Store(true)
	time.Sleep(500 * time.Millisecond) // check-ins in flight
	if out := l.mustVolunteer("log"); !strings.Contains(out, id) || !strings.Contains(out, harnessMaintainer) {
		t.Fatalf("log with labd down lost the entries:\n%s", out)
	}
}

func TestLabdKeepsItsOwnCopyOfTheAuditLog(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	l.alSetAccess("full")
	if r, _, body := l.alExec(harnessToken, "uptime # al-labd-copy"); r.StatusCode != 200 {
		t.Fatalf("exec: %s %s", r.Status, body)
	}
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-copied behavior=ok")})
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
	path := "/api/devices/" + l.name + "/audit"
	var body string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		var r *http.Response
		r, body = l.get("GET", path)
		if r.StatusCode == 200 && alContainsAll(body, harnessMaintainer, "uptime # al-labd-copy", id) {
			break
		}
	}
	if !alContainsAll(body, harnessMaintainer, "uptime # al-labd-copy", id) {
		t.Fatalf("labd's copy of the Audit log (GET %s) lacks the Maintainer's actions:\n%s", path, body)
	}
	if r, _ := l.as("", "GET", path, nil); r.StatusCode != 401 {
		t.Fatalf("labd's Audit log without a Maintainer's token: %s", r.Status)
	}
}

func TestJobsListsTheLabsJobsOnTheMac(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	id := l.submitJob(api.JobSpec{Kernel: l.artifact("krel=7.2-listed behavior=ok")})
	l.expect(l.jobAPI(id, 60*time.Second), api.OutcomePass)
	out := l.mustVolunteer("jobs")
	for _, j := range l.jobsOf() {
		if !strings.Contains(out, j.ID) {
			t.Fatalf("jobs does not list %s (%s):\n%s", j.ID, j.Outcome, out)
		}
	}
}

func TestStatusShowsTheLatestAuditEntries(t *testing.T) {
	l, _ := windowEndLab(t, labConfig{})
	l.alSetAccess("full")
	if r, _, body := l.alExec(harnessToken, "df -h # al-in-status"); r.StatusCode != 200 {
		t.Fatalf("exec: %s %s", r.Status, body)
	}
	l.alWaitLog("al-in-status")
	if out := l.mustVolunteer("status"); !strings.Contains(out, "al-in-status") || !strings.Contains(out, harnessMaintainer) {
		t.Fatalf("status does not show the latest Audit entry:\n%s", out)
	}
}

func TestPublishingIsOffOnAVolunteerMacUntilPublishOn(t *testing.T) {
	var mu sync.Mutex
	var posts int
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		n := posts
		mu.Unlock()
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"id":"r%d","report_url":"https://site/reports/r%d","deletion_url":"https://site/del/r%d?token=x"}`, n, n, n)
	}))
	defer site.Close()
	published := func() int { mu.Lock(); defer mu.Unlock(); return posts }
	l, _ := windowEndLab(t, labConfig{config: func(c *Config) { c.OMT, c.OMTSite, c.OMTPublish = true, site.URL, true }})
	if n := published(); n != 0 {
		t.Fatalf("the Volunteer Mac's baseline was published without their consent: %d posts", n)
	}
	// Neither a job asking for it nor a Maintainer by hand publishes it.
	j := l.jobAPI(l.submitJob(api.JobSpec{Baseline: true, Publish: true}), 90*time.Second)
	l.expect(j, api.OutcomePass)
	if r, body := l.post("/api/jobs/"+j.ID+"/publish", nil); r.StatusCode == 200 {
		t.Fatalf("a Maintainer published a report of a Volunteer's Mac with publishing off: %s", body)
	}
	if n := published(); n != 0 {
		t.Fatalf("published with publishing off: %d posts", n)
	}

	l.mustVolunteer("publish", "on")
	time.Sleep(time.Second) // check-ins carry it to labd
	j = l.jobAPI(l.submitJob(api.JobSpec{Baseline: true}), 90*time.Second)
	l.expect(j, api.OutcomePass)
	if n := published(); n != 1 || j.Result.OMT == nil || j.Result.OMT.Published == "" {
		t.Fatalf("publish on did not publish the next baseline: %d posts, omt %+v", n, j.Result.OMT)
	}
	var out string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if out = l.mustVolunteer("publish", "on"); strings.Contains(out, "https://site/del/r1?token=x") {
			break
		}
	}
	if !strings.Contains(out, "https://site/del/r1?token=x") {
		t.Fatalf("publish on does not show the deletion link:\n%s", out)
	}

	l.mustVolunteer("publish", "off")
	time.Sleep(time.Second)
	l.expect(l.jobAPI(l.submitJob(api.JobSpec{Baseline: true}), 90*time.Second), api.OutcomePass)
	if n := published(); n != 1 {
		t.Fatalf("published after publish off: %d posts", n)
	}
}

func TestAccessLevelDoesNotApplyToALabOwnedMac(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	l.volunteer("access", "qualification") // a Lab-owned Mac has no Access level, whatever this answers
	time.Sleep(time.Second)
	r, res, body := l.alExec(harnessToken, "uname -a")
	if r.StatusCode != 200 || !strings.Contains(res.Stdout, "sim ran: uname -a") {
		t.Fatalf("lab exec on a Lab-owned Mac: %s %s", r.Status, body)
	}
	r, body = l.alSubmit(l.alScriptJob("7.2-gui-owned", "echo hi", true))
	var j api.Job
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil {
		t.Fatalf("a --gui-script job on a Lab-owned Mac: %s %s", r.Status, body)
	}
	l.wait(j.ID, 90*time.Second)
	l.alWatchAllowed("a Lab-owned Mac needs no lease to be watched")
}

func TestAccessAndPublishRejectBadInput(t *testing.T) {
	l, _, _ := windowLab(t, labConfig{})
	for _, args := range [][]string{
		{"access"},
		{"access", "root"},
		{"access", "full", "qualification"},
		{"publish", "maybe"},
		{"publish", "on", "off"},
	} {
		if out, err := l.volunteer(args...); err == nil {
			t.Errorf("lab-agent %s was accepted:\n%s", strings.Join(args, " "), out)
		}
	}
	if out := l.mustVolunteer("status"); alStatusLevel(out) != "qualification" {
		t.Fatalf("bad input changed the Access level:\n%s", out)
	}
}

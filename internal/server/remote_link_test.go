package server

import (
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
	"github.com/iconidentify/maclab/internal/labhttp"
)

// wire is a flaky link in front of labd: it can cut an artifact response
// part-way, stall one for good, and swallow the Mac's check-ins, while
// recording what the Mac asked for.
type wire struct {
	mu      sync.Mutex
	sha     string // the artifact the link misbehaves on
	cutAt   int    // cut the first whole-file response after this many bytes; 0 never
	cutDone bool
	stalled bool
	silent  bool // the Mac's check-ins and reports go nowhere
	reqs    []wireRequest

	hung    chan struct{} // closed when a request to the stalled artifact arrives
	hungOne sync.Once
	release chan struct{} // closed at the end of the test to free stalled requests
}

type wireRequest struct {
	rng  string // the Range header the Mac sent
	sent int    // bytes of body that left labd
}

func newWire(t *testing.T) *wire {
	w := &wire{hung: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(w.release) })
	return w
}

func (w *wire) cutFirstResponse(sha string, after int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sha, w.cutAt = sha, after
}

func (w *wire) stall(sha string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sha, w.stalled = sha, true
}

func (w *wire) goSilent() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.silent = true
}

func (w *wire) requests() []wireRequest {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]wireRequest(nil), w.reqs...)
}

func (w *wire) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		silent := w.silent
		onArtifact := w.sha != "" && r.URL.Path == "/api/agent/artifacts/"+w.sha
		w.mu.Unlock()
		if silent && (r.URL.Path == "/api/agent/checkin" || r.URL.Path == "/api/agent/report") {
			http.Error(rw, "the link is down", http.StatusServiceUnavailable)
			return
		}
		if !onArtifact {
			next.ServeHTTP(rw, r)
			return
		}
		w.mu.Lock()
		stalled := w.stalled
		limit := 0
		if !stalled && w.cutAt > 0 && !w.cutDone && r.Header.Get("Range") == "" {
			w.cutDone, limit = true, w.cutAt
		}
		w.reqs = append(w.reqs, wireRequest{rng: r.Header.Get("Range")})
		i := len(w.reqs) - 1
		w.mu.Unlock()
		if stalled {
			w.hungOne.Do(func() { close(w.hung) })
			select {
			case <-r.Context().Done():
			case <-w.release:
			}
			return
		}
		cw := &cutWriter{ResponseWriter: rw, limit: limit}
		defer func() {
			w.mu.Lock()
			w.reqs[i].sent = cw.sent
			w.mu.Unlock()
		}()
		next.ServeHTTP(cw, r)
	})
}

// cutWriter lets limit bytes of the body through (0 means all of it), then
// drops the connection, so the Mac sees a body shorter than its Content-Length.
type cutWriter struct {
	http.ResponseWriter
	limit, sent int
}

func (c *cutWriter) Write(p []byte) (int, error) {
	if c.limit > 0 && c.sent+len(p) > c.limit {
		n, _ := c.ResponseWriter.Write(p[:c.limit-c.sent])
		c.sent += n
		c.Flush()
		panic(http.ErrAbortHandler)
	}
	n, err := c.ResponseWriter.Write(p)
	c.sent += n
	return n, err
}

func (c *cutWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// pumpClock lets a fake clock run at wall speed until the returned stop is
// called, so a baseline gets through as it does on the wall clock.
func pumpClock(c *agent.FakeClock) (stop func()) {
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-quit:
				return
			case <-time.After(10 * time.Millisecond):
				c.Advance(10 * time.Millisecond)
			}
		}
	}()
	return func() { close(quit); <-done }
}

// advance moves a fake clock on in one-second steps, giving labd time to
// look at each.
func advance(c *agent.FakeClock, d time.Duration) {
	for ; d > 0; d -= time.Second {
		c.Advance(time.Second)
		time.Sleep(10 * time.Millisecond)
	}
}

// agentGet is a Mac's GET of an artifact, with whatever Range it chooses.
func (l *lab) agentGet(secret, sha, rng string) (*http.Response, []byte) {
	l.t.Helper()
	req, _ := http.NewRequest("GET", l.url+"/api/agent/artifacts/"+sha, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	if rng != "" {
		req.Header.Set("Range", rng)
	}
	resp, err := l.client().Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

// grantForTest lets the lab's Mac fetch sha the way labd does when a job
// holding the Mac stages it: the job is the Mac's active one, submitted for
// its enrollment. (Adapted from Naeem Malik's helper in maclab PR #53.)
func (l *lab) grantForTest(sha string) {
	l.t.Helper()
	args, _ := json.Marshal(api.StageArgs{Artifact: sha})
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.ActiveJob = "range-test"
	v.grantLocked(api.Command{Kind: api.CmdStage, JobID: "range-test", Args: args})
	v.mu.Unlock()
}

func TestArtifactIsServedWhole(t *testing.T) {
	l := newLab(t, false)
	content := strings.Repeat("0123456789", 100)
	sha := l.artifact(content)
	l.grantForTest(sha)
	resp, body := l.agentGet(l.secret, sha, "")
	if resp.StatusCode != 200 || string(body) != content {
		t.Fatalf("whole artifact: %s, %d bytes", resp.Status, len(body))
	}
	if resp.Header.Get("Accept-Ranges") != "bytes" || resp.Header.Get("Content-Length") != fmt.Sprint(len(content)) {
		t.Fatalf("a Mac can't tell it may resume: Accept-Ranges %q Content-Length %q", resp.Header.Get("Accept-Ranges"), resp.Header.Get("Content-Length"))
	}
}

func TestArtifactResumesFromTheOffsetAMacAsksFor(t *testing.T) {
	l := newLab(t, false)
	content := strings.Repeat("0123456789", 100)
	sha := l.artifact(content)
	l.grantForTest(sha)
	resp, body := l.agentGet(l.secret, sha, "bytes=250-")
	if resp.StatusCode != 206 || string(body) != content[250:] {
		t.Fatalf("resume: %s, %d bytes", resp.Status, len(body))
	}
	if want := fmt.Sprintf("bytes 250-%d/%d", len(content)-1, len(content)); resp.Header.Get("Content-Range") != want {
		t.Fatalf("Content-Range %q, want %q", resp.Header.Get("Content-Range"), want)
	}
}

func TestArtifactRangePastTheEndIsRefused(t *testing.T) {
	l := newLab(t, false)
	content := strings.Repeat("0123456789", 100)
	sha := l.artifact(content)
	l.grantForTest(sha)
	for _, off := range []int{len(content), len(content) + 50} {
		if resp, _ := l.agentGet(l.secret, sha, fmt.Sprintf("bytes=%d-", off)); resp.StatusCode != 416 {
			t.Errorf("Range from %d of %d bytes: %s", off, len(content), resp.Status)
		}
	}
}

func TestArtifactRangeKeepsTheArtifactRoutesGuards(t *testing.T) {
	l := newLab(t, false)
	sha := l.artifact(strings.Repeat("0123456789", 100))
	if resp, _ := l.agentGet(l.secret, "not-a-sha", "bytes=10-"); resp.StatusCode != 400 {
		t.Errorf("a bad sha with a Range: %s", resp.Status)
	}
	for what, token := range map[string]string{"no secret": "", "a Maintainer's token": harnessToken, "a made-up secret": "dev_nope"} {
		if resp, _ := l.agentGet(token, sha, "bytes=10-"); resp.StatusCode != 401 {
			t.Errorf("%s with a Range: %s", what, resp.Status)
		}
	}
}

func TestInterruptedDownloadResumesWhereItStopped(t *testing.T) {
	w := newWire(t)
	l := newLabWith(t, labConfig{oob: true, wrap: w.wrap})
	l.baseline()
	content := "krel=7.2-resumed behavior=ok " + strings.Repeat("x", 64<<10)
	sha := l.artifact(content)
	const cutAt = 1000
	w.cutFirstResponse(sha, cutAt)

	j := l.run(api.JobSpec{Kernel: sha})
	l.expect(j, api.OutcomePass)

	reqs := w.requests()
	if len(reqs) < 2 {
		t.Fatalf("the Mac asked for the artifact %d time(s); the cut download was never continued", len(reqs))
	}
	if reqs[0].rng != "" || reqs[0].sent != cutAt {
		t.Fatalf("first request: %+v, want a whole-file request cut after %d bytes", reqs[0], cutAt)
	}
	if want := fmt.Sprintf("bytes=%d-", cutAt); reqs[1].rng != want {
		t.Fatalf("second request asked for %q, want %q", reqs[1].rng, want)
	}
	total := 0
	for _, r := range reqs {
		total += r.sent
	}
	if total > len(content)+len(content)/4 {
		t.Fatalf("labd served %d bytes for a %d-byte artifact: the download started over", total, len(content))
	}
}

func TestStageTimeoutBoundsAStageThatNeverFinishes(t *testing.T) {
	w := newWire(t)
	l := newLabWith(t, labConfig{oob: true, wrap: w.wrap, config: func(c *Config) { c.StageTimeout = 2 * time.Second }})
	l.baseline()
	sha := l.artifact("krel=7.2-stuck behavior=ok")
	w.stall(sha)

	start := time.Now()
	j := l.run(api.JobSpec{Kernel: sha})
	l.expect(j, api.OutcomeStageFailed)
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("a stage with a 2s Config.StageTimeout took %s to fail", took)
	}
}

// silentStage is a lab whose Mac has gone quiet in the middle of staging:
// the download is stalled and its check-ins no longer arrive. The fake clock
// stands still from here on.
func silentStage(t *testing.T, config func(*Config)) (*lab, *agent.FakeClock, string) {
	t.Helper()
	clock := agent.NewFakeClock(time.Now())
	w := newWire(t)
	l := newLabWith(t, labConfig{oob: true, clock: clock, wrap: w.wrap, config: config})
	stop := pumpClock(clock)
	l.baseline()
	sha := l.artifact("krel=7.2-quiet behavior=ok")
	w.stall(sha)
	j, _, err := l.s.Submit(api.JobSpec{Device: l.name, Kernel: sha})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.hung:
	case <-time.After(20 * time.Second):
		t.Fatal("the Mac never started the stalled download")
	}
	stop()
	w.goSilent()
	time.Sleep(300 * time.Millisecond) // check-ins already in flight
	return l, clock, j.ID
}

// jobDone is the job if it has finished, else nil.
func (l *lab) jobDone(id string) *api.Job {
	l.t.Helper()
	j, err := l.s.store.job(id)
	if err != nil {
		l.t.Fatal(err)
	}
	if j.State == api.JobDone {
		return j
	}
	return nil
}

// waitLost advances the clock until the job is over and returns it.
func (l *lab) waitLost(clock *agent.FakeClock, id string, upTo time.Duration) *api.Job {
	l.t.Helper()
	for waited := time.Duration(0); waited <= upTo; waited += time.Second {
		if j := l.jobDone(id); j != nil {
			return j
		}
		advance(clock, time.Second)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if j := l.jobDone(id); j != nil {
			return j
		}
		time.Sleep(50 * time.Millisecond)
	}
	l.t.Fatalf("job %s still running after %s of silence", id, upTo)
	return nil
}

func TestQuietGraceSetsHowLongASilentMacIsWaitedFor(t *testing.T) {
	l, clock, id := silentStage(t, func(c *Config) { c.QuietGrace = 2 * time.Minute })
	advance(clock, 30*time.Second)
	time.Sleep(200 * time.Millisecond)
	if l.jobDone(id) != nil {
		t.Fatal("the Mac was written off after 30s of silence though Config.QuietGrace is 2 minutes")
	}
	j := l.waitLost(clock, id, 5*time.Minute)
	if j.Outcome == api.OutcomePass {
		t.Fatalf("a Mac silent for minutes passed: %+v", j)
	}
}

func TestAliveWindowSetsHowStaleAHeartbeatMayBe(t *testing.T) {
	l, clock, id := silentStage(t, func(c *Config) { c.AliveWindow, c.QuietGrace = 10*time.Minute, 5*time.Second })
	advance(clock, 90*time.Second)
	time.Sleep(200 * time.Millisecond)
	if l.jobDone(id) != nil {
		t.Fatal("a heartbeat 90s old counted as stale though Config.AliveWindow is 10 minutes")
	}
	j := l.waitLost(clock, id, 15*time.Minute)
	if j.Outcome == api.OutcomePass {
		t.Fatalf("a Mac silent for 15 minutes passed: %+v", j)
	}
}

// enrollToken is a Maintainer minting a token for a new Mac.
func (l *lab) enrollToken(name string) string {
	l.t.Helper()
	resp, body := l.post("/api/enroll-tokens", api.EnrollTokenRequest{Name: name})
	var tok api.EnrollTokenResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil {
		l.t.Fatalf("enroll token for %s: %s %s", name, resp.Status, body)
	}
	return tok.Token
}

func (l *lab) enrollRaw(token string) (*http.Response, string) {
	l.t.Helper()
	return l.as("", "POST", "/api/agent/enroll", api.EnrollRequest{Token: token, Facts: l.sim.Facts(), ActivationKey: testActivationKey, TermsSHA256: termsSum()})
}

func (l *lab) checkinAs(secret string) *http.Response {
	l.t.Helper()
	resp, _ := l.as(secret, "POST", "/api/agent/checkin", api.Checkin{BootID: "boot-1", Kernel: "6.1"})
	return resp
}

const spentToken = "enrollment token unknown, used or expired"

func TestEnrollingAgainBeforeTheFirstCheckinKeepsTheMacAndRenewsItsSecret(t *testing.T) {
	l := newLab(t, false)
	tok := l.enrollToken("retry-mac")
	act := agent.Activation{Key: agent.NewActivationKey(), TermsSHA256: termsSum()}
	first, err := agent.EnrollWith(l.ctx, l.url, tok, l.sim.Facts(), labhttp.Policy{}, act)
	if err != nil {
		t.Fatal(err)
	}
	// Another Mac holding only the token gets nothing: the token is used up.
	if _, err := agent.EnrollWith(l.ctx, l.url, tok, l.sim.Facts(), labhttp.Policy{}, agent.Activation{Key: agent.NewActivationKey(), TermsSHA256: termsSum()}); err == nil || !strings.Contains(err.Error(), spentToken) {
		t.Fatalf("the used token with another activation key: %v", err)
	}
	// the answer never reached the Mac, so it tries again with the same token
	// and its own activation key
	second, err := agent.EnrollWith(l.ctx, l.url, tok, l.sim.Facts(), labhttp.Policy{}, act)
	if err != nil {
		t.Fatalf("enrolling again with the same activation: %v", err)
	}
	if second.DeviceID != first.DeviceID || second.Name != first.Name || second.Name != "retry-mac" {
		t.Fatalf("the retry made a different Mac: %+v then %+v", first, second)
	}
	if second.Secret == "" || second.Secret == first.Secret {
		t.Fatalf("the retry did not issue a new secret: %q then %q", first.Secret, second.Secret)
	}
	if resp := l.checkinAs(first.Secret); resp.StatusCode != 401 {
		t.Fatalf("the first secret still works after the retry: %s", resp.Status)
	}
	if resp := l.checkinAs(second.Secret); resp.StatusCode != 200 {
		t.Fatalf("the new secret doesn't work: %s", resp.Status)
	}
	_, body := l.get("GET", "/api/devices")
	if n := strings.Count(body, `"name":"retry-mac"`); n != 1 {
		t.Fatalf("retry-mac is listed %d times: %s", n, body)
	}
}

func TestFirstCheckinSpendsTheEnrollmentToken(t *testing.T) {
	l := newLab(t, false)
	tok := l.enrollToken("spent-mac")
	resp, body := l.enrollRaw(tok)
	var enrolled api.EnrollResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &enrolled) != nil {
		t.Fatalf("enroll: %s %s", resp.Status, body)
	}
	if resp := l.checkinAs(enrolled.Secret); resp.StatusCode != 200 {
		t.Fatalf("first check-in: %s", resp.Status)
	}
	if resp, body := l.enrollRaw(tok); resp.StatusCode != 403 || !strings.Contains(body, spentToken) {
		t.Fatalf("enrolling after the first check-in: %s %s", resp.Status, body)
	}
}

func TestHarnessMacsTokenIsSpentOnceItChecksIn(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	if resp, body := l.enrollRaw("enr_test_" + l.name); resp.StatusCode != 403 || !strings.Contains(body, spentToken) {
		t.Fatalf("re-enrolling a Mac that has checked in: %s %s", resp.Status, body)
	}
}

func TestEnrollingUnderAnotherTokenForAnEnrolledNameIsStillRefused(t *testing.T) {
	l := newLab(t, false)
	a, b := l.enrollToken("twin"), l.enrollToken("twin")
	if resp, body := l.enrollRaw(a); resp.StatusCode != 200 {
		t.Fatalf("enroll twin: %s %s", resp.Status, body)
	}
	if resp, body := l.enrollRaw(b); resp.StatusCode != 409 {
		t.Fatalf("a second token for the same Mac: %s %s", resp.Status, body)
	}
}

func TestExpiredEnrollmentTokenIsRefusedEvenOnRetry(t *testing.T) {
	clock := agent.NewFakeClock(time.Now())
	l := newLabWith(t, labConfig{clock: clock})
	untried, tried := l.enrollToken("never-tried"), l.enrollToken("half-done")
	if resp, body := l.enrollRaw(tried); resp.StatusCode != 200 {
		t.Fatalf("enroll half-done: %s %s", resp.Status, body)
	}
	clock.Advance(25 * time.Hour)
	for _, tok := range []string{untried, tried} {
		if resp, body := l.enrollRaw(tok); resp.StatusCode != 403 || !strings.Contains(body, spentToken) {
			t.Errorf("an expired token: %s %s", resp.Status, body)
		}
	}
}

func TestNtfyPriorityAndTagsFollowTheNotification(t *testing.T) {
	type seen struct{ priority, tags string }
	got := make(chan seen, 8)
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.Header.Get("Title") == "ntfy-test" {
			got <- seen{r.Header.Get("Priority"), r.Header.Get("Tags")}
		}
	}))
	t.Cleanup(ntfy.Close)
	l := newLabWith(t, labConfig{config: func(c *Config) { c.NtfyURL = ntfy.URL }})

	cases := []struct{ priority, wantPriority, wantTags string }{
		{"urgent", "urgent", "rotating_light"},
		{"high", "high", "warning"},
		{"default", "", ""},
		{"low", "low", "information_source"},
	}
	for _, c := range cases {
		l.s.notify(Notification{Device: l.name, Title: "ntfy-test", Body: c.priority, Priority: c.priority})
		select {
		case s := <-got:
			if c.wantPriority == "" && s.priority == "default" {
				s.priority = ""
			}
			if s.priority != c.wantPriority || s.tags != c.wantTags {
				t.Errorf("%s: ntfy got Priority %q Tags %q, want %q and %q", c.priority, s.priority, s.tags, c.wantPriority, c.wantTags)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: nothing reached ntfy", c.priority)
		}
	}
}

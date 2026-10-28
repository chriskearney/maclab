package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// ntfyPost is one POST that reached a fake ntfy server.
type ntfyPost struct {
	path, title, body, priority string
}

// ntfyCatcher is a fake ntfy server recording every post to it.
type ntfyCatcher struct {
	*httptest.Server
	mu    sync.Mutex
	posts []ntfyPost
}

func newNtfyCatcher(t *testing.T) *ntfyCatcher {
	c := &ntfyCatcher{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(strings.Builder)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		c.mu.Lock()
		c.posts = append(c.posts, ntfyPost{r.URL.Path, r.Header.Get("Title"), b.String(), r.Header.Get("Priority")})
		c.mu.Unlock()
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *ntfyCatcher) all() []ntfyPost {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ntfyPost(nil), c.posts...)
}

// at is the posts to one topic path.
func (c *ntfyCatcher) at(path string) []ntfyPost {
	var out []ntfyPost
	for _, p := range c.all() {
		if p.path == path {
			out = append(out, p)
		}
	}
	return out
}

// text is a post's title and body, lower-cased, for matching on.
func (p ntfyPost) text() string { return strings.ToLower(p.title + "\n" + p.body) }

const labWideTopic = "/lab-wide"

// asksForHands is whether a post is a needs-hands notice: it names the power
// button steps.
func (p ntfyPost) asksForHands() bool {
	t := p.text()
	return strings.Contains(t, "hold") && strings.Contains(t, "10 s")
}

// asksForDiskPassword is whether a post is the "waiting for your disk
// password" notice.
func (p ntfyPost) asksForDiskPassword() bool {
	return strings.Contains(p.text(), "disk password")
}

// endedEnrollment is whether a post is the "enrollment ended" notice.
func (p ntfyPost) endedEnrollment() bool {
	t := p.text()
	return strings.Contains(t, "enrollment") && strings.Contains(t, "ended")
}

// noticeLab is a Volunteer lab on a fake clock (running at wall speed unless a
// test jumps it) whose labd posts to a fake lab-wide ntfy topic.
type noticeLab struct {
	*lab
	clock *agent.FakeClock
	ntfy  *ntfyCatcher
	cmds  string // the file --notify-cmd appends to
}

func newNoticeLab(t *testing.T, c labConfig) *noticeLab {
	t.Helper()
	n := &noticeLab{ntfy: newNtfyCatcher(t), cmds: filepath.Join(t.TempDir(), "notify-cmd.log")}
	n.clock = agent.NewFakeClock(time.Now())
	c.clock = n.clock
	c.config = func(cfg *Config) {
		cfg.NtfyURL = n.ntfy.URL + labWideTopic
		cfg.NotifyCmd = `printf '%s | %s | %s\n' "$MACLAB_DEVICE" "$MACLAB_TITLE" "$(printf %s "$MACLAB_BODY" | tr '\n' ' ')" >> ` + n.cmds
	}
	n.lab = newLabWith(t, c)
	t.Cleanup(pumpClock(n.clock))
	if c.volunteer {
		n.openWindowForNotices()
	}
	n.baseline()
	return n
}

// openWindowForNotices opens the Volunteer Mac's Availability window for the
// next 12 hours of lab time, as a Volunteer would with `open --until`: a
// Volunteer Mac with no window is closed. Until #26 lands, "open" not being a
// Volunteer command is tolerated; any other error fails the test.
func (n *noticeLab) openWindowForNotices() {
	n.t.Helper()
	until := n.clock.Now().Add(12 * time.Hour).Format("15:04")
	if out, err := n.volunteer("open", "--until", until); err != nil && !strings.Contains(err.Error(), `"open" is not a Volunteer command`) {
		n.t.Fatalf("open --until %s: %v\n%s", until, err, out)
	}
}

// cmdLines is what --notify-cmd was run with, one line per run.
func (n *noticeLab) cmdLines() []string {
	b, _ := os.ReadFile(n.cmds)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

var subscribeLine = regexp.MustCompile(`(?m)subscribe to:\s+(\S+)`)

// macTopic is the path of the Mac's own topic on the lab's ntfy server, as
// `status` tells the Volunteer.
func (n *noticeLab) macTopic() string {
	n.t.Helper()
	out, err := n.volunteer("status")
	if err != nil {
		n.t.Fatalf("status: %v", err)
	}
	m := subscribeLine.FindStringSubmatch(out)
	if m == nil || !strings.HasPrefix(m[1], n.ntfy.URL+"/") {
		n.t.Fatalf("status does not show the Mac's topic on the lab's ntfy server %s:\n%s", n.ntfy.URL, out)
	}
	path := strings.TrimPrefix(m[1], n.ntfy.URL)
	if path == labWideTopic {
		n.t.Fatalf("the Mac's topic is the lab-wide topic %s", path)
	}
	return path
}

// hang submits a job whose Lab boot hangs for good: nothing on the Mac can
// bring it back, so only a human can.
func (n *noticeLab) hang() string {
	return n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-hang behavior=hang")})
}

// step moves the clock on in steps of by until cond holds, giving labd time
// to look at each (keep by under the harness's 3s quietGrace: a bigger jump can
// land between a command and its result, which labd counts as lost), and
// returns how far past start it got. It gives up after max.
func (n *noticeLab) step(start time.Time, by, max time.Duration, cond func() bool) time.Duration {
	n.t.Helper()
	for n.clock.Now().Sub(start) < max {
		if cond() {
			return n.clock.Now().Sub(start)
		}
		n.clock.Advance(by)
		time.Sleep(20 * time.Millisecond)
	}
	n.t.Fatalf("not true after %s of lab time", max)
	return 0
}

func (n *noticeLab) state() api.DeviceState { return n.s.dev(n.name).snapshot().State }

// waitPosts waits up to wall time d for cond to hold of the posts to path.
func (n *noticeLab) waitPosts(path string, d time.Duration, cond func([]ntfyPost) bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond(n.ntfy.at(path)) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func anyPost(f func(ntfyPost) bool) func([]ntfyPost) bool {
	return func(ps []ntfyPost) bool {
		for _, p := range ps {
			if f(p) {
				return true
			}
		}
		return false
	}
}

// needsHandsAfter hangs a Lab boot and returns how far into the job the
// Volunteer was asked for hands (a needs-hands post on topic), with the
// check that nothing asked sooner.
func (n *noticeLab) needsHandsAfter(topic string) time.Duration {
	n.t.Helper()
	start := n.clock.Now()
	n.hang()
	return n.step(start, 2*time.Second, time.Hour, func() bool {
		return anyPost(ntfyPost.asksForHands)(n.ntfy.at(topic))
	})
}

// finish is the Volunteer power cycling their Mac; the job then ends.
func (n *noticeLab) finish() {
	n.t.Helper()
	before := n.waitDevice(func(d api.Device) bool { return d.State == api.StateNeedsHands })
	n.sim.PowerCycle()
	n.waitDevice(func(d api.Device) bool { return d.BootID != before.BootID && d.Kernel == agent.SimKnownGood })
}

// A job is at least its boot timeout, the time labd gives a Lab boot to come
// back by itself (twice that) and five minutes: its hard ceiling is no
// earlier. labd's boot timeout in the harness is 4 s.
const earliestCeiling = 4*time.Second + 2*4*time.Second + 5*time.Minute

func TestNeedsHandsOnAVolunteerMacOnlyAfterTheHardCeilingPlusABootTimeout(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	topic := n.macTopic()
	start := n.clock.Now()
	n.hang()
	var asked time.Duration
	asked = n.step(start, 2*time.Second, time.Hour, func() bool {
		if anyPost(ntfyPost.asksForHands)(n.ntfy.at(topic)) {
			return true
		}
		if n.state() == api.StateNeedsHands && n.clock.Now().Sub(start) < earliestCeiling+4*time.Second {
			t.Fatalf("the Mac was marked needs hands %s into the job, before the ceiling plus a boot timeout", n.clock.Now().Sub(start))
		}
		return false
	})
	if min := earliestCeiling + 4*time.Second; asked < min {
		t.Fatalf("asked for hands %s into the job: the hard ceiling is at least %s away, plus a 4s boot timeout", asked, min)
	}
	n.finish()
}

func TestNeedsHandsStateAndNoticeComeTogetherOnAVolunteerMac(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	topic := n.macTopic()
	n.needsHandsAfter(topic)
	d := n.waitDevice(func(d api.Device) bool { return d.State == api.StateNeedsHands })
	if d.Action == nil {
		t.Fatalf("needs hands with no action: %+v", d)
	}
	n.finish()
}

func TestNeedsHandsNoticeGivesExactStepsHoldPowerTenSecondsThenPowerOn(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	topic := n.macTopic()
	n.needsHandsAfter(topic)
	var post ntfyPost
	for _, p := range n.ntfy.at(topic) {
		if p.asksForHands() {
			post = p
		}
	}
	t.Logf("notice: %q / %q", post.title, post.body)
	text := post.text()
	hold := strings.Index(text, "hold")
	ten := strings.Index(text, "10 s")
	if hold < 0 || ten < 0 || !strings.Contains(text, "power") {
		t.Fatalf("no 'hold the power button for 10 seconds' step: %q", post.body)
	}
	if on := strings.LastIndex(text, "on"); !(strings.Contains(text, "turn it back on") || strings.Contains(text, "power on")) || on < ten {
		t.Fatalf("no 'power on' step after the hold: %q", post.body)
	}
	if post.priority != "urgent" {
		t.Fatalf("needs hands is %q priority on ntfy, want urgent", post.priority)
	}
	n.finish()
}

func TestNeedsHandsOnAVolunteerMacGoesToItsOwnTopicNotTheLabWideOne(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	topic := n.macTopic()
	n.needsHandsAfter(topic)
	n.finish()
	time.Sleep(300 * time.Millisecond)
	if got := len(n.ntfy.at(topic)); got != 1 {
		t.Fatalf("%d posts to the Mac's topic, want exactly the one needs-hands: %+v", got, n.ntfy.at(topic))
	}
	for _, p := range n.ntfy.at(labWideTopic) {
		if p.asksForHands() {
			t.Fatalf("a Volunteer's needs hands reached the lab-wide topic: %+v", p)
		}
	}
	for _, p := range n.ntfy.all() {
		if p.path != topic && p.path != labWideTopic {
			t.Fatalf("a post to a topic that is neither the Mac's nor the lab-wide one: %+v", p)
		}
	}
}

func TestMacTopicCarriesOnlyNeedsHandsNotJobResultsOrBackOrAsleepNotices(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	topic := n.macTopic()
	// a passing job, a failing test, a lost-contact job, a hang with its
	// "back" notice: routine traffic for Maintainers, none for the Volunteer
	n.expect(n.jobAPI(n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")}), 60*time.Second), api.OutcomePass)
	n.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	n.expect(n.jobAPI(n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-nn behavior=no-network")}), 60*time.Second), api.OutcomeLostContact)
	n.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	n.needsHandsAfter(topic)
	n.finish()
	time.Sleep(500 * time.Millisecond)
	posts := n.ntfy.at(topic)
	if len(posts) != 1 || !posts[0].asksForHands() {
		t.Fatalf("the Mac's topic got %+v, want only the one needs-hands", posts)
	}
	// and Maintainers still get the job results on the lab-wide topic
	if !n.waitPosts(labWideTopic, 5*time.Second, anyPost(func(p ntfyPost) bool { return strings.Contains(p.title, "job ") })) {
		t.Fatalf("no job result reached the lab-wide topic: %+v", n.ntfy.all())
	}
}

func TestNotifyTopicSendsNeedsHandsToTheVolunteersOwnTopic(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	generated := n.macTopic()
	own := newNtfyCatcher(t)
	if out, err := n.volunteer("notify", "--topic", own.URL+"/my-own-topic"); err != nil {
		t.Fatalf("notify --topic: %v\n%s", err, out)
	}
	time.Sleep(time.Second) // it syncs to labd at the next check-in
	start := n.clock.Now()
	n.hang()
	n.step(start, 2*time.Second, time.Hour, func() bool { return len(own.at("/my-own-topic")) > 0 })
	n.finish()
	if p := own.at("/my-own-topic"); len(p) != 1 || !p[0].asksForHands() {
		t.Fatalf("the Volunteer's own topic got %+v, want the one needs-hands", p)
	}
	if got := n.ntfy.at(generated); len(got) != 0 {
		t.Fatalf("the lab's generated topic still got %+v after notify --topic", got)
	}
	for _, p := range n.ntfy.at(labWideTopic) {
		if p.asksForHands() {
			t.Fatalf("needs hands reached the lab-wide topic: %+v", p)
		}
	}
}

func TestNotifyTopicRefusesABadURLAndKeepsTheMacsTopic(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	topic := n.macTopic()
	for _, bad := range []string{"", "not a url", "ftp://ntfy.example.org/t", "http://", "http://ntfy.example.org", "/just/a/path"} {
		args := []string{"notify", "--topic"}
		if bad != "" {
			args = append(args, bad)
		}
		if out, err := n.volunteer(args...); err == nil {
			t.Fatalf("notify --topic %q was accepted: %s", bad, out)
		}
	}
	if _, err := n.volunteer("notify", "--topic"); err == nil {
		t.Fatal("notify --topic with no URL was accepted")
	}
	time.Sleep(time.Second)
	if again := n.macTopic(); again != topic {
		t.Fatalf("a refused notify --topic changed the Mac's topic from %s to %s", topic, again)
	}
	n.needsHandsAfter(topic)
	n.finish()
}

func TestNotifyCmdIsRunForMaintainersNoticesOnAVolunteerMacButNotNeedsHands(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	topic := n.macTopic()
	n.expect(n.jobAPI(n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")}), 60*time.Second), api.OutcomePass)
	n.needsHandsAfter(topic)
	n.finish()
	time.Sleep(500 * time.Millisecond)
	lines := n.cmdLines()
	var jobResult bool
	for _, l := range lines {
		low := strings.ToLower(l)
		if strings.Contains(low, "hold") && strings.Contains(low, "10 s") || strings.Contains(low, "power cycle") {
			t.Fatalf("--notify-cmd was run for the Volunteer's needs hands: %q", l)
		}
		jobResult = jobResult || strings.Contains(l, "job ")
	}
	if !jobResult {
		t.Fatalf("--notify-cmd no longer runs for Maintainers' job notices on a Volunteer Mac: %q", lines)
	}
}

func TestLabWideTopicStillGetsMaintainersNoticesAboutAVolunteerMac(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-nn behavior=no-network")})
	n.lostBoot("7.2-nn")
	n.clock.Advance(2 * 4 * time.Second)
	n.expect(n.jobAPI(id, 60*time.Second), api.OutcomeLostContact)
	if !n.waitPosts(labWideTopic, 5*time.Second, anyPost(func(p ntfyPost) bool {
		return strings.Contains(p.title, id) && strings.Contains(p.title, api.OutcomeLostContact)
	})) {
		t.Fatalf("no failed-job notice for %s on the lab-wide topic: %+v", id, n.ntfy.all())
	}
}

func TestLabOwnedMacNeedsHandsStillGoesToTheLabWideTopicAndNotifyCmd(t *testing.T) {
	n := newNoticeLab(t, labConfig{})
	n.hang()
	n.waitDevice(func(d api.Device) bool { return d.State == api.StateNeedsHands })
	if !n.waitPosts(labWideTopic, 10*time.Second, anyPost(ntfyPost.asksForHands)) {
		t.Fatalf("a Lab-owned Mac's needs hands did not reach the lab-wide topic: %+v", n.ntfy.all())
	}
	var ran bool
	for deadline := time.Now().Add(10 * time.Second); !ran && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, l := range n.cmdLines() {
			low := strings.ToLower(l)
			ran = ran || strings.Contains(low, "hold") && strings.Contains(low, "10 s")
		}
	}
	if !ran {
		t.Fatalf("--notify-cmd not run for a Lab-owned Mac's needs hands: %q", n.cmdLines())
	}
	for _, p := range n.ntfy.all() {
		if p.path != labWideTopic {
			t.Fatalf("a Lab-owned Mac posted to a per-Mac topic: %+v", p)
		}
	}
	n.sim.PowerCycle()
}

func TestLabOwnedMacIsAskedForHandsAfterTheBootTimeoutNotTheCeiling(t *testing.T) {
	n := newNoticeLab(t, labConfig{})
	start := n.clock.Now()
	n.hang()
	asked := n.step(start, 2*time.Second, time.Hour, func() bool { return anyPost(ntfyPost.asksForHands)(n.ntfy.at(labWideTopic)) })
	if asked >= earliestCeiling {
		t.Fatalf("a Lab-owned Mac waited %s for hands: its ladder is unchanged and does not wait for the ceiling", asked)
	}
	n.sim.PowerCycle()
}

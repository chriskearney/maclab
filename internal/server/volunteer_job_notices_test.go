package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// jobNotice is whether a post is the "a job is starting on your Mac" notice for job id.
func (p ntfyPost) jobStarting(id string) bool {
	t := p.text()
	return strings.Contains(t, id) && strings.Contains(t, "starting")
}

// jobDone is whether a post is the "the job is done" notice for job id.
func (p ntfyPost) jobDone(id string) bool {
	t := p.text()
	return strings.Contains(t, id) && strings.Contains(t, "done") && !strings.Contains(t, "starting")
}

// forJob is the posts on a topic that are about job id (the harness's baseline job posts too).
func forJob(posts []ntfyPost, id string) []ntfyPost {
	var out []ntfyPost
	for _, p := range posts {
		if strings.Contains(p.text(), id) {
			out = append(out, p)
		}
	}
	return out
}

// newJobNoticeLab is a Volunteer lab whose Volunteer has run `notify --jobs on`
// (or has not, with on false) and whose labd has seen it.
func newJobNoticeLab(t *testing.T, on bool) *noticeLab {
	t.Helper()
	n := newNoticeLab(t, labConfig{volunteer: true})
	if on {
		if out, err := n.volunteer("notify", "--jobs", "on"); err != nil {
			t.Fatalf("notify --jobs on: %v\n%s", err, out)
		}
		n.waitDevice(func(d api.Device) bool { return d.JobNotices })
	}
	return n
}

func TestVolunteerGetsAStartingAndADoneNoticeOnTheirOwnTopicForAJob(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")})
	n.expect(n.jobAPI(id, 60*time.Second), api.OutcomePass)
	if !n.waitPosts(topic, 5*time.Second, anyPost(func(p ntfyPost) bool { return p.jobDone(id) })) {
		t.Fatalf("no done notice for %s on the Mac's topic: %+v", id, n.ntfy.at(topic))
	}
	posts := forJob(n.ntfy.at(topic), id)
	if len(posts) != 2 || !posts[0].jobStarting(id) || !posts[1].jobDone(id) {
		t.Fatalf("the Mac's topic got %+v, want the starting notice then the done notice for %s", posts, id)
	}
}

func TestTheStartingNoticeNamesTheJobTheLengthAndAsksNotToReboot(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")})
	n.expect(n.jobAPI(id, 60*time.Second), api.OutcomePass)
	if !n.waitPosts(topic, 5*time.Second, anyPost(func(p ntfyPost) bool { return p.jobStarting(id) })) {
		t.Fatalf("no starting notice for %s: %+v", id, n.ntfy.at(topic))
	}
	start := forJob(n.ntfy.at(topic), id)[0]
	text := start.text()
	for _, want := range []string{id, n.name, "reboot", "do not reboot", "until", "done", "min"} {
		if !strings.Contains(text, want) {
			t.Errorf("the starting notice lacks %q:\n%s\n%s", want, start.title, start.body)
		}
	}
	if start.priority == "urgent" || start.priority == "5" {
		t.Errorf("a routine heads-up must not be urgent: %q", start.priority)
	}
}

func TestTheDoneNoticeSaysHowTheJobEndedAndThatTheMacIsFree(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-nn behavior=no-network")})
	j := n.jobAPI(id, 60*time.Second)
	n.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
	if !n.waitPosts(topic, 5*time.Second, anyPost(func(p ntfyPost) bool { return p.jobDone(id) })) {
		t.Fatalf("no done notice for %s: %+v", id, n.ntfy.at(topic))
	}
	var done ntfyPost
	for _, p := range forJob(n.ntfy.at(topic), id) {
		if p.jobDone(id) {
			done = p
		}
	}
	text := done.text()
	if !strings.Contains(text, strings.ToLower(j.Outcome)) {
		t.Errorf("the done notice does not say the outcome %q:\n%s\n%s", j.Outcome, done.title, done.body)
	}
	if !strings.Contains(text, "you can reboot") {
		t.Errorf("the done notice does not say the Mac may be rebooted:\n%s\n%s", done.title, done.body)
	}
}

func TestVolunteerJobNoticesAreOffUntilTheVolunteerAsks(t *testing.T) {
	n := newJobNoticeLab(t, false)
	topic := n.macTopic()
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")})
	n.expect(n.jobAPI(id, 60*time.Second), api.OutcomePass)
	time.Sleep(500 * time.Millisecond)
	if posts := n.ntfy.at(topic); len(posts) != 0 {
		t.Fatalf("the Mac's topic got %+v with the notices off", posts)
	}
	n.waitDevice(func(d api.Device) bool { return d.State == api.StateReady })
}

func TestVolunteerJobNoticesNeverGoToTheLabWideTopicOrNotifyCmd(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")})
	n.expect(n.jobAPI(id, 60*time.Second), api.OutcomePass)
	n.waitPosts(topic, 5*time.Second, anyPost(func(p ntfyPost) bool { return p.jobDone(id) }))
	for _, p := range n.ntfy.at(labWideTopic) {
		if strings.Contains(p.text(), "do not reboot") || strings.Contains(p.text(), "you can reboot") {
			t.Fatalf("a Volunteer's notice reached the lab-wide topic: %+v", p)
		}
	}
	for _, line := range n.cmdLines() {
		if strings.Contains(strings.ToLower(line), "do not reboot") || strings.Contains(strings.ToLower(line), "you can reboot") {
			t.Fatalf("a Volunteer's notice reached --notify-cmd: %s", line)
		}
	}
}

func TestAHangEndsWithTheNeedsHandsNoticeAndNoAllClear(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	allClears := func() int {
		c := 0
		for _, p := range n.ntfy.at(topic) {
			if strings.Contains(p.text(), "you can reboot") {
				c++
			}
		}
		return c
	}
	before := allClears() // the harness's baseline jobs ended well
	n.needsHandsAfter(topic)
	time.Sleep(500 * time.Millisecond)
	if allClears() != before {
		t.Fatalf("an all-clear went out while the Mac needed hands: %+v", n.ntfy.at(topic))
	}
	n.finish()
	if !anyPost(ntfyPost.asksForHands)(n.ntfy.at(topic)) {
		t.Fatalf("the needs-hands notice is missing: %+v", n.ntfy.at(topic))
	}
}

func TestALabOwnedMacGetsNoVolunteerNotices(t *testing.T) {
	n := newNoticeLab(t, labConfig{})
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")})
	n.expect(n.jobAPI(id, 60*time.Second), api.OutcomePass)
	time.Sleep(500 * time.Millisecond)
	for _, p := range n.ntfy.all() {
		if strings.Contains(p.text(), "do not reboot") || strings.Contains(p.text(), "you can reboot") {
			t.Fatalf("a lab-owned Mac's job produced a Volunteer notice: %+v", p)
		}
	}
}

func TestNotifyJobsOffStopsTheNoticesAgain(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	if out, err := n.volunteer("notify", "--jobs", "off"); err != nil {
		t.Fatalf("notify --jobs off: %v\n%s", err, out)
	}
	n.waitDevice(func(d api.Device) bool { return !d.JobNotices })
	id := n.submitJob(api.JobSpec{Kernel: n.artifact("krel=7.2-ok behavior=ok")})
	n.expect(n.jobAPI(id, 60*time.Second), api.OutcomePass)
	time.Sleep(500 * time.Millisecond)
	if got := forJob(n.ntfy.at(topic), id); len(got) != 0 {
		t.Fatalf("notices after notify --jobs off: %+v", got)
	}
}

func TestNotifyJobsOnlyTakesOnOrOff(t *testing.T) {
	n := newNoticeLab(t, labConfig{volunteer: true})
	for _, bad := range [][]string{{"notify", "--jobs"}, {"notify", "--jobs", "maybe"}, {"notify", "--jobs", ""}, {"notify", "--jobs", "on", "extra"}} {
		if out, err := n.volunteer(bad...); err == nil {
			t.Fatalf("%v was accepted: %s", bad, out)
		}
	}
	if st, _ := n.volunteer("status"); !strings.Contains(st, "job notices:    off") {
		t.Fatalf("status does not say job notices are off:\n%s", st)
	}
}

func TestStatusShowsWhetherJobNoticesAreOn(t *testing.T) {
	n := newJobNoticeLab(t, true)
	st, err := n.volunteer("status")
	if err != nil || !strings.Contains(st, "job notices:    on") {
		t.Fatalf("status = %q, %v; want job notices on", st, err)
	}
}

// A check-in without the setting (an old agent, or a Mac that could not read
// its file) must keep the Volunteer's choice, not turn the notices off.
func TestACheckInWithoutTheSettingKeepsTheVolunteersChoice(t *testing.T) {
	n := newJobNoticeLab(t, true)
	v := n.s.dev(n.name)
	d := v.snapshot()
	v.heartbeat(api.Checkin{BootID: d.BootID, Kernel: d.Kernel, Cmdline: d.Cmdline, Health: d.Health, SnapshotEligible: d.SnapshotEligible})
	if !v.snapshot().JobNotices {
		t.Fatal("a check-in with no job-notices setting turned the notices off")
	}
}

func countDone(n *noticeLab, topic, id string) int {
	c := 0
	for _, p := range forJob(n.ntfy.at(topic), id) {
		if p.jobDone(id) {
			c++
		}
	}
	return c
}

// labd restarting while a job held the Mac closes that job with nothing left
// to send the done notice, so the restart sends it.
func TestARestartDuringAJobSendsTheDoneNoticeTheJobOwed(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, id := range []string{"lost-testing", "lost-booting"} {
		if err := n.s.store.saveJob(&api.Job{ID: id, Spec: api.JobSpec{Device: n.name}, State: api.JobTesting, Created: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"lost-building"} {
		if err := n.s.store.saveJob(&api.Job{ID: id, Spec: api.JobSpec{Device: n.name}, State: api.JobBuilding, Created: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(ctx, n.s.cfg, nil); err != nil {
		t.Fatal(err)
	}
	if !n.waitPosts(topic, 5*time.Second, anyPost(func(p ntfyPost) bool { return p.jobDone("lost-testing") })) {
		t.Fatalf("no done notice for the job labd lost: %+v", n.ntfy.at(topic))
	}
	time.Sleep(300 * time.Millisecond)
	got := forJob(n.ntfy.at(topic), "lost-testing")
	if len(got) != 1 || !strings.Contains(got[0].text(), "infra") {
		t.Fatalf("the lost job's notice: %+v", got)
	}
	if countDone(n, topic, "lost-booting") != 1 {
		t.Fatalf("no done notice for the lost booting job: %+v", n.ntfy.at(topic))
	}
	if countDone(n, topic, "lost-building") != 0 {
		t.Fatalf("a job that never reached the Mac got a done notice: %+v", forJob(n.ntfy.at(topic), "lost-building"))
	}
}

func TestARestartSendsNothingToAVolunteerWhoDidNotAsk(t *testing.T) {
	n := newJobNoticeLab(t, false)
	topic := n.macTopic()
	if err := n.s.store.saveJob(&api.Job{ID: "lost-quiet", Spec: api.JobSpec{Device: n.name}, State: api.JobTesting, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := New(ctx, n.s.cfg, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := forJob(n.ntfy.at(topic), "lost-quiet"); len(got) != 0 {
		t.Fatalf("a Volunteer who did not ask got %+v", got)
	}
}

// A done notice that falls while the Mac is being recovered or needs hands is
// held, not dropped, and goes once the Mac is back.
func TestADoneNoticeHeldWhileTheMacIsBeingRecoveredGoesWhenItIsBack(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	v := n.s.dev(n.name)
	r := &jobRun{s: n.s, v: v, j: &api.Job{ID: "held-1", Spec: api.JobSpec{Device: n.name}}, volunteerTold: true}
	v.setState(api.StateRecovering, "test")
	r.tellVolunteerJobDone("pass")
	time.Sleep(500 * time.Millisecond)
	if got := countDone(n, topic, "held-1"); got != 0 {
		t.Fatalf("the done notice went while the Mac was being recovered: %+v", n.ntfy.at(topic))
	}
	v.mu.Lock()
	v.sendOwedDoneLocked() // still being recovered: still held
	v.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	if got := countDone(n, topic, "held-1"); got != 0 {
		t.Fatalf("the held notice went while the Mac was still being recovered: %+v", n.ntfy.at(topic))
	}
	v.setState(api.StateReady, "")
	v.mu.Lock()
	v.sendOwedDoneLocked()
	v.mu.Unlock()
	if !n.waitPosts(topic, 5*time.Second, anyPost(func(p ntfyPost) bool { return p.jobDone("held-1") })) {
		t.Fatalf("the held done notice never went: %+v", n.ntfy.at(topic))
	}
	v.mu.Lock()
	v.sendOwedDoneLocked() // nothing owed any more
	v.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	if got := countDone(n, topic, "held-1"); got != 1 {
		t.Fatalf("%d done notices for held-1, want 1", got)
	}
}

func TestADoneNoticeHeldWhileTheMacNeedsHandsGoesAtTheBackCheckIn(t *testing.T) {
	n := newJobNoticeLab(t, true)
	topic := n.macTopic()
	v := n.s.dev(n.name)
	r := &jobRun{s: n.s, v: v, j: &api.Job{ID: "held-2", Spec: api.JobSpec{Device: n.name}}, volunteerTold: true}
	v.setState(api.StateNeedsHands, "test")
	r.tellVolunteerJobDone("pass")
	// the Mac checks in again: that is the "back" moment
	if !n.waitPosts(topic, 5*time.Second, anyPost(func(p ntfyPost) bool { return p.jobDone("held-2") })) {
		t.Fatalf("the held done notice never went at the back check-in: %+v", n.ntfy.at(topic))
	}
	time.Sleep(300 * time.Millisecond)
	if got := countDone(n, topic, "held-2"); got != 1 {
		t.Fatalf("%d done notices for held-2, want 1", got)
	}
}

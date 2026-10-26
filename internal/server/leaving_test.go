package server

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// Seams invented for #33 (the ticket names none):
//   - `sudo lab-agent leave` asks to confirm; l.volunteer("leave", "--yes")
//     is the Volunteer saying yes. Without --yes (no terminal in the harness)
//     it must refuse and change nothing.
//   - A Maintainer ends a Mac's enrollment with DELETE /api/devices/{name}
//     under their own token. Afterwards the Mac is gone from labd's API and
//     its device secret is rejected with 401 at once.
//   - "Told on both channels": the Mac's ntfy topic gets an "enrollment
//     ended" notice and the Sim shows the Volunteer a desktop notice, both
//     naming the Maintainer.

const leavingMaintainer = "grace"

// leavingLink is a transport that can drop labd off the network.
type leavingLink struct{ down atomic.Bool }

func (k *leavingLink) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if k.down.Load() {
			http.Error(w, "labd is unreachable", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// leavingLab is a Volunteer lab with a second Maintainer (grace) and a window open.
func leavingLab(t *testing.T, c labConfig) (*noticeLab, string) {
	t.Helper()
	c.volunteer = true
	n := newNoticeLab(t, c)
	return n, n.addMaintainer(harnessToken, leavingMaintainer).Token
}

// leavingEnd is a Maintainer ending the enrollment of the Mac called name.
func (l *lab) leavingEnd(token, name string) (*http.Response, string) {
	l.t.Helper()
	return l.as(token, "POST", "/api/devices/"+name+"/end-enrollment", nil)
}

func (l *lab) leavingMustEnd(token, name string) {
	l.t.Helper()
	if r, body := l.leavingEnd(token, name); r.StatusCode/100 != 2 {
		l.t.Fatalf("ending %s's enrollment: %s %s", name, r.Status, body)
	}
}

// leavingGone waits up to d for labd to know no Mac called name.
func (l *lab) leavingGone(name string, d time.Duration) bool {
	l.t.Helper()
	for end := time.Now().Add(d); ; time.Sleep(50 * time.Millisecond) {
		if r, _ := l.get("GET", "/api/devices/"+name); r.StatusCode == 404 {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

func (l *lab) leavingRequireGone(name string) {
	l.t.Helper()
	if !l.leavingGone(name, 15*time.Second) {
		_, body := l.get("GET", "/api/devices/"+name)
		l.t.Fatalf("labd still knows %s: %s", name, body)
	}
}

func (l *lab) leavingStillEnrolled() {
	l.t.Helper()
	time.Sleep(500 * time.Millisecond)
	if r, body := l.get("GET", "/api/devices/"+l.name); r.StatusCode != 200 {
		l.t.Fatalf("%s is no longer enrolled: %s %s", l.name, r.Status, body)
	}
	if r := l.checkinAs(l.secret); r.StatusCode != 200 {
		l.t.Fatalf("the Mac's device secret stopped working: %s", r.Status)
	}
}

// leavingTopic is the path of a Volunteer Mac's own topic from labd's enroll answer.
func (n *noticeLab) leavingTopic(topic string) string {
	topic = strings.TrimPrefix(topic, n.ntfy.URL)
	return "/" + strings.TrimPrefix(topic, "/")
}

func (n *noticeLab) leavingEndedNotices(path string) []ntfyPost {
	var out []ntfyPost
	for _, p := range n.ntfy.at(path) {
		if p.endedEnrollment() {
			out = append(out, p)
		}
	}
	return out
}

// leavingDesktopNotice is whether the Volunteer was shown a desktop notice
// that the Maintainer ended the enrollment.
func leavingDesktopNotice(sim *agent.Sim, maintainer string) bool {
	for _, t := range sim.Notices() {
		low := strings.ToLower(t)
		if strings.Contains(low, "ended") && strings.Contains(low, maintainer) {
			return true
		}
	}
	return false
}

// ---- the Volunteer leaving ----

func TestLeaveAsksToConfirmFirstAndWithoutAnAnswerChangesNothing(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	if out, err := n.volunteer("leave"); err == nil {
		t.Fatalf("leave went ahead with no confirmation: %s", out)
	}
	n.leavingStillEnrolled()
}

func TestLeaveRefusesStrayArgumentsAndChangesNothing(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	for _, args := range [][]string{{"leave", "--yes", "now"}, {"leave", "--bogus"}, {"leave", "--yes", "--yes=maybe"}} {
		if out, err := n.volunteer(args...); err == nil {
			t.Fatalf("lab-agent %s was accepted: %s", strings.Join(args, " "), out)
		}
	}
	n.leavingStillEnrolled()
}

func TestVolunteerLeavingRemovesTheMacFromLabdAndRevokesItsDeviceSecret(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	n.mustVolunteer("leave", "--yes")
	n.leavingRequireGone(n.name)
	if r := n.checkinAs(n.secret); r.StatusCode != 401 {
		t.Fatalf("the device secret of a Mac that left still works: %s", r.Status)
	}
	if _, _, err := n.s.Submit(api.JobSpec{Device: n.name, Kernel: n.artifact("krel=7.2-ok behavior=ok")}); err == nil {
		t.Fatal("a job was accepted for a Mac that left")
	}
}

func TestVolunteerLeavingPrintsWhatIsLeftToRemoveByHand(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	out := strings.ToLower(n.mustVolunteer("leave", "--yes"))
	if !strings.Contains(out, "tailscale") {
		t.Fatalf("leave does not mention the Tailscale node left to remove:\n%s", out)
	}
	if !strings.Contains(out, "lab-agent") || !strings.Contains(out, "package") {
		t.Fatalf("leave does not mention the lab-agent package left to remove:\n%s", out)
	}
}

func TestVolunteerLeavingStopsAJobInProgressIncompleteAndReturnsToTheKnownGoodKernel(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	id, _ := n.longJob("7.2-leaving")
	labBoot, _, _ := n.sim.Identity()
	n.mustVolunteer("leave", "--yes")
	n.backOnItsOwnSystem(labBoot, 8*time.Second, "the Volunteer left during the Lab boot")
	n.expect(n.jobAPI(id, 30*time.Second), api.OutcomeIncomplete)
	n.leavingRequireGone(n.name)
	if k := n.sim.LeavingStagedEntries(); k != 0 {
		t.Fatalf("%d lab boot entries are still staged on the Mac that left", k)
	}
}

func TestVolunteerLeavingEndsALeaseOnTheirMac(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	n.takeLease("connor (homework)", time.Hour)
	n.mustVolunteer("leave", "--yes")
	n.leavingRequireGone(n.name)
	if r, body := n.post("/api/devices/"+n.name+"/lease", api.LeaseRequest{Holder: "connor", TTLSec: 60}); r.StatusCode == 200 {
		t.Fatalf("a lease was granted on a Mac that left: %s", body)
	}
}

func TestVolunteerLeavingWorksAtOnceWithLabdDownAndTellsLabdAtTheNextChance(t *testing.T) {
	var link leavingLink
	n, _ := leavingLab(t, labConfig{wrap: link.wrap})
	link.down.Store(true)
	n.mustVolunteer("leave", "--yes") // immediate: never waits for labd
	link.down.Store(false)
	n.leavingRequireGone(n.name)
	if r := n.checkinAs(n.secret); r.StatusCode != 401 {
		t.Fatalf("the Mac left while labd was down, yet its device secret works: %s", r.Status)
	}
}

func TestVolunteerLeavingMidJobWithLabdDownStillReturnsTheMacToItsOwnSystem(t *testing.T) {
	var link leavingLink
	n, _ := leavingLab(t, labConfig{wrap: link.wrap})
	id, _ := n.longJob("7.2-leaving-dark")
	labBoot, _, _ := n.sim.Identity()
	link.down.Store(true)
	n.mustVolunteer("leave", "--yes")
	n.backOnItsOwnSystem(labBoot, 8*time.Second, "the Volunteer left during the Lab boot with labd down")
	link.down.Store(false)
	n.leavingRequireGone(n.name)
	if j := n.jobAPI(id, 60*time.Second); j.Outcome == api.OutcomePass {
		t.Fatalf("a job its Mac left in the middle of passed: %v", j.Events)
	}
}

func TestMacThatLeftRunsNoMoreLabWorkAndNothingComesBackWithoutANewEnrollment(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	n.mustVolunteer("leave", "--yes")
	n.leavingRequireGone(n.name)
	boot, _, _ := n.sim.Identity()
	time.Sleep(2 * time.Second) // the agent must not check in again and bring the Mac back
	if !n.leavingGone(n.name, time.Second) {
		t.Fatal("the Mac that left is listed again without being enrolled")
	}
	if b, _, _ := n.sim.Identity(); b != boot {
		t.Fatal("the Mac that left rebooted")
	}
}

func TestMacThatLeftCanEnrollAgainOnlyWithANewToken(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	oldSecret := n.secret
	n.mustVolunteer("leave", "--yes")
	n.leavingRequireGone(n.name)
	// the old, spent enrollment token does not work
	if r, _ := n.enrollRaw("enr_test_" + n.name); r.StatusCode == 200 {
		t.Fatal("the spent enrollment token enrolled a Mac that left")
	}
	// the old device secret does not work
	if r := n.checkinAs(oldSecret); r.StatusCode != 401 {
		t.Fatalf("old secret: %s", r.Status)
	}
	// a Maintainer's new token for the same name does
	tok := n.enrollToken(n.name)
	resp, body := n.enrollRaw(tok)
	if resp.StatusCode != 200 {
		t.Fatalf("enrolling again with a new token: %s %s", resp.Status, body)
	}
	if strings.Contains(body, oldSecret) {
		t.Fatal("the new enrollment reuses the old device secret")
	}
	// and the Mac's kind is whatever the new token says: this one is Lab-owned
	if d := n.deviceJSON(n.name); d["kind"] == kindVolunteer {
		t.Fatalf("a Mac that left and enrolled again with a Lab-owned token is still a Volunteer's: %v", d)
	}
}

func TestLabOwnedMacHasNoLeaveAndStaysEnrolled(t *testing.T) {
	n := newNoticeLab(t, labConfig{})
	if out, err := n.volunteer("leave", "--yes"); err == nil {
		t.Fatalf("a Lab-owned Mac left with a Volunteer command: %s", out)
	}
	n.leavingStillEnrolled()
}

// ---- the Maintainers ending an enrollment ----

func TestMaintainerEndingAnEnrollmentRemovesTheMacAndRevokesItsDeviceSecretAtOnce(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	n.leavingMustEnd(grace, n.name)
	// no wait: the secret is revoked on labd the moment the call returns
	if r := n.checkinAs(n.secret); r.StatusCode != 401 {
		t.Fatalf("the device secret of a Mac whose enrollment ended still works: %s", r.Status)
	}
	n.leavingRequireGone(n.name)
}

func TestMaintainerEndingAnEnrollmentOfAMacThatNeverChecksInAgainRevokesItsSecret(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	out := n.enrollMac("lost-mbp", ada, agent.NewSim(t.TempDir()), false)
	secret, _ := out["secret"].(string)
	if r := n.checkinAs(secret); r.StatusCode != 200 {
		t.Fatalf("first check-in of lost-mbp: %s", r.Status)
	}
	n.leavingMustEnd(grace, "lost-mbp") // the Mac is lost: it never comes back
	if r := n.checkinAs(secret); r.StatusCode != 401 {
		t.Fatalf("a lost Mac's device secret works after its enrollment ended: %s", r.Status)
	}
	n.leavingRequireGone("lost-mbp")
}

func TestVolunteerIsToldOnTheirMacsTopicWhichMaintainerEndedTheEnrollment(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	topic := n.macTopic()
	n.leavingMustEnd(grace, n.name)
	if !n.waitPosts(topic, 10*time.Second, anyPost(func(p ntfyPost) bool {
		return p.endedEnrollment() && strings.Contains(p.text(), leavingMaintainer)
	})) {
		t.Fatalf("no 'enrollment ended' notice naming %s on the Mac's topic: %+v", leavingMaintainer, n.ntfy.at(topic))
	}
}

func TestVolunteerIsToldOnTheDesktopWhichMaintainerEndedTheEnrollment(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	n.leavingMustEnd(grace, n.name)
	deadline := time.Now().Add(10 * time.Second)
	for !leavingDesktopNotice(n.sim, leavingMaintainer) {
		if time.Now().After(deadline) {
			t.Fatalf("no desktop notice naming %s: %q", leavingMaintainer, n.sim.Notices())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestVolunteerOfAMacThatNeverReturnsStillGetsTheEnrollmentEndedNoticeOnItsTopic(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	out := n.enrollMac("lost-mbp", ada, agent.NewSim(t.TempDir()), false)
	topic := n.leavingTopic(out["ntfy_topic"].(string))
	if r := n.checkinAs(out["secret"].(string)); r.StatusCode != 200 {
		t.Fatalf("first check-in of lost-mbp: %s", r.Status)
	}
	n.leavingMustEnd(grace, "lost-mbp")
	if !n.waitPosts(topic, 10*time.Second, anyPost(func(p ntfyPost) bool { return p.endedEnrollment() })) {
		t.Fatalf("no 'enrollment ended' notice on lost-mbp's topic %s: %+v", topic, n.ntfy.all())
	}
}

func TestEnrollmentEndedNoticeIsOnlyForTheVolunteersMacTopicNotTheLabWideOne(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	topic := n.macTopic()
	n.leavingMustEnd(grace, n.name)
	n.waitPosts(topic, 10*time.Second, anyPost(ntfyPost.endedEnrollment))
	time.Sleep(500 * time.Millisecond)
	for _, p := range n.ntfy.at(labWideTopic) {
		if p.endedEnrollment() && strings.Contains(p.text(), "volunteer") {
			t.Fatalf("a Volunteer's enrollment-ended notice reached the lab-wide topic: %+v", p)
		}
	}
	if got := n.leavingEndedNotices(topic); len(got) != 1 {
		t.Fatalf("%d enrollment-ended notices on the Mac's topic, want exactly one: %+v", len(got), n.ntfy.at(topic))
	}
}

func TestMaintainerEndingAnEnrollmentMidJobHasTheMacCleanUpAtItsNextCheckin(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	id, _ := n.longJob("7.2-ended")
	labBoot, _, _ := n.sim.Identity()
	n.leavingMustEnd(grace, n.name)
	n.backOnItsOwnSystem(labBoot, 10*time.Second, "the Maintainers ended the enrollment during the Lab boot")
	if j := n.jobAPI(id, 60*time.Second); j.Outcome == api.OutcomePass {
		t.Fatalf("a job on a Mac whose enrollment ended passed: %v", j.Events)
	}
	if !leavingDesktopNotice(n.sim, leavingMaintainer) {
		// the notice may come just after the cleanup
		time.Sleep(time.Second)
		if !leavingDesktopNotice(n.sim, leavingMaintainer) {
			t.Fatalf("the Volunteer was not told on the desktop: %q", n.sim.Notices())
		}
	}
}

func TestMacWhoseEnrollmentEndedDoesNotComeBackOnItsOwn(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	n.leavingMustEnd(grace, n.name)
	n.leavingRequireGone(n.name)
	time.Sleep(2 * time.Second) // lab-agent keeps checking in until it learns; it must not re-create the Mac
	if !n.leavingGone(n.name, time.Second) {
		t.Fatal("the Mac whose enrollment ended is listed again")
	}
}

func TestMacWhoseEnrollmentEndedCanEnrollAgainOnlyWithANewToken(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	oldSecret := n.secret
	n.leavingMustEnd(grace, n.name)
	n.leavingRequireGone(n.name)
	if r, _ := n.enrollRaw("enr_test_" + n.name); r.StatusCode == 200 {
		t.Fatal("the spent enrollment token enrolled a Mac whose enrollment ended")
	}
	resp, body := n.enrollRaw(n.enrollToken(n.name))
	if resp.StatusCode != 200 || strings.Contains(body, oldSecret) {
		t.Fatalf("enrolling again with a new token: %s %s", resp.Status, body)
	}
}

func TestEndingAnEnrollmentIsRecordedInTheMacsOwnAuditLogNamingTheMaintainer(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	n.leavingMustEnd(grace, n.name)
	deadline := time.Now().Add(10 * time.Second)
	var out string
	for {
		out, _ = n.volunteer("log")
		if l := strings.ToLower(out); strings.Contains(l, leavingMaintainer) && strings.Contains(l, "enrollment") && strings.Contains(l, "end") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("`log` does not show %s ending the enrollment:\n%s", leavingMaintainer, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAuditLogStillReadsAfterTheVolunteerLeaves(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	n.takeLease("connor (homework)", time.Hour) // a Maintainer action to leave a record
	_ = grace
	before, err := n.volunteer("log")
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	n.mustVolunteer("leave", "--yes")
	n.leavingRequireGone(n.name)
	after, err := n.volunteer("log")
	if err != nil {
		t.Fatalf("`log` fails after leave: %v", err)
	}
	if strings.TrimSpace(before) != "" && !strings.Contains(after, strings.Split(strings.TrimSpace(before), "\n")[0]) {
		t.Fatalf("`log` lost its entries after leave:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// ---- bad input ----

func TestEndingTheEnrollmentOfAMacLabdDoesNotKnowIsNotFound(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	if r, body := n.leavingEnd(grace, "no-such-mac"); r.StatusCode != 404 {
		t.Fatalf("ending an unknown Mac: %s %s", r.Status, body)
	}
	n.leavingStillEnrolled()
}

func TestEndingAnEnrollmentTwiceIsNotFoundTheSecondTimeAndNoticesOnlyOnce(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	topic := n.macTopic()
	n.leavingMustEnd(grace, n.name)
	n.leavingRequireGone(n.name)
	if r, body := n.leavingEnd(grace, n.name); r.StatusCode != 404 {
		t.Fatalf("ending an enrollment twice: %s %s", r.Status, body)
	}
	n.waitPosts(topic, 10*time.Second, anyPost(ntfyPost.endedEnrollment))
	time.Sleep(500 * time.Millisecond)
	if got := n.leavingEndedNotices(topic); len(got) != 1 {
		t.Fatalf("%d enrollment-ended notices, want 1: %+v", len(got), got)
	}
}

func TestOnlyAMaintainerCanEndAnEnrollmentNotAMacNorAnUnknownToken(t *testing.T) {
	n, _ := leavingLab(t, labConfig{})
	other := n.enrollMac("other-mbp", ada, agent.NewSim(t.TempDir()), false)
	for who, tok := range map[string]string{"no token": "", "an unknown token": "nope", "a Mac's own device secret": n.secret, "another Mac's device secret": other["secret"].(string)} {
		for _, name := range []string{n.name, "other-mbp"} {
			if r, body := n.as(tok, "POST", "/api/devices/"+name+"/end-enrollment", nil); r.StatusCode != 401 && r.StatusCode != 403 {
				t.Fatalf("%s ended %s's enrollment: %s %s", who, name, r.Status, body)
			}
		}
	}
	n.leavingStillEnrolled()
	if r, _ := n.get("GET", "/api/devices/other-mbp"); r.StatusCode != 200 {
		t.Fatalf("other-mbp was removed: %s", r.Status)
	}
}

func TestRemovedMaintainersTokenCannotEndAnEnrollment(t *testing.T) {
	n, grace := leavingLab(t, labConfig{})
	if r, body := n.as(harnessToken, "DELETE", "/api/maintainers/"+leavingMaintainer, nil); r.StatusCode/100 != 2 {
		t.Fatalf("removing %s: %s %s", leavingMaintainer, r.Status, body)
	}
	if r, _ := n.leavingEnd(grace, n.name); r.StatusCode != 401 {
		t.Fatalf("a removed Maintainer ended an enrollment: %s", r.Status)
	}
	n.leavingStillEnrolled()
}

func TestMaintainerEndingALabOwnedMacSendsNoVolunteerNotice(t *testing.T) {
	n := newNoticeLab(t, labConfig{})
	n.leavingMustEnd(harnessToken, n.name)
	n.leavingRequireGone(n.name)
	time.Sleep(500 * time.Millisecond)
	for _, p := range n.ntfy.all() {
		if p.endedEnrollment() && p.path != labWideTopic {
			t.Fatalf("a Lab-owned Mac has no Volunteer, yet %+v was posted", p)
		}
	}
	if r := n.checkinAs(n.secret); r.StatusCode != 401 {
		t.Fatalf("a Lab-owned Mac's secret works after its enrollment ended: %s", r.Status)
	}
}

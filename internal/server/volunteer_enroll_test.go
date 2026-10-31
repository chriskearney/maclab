package server

import (
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// The JSON names #25 adds are read from raw maps, so these tests need no
// struct changes: device "kind" ("volunteer" or "lab-owned"), "volunteer_name",
// "contact", "ntfy_topic" and "snapshot_eligible"; the enroll answer's
// "ntfy_topic"; the enroll-token request's "volunteer_name" and "contact".
const kindVolunteer = "volunteer"

// enrollMac asks for a token with extra fields, enrolls sim with it and
// returns labd's answer. If run, the Mac's lab-agent then checks in.
func (l *lab) enrollMac(name string, extra map[string]any, sim *agent.Sim, run bool) map[string]any {
	l.t.Helper()
	req := map[string]any{"name": name, "model": api.ModelLaptop}
	for k, v := range extra {
		req[k] = v
	}
	resp, body := l.post("/api/enroll-tokens", req)
	var tok api.EnrollTokenResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil {
		l.t.Fatalf("enroll token for %s: %s %s", name, resp.Status, body)
	}
	resp, body = l.as("", "POST", "/api/agent/enroll", api.EnrollRequest{Token: tok.Token, Facts: sim.Facts(), ActivationKey: testActivationKey, TermsSHA256: termsSum()})
	if resp.StatusCode != 200 {
		l.t.Fatalf("enroll %s: %s %s", name, resp.Status, body)
	}
	out := map[string]any{}
	json.Unmarshal([]byte(body), &out)
	if run {
		cfg := &agent.Config{Server: l.url, DeviceID: out["device_id"].(string), Name: name, Secret: out["secret"].(string),
			WorkDir: l.t.TempDir(), Clock: agent.WallClock}
		go agent.New(cfg, sim, log.New(io.Discard, "", 0)).Run(l.ctx)
	}
	return out
}

func (l *lab) deviceJSON(name string) map[string]any {
	l.t.Helper()
	resp, body := l.get("GET", "/api/devices/"+name)
	if resp.StatusCode != 200 {
		l.t.Fatalf("device %s: %s %s", name, resp.Status, body)
	}
	m := map[string]any{}
	json.Unmarshal([]byte(body), &m)
	return m
}

func (l *lab) waitDeviceJSON(name string, cond func(map[string]any) bool) map[string]any {
	l.t.Helper()
	var m map[string]any
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if m = l.deviceJSON(name); cond(m) {
			return m
		}
	}
	l.t.Fatalf("device %s never met the condition: %v", name, m)
	return nil
}

var ada = map[string]any{"volunteer_name": "Ada Lovelace", "contact": "ada@example.org"}

func TestVolunteerTokenMakesAVolunteerMacWithTheirNameAndContact(t *testing.T) {
	l := newLab(t, false)
	l.enrollMac("ada-mbp", ada, agent.NewSim(t.TempDir()), true)
	d := l.waitDeviceJSON("ada-mbp", func(m map[string]any) bool { return m["boot_id"] != "" })
	if d["kind"] != kindVolunteer || d["volunteer_name"] != "Ada Lovelace" || d["contact"] != "ada@example.org" {
		t.Fatalf("device record: %v", d)
	}
}

func TestTokenWithoutVolunteerMakesALabOwnedMac(t *testing.T) {
	l := newLab(t, false)
	l.enrollMac("rack-mac", nil, agent.NewSim(t.TempDir()), true)
	d := l.waitDeviceJSON("rack-mac", func(m map[string]any) bool { return m["boot_id"] != "" })
	if d["kind"] == kindVolunteer {
		t.Fatalf("a Lab-owned Mac enrolled as a Volunteer's: %v", d)
	}
	if v, _ := d["volunteer_name"].(string); v != "" {
		t.Fatalf("a Lab-owned Mac has a Volunteer: %v", d)
	}
}

func TestVolunteerTokenNeedsBothNameAndContact(t *testing.T) {
	l := newLab(t, false)
	for _, extra := range []map[string]any{{"volunteer_name": "Ada"}, {"contact": "ada@example.org"}, {"volunteer_name": " ", "contact": "x"}} {
		req := map[string]any{"name": "half-mac", "model": api.ModelLaptop}
		for k, v := range extra {
			req[k] = v
		}
		if resp, body := l.post("/api/enroll-tokens", req); resp.StatusCode != 400 {
			t.Fatalf("token with %v: %s %s", extra, resp.Status, body)
		}
	}
	// and the refused requests left no token behind: the name is still free
	l.enrollMac("half-mac", ada, agent.NewSim(t.TempDir()), false)
}

func TestMacKindIsFixedUntilItIsReenrolled(t *testing.T) {
	l := newLab(t, false)
	l.enrollMac("ada-mbp", ada, agent.NewSim(t.TempDir()), true)
	l.waitDeviceJSON("ada-mbp", func(m map[string]any) bool { return m["boot_id"] != "" })
	for _, patch := range []map[string]any{{"kind": "lab-owned"}, {"volunteer_name": ""}, {"volunteer_name": "Someone Else"}, {"contact": "else@example.org"}} {
		l.as(harnessToken, "PATCH", "/api/devices/ada-mbp", patch)
		if d := l.deviceJSON("ada-mbp"); d["kind"] != kindVolunteer || d["volunteer_name"] != "Ada Lovelace" || d["contact"] != "ada@example.org" {
			t.Fatalf("patch %v changed the Mac: %v", patch, d)
		}
	}
	// a token for a Mac that is enrolled and has checked in is refused: no kind change that way either
	if resp, body := l.post("/api/enroll-tokens", map[string]any{"name": "ada-mbp", "model": api.ModelLaptop}); resp.StatusCode != 409 {
		t.Fatalf("a Lab-owned token for an enrolled Volunteer Mac: %s %s", resp.Status, body)
	}
}

func TestEnrollingAVolunteerMacReturnsItsOwnNtfyTopic(t *testing.T) {
	l := newLab(t, false)
	out := l.enrollMac("ada-mbp", ada, agent.NewSim(t.TempDir()), false)
	if topic, _ := out["ntfy_topic"].(string); topic == "" {
		t.Fatalf("enroll answer has no topic: %v", out)
	}
}

func TestNtfyTopicsAreUnguessableAndPerMac(t *testing.T) {
	l := newLab(t, false)
	a, _ := l.enrollMac("ada-mbp", ada, agent.NewSim(t.TempDir()), false)["ntfy_topic"].(string)
	b, _ := l.enrollMac("bob-mbp", map[string]any{"volunteer_name": "Bob", "contact": "bob@example.org"}, agent.NewSim(t.TempDir()), false)["ntfy_topic"].(string)
	if a == "" || a == b {
		t.Fatalf("topics %q and %q", a, b)
	}
	for _, topic := range []string{a, b} {
		if len(topic) < 20 {
			t.Fatalf("topic %q is short enough to guess", topic)
		}
		if strings.ContainsAny(topic, " /?#") {
			t.Fatalf("topic %q is not a plain ntfy topic", topic)
		}
		for _, name := range []string{"ada", "bob", "mbp", "Lovelace"} {
			if strings.Contains(strings.ToLower(topic), strings.ToLower(name)) {
				t.Fatalf("topic %q is built from %q", topic, name)
			}
		}
	}
}

func TestLabOwnedEnrollmentGetsNoVolunteerTopic(t *testing.T) {
	l := newLab(t, false)
	out := l.enrollMac("rack-mac", nil, agent.NewSim(t.TempDir()), false)
	if topic, _ := out["ntfy_topic"].(string); topic != "" {
		t.Fatalf("a Lab-owned Mac got a Volunteer topic: %v", out)
	}
}

func TestRetriedEnrollmentOfAVolunteerMacKeepsItsTopic(t *testing.T) {
	l := newLab(t, false)
	resp, body := l.post("/api/enroll-tokens", map[string]any{"name": "ada-mbp", "model": api.ModelLaptop, "volunteer_name": "Ada Lovelace", "contact": "ada@example.org"})
	var tok api.EnrollTokenResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil {
		t.Fatalf("token: %s %s", resp.Status, body)
	}
	sim := agent.NewSim(t.TempDir())
	var topics [2]string
	for i := range topics {
		resp, body = l.as("", "POST", "/api/agent/enroll", api.EnrollRequest{Token: tok.Token, Facts: sim.Facts(), ActivationKey: testActivationKey, TermsSHA256: termsSum()})
		out := map[string]any{}
		json.Unmarshal([]byte(body), &out)
		topics[i], _ = out["ntfy_topic"].(string)
		if resp.StatusCode != 200 || topics[i] == "" {
			t.Fatalf("enroll %d: %s %s", i, resp.Status, body)
		}
	}
	if topics[0] != topics[1] {
		t.Fatalf("the retry changed the topic: %v", topics)
	}
}

func TestSnapshotEligibilityIsReportedAtSetup(t *testing.T) {
	l := newLab(t, false)
	l.enrollMac("ada-mbp", ada, agent.NewSim(t.TempDir()), true)
	d := l.waitDeviceJSON("ada-mbp", func(m map[string]any) bool { return m["boot_id"] != "" })
	if d["snapshot_eligible"] != true {
		t.Fatalf("a Mac whose @ can be snapshotted: %v", d)
	}
}

func TestMacWhoseRootCannotBeSnapshottedIsShownNotEligible(t *testing.T) {
	l := newLab(t, false)
	sim := agent.NewSim(t.TempDir())
	sim.SetSnapshotable(false)
	l.enrollMac("ada-mbp", ada, sim, true)
	d := l.waitDeviceJSON("ada-mbp", func(m map[string]any) bool { return m["boot_id"] != "" })
	if d["snapshot_eligible"] != false {
		t.Fatalf("a Mac whose @ cannot be snapshotted: %v", d)
	}
}

func TestEveryCheckinReportsSnapshotEligibilityAgain(t *testing.T) {
	l := newLab(t, false)
	sim := agent.NewSim(t.TempDir())
	l.enrollMac("ada-mbp", ada, sim, true)
	l.waitDeviceJSON("ada-mbp", func(m map[string]any) bool { return m["snapshot_eligible"] == true })
	sim.SetSnapshotable(false)
	l.waitDeviceJSON("ada-mbp", func(m map[string]any) bool { return m["snapshot_eligible"] == false })
	sim.SetSnapshotable(true)
	l.waitDeviceJSON("ada-mbp", func(m map[string]any) bool { return m["snapshot_eligible"] == true })
}

func TestVolunteerMacEnrollsEndToEndInTheHarness(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	d := l.waitDeviceJSON(l.name, func(m map[string]any) bool { return m["boot_id"] != "" })
	if d["kind"] != kindVolunteer {
		t.Fatalf("the harness's Volunteer Mac: %v", d)
	}
	if v, _ := d["volunteer_name"].(string); v == "" {
		t.Fatalf("no Volunteer name: %v", d)
	}
	if c, _ := d["contact"].(string); c == "" {
		t.Fatalf("no contact: %v", d)
	}
}

func TestStatusShowsKindTopicAndEligibility(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	d := l.waitDeviceJSON(l.name, func(m map[string]any) bool { return m["boot_id"] != "" })
	out, err := l.volunteer("status")
	if err != nil {
		t.Fatal(err)
	}
	low := strings.ToLower(out)
	if !strings.Contains(low, "volunteer") {
		t.Fatalf("status does not show the kind:\n%s", out)
	}
	if topic, _ := d["ntfy_topic"].(string); topic == "" || !strings.Contains(out, topic) {
		t.Fatalf("status does not show the topic %q:\n%s", topic, out)
	}
	if !strings.Contains(low, "eligible") || strings.Contains(low, "not eligible") {
		t.Fatalf("status does not show the Mac as eligible:\n%s", out)
	}
}

func TestStatusShowsAMacThatCannotSnapshotAsNotEligible(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.waitDeviceJSON(l.name, func(m map[string]any) bool { return m["boot_id"] != "" })
	l.sim.SetSnapshotable(false)
	out, err := l.volunteer("status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "not eligible") {
		t.Fatalf("status:\n%s", out)
	}
}

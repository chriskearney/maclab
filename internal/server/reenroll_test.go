package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// A Mac that enrolled but never checked in keeps its name, even once its
// token has run out: activation is one-time, so a new token for the name is
// refused, with what to do. After lab forget, the name takes a new
// enrollment, and the old secret is worth nothing.
func TestMacThatNeverCheckedInKeepsItsNameUntilForgotten(t *testing.T) {
	clock := agent.NewFakeClock(time.Now())
	l := newLabWith(t, labConfig{clock: clock})
	first := l.enrollToken("ghost-mac")
	resp, body := l.enrollRaw(first)
	var old api.EnrollResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &old) != nil {
		t.Fatalf("enroll ghost-mac: %s %s", resp.Status, body)
	}
	// the Mac never checks in, and its token runs out
	clock.Advance(25 * time.Hour)

	resp, body = l.post("/api/enroll-tokens", api.EnrollTokenRequest{Name: "ghost-mac"})
	if resp.StatusCode != 409 || !strings.Contains(body, "lab forget ghost-mac") {
		t.Fatalf("a new token for a Mac that never checked in: %s %s", resp.Status, body)
	}
	if resp, body := l.get("DELETE", "/api/devices/ghost-mac?force=true"); resp.StatusCode != 200 {
		t.Fatalf("forget: %s %s", resp.Status, body)
	}
	resp, body = l.post("/api/enroll-tokens", api.EnrollTokenRequest{Name: "ghost-mac"})
	var tok api.EnrollTokenResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil {
		t.Fatalf("a new token after forget: %s %s", resp.Status, body)
	}
	resp, body = l.enrollRaw(tok.Token)
	var renewed api.EnrollResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &renewed) != nil {
		t.Fatalf("enrolling with the new token: %s %s", resp.Status, body)
	}
	if renewed.Name != "ghost-mac" || renewed.DeviceID == old.DeviceID || renewed.Secret == "" || renewed.Secret == old.Secret {
		t.Fatalf("the new enrollment: %+v after %+v", renewed, old)
	}
	if resp := l.checkinAs(old.Secret); resp.StatusCode != 401 {
		t.Fatalf("the old secret still works: %s", resp.Status)
	}
	if resp := l.checkinAs(renewed.Secret); resp.StatusCode != 200 {
		t.Fatalf("the new secret doesn't work: %s", resp.Status)
	}
	_, devices := l.get("GET", "/api/devices")
	if n := strings.Count(devices, `"name":"ghost-mac"`); n != 1 {
		t.Fatalf("ghost-mac is listed %d times: %s", n, devices)
	}
}

func TestMacThatCheckedInKeepsItsName(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	if resp, body := l.post("/api/enroll-tokens", api.EnrollTokenRequest{Name: l.name}); resp.StatusCode != 409 {
		t.Fatalf("a token for a Mac that has checked in: %s %s", resp.Status, body)
	}
}

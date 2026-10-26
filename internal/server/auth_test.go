package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// maintainerRoutes is a sample of routes behind Maintainer auth, old and new.
var maintainerRoutes = []struct{ method, path string }{
	{"GET", "/api/devices"},
	{"GET", "/api/devices/sim-mac"},
	{"POST", "/api/devices/sim-mac/reset"},
	{"GET", "/api/stream"},
	{"POST", "/api/enroll-tokens"},
	{"POST", "/api/jobs"},
	{"GET", "/api/jobs"},
	{"GET", "/api/builds"},
	{"POST", "/api/installed/9.9/promote"},
	{"GET", "/api/maintainers"},
	{"POST", "/api/maintainers"},
	{"DELETE", "/api/maintainers/" + harnessMaintainer},
}

func TestNoNetworkGetsInWithoutAToken(t *testing.T) {
	l := newLab(t, false) // the harness labd is on loopback
	for _, r := range maintainerRoutes {
		if resp, body := l.as("", r.method, r.path, nil); resp.StatusCode != 401 || !strings.Contains(body, "not a Maintainer's token") {
			t.Errorf("%s %s without a token: %s %s", r.method, r.path, resp.Status, body)
		}
	}
	// the UI no longer asks labd whether it may skip the token
	resp, body := l.as("", "GET", "/api/auth", nil)
	var auth map[string]any
	if resp.StatusCode == 200 && json.Unmarshal([]byte(body), &auth) == nil {
		t.Fatalf("GET /api/auth still answers: %s", body)
	}
}

func TestMaintainerRoutesRefuseEverythingButAMaintainersToken(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	gone := l.addMaintainer(harnessToken, "gone")
	if resp, body := l.as(harnessToken, "DELETE", "/api/maintainers/gone", nil); resp.StatusCode != 200 {
		t.Fatalf("remove gone: %s %s", resp.Status, body)
	}
	tokens := []struct{ what, token string }{
		{"an unknown token", "mnt_0000000000000000000000000000000000000000"},
		{"a removed Maintainer's token", gone.Token},
		{"the Mac's device secret", l.secret},
		{"the builder token", "bld"},
	}
	for _, tok := range tokens {
		for _, r := range maintainerRoutes {
			if resp, body := l.as(tok.token, r.method, r.path, nil); resp.StatusCode != 401 || !strings.Contains(body, "not a Maintainer's token") {
				t.Errorf("%s on %s %s: %s %s", tok.what, r.method, r.path, resp.Status, body)
			}
		}
	}
	if ms, body := l.maintainers(harnessToken); strings.Join(maintainerNames(ms), ",") != harnessMaintainer {
		t.Fatalf("a refused token changed the Maintainers: %s", body)
	}
}

func TestAgentRoutesRefuseMaintainerTokens(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	grace := l.addMaintainer(harnessToken, "grace")
	agentRoutes := []struct{ method, path string }{
		{"POST", "/api/agent/checkin"},
		{"POST", "/api/agent/report"},
		{"GET", "/api/agent/artifacts/" + tVml},
		{"POST", "/api/agent/upload"},
		{"POST", "/api/agent/screen"},
	}
	tokens := []struct{ what, token string }{
		{"the first Maintainer's token", harnessToken},
		{"an added Maintainer's token", grace.Token},
		{"the builder token", "bld"},
		{"no token", ""},
	}
	for _, tok := range tokens {
		for _, r := range agentRoutes {
			if resp, body := l.as(tok.token, r.method, r.path, nil); resp.StatusCode != 401 || !strings.Contains(body, "unknown device secret") {
				t.Errorf("%s on %s %s: %s %s", tok.what, r.method, r.path, resp.Status, body)
			}
		}
	}
	// the device secret still gets through
	if resp, body := l.as(l.secret, "GET", "/api/agent/artifacts/"+tVml, nil); resp.StatusCode == 401 {
		t.Fatalf("the device secret on an agent route: %s %s", resp.Status, body)
	}
}

func TestBuilderRoutesRefuseMaintainerTokens(t *testing.T) {
	l := newLab(t, false)
	grace := l.addMaintainer(harnessToken, "grace")
	for _, tok := range []string{harnessToken, grace.Token} {
		// not the long-polling /api/builder/poll: a wrongly accepted token
		// would hold the test up there instead of failing it
		if resp, body := l.as(tok, "POST", "/api/builder/artifacts", nil); resp.StatusCode != 401 || !strings.Contains(body, "bad builder token") {
			t.Errorf("a Maintainer's token on a builder route: %s %s", resp.Status, body)
		}
	}
}

func TestJobRecordsTheSubmittingMaintainer(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	grace := l.addMaintainer(harnessToken, "grace")
	// a client-sent maintainer is ignored: the name comes from the token
	resp, body := l.as(grace.Token, "POST", "/api/jobs", map[string]any{"device": l.name, "baseline": true, "maintainer": "mallory"})
	var j map[string]any
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil || j["maintainer"] != "grace" {
		t.Fatalf("submit as grace: %s %s", resp.Status, body)
	}
	id, _ := j["id"].(string)
	l.expect(l.wait(id, 60*time.Second), api.OutcomePass)
	resp, body = l.as(harnessToken, "GET", "/api/jobs/"+id, nil)
	j = nil
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil || j["maintainer"] != "grace" {
		t.Fatalf("the finished job: %s %s", resp.Status, body)
	}
}

func TestJobLabdQueuesItselfRecordsNoMaintainer(t *testing.T) {
	l := newLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	// through Server.Submit, as labd's own --omt-every refreshes are
	queued := l.run(api.JobSpec{Baseline: true})
	resp, body := l.as(harnessToken, "GET", "/api/jobs/"+queued.ID, nil)
	var j map[string]any
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &j) != nil {
		t.Fatalf("job: %s %s", resp.Status, body)
	}
	if m, ok := j["maintainer"]; ok && m != "" {
		t.Fatalf("a job labd queued itself names a Maintainer: %s", body)
	}
}

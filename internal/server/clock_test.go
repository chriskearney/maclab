package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

func TestLeaseRunsOutOnTheLabClock(t *testing.T) {
	clock := agent.NewFakeClock(time.Now())
	l := newLabWith(t, labConfig{clock: clock})
	if r, body := l.post("/api/devices/sim-mac/lease", api.LeaseRequest{Holder: "connor", TTLSec: 60}); r.StatusCode != 200 {
		t.Fatalf("lease: %s %s", r.Status, body)
	}
	if r, _ := l.post("/api/devices/sim-mac/lease", api.LeaseRequest{Holder: "ada", TTLSec: 60}); r.StatusCode != 409 {
		t.Fatalf("second holder got a held lease: %s", r.Status)
	}
	clock.Advance(61 * time.Second)
	if r, body := l.post("/api/devices/sim-mac/lease", api.LeaseRequest{Holder: "ada", TTLSec: 60}); r.StatusCode != 200 {
		t.Fatalf("lease did not run out on the lab clock: %s %s", r.Status, body)
	}
}

func TestAgentStampsEventsWithTheLabClock(t *testing.T) {
	clock := agent.NewFakeClock(time.Now())
	l := newLabWith(t, labConfig{clock: clock})
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	clock.Advance(48 * time.Hour) // a wall-clock stamp would now fall outside labd's last 24 hours
	l.sim.Sleep()
	want := clock.Now()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var d struct {
			Events []api.KernelEvent `json:"recent_events"`
		}
		_, body := l.get("GET", "/api/devices/sim-mac")
		json.Unmarshal([]byte(body), &d)
		for _, e := range d.Events {
			if e.Line == "going to sleep" {
				if !e.Time.Equal(want) {
					t.Fatalf("event stamped %s, want the lab clock's %s", e.Time, want)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sleep event on the lab clock: %s", body)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

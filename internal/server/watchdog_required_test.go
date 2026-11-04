package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

func TestRequiredWatchdogRejectsOlderAgent(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Facts.AgentVersion = "0.8.0"
	v.mu.Unlock()
	job, code, err := l.s.Submit(api.JobSpec{Device: l.name, Tests: []api.TestSpec{{Name: "preflight", Builtin: "boot-health", RequireWatchdog: true}}})
	if job != nil || code != http.StatusConflict || err == nil || !strings.Contains(err.Error(), "watchdog") {
		t.Fatalf("older agent accepted: job=%v code=%d err=%v", job, code, err)
	}
}

func TestRequiredWatchdogVersionContract(t *testing.T) {
	test := api.TestSpec{Name: "preflight", RequireWatchdog: true}
	for _, tc := range []struct {
		version   string
		required  bool
		wantError bool
	}{
		{"", true, true},
		{"0.8.0", true, true},
		{"0.8.1", true, false},
		{"0.8.1+build", true, false},
		{"0.8.0", false, false},
	} {
		test.RequireWatchdog = tc.required
		d := api.Device{Name: "mac", Facts: api.Facts{AgentVersion: tc.version}}
		if err := validateRequiredWatchdog([]api.TestSpec{test}, d); (err != nil) != tc.wantError {
			t.Errorf("version %q required=%v: %v", tc.version, tc.required, err)
		}
	}
}

func TestRequiredWatchdogStoredJobRejectsOlderAgent(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Facts.AgentVersion = "0.8.0"
	boot := v.d.BootID
	v.mu.Unlock()
	now := time.Now()
	j := &api.Job{ID: "j1104-000000-dead", DeviceID: v.snapshot().ID, State: api.JobQueued, Created: now, Updated: now,
		Spec: api.JobSpec{Device: l.name, Tests: []api.TestSpec{{Name: "preflight", Builtin: "boot-health", RequireWatchdog: true}}}}
	if err := l.s.store.saveJob(j); err != nil {
		t.Fatal(err)
	}
	l.s.runJob(context.Background(), v, j)
	got, err := l.s.store.job(j.ID)
	if err != nil || got.State != api.JobDone || got.Outcome != api.OutcomeInfra {
		t.Fatalf("stored job was not refused: %+v %v", got, err)
	}
	if snap := v.snapshot(); snap.BootID != boot || snap.ActiveJob != "" {
		t.Fatalf("device was touched: boot=%s active=%s", snap.BootID, snap.ActiveJob)
	}
}

package workflow

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

type liveM1Fixture struct {
	d         client.Device
	oob       map[string]any
	calls     []string
	change    func(*liveM1Fixture, string)
	submitted int
}

func (f *liveM1Fixture) Device(_ context.Context, _ string) (*client.Device, error) {
	f.calls = append(f.calls, "device")
	if f.change != nil {
		f.change(f, "device")
	}
	d := f.d
	return &d, nil
}
func (f *liveM1Fixture) OOBStatus(_ context.Context, _ string) (map[string]any, error) {
	f.calls = append(f.calls, "oob")
	if f.change != nil {
		f.change(f, "oob")
	}
	return f.oob, nil
}
func (f *liveM1Fixture) Submit(_ context.Context, s api.JobSpec) (*api.Job, error) {
	f.calls = append(f.calls, "POST")
	f.submitted++
	return &api.Job{ID: "actual-fixture-job", Spec: s}, nil
}
func admissionFixture() (*M1Backend, *liveM1Fixture, api.JobSpec, time.Time) {
	now := time.Now()
	f := &liveM1Fixture{d: client.Device{Device: api.Device{Name: "m1", State: api.StateReady, BootID: "actual-fixture-boot", Kernel: "7.2.11-6-1-ARCH", Cmdline: "ordinary", Facts: api.Facts{Machine: "aarch64", Compatible: []string{"apple,j293", "apple,t8103"}}, Lease: &api.Lease{Holder: "own-holder", Expires: now.Add(time.Hour)}}, Alive: true, Tier: 2}, oob: map[string]any{"controller": "oobd fixture", "status": "connected"}}
	return &M1Backend{Client: f, Now: func() time.Time { return now }}, f, api.JobSpec{Device: "m1", Holder: "own-holder", InstalledManifest: strings.Repeat("a", 64)}, now
}
func TestM1AdmissionFreshReadIsBetweenEveryActualSubmit(t *testing.T) {
	b, f, s, _ := admissionFixture()
	if _, e := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700); e != nil {
		t.Fatal(e)
	}
	if strings.Join(f.calls, ",") != "device,oob,device,POST" {
		t.Fatal(f.calls)
	}
	f.oob["error"] = "No connection detected"
	f.oob["status"] = ""
	if _, e := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700); e == nil {
		t.Fatal("retained earlier healthy state reused")
	}
	if f.submitted != 1 {
		t.Fatal("unhealthy retry submitted")
	}
}
func TestM1AdmissionCurrentDriftNeverPosts(t *testing.T) {
	cases := map[string]func(*liveM1Fixture){"model": func(f *liveM1Fixture) { f.d.Facts.Compatible = []string{"apple,j313"} }, "wrongboot": func(f *liveM1Fixture) { f.d.BootID = "different" }, "tagged": func(f *liveM1Fixture) { f.d.Cmdline = "maclab.job=old" }, "tier": func(f *liveM1Fixture) { f.d.Tier = 1 }, "shortlease": func(f *liveM1Fixture) { f.d.Lease.Expires = time.Now().Add(time.Minute) }, "foreignlease": func(f *liveM1Fixture) { f.d.Lease.Holder = "other" }, "busy": func(f *liveM1Fixture) { f.d.ActiveJob = "running" }, "queued": func(f *liveM1Fixture) { f.d.Queued = 1 }, "wrongkernel": func(f *liveM1Fixture) { f.d.Kernel = "7.2.11-7-1-ARCH" }, "oobempty": func(f *liveM1Fixture) { f.oob["status"] = "" }, "oobwrongroute": func(f *liveM1Fixture) { f.oob["controller"] = "other" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b, f, s, _ := admissionFixture()
			change(f)
			if _, e := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700); e == nil || f.submitted != 0 {
				t.Fatal("unsafe submission", e)
			}
		})
	}
}
func TestM1AdmissionRechecksAfterOOBAndRejectsSlowOrCanceledObservation(t *testing.T) {
	t.Run("drift-during-status", func(t *testing.T) {
		b, f, s, _ := admissionFixture()
		f.change = func(f *liveM1Fixture, k string) {
			if k == "oob" {
				f.d.BootID = "changed-during-status"
			}
		}
		if _, e := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700); e == nil || f.submitted != 0 {
			t.Fatal(e)
		}
	})
	t.Run("slow", func(t *testing.T) {
		b, f, s, now := admissionFixture()
		f.change = func(f *liveM1Fixture, k string) {
			if k == "oob" {
				now = now.Add(21 * time.Second)
			}
		}
		b.Now = func() time.Time { return now }
		if _, e := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700); e == nil || f.submitted != 0 {
			t.Fatal(e)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		b, f, s, _ := admissionFixture()
		ctx, cancel := context.WithCancel(context.Background())
		f.change = func(f *liveM1Fixture, k string) {
			if k == "oob" {
				cancel()
			}
		}
		if _, e := b.SubmitM1(ctx, s, "actual-fixture-boot", 2700); e == nil || f.submitted != 0 {
			t.Fatal(e)
		}
	})
}
func TestM1AdmissionPlanRejectsUngroundedBootOrForeignDevice(t *testing.T) {
	p := Plan{Schema: "maclab.workflow/1", ID: "fixture", Device: "m1", Inputs: raw(map[string]any{"boot": "not-a-live-observation"}), Phases: []Phase{{ID: "spec", Kind: "bind", TimeoutSec: 2, Template: raw(api.JobSpec{Device: "m1"})}, {ID: "submit", Kind: "submit", TimeoutSec: 30, InputPhase: "spec", Mutates: true, Scope: "test", M1Admission: &M1SubmissionAdmission{BootID: Value{From: "inputs", Pointer: "/boot"}, MinimumLeaseSec: 2700}}}}
	if e := p.Validate(); e == nil {
		t.Fatal("input boolean/boot accepted as observation")
	}
	p.Phases[1].M1Admission.BootID = Value{From: "spec", Pointer: "/boot"}
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	p.Device = "m3pro"
	if e := p.Validate(); e == nil {
		t.Fatal("M1 admission applied to another model")
	}
}

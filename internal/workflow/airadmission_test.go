package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

type liveAirFixture struct{ *liveM1Fixture }

func (f *liveAirFixture) Device(ctx context.Context, name string) (*client.Device, error) {
	if name != "m1air" {
		return nil, errors.New("foreign device request")
	}
	return f.liveM1Fixture.Device(ctx, name)
}
func (f *liveAirFixture) OOBStatus(ctx context.Context, name string) (map[string]any, error) {
	if name != "m1air" {
		return nil, errors.New("foreign OOB request")
	}
	return f.liveM1Fixture.OOBStatus(ctx, name)
}
func (f *liveAirFixture) Exec(_ context.Context, name string, a api.ExecArgs) (*api.ExecResult, error) {
	f.calls = append(f.calls, "marker")
	if f.change != nil {
		f.change(f.liveM1Fixture, "marker")
	}
	if name != "m1air" || a.TimeoutSec != 15 || !strings.Contains(a.Command, `"device":"m1air"`) {
		return nil, errors.New("Air fixed probe route/data differs")
	}
	return f.result, f.execErr
}
func airFixture(mode string) (*M1Backend, *liveAirFixture, api.JobSpec, time.Time) {
	b, base, s, now := admissionFixture()
	f := &liveAirFixture{base}
	b.Client = f
	s.Device = "m1air"
	s.RecoveryMode = mode
	s.RecoveryTransaction = "actual-air-transaction"
	f.d.Name = "m1air"
	f.d.Facts.Compatible = []string{"apple,j313", "apple,t8103"}
	f.d.EffectiveRecoveryMode = mode
	f.d.RecoveryTransaction = s.RecoveryTransaction
	f.d.RecoveryHolder = s.Holder
	var v map[string]any
	_ = json.Unmarshal([]byte(f.result.Stdout), &v)
	v["device"] = "m1air"
	v["board"] = "apple,j313"
	r, _ := json.Marshal(v)
	f.result.Stdout = string(r)
	f.d.KnownGood = f.d.Kernel
	f.d.Facts.PreflightOK = true
	f.d.Facts.Watchdog = true
	f.d.Facts.WatchdogArmed = true
	f.d.Facts.PanicTimeout = 10
	return b, f, s, now
}
func TestAirSubmissionActualModeRoutesAndLegacyModel(t *testing.T) {
	for _, mode := range []string{api.RecoveryNetworkOnly, api.RecoverySerialAssisted} {
		for _, legacy := range []bool{false, true} {
			b, f, s, _ := airFixture(mode)
			if legacy {
				f.d.Facts.Compatible = nil
				f.d.Facts.DTModel = "Apple MacBook Air (M1, 2020)"
			}
			if mode == api.RecoveryNetworkOnly {
				f.d.Tier = 1
				f.oob = map[string]any{"error": "stale unrelated route"}
			}
			job, err := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700, strings.Repeat("9", 64))
			if err != nil {
				t.Fatal(mode, legacy, err)
			}
			want := "device,oob,marker,device,POST"
			if mode == api.RecoveryNetworkOnly {
				want = "device,marker,device,POST"
			}
			if strings.Join(f.calls, ",") != want || job.Spec.Device != "m1air" || job.Spec.RecoveryMode != mode || job.Spec.RecoveryTransaction != s.RecoveryTransaction {
				t.Fatal(f.calls, job)
			}
		}
	}
}
func TestAirSubmissionWrongBoardModeTransactionAndMarkersNeverPost(t *testing.T) {
	cases := map[string]func(*liveAirFixture, *api.JobSpec){
		"M1-board": func(f *liveAirFixture, _ *api.JobSpec) { f.d.Facts.Compatible = []string{"apple,j293"} },
		"foreign-model": func(f *liveAirFixture, _ *api.JobSpec) {
			f.d.Facts.Compatible = nil
			f.d.Facts.DTModel = "Apple MacBook Pro (13-inch, M1, 2020)"
		},
		"actual-compatible-overrides-label": func(f *liveAirFixture, _ *api.JobSpec) {
			f.d.Facts.Compatible = []string{"apple,j293"}
			f.d.Facts.DTModel = "Apple MacBook Air (M1, 2020)"
		},
		"wrong-device":        func(f *liveAirFixture, _ *api.JobSpec) { f.d.Name = "m1" },
		"mode-drift":          func(f *liveAirFixture, _ *api.JobSpec) { f.d.EffectiveRecoveryMode = api.RecoverySerialAssisted },
		"transaction-drift":   func(f *liveAirFixture, _ *api.JobSpec) { f.d.RecoveryTransaction = "old" },
		"holder-drift":        func(f *liveAirFixture, _ *api.JobSpec) { f.d.RecoveryHolder = "foreign" },
		"missing-transaction": func(_ *liveAirFixture, s *api.JobSpec) { s.RecoveryTransaction = "" },
		"M1-marker-response": func(f *liveAirFixture, _ *api.JobSpec) {
			f.result = markerResult("actual-fixture-boot", strings.Repeat("9", 64))
		},
		"serial-fallback": func(f *liveAirFixture, _ *api.JobSpec) { f.result.Via = "serial" },
		"marker-present": func(f *liveAirFixture, _ *api.JobSpec) {
			f.result.Stdout = strings.Replace(f.result.Stdout, "true", "false", 1)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b, f, s, _ := airFixture(api.RecoveryNetworkOnly)
			change(f, &s)
			if _, err := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700, strings.Repeat("9", 64)); err == nil || f.submitted != 0 {
				t.Fatal("unsafe Air submission", err)
			}
			for _, call := range f.calls {
				if call == "oob" {
					t.Fatal("network-only touched OOB")
				}
			}
		})
	}
}
func TestAirSubmissionRechecksLiveModeAndFreshnessAfterMarker(t *testing.T) {
	for _, mode := range []string{api.RecoveryNetworkOnly, api.RecoverySerialAssisted} {
		b, f, s, _ := airFixture(mode)
		f.change = func(f *liveM1Fixture, at string) {
			if at == "marker" {
				f.d.RecoveryTransaction = "changed-during-probe"
			}
		}
		if _, err := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700, strings.Repeat("9", 64)); err == nil || f.submitted != 0 {
			t.Fatal("changed transaction admitted")
		}
	}
	b, f, s, now := airFixture(api.RecoveryNetworkOnly)
	b.Now = func() time.Time { return now }
	f.change = func(_ *liveM1Fixture, at string) {
		if at == "marker" {
			now = now.Add(21 * time.Second)
		}
	}
	if _, err := b.SubmitM1(context.Background(), s, "actual-fixture-boot", 2700, strings.Repeat("9", 64)); err == nil || f.submitted != 0 {
		t.Fatal("stale marker observation admitted")
	}
}
func TestAirPlanAcceptsOnlySubmitAndPriorObservedFields(t *testing.T) {
	p := Plan{Schema: "maclab.workflow/1", ID: "air-fixture", Device: "m1air", Inputs: raw(map[string]any{}), Phases: []Phase{{ID: "observed", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"boot": "cpu", "agent": "cpu"})}, {ID: "spec", Kind: "bind", TimeoutSec: 2, Template: raw(api.JobSpec{Device: "m1air"})}, {ID: "submit", Kind: "submit", TimeoutSec: 30, InputPhase: "spec", Mutates: true, Scope: "test", M1Admission: &M1SubmissionAdmission{BootID: Value{From: "observed", Pointer: "/boot"}, AgentSHA256: Value{From: "observed", Pointer: "/agent"}, MinimumLeaseSec: 2700}}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Phases[2].Kind = "bind"
	if err := p.Validate(); err == nil {
		t.Fatal("non-submit admission allowed")
	}
	p.Phases[2].Kind = "submit"
	p.Device = "m3pro"
	if err := p.Validate(); err == nil {
		t.Fatal("unreviewed model allowed")
	}
}

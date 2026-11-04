package server

import (
	"context"
	"fmt"
	"github.com/iconidentify/maclab/internal/api"
	"os"
	"testing"
	"time"
)

func TestReviewMesaUnfinishedSurvivesHistoryWindow(t *testing.T) {
	for _, newer := range []int{299, 300} {
		t.Run(fmt.Sprint(newer), func(t *testing.T) {
			l := newLab(t, false)
			spec := mesaSpec(l)
			old := time.Now().Add(-48 * time.Hour)
			for _, p := range spec.Mesa.Packages {
				if e := os.Chtimes(l.s.artifactPath(p.SHA256), old, old); e != nil {
					t.Fatal(e)
				}
			}
			j := &api.Job{ID: "j-review-old-active", Spec: spec, State: api.JobQueued, Created: old, Updated: old}
			if e := l.s.store.saveJob(j); e != nil {
				t.Fatal(e)
			}
			for i := 0; i < newer; i++ {
				done := &api.Job{ID: fmt.Sprintf("j-review-done-%03d", i), Spec: api.JobSpec{Device: l.name}, State: api.JobDone, Created: time.Now().Add(time.Duration(i) * time.Nanosecond), Updated: time.Now()}
				if e := l.s.store.saveJob(done); e != nil {
					t.Fatal(e)
				}
			}
			l.s.cfg.ArtifactBudget = 1
			l.s.gcArtifacts()
			for _, p := range spec.Mesa.Packages {
				if _, e := os.Stat(l.s.artifactPath(p.SHA256)); e != nil {
					t.Errorf("unfinished split package %s was GCed behind %d newer jobs: %v", p.Name, newer, e)
				}
			}
		})
	}
}
func TestReviewStoredUnsupportedMesaMustNotReboot(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	sr, e := l.sim.Stage(context.Background(), "orphan-review", api.StageArgs{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = l.sim.BootOnce(sr.Entry); e != nil {
		t.Fatal(e)
	}
	if e = l.sim.Reboot(); e != nil {
		t.Fatal(e)
	}
	before := l.waitDevice(func(d api.Device) bool { return d.Health.JobTag == "orphan-review" })
	j := &api.Job{ID: "j-review-stored-mesa", Spec: mesaSpec(l), DeviceID: l.s.dev(l.name).snapshot().ID, State: api.JobQueued, Created: time.Now(), Updated: time.Now()}
	// Staged execution is implemented now; official mode remains explicitly gated.
	j.Spec.Mesa.OfficialGPU = true
	if e = l.s.store.saveJob(j); e != nil {
		t.Fatal(e)
	}
	l.s.dev(l.name).queue <- j.ID
	done := l.wait(j.ID, 15*time.Second)
	if done.Outcome != api.OutcomeInfra {
		t.Fatalf("wrong rejection: %+v", done)
	}
	after := l.s.dev(l.name).snapshot()
	if after.BootID != before.BootID {
		t.Fatalf("unsupported stored Mesa job rebooted before refusal: before=%s after=%s summary=%s", before.BootID, after.BootID, done.Summary)
	}
}
func TestReviewMesaCoherentIdentityNotYetAdmitted(t *testing.T) {
	l := newLab(t, false)
	d := api.Device{Name: "sim", Facts: api.Facts{GUIUser: "user", AgentVersion: mesaMinAgent}}
	s := mesaSpec(l)
	s.Mesa.Packages[1].SHA256 = s.Mesa.Packages[0].SHA256
	if _, e := l.s.validateMesa(s, d); e == nil {
		t.Errorf("same archive is accepted under two different split package names")
	}
	s = mesaSpec(l)
	s.Mesa.Build = "b1234-123456-abcd"
	if _, e := l.s.validateMesa(s, d); e == nil {
		t.Errorf("nonexistent producing build is accepted as package provenance")
	}
}
func TestReviewGCReferenceReadFailureMustNotDelete(t *testing.T) {
	l := newLab(t, false)
	sha := l.artifact("only copy of a package whose references are temporarily unreadable")
	old := time.Now().Add(-48 * time.Hour)
	j := &api.Job{ID: "j-review-active-db-failure", State: api.JobQueued, Created: old, Updated: old, Spec: api.JobSpec{Device: l.name, Mesa: &api.MesaSpec{Mode: api.MesaStaged, Packages: []api.MesaPackage{{Name: "mesa-aurora", SHA256: sha}}}}}
	if e := l.s.store.saveJob(j); e != nil {
		t.Fatal(e)
	}
	l.cancel()
	if e := l.s.store.db.Close(); e != nil {
		t.Fatal(e)
	}
	// The startup GC may have read an empty catalog before this fixture was
	// saved. Let that pass finish while the object is still fresh; only then
	// make it old. The pass under test must read the now-unavailable catalog.
	func() {
		gcMu.Lock()
		defer gcMu.Unlock()
		if err := os.Chtimes(l.s.artifactPath(sha), old, old); err != nil {
			t.Fatal(err)
		}
		l.s.cfg.ArtifactBudget = 1
	}()
	l.s.gcArtifacts()
	if _, e := os.Stat(l.s.artifactPath(sha)); e != nil {
		t.Fatalf("GC deleted content despite failing reference query: %v", e)
	}
}

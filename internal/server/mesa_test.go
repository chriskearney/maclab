package server

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

func mesaSpec(l *lab) api.JobSpec {
	return api.JobSpec{Device: l.name, Mesa: &api.MesaSpec{Mode: api.MesaStaged, Packages: []api.MesaPackage{
		{Name: "mesa-aurora", SHA256: l.artifact("mesa-aurora package bytes")},
		{Name: "vulkan-aurora", SHA256: l.artifact("vulkan-aurora package bytes")},
	}}}
}

func TestMesaValidation(t *testing.T) {
	l := newLab(t, false)
	able := api.Device{Name: "mac", Facts: api.Facts{GUIUser: "user", AgentVersion: mesaMinAgent}}
	if code, err := l.s.validateMesa(mesaSpec(l), able); err != nil {
		t.Fatalf("a well-formed staged request is refused: %d %v", code, err)
	}
	missing := strings.Repeat("ab", 32)
	cases := []struct {
		name string
		edit func(*api.JobSpec)
		dev  func(*api.Device)
		code int
		want string
	}{
		{"installed mode", func(s *api.JobSpec) { s.Mesa.Mode = api.MesaInstalled }, nil, 400, "not supported yet"},
		{"unknown mode", func(s *api.JobSpec) { s.Mesa.Mode = "magic" }, nil, 400, "unknown Mesa mode"},
		{"with installed manifest", func(s *api.JobSpec) { s.InstalledManifest = missing }, nil, 400, "drop --installed"},
		{"baseline", func(s *api.JobSpec) { s.Baseline = true }, nil, 400, "baseline"},
		{"crash", func(s *api.JobSpec) { s.Crash = "panic" }, nil, 400, "crash"},
		{"publish", func(s *api.JobSpec) { s.Publish = true }, nil, 400, "never published"},
		{"no packages", func(s *api.JobSpec) { s.Mesa.Packages = nil }, nil, 400, "1 to 8"},
		{"too many packages", func(s *api.JobSpec) {
			for i := 0; i < mesaMaxPackages; i++ {
				s.Mesa.Packages = append(s.Mesa.Packages, api.MesaPackage{Name: "mesa-x" + string(rune('a'+i)), SHA256: s.Mesa.Packages[0].SHA256})
			}
		}, nil, 400, "1 to 8"},
		{"not a Mesa package", func(s *api.JobSpec) { s.Mesa.Packages[0].Name = "linux-aurora" }, nil, 400, "not a Mesa split package"},
		{"path in name", func(s *api.JobSpec) { s.Mesa.Packages[0].Name = "mesa-../x" }, nil, 400, "not a Mesa split package"},
		{"pinned twice", func(s *api.JobSpec) { s.Mesa.Packages[1].Name = s.Mesa.Packages[0].Name }, nil, 400, "pinned twice"},
		{"not a sha", func(s *api.JobSpec) { s.Mesa.Packages[0].SHA256 = "mesa-aurora.pkg.tar.zst" }, nil, 400, "artifact sha256"},
		{"not uploaded", func(s *api.JobSpec) { s.Mesa.Packages[0].SHA256 = missing }, nil, 400, "not uploaded"},
		{"bad build id", func(s *api.JobSpec) { s.Mesa.Build = "latest" }, nil, 400, "not a build id"},
		{"no GUI user", nil, func(d *api.Device) { d.Facts.GUIUser = "" }, 409, "no GUI user"},
		{"old agent", nil, func(d *api.Device) { d.Facts.AgentVersion = "0.7.5" }, 409, "need " + mesaMinAgent},
	}
	for _, c := range cases {
		spec, d := mesaSpec(l), able
		if c.edit != nil {
			c.edit(&spec)
		}
		if c.dev != nil {
			c.dev(&d)
		}
		code, err := l.s.validateMesa(spec, d)
		if err == nil || code != c.code || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %d %v, want %d %q", c.name, code, err, c.code, c.want)
		}
	}
	if _, err := l.s.validateMesa(func() api.JobSpec { s := mesaSpec(l); s.Mesa.Build = "b1025-202302-9402"; return s }(), able); err != nil {
		t.Errorf("a real build id is refused: %v", err)
	}
}

// Until an agent implements the staged mode, no Mesa job is ever queued.
func TestMesaRefusedOnCurrentAgents(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	j, code, err := l.s.Submit(mesaSpec(l))
	if err == nil || j != nil || code != 409 || !strings.Contains(err.Error(), "Mesa") {
		t.Fatalf("a Mesa job was accepted or refused for the wrong reason: %v %d %v", j, code, err)
	}
}

// The package artifacts of an unfinished Mesa job survive an over-budget GC;
// once the job is done they are ordinary old artifacts again.
func TestMesaPackagesPinnedWhileUnfinished(t *testing.T) {
	l := newLab(t, false)
	spec := mesaSpec(l)
	old := time.Now().Add(-48 * time.Hour)
	for _, p := range spec.Mesa.Packages {
		os.Chtimes(l.s.artifactPath(p.SHA256), old, old)
	}
	j := &api.Job{ID: "j1026-000000-ab12", Spec: spec, State: api.JobQueued, Created: time.Now(), Updated: time.Now()}
	if err := l.s.store.saveJob(j); err != nil {
		t.Fatal(err)
	}
	budget := l.s.cfg.ArtifactBudget
	l.s.cfg.ArtifactBudget = 1
	defer func() { l.s.cfg.ArtifactBudget = budget }()
	l.s.gcArtifacts()
	for _, p := range spec.Mesa.Packages {
		if _, err := os.Stat(l.s.artifactPath(p.SHA256)); err != nil {
			t.Fatalf("GC removed %s of an unfinished Mesa job: %v", p.Name, err)
		}
	}
	j.State = api.JobDone
	if err := l.s.store.saveJob(j); err != nil {
		t.Fatal(err)
	}
	l.s.gcArtifacts()
	for _, p := range spec.Mesa.Packages {
		if _, err := os.Stat(l.s.artifactPath(p.SHA256)); err == nil {
			t.Fatalf("%s is still pinned after its job finished", p.Name)
		}
	}
}

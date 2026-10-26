package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/mesa"
)

func mesaSpec(l *lab) api.JobSpec {
	// Protocol/simulator fixtures only; real agent staging rehashes actual tools.
	for _, sha := range []string{mesa.GLProbeSHA, mesa.VKProbeSHA} {
		if err := os.WriteFile(l.s.artifactPath(sha), []byte("SIMULATED helper fixture, not an executable or GPU evidence"), 0600); err != nil {
			l.t.Fatal(err)
		}
	}
	return api.JobSpec{Device: l.name, Mesa: &api.MesaSpec{Mode: api.MesaStaged, Packages: []api.MesaPackage{
		{Name: "mesa-aurora", SHA256: l.artifact("mesa-aurora package bytes")},
		{Name: "vulkan-aurora", SHA256: l.artifact("vulkan-aurora package bytes")},
	}}}
}

func TestMesaValidation(t *testing.T) {
	l := newLab(t, false)
	able := api.Device{Name: "mac", Facts: api.Facts{GUIUser: "user", AgentVersion: mesaMinAgent, MesaStaged: true}}
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
		{"omt allowlist", func(s *api.JobSpec) { s.OMTAllow = []string{"hardware.drivers:apple,agx"} }, nil, 400, "waives no check"},
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
	// A named build is provenance, not a label: it must be a finished package
	// build whose files are exactly the pinned packages.
	spec := mesaSpec(l)
	now := time.Now()
	files := []api.BuildFile{{Name: "mesa-aurora-1:26.3.0-1-aarch64.pkg.tar.zst", SHA256: spec.Mesa.Packages[0].SHA256},
		{Name: "vulkan-aurora-1:26.3.0-1-aarch64.pkg.tar.zst", SHA256: spec.Mesa.Packages[1].SHA256}}
	builds := map[string]*api.Build{
		"b1026-000000-0001": {Kind: api.BuildPackage, State: api.BuildDone, Files: files},
		"b1026-000000-0002": {Kind: "", State: api.BuildDone, Files: files},
		"b1026-000000-0003": {Kind: api.BuildPackage, State: api.BuildDone, Files: files[:1]},
		"b1026-000000-0004": {Kind: api.BuildPackage, State: api.BuildRunning, Files: files},
	}
	for id, b := range builds {
		b.ID, b.Created, b.Updated = id, now, now
		if err := l.s.store.saveBuild(b); err != nil {
			t.Fatal(err)
		}
	}
	for id, want := range map[string]string{"b1026-000000-0009": "not a lab build", "b1026-000000-0002": "not a finished package build",
		"b1026-000000-0003": "is not a file of build", "b1026-000000-0004": "not a finished package build"} {
		s := mesaSpec(l)
		s.Mesa.Packages = spec.Mesa.Packages
		s.Mesa.Build = id
		if code, err := l.s.validateMesa(s, able); err == nil || code != 400 || !strings.Contains(err.Error(), want) {
			t.Errorf("build %s: got %d %v, want 400 %q", id, code, err, want)
		}
	}
	spec.Mesa.Build = "b1026-000000-0001"
	if _, err := l.s.validateMesa(spec, able); err != nil {
		t.Errorf("the packages' own finished package build is refused: %v", err)
	}
	// A name that only prefixes the file's package name is not that package,
	// even with the same bytes: mesa is not mesa-aurora, mesa-foo not mesa-foo-bar.
	prefix := map[string]api.BuildFile{
		"mesa":     {Name: "mesa-aurora-1:26.3.0-1-aarch64.pkg.tar.zst", SHA256: spec.Mesa.Packages[0].SHA256},
		"mesa-foo": {Name: "mesa-foo-bar-26.3.0-1-aarch64.pkg.tar.zst", SHA256: spec.Mesa.Packages[0].SHA256},
	}
	i := 5
	for name, f := range prefix {
		id := fmt.Sprintf("b1026-000000-%04d", i)
		i++
		if err := l.s.store.saveBuild(&api.Build{ID: id, Kind: api.BuildPackage, State: api.BuildDone, Files: []api.BuildFile{f}, Created: now, Updated: now}); err != nil {
			t.Fatal(err)
		}
		s := mesaSpec(l)
		s.Mesa.Packages = []api.MesaPackage{{Name: name, SHA256: f.SHA256}}
		s.Mesa.Build = id
		if code, err := l.s.validateMesa(s, able); err == nil || code != 400 || !strings.Contains(err.Error(), "is not a file of build") {
			t.Errorf("%s accepted from %s: %d %v", name, f.Name, code, err)
		}
	}
	for file, want := range map[string]string{"mesa-aurora-1:26.3.0-1-aarch64.pkg.tar.zst": "mesa-aurora", "mesa-26.3.0-1-aarch64.pkg.tar.zst": "mesa",
		"vulkan-asahi-git-1-2-any.pkg.tar.zst": "vulkan-asahi-git", "mesa-1-aarch64.pkg.tar.zst": "", "mesa--1-x.pkg.tar.zst": "", "mesa-1-1-x.tar.zst": ""} {
		if got, ok := pkgFileName(file); got != want || ok != (want != "") {
			t.Errorf("pkgFileName(%q) = %q %v, want %q", file, got, ok, want)
		}
	}
}

// Adapted from the independent review's TestReviewGCReferenceReadFailureMustNotDelete:
// when the reference catalog cannot be read, an over-budget GC deletes nothing.
func TestMesaGCReferenceReadFailureDeletesNothing(t *testing.T) {
	l := newLab(t, false)
	sha := l.artifact("only copy of a package whose references are temporarily unreadable")
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(l.s.artifactPath(sha), old, old)
	j := &api.Job{ID: "j1026-000002-ab12", State: api.JobQueued, Created: old, Updated: old,
		Spec: api.JobSpec{Device: l.name, Mesa: &api.MesaSpec{Mode: api.MesaStaged, Packages: []api.MesaPackage{{Name: "mesa-aurora", SHA256: sha}}}}}
	if err := l.s.store.saveJob(j); err != nil {
		t.Fatal(err)
	}
	l.cancel()
	if err := l.s.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	l.s.cfg.ArtifactBudget = 1
	l.s.gcArtifacts()
	if _, err := os.Stat(l.s.artifactPath(sha)); err != nil {
		t.Fatalf("GC deleted an artifact while its references were unreadable: %v", err)
	}
}

// However many newer jobs exist, an unfinished Mesa job keeps its packages
// through an over-budget GC (the recent-jobs window is not the pin).
func TestMesaPackagesPinnedBeyondRecentWindow(t *testing.T) {
	l := newLab(t, false)
	spec := mesaSpec(l)
	old := time.Now().Add(-48 * time.Hour)
	for _, p := range spec.Mesa.Packages {
		os.Chtimes(l.s.artifactPath(p.SHA256), old, old)
	}
	if err := l.s.store.saveJob(&api.Job{ID: "j1020-000000-0001", Spec: spec, State: api.JobQueued, Created: old, Updated: old}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 301; i++ {
		at := old.Add(time.Duration(i+1) * time.Minute)
		j := &api.Job{ID: fmt.Sprintf("j1021-%06d-ab12", i), Spec: api.JobSpec{Device: l.name}, State: api.JobDone, Created: at, Updated: at}
		if err := l.s.store.saveJob(j); err != nil {
			t.Fatal(err)
		}
	}
	budget := l.s.cfg.ArtifactBudget
	l.s.cfg.ArtifactBudget = 1
	defer func() { l.s.cfg.ArtifactBudget = budget }()
	l.s.gcArtifacts()
	for _, p := range spec.Mesa.Packages {
		if _, err := os.Stat(l.s.artifactPath(p.SHA256)); err != nil {
			t.Fatalf("GC removed %s of an old unfinished Mesa job behind 301 newer jobs: %v", p.Name, err)
		}
	}
}

// A stored Mesa job (one submission would refuse) finishes before anything
// reaches the Mac: no restore of a leftover lab entry, no busy state, no stage.
func TestMesaStoredJobReachesNothing(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Health.JobTag = "j0101-000000-dead" // a leftover lab entry: the normal path would restore first
	v.mu.Unlock()
	now := time.Now()
	blocked := mesaSpec(l)
	blocked.Mesa.Mode = api.MesaInstalled
	j := &api.Job{ID: "j1026-000001-ab12", Spec: blocked, State: api.JobQueued, Created: now, Updated: now,
		Events: []api.JobEvent{{Time: now, Msg: "queued"}}}
	if err := l.s.store.saveJob(j); err != nil {
		t.Fatal(err)
	}
	l.s.runJob(context.Background(), v, j)
	got, err := l.s.store.job(j.ID)
	if err != nil || got.State != api.JobDone || got.Outcome != api.OutcomeInfra {
		t.Fatalf("stored Mesa job: %+v %v", got, err)
	}
	for _, e := range got.Events {
		if strings.Contains(e.Msg, "restoring") || strings.Contains(e.Msg, "staging") || strings.Contains(e.Msg, "lab entry") {
			t.Fatalf("a stored Mesa job reached the Mac: %q", e.Msg)
		}
	}
	snap := v.snapshot()
	if snap.ActiveJob != "" || snap.State == api.StateBusy || snap.Health.JobTag != "j0101-000000-dead" {
		t.Fatalf("the device was touched: active %q state %s tag %q", snap.ActiveJob, snap.State, snap.Health.JobTag)
	}
}

// Until an agent implements the staged mode, no Mesa job is ever queued.
func TestMesaRefusedOnCurrentAgents(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	spec := mesaSpec(l)
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Facts.AgentVersion = "0.7.5"
	v.mu.Unlock()
	j, code, err := l.s.Submit(spec)
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

func TestMesaStagedJobLifecycleIsExplicitlySimulatedPrivateAndNonPromoting(t *testing.T) {
	l := newLab(t, false)
	l.s.cfg.OMT = true
	l.baseline()
	path := l.s.omtBaselinePath(l.name)
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	j := l.run(mesaSpec(l))
	if j.Outcome != api.OutcomePass {
		t.Fatalf("simulated staged lifecycle failed: %s %s events%v", j.Outcome, j.Summary, j.Events)
	}
	m := j.Result.Mesa
	if m == nil || !m.Simulated || m.Mode != api.MesaStaged || m.Verdict != "PASS" || m.Provider["gl"] != "NATIVE_STAGED" || m.Provider["vulkan"] != "NATIVE_STAGED" || !m.CleanupVerified || m.Kernel != j.Result.BootKernel || m.BootID == "" {
		t.Fatalf("missing explicit simulated result: %+v", m)
	}
	if j.Result.OMT != nil && strings.Contains(j.Result.OMT.Reference, "became") {
		t.Fatal("staged job promoted OMT")
	}
	after, e := os.ReadFile(path)
	if e != nil || string(after) != string(before) {
		t.Fatal("Mesa job rewrote installed-desktop reference", e)
	}
	if _, e = l.s.publishOMT(context.Background(), j); e == nil || !strings.Contains(e.Error(), "never published") {
		t.Fatal("Mesa report publication admitted", e)
	}
}
func TestMesaMandatoryProbeAndReservedOverride(t *testing.T) {
	l := newLab(t, false)
	s := mesaSpec(l)
	n := 0
	for _, test := range testsFor(s) {
		if test.Builtin == "mesa-provider" {
			n++
			if test.TimeoutSec < 120 {
				t.Fatal("probe budget missing")
			}
		}
	}
	if n != 1 {
		t.Fatal("mandatory provider omitted/duplicated")
	}
	s.Tests = []api.TestSpec{{Name: "mesa-provider", Builtin: "boot-health"}}
	d := api.Device{Name: "sim", Facts: api.Facts{GUIUser: "user", AgentVersion: mesaMinAgent, MesaStaged: true}}
	if _, e := l.s.validateMesa(s, d); e == nil {
		t.Fatal("overrode reserved probe")
	}
}
func TestMesaEvidenceCannotSalvageMissingIdentityOrCleanup(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	v := l.s.dev(l.name)
	d := v.snapshot()
	spec := mesaSpec(l)
	r := &jobRun{s: l.s, v: v, j: &api.Job{ID: "j1026-010203-abcd", Spec: spec}, bootID: d.BootID, mesaManifest: strings.Repeat("a", 64)}
	valid := func() *api.TestResult {
		return &api.TestResult{Name: "mesa-provider", Passed: true, Mesa: &api.MesaResult{Mode: api.MesaStaged, Job: r.j.ID, BootID: d.BootID, Kernel: d.Kernel, ManifestSHA256: r.mesaManifest, CleanupVerified: true, Provider: map[string]string{"gl": "NATIVE_STAGED", "vulkan": "NATIVE_STAGED"}, Verdict: "PASS", Packages: append([]api.MesaPackage{}, spec.Mesa.Packages...)}}
	}
	if e := r.acceptMesa(valid()); e != "" {
		t.Fatal(e)
	}
	for _, which := range []string{"missing", "boot", "manifest", "system-provider", "cleanup", "packages"} {
		tr := valid()
		switch which {
		case "missing":
			tr.Mesa = nil
		case "boot":
			tr.Mesa.BootID = "foreign"
		case "manifest":
			tr.Mesa.ManifestSHA256 = strings.Repeat("b", 64)
		case "system-provider":
			tr.Mesa.Provider["vulkan"] = "SYSTEM_PROVIDER"
		case "cleanup":
			tr.Mesa.CleanupVerified = false
		case "packages":
			tr.Mesa.Packages[0].SHA256 = strings.Repeat("c", 64)
		}
		if e := r.acceptMesa(tr); e == "" {
			t.Fatal("accepted invalid evidence", which)
		}
	}
}

package server

import (
	"encoding/json"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// skipsOnScreenChecks is whether the omarchy-m-test spec of a job tells the
// Mac to leave out the checks that need the screen visible. It reads the spec
// as JSON ("skip_on_screen") so the test compiles before the field exists.
func skipsOnScreenChecks(t *testing.T, j *api.Job) bool {
	t.Helper()
	for _, ts := range j.Spec.Tests {
		if ts.Builtin != "omarchy-m-test" {
			continue
		}
		b, _ := json.Marshal(ts)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		v, _ := m["skip_on_screen"].(bool)
		return v
	}
	t.Fatalf("job %s ran no omarchy-m-test: %+v", j.ID, j.Spec.Tests)
	return false
}

func omtLab(t *testing.T, volunteer bool) *lab {
	l := newLabWith(t, labConfig{volunteer: volunteer, config: func(c *Config) { c.OMT = true }})
	if volunteer {
		l.openForTheLab(l.s.now())
	}
	return l
}

func TestVolunteerMacsOmarchyMTestRunLeavesOutOnScreenChecks(t *testing.T) {
	l := omtLab(t, true)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-rc1 behavior=ok")})
	l.expect(j, api.OutcomePass)
	if !skipsOnScreenChecks(t, j) {
		t.Errorf("a Volunteer Mac's test run still asks for on-screen checks: %+v", j.Spec.Tests)
	}
}

func TestVolunteerMacsReferenceLeavesOutOnScreenChecks(t *testing.T) {
	l := omtLab(t, true)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	j := l.run(api.JobSpec{Baseline: true})
	l.expect(j, api.OutcomePass)
	if !skipsOnScreenChecks(t, j) {
		t.Errorf("a Volunteer Mac's baseline (the reference) still asks for on-screen checks: %+v", j.Spec.Tests)
	}
}

func TestLabOwnedMacsOmarchyMTestRunKeepsOnScreenChecks(t *testing.T) {
	l := omtLab(t, false)
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-rc1 behavior=ok")})
	l.expect(j, api.OutcomePass)
	if skipsOnScreenChecks(t, j) {
		t.Errorf("a Lab-owned Mac's run left out on-screen checks: %+v", j.Spec.Tests)
	}
}

func TestLabOwnedMacsReferenceKeepsOnScreenChecks(t *testing.T) {
	l := omtLab(t, false)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	j := l.run(api.JobSpec{Baseline: true})
	l.expect(j, api.OutcomePass)
	if skipsOnScreenChecks(t, j) {
		t.Errorf("a Lab-owned Mac's baseline left out on-screen checks: %+v", j.Spec.Tests)
	}
}

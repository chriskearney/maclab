package server

import (
	"os"
	"slices"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// With two displays active, a job keeps its screenshots under their old
// names and adds one per display, named for its connector.
func TestJobScreenshotsEachDisplay(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	l.sim.Outputs = []string{"eDP-1", "DP-1"}
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-two-displays behavior=ok")})
	l.expect(j, api.OutcomePass)
	for _, f := range []string{"screen/after-boot.jpg", "screen/after-boot-eDP-1.jpg", "screen/after-boot-DP-1.jpg",
		"screen/after-tests.jpg", "screen/after-tests-eDP-1.jpg", "screen/after-tests-DP-1.jpg"} {
		if !slices.Contains(j.Result.Logs, f) {
			t.Errorf("result.logs lacks %s: %v", f, j.Result.Logs)
		}
		if st, err := os.Stat(l.s.jobDir(j.ID) + "/" + f); err != nil || st.Size() == 0 {
			t.Errorf("job file %s: %v", f, err)
		}
	}
}

// With one display, nothing changes: no per-display files.
func TestJobScreenshotOneDisplay(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	l.sim.Outputs = []string{"eDP-1"}
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-one-display behavior=ok")})
	l.expect(j, api.OutcomePass)
	if !slices.Contains(j.Result.Logs, "screen/after-boot.jpg") || slices.Contains(j.Result.Logs, "screen/after-boot-eDP-1.jpg") {
		t.Errorf("result.logs: %v", j.Result.Logs)
	}
}

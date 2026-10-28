package agent

import (
	"slices"
	"strings"
	"testing"
)

// The real Mac's suspend inhibitor blocks sleep and leaves the idle hint
// alone: the Volunteer's idle lock and screensaver keep working during a job.
func TestSuspendInhibitorBlocksSleepButNeverTheIdleLock(t *testing.T) {
	args := inhibitSuspendArgs("maclab job j1 holds the Mac")
	if len(args) == 0 || args[0] != "systemd-inhibit" {
		t.Fatalf("not a systemd-inhibit command: %q", args)
	}
	var what []string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--what="); ok {
			what = append(what, strings.Split(v, ":")...)
		}
	}
	if !slices.Contains(what, "sleep") {
		t.Errorf("the inhibitor does not block sleep: %q", args)
	}
	if slices.Contains(what, "idle") {
		t.Errorf("the inhibitor touches the idle lock and screensaver: %q", args)
	}
	if !slices.Contains(args, "--mode=block") {
		t.Errorf("the inhibitor only delays suspend: %q", args)
	}
}

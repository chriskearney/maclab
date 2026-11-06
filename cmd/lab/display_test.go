package main

import (
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

func TestDisplayFlagsGoToDisplayCheck(t *testing.T) {
	tests := []api.TestSpec{{Name: "gui-smoke", Builtin: "gui-smoke", GUI: true}, {Name: "display-check", Builtin: api.DisplayCheckTest}}
	got, err := withDisplay(tests, "DP-*", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Display != nil || got[1].Display == nil || *got[1].Display != (api.DisplayCheck{Expect: "DP-*", WaitSec: 600}) {
		t.Errorf("display options: %+v %+v", got[0].Display, got[1].Display)
	}
	if got[1].TimeoutSec != 720 {
		t.Errorf("timeout %d, want the wait and 2 minutes to record", got[1].TimeoutSec)
	}
	// A short wait keeps the default timeout.
	if got, _ := withDisplay([]api.TestSpec{{Name: "d", Builtin: api.DisplayCheckTest}}, "any", 0); got[0].TimeoutSec != 0 || got[0].Display.Wait() != 2*time.Minute {
		t.Errorf("default wait: %+v", got[0])
	}
	if got, _ := withDisplay(tests[:1], "", 0); got[0].Display != nil {
		t.Errorf("no flags, but options: %+v", got[0])
	}
	for _, c := range []struct {
		tests  []api.TestSpec
		expect string
		wait   time.Duration
		want   string
	}{
		{tests[:1], "any", 0, "need --test display-check"},
		{[]api.TestSpec{{Name: "d", Builtin: api.DisplayCheckTest}}, "DP 1", 0, "a connector name"},
		{[]api.TestSpec{{Name: "d", Builtin: api.DisplayCheckTest}}, "", 2 * time.Hour, "from 0 to"},
		{[]api.TestSpec{{Name: "d", Builtin: api.DisplayCheckTest, GUI: true}}, "any", 0, "not in the GUI session"},
	} {
		if _, err := withDisplay(c.tests, c.expect, c.wait); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("withDisplay(%q, %s): err = %v, want %q", c.expect, c.wait, err, c.want)
		}
	}
}

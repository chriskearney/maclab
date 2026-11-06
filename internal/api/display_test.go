package api

import (
	"strings"
	"testing"
)

func TestDisplayError(t *testing.T) {
	dc := func(d *DisplayCheck) TestSpec { return TestSpec{Name: "d", Builtin: DisplayCheckTest, Display: d} }
	for _, ok := range []TestSpec{
		{Name: "boot-health", Builtin: "boot-health"},
		dc(nil), dc(&DisplayCheck{}), dc(&DisplayCheck{Expect: "any"}), dc(&DisplayCheck{Expect: "HDMI-A-1", WaitSec: 3600}), dc(&DisplayCheck{Expect: "DP-?"}),
	} {
		if err := ok.DisplayError(); err != nil {
			t.Errorf("%+v: %v", ok.Display, err)
		}
	}
	for _, c := range []struct {
		t    TestSpec
		want string
	}{
		{TestSpec{Name: "x", Builtin: "boot-health", Display: &DisplayCheck{}}, "only with the display-check builtin"},
		{TestSpec{Name: "x", Script: "s", Display: &DisplayCheck{}}, "only with the display-check builtin"},
		{dc(&DisplayCheck{WaitSec: -1}), "from 0 to"},
		{dc(&DisplayCheck{WaitSec: 3601}), "from 0 to"},
		{dc(&DisplayCheck{Expect: "../DP-1"}), "a connector name"},
		{dc(&DisplayCheck{Expect: "DP-[12]"}), "a connector name"},
	} {
		if err := c.t.DisplayError(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: err = %v, want %q", c.t, err, c.want)
		}
	}
}

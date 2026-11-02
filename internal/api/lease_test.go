package api

import "testing"

func TestLeaseWho(t *testing.T) {
	for _, c := range []struct{ holder, by, want string }{
		{"w7C-reload", "josh", "w7C-reload (josh)"},
		{"scott@pancake", "", "scott@pancake"},
		{"chris", "chris", "chris"},
	} {
		if got := (&Lease{Holder: c.holder, By: c.by}).Who(); got != c.want {
			t.Errorf("Who(%q, %q) = %q, want %q", c.holder, c.by, got, c.want)
		}
	}
}

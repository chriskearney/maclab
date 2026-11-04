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

func TestLeaseRecordedByOlderControllerKeepsItsOwner(t *testing.T) {
	lease := &Lease{Holder: "review-worker", By: "ada"}
	if !lease.HeldBy("review-worker", "ada") {
		t.Fatal("recorded owner lost access to its lease")
	}
	if lease.HeldBy("review-worker", "other") {
		t.Fatal("matching holder string bypassed the recorded owner")
	}
	lease.Maintainer = "new-owner"
	if lease.HeldBy("review-worker", "ada") || !lease.HeldBy("review-worker", "new-owner") {
		t.Fatal("explicit ownership must take precedence over legacy attribution")
	}
}

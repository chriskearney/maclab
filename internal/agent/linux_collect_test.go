package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// journalctl on systemd 262 refuses a dashed boot ID; the stand-in does too.
func TestCollectGivesJournalctlTheUndashedBootID(t *testing.T) {
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "journalctl"), []byte(`#!/bin/sh
for a; do case "$a" in ????????-????-????-????-????????????) echo "Failed to add match '$a': Invalid argument"; exit 1 ;; esac; done
echo "journal $*"
`), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := t.TempDir()
	if err := (&Linux{}).Collect(context.Background(), "ce581b0f-c3b1-45dc-99fc-3801e5f8178f", out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"journal.txt", "kernel.txt", "dmesg-errors.txt"} {
		b, _ := os.ReadFile(filepath.Join(out, f))
		if !strings.Contains(string(b), "-b ce581b0fc3b145dc99fc3801e5f8178f") {
			t.Errorf("%s: %s", f, b)
		}
	}
}

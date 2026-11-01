package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	ledger := `{"iter":1,"mode":"none","outcome":"pass","agent":{"fault":"marker"}}
{"iter":2,"mode":"hang_early","outcome":"boot_failed","agent":{"fault":"unsure"}}
`
	if err := os.WriteFile(path, []byte(ledger), 0o644); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := summary(&b, []string{path}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{"none        1      1             1/1", "hang_early  1      1             1/1", "total       2      2             2/2"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	if err := summary(&b, nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("no ledger: %v", err)
	}
}

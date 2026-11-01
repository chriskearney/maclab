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
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		got = append(got, strings.Join(strings.Fields(l), " "))
	}
	want := []string{
		"mode boots as predicted judge class judge exact abstained needs hands",
		"none 1 1 1/1 0/1 0 0",
		"hang_early 1 1 0/1 0/1 1 0",
		"total 2 2 1/2 0/2 1 0",
		"label baseline 2 - 1/2 1/2 1 -",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if err := summary(&b, nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("no ledger: %v", err)
	}
}

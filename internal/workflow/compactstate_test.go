package workflow

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompactCheckpointPreservesEvidenceHashesAndReadsBothFormats(t *testing.T) {
	r := fixture(t, Phase{ID: "evidence", Kind: "bind", TimeoutSec: 1, Template: raw(map[string]any{})})
	lock, s, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	output := []byte(`{"actual_exec":{"stdout":"{\"mtime_ns\":1793026027181000123}\n","via":"agent"},"identity":{"mtime_ns":1793026027181000123},"lines":[{"all":"retained"}]}`)
	canonicalOutput, e := canonical(output)
	if e != nil {
		t.Fatal(e)
	}
	s.Records["evidence"] = &Record{State: "done", Attempt: strings.Repeat("a", 32), Started: time.Now().UTC(), Finished: time.Now().UTC(), Output: canonicalOutput, OutputSHA256: Hash(canonicalOutput)}
	if e = r.save(s); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(r.Dir, "state.json")
	compact, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Count(compact, []byte("\n")) != 1 {
		t.Fatal("checkpoint still contains formatting whitespace")
	}
	lock, reopened, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	if !bytes.Equal(reopened.Records["evidence"].Output, canonicalOutput) || reopened.Records["evidence"].OutputSHA256 != Hash(canonicalOutput) {
		t.Fatal("compact checkpoint lost evidence or integer identity")
	}
	pretty, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if len(pretty) <= len(compact) {
		t.Fatal("fixture lacks nested formatting overhead")
	}
	if e = atomicWrite(p, append(pretty, '\n')); e != nil {
		t.Fatal(e)
	}
	lock, reopened, e = r.Open()
	if e != nil {
		t.Fatal("historical pretty checkpoint no longer readable", e)
	}
	lock.Close()
	if !bytes.Equal(reopened.Records["evidence"].Output, canonicalOutput) {
		t.Fatal("historical evidence changed")
	}
	if e = r.save(reopened); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Blocker = strings.Repeat("E", MaxJSON)
	if e = r.save(reopened); e == nil {
		t.Fatal("compact encoding bypassed hard cap")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("failed compact save replaced durable prior evidence")
	}
	if MaxJSON != 4194304 {
		t.Fatal("content cap changed")
	}
}

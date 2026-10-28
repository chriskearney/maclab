package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBindArchiveRoundTripResumeAndOriginalHashes(t *testing.T) {
	r := fixture(t, Phase{ID: "one", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"mtime_ns": json.Number("1793026027181000123"), "actual_stdout": "all raw evidence\n"})}, Phase{ID: "two", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"actual": nil}), Bind: map[string]Value{"/actual": {"one", ""}}})
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	coldBytes, e := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	var cold State
	if e = Decode(coldBytes, &cold); e != nil {
		t.Fatal(e)
	}
	if len(cold.Records["one"].Output) != 0 || cold.Records["one"].OutputPin == nil {
		t.Fatal("consumed bind not archived")
	}
	if len(cold.Records["two"].Output) == 0 || cold.Records["two"].OutputPin != nil {
		t.Fatal("terminal leaf assertion must remain inline")
	}
	lock, hot, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	for id, rec := range hot.Records {
		if Hash(rec.Output) != rec.OutputSHA256 || !bytes.Contains(rec.Output, []byte("1793026027181000123")) {
			t.Fatal("original canonical identity lost", id)
		}
	}
	if _, e = r.Status(); e != nil {
		t.Fatal(e)
	}
	before := append([]byte(nil), coldBytes...)
	if e = r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("completed resume rewrote records")
	}
}
func archiveFixture(t *testing.T) (*Runner, *State, *Pin) {
	t.Helper()
	r := fixture(t, bindPhase(), Phase{ID: "leaf", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"prior": nil}), Bind: map[string]Value{"/prior": {"binding", ""}}})
	if e := r.Run(context.Background(), "", false); e != nil {
		t.Fatal(e)
	}
	lock, s, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	return r, s, s.Records["binding"].OutputPin
}
func TestBindArchiveCorruptionMissingSymlinkFIFOAndModeRefused(t *testing.T) {
	for _, kind := range []string{"missing", "bytes", "symlink", "fifo", "mode", "path", "size", "hash"} {
		t.Run(kind, func(t *testing.T) {
			r, s, p := archiveFixture(t)
			switch kind {
			case "missing":
				os.Remove(p.Path)
			case "bytes":
				os.WriteFile(p.Path, []byte(`{"forged":true}`), 0600)
			case "symlink":
				os.Remove(p.Path)
				os.Symlink("/dev/null", p.Path)
			case "fifo":
				os.Remove(p.Path)
				if e := syscall.Mkfifo(p.Path, 0600); e != nil {
					t.Fatal(e)
				}
			case "mode":
				os.Chmod(p.Path, 0644)
			default:
				// Keep cold serialization, but alter precisely one retained identity field.
				var cold State
				b, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
				Decode(b, &cold)
				q := cold.Records["binding"].OutputPin
				if kind == "path" {
					q.Path = filepath.Join(t.TempDir(), filepath.Base(q.Path))
				}
				if kind == "size" {
					q.Bytes++
				}
				if kind == "hash" {
					q.SHA256 = strings.Repeat("f", 64)
				}
				b, _ = json.Marshal(cold)
				os.WriteFile(filepath.Join(r.Dir, "state.json"), b, 0600)
			}
			_ = s
			if l, _, e := r.Open(); e == nil {
				l.Close()
				t.Fatal("bad archive admitted")
			}
			if _, e := r.Status(); e == nil {
				t.Fatal("status admitted bad archive")
			}
		})
	}
}
func TestBindArchiveNeverOverwritesForeignDestination(t *testing.T) {
	r := fixture(t, bindPhase(), Phase{ID: "leaf", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"prior": nil}), Bind: map[string]Value{"/prior": {"binding", ""}}})
	lock, s, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	b := raw(map[string]any{"all": "actual"})
	s.Records["binding"] = &Record{State: "done", Attempt: "actual-attempt", Output: b, OutputSHA256: Hash(b), AuthorizationSHA256: strings.Repeat("a", 64), RequestSHA256: strings.Repeat("b", 64)}
	dir, e := r.bindArchiveDir(true)
	if e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(dir, Hash(b)+".json")
	foreign := []byte(`{"foreign":true}`)
	os.WriteFile(dest, foreign, 0600)
	before, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	if e = r.save(s); e == nil {
		t.Fatal("foreign archive adopted")
	}
	after, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(before, after) || !bytes.Equal(got, foreign) {
		t.Fatal("prior state/foreign file overwritten")
	}
}
func TestBindArchiveHelperOutputsStayInlineAndCapUnchanged(t *testing.T) {
	r := fixture(t, bindPhase(), Phase{ID: "wait1", Kind: "wait", InputPhase: "binding", TimeoutSec: 2}, Phase{ID: "wait2", Kind: "wait", InputPhase: "binding", TimeoutSec: 2})
	lock, s, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	big := raw(map[string]string{"evidence": strings.Repeat("x", 2200000)})
	s.Records["wait1"] = &Record{State: "done", Output: big, OutputSHA256: Hash(big)}
	if e = r.save(s); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	var cold State
	Decode(before, &cold)
	if cold.Records["wait1"].OutputPin != nil || !bytes.Equal(cold.Records["wait1"].Output, big) {
		t.Fatal("non-bind output externalized")
	}
	s.Records["wait2"] = &Record{State: "done", Output: big, OutputSHA256: Hash(big)}
	if e = r.save(s); e == nil {
		t.Fatal("inline aggregate cap bypassed")
	}
	after, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	if !bytes.Equal(before, after) || MaxJSON != 4194304 {
		t.Fatal("hard cap or prior state changed")
	}
}
func TestBindArchiveRejectsPinOnNonBindAndUnfinishedOrBothPayloads(t *testing.T) {
	for _, kind := range []string{"non-bind", "unfinished", "both"} {
		t.Run(kind, func(t *testing.T) {
			r, _, _ := archiveFixture(t)
			b, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
			var s State
			Decode(b, &s)
			rec := s.Records["binding"]
			if kind == "non-bind" {
				r.Plan.Phases[0].Kind = "wait"
			}
			if kind == "unfinished" {
				rec.State = "running"
			}
			if kind == "both" {
				rec.Output = raw(map[string]bool{"forged": true})
			}
			b, _ = json.Marshal(s)
			os.WriteFile(filepath.Join(r.Dir, "state.json"), b, 0600)
			if l, _, e := r.Open(); e == nil {
				l.Close()
				t.Fatal("invalid output-pin placement admitted")
			}
		})
	}
}

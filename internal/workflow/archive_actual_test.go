package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Explicit opt-in calibration against a COPY of real local evidence. Never
// executes a helper/backend, changes the original Plan/state, or contacts a Mac.
func TestBindArchiveActualStateCloneAndPendingPureBind(t *testing.T) {
	planPath, statePath := os.Getenv("MACLAB_ARCHIVE_TEST_PLAN"), os.Getenv("MACLAB_ARCHIVE_TEST_STATE")
	if planPath == "" || statePath == "" {
		t.Skip("actual retained evidence calibration is opt-in")
	}
	original, err := readRegular(statePath, MaxJSON)
	if err != nil {
		t.Fatal(err)
	}
	r, err := LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}
	r.Dir = filepath.Join(t.TempDir(), "state")
	if err = os.Mkdir(r.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(r.Dir, "state.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	lock, before, err := r.Open()
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	beforeJSON, _ := json.Marshal(before)
	if err = r.save(before); err != nil {
		t.Fatal(err)
	}
	cold, err := readRegular(filepath.Join(r.Dir, "state.json"), MaxJSON)
	if err != nil {
		t.Fatal(err)
	}
	lock, after, err := r.Open()
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	archived := 0
	for id, want := range before.Records {
		got := after.Records[id]
		if !bytes.Equal(want.Output, got.Output) || want.OutputSHA256 != got.OutputSHA256 {
			t.Fatal("actual retained evidence lost", id)
		}
		a, b := *want, *got
		a.OutputPin = nil
		b.OutputPin = nil
		if !reflect.DeepEqual(a, b) {
			t.Fatal("actual record attempt/auth/request/timing drift", id)
		}
		if got.OutputPin != nil {
			archived++
		}
	}
	if _, err = r.Status(); err != nil {
		t.Fatal(err)
	}
	pending := ""
	pendingBytes := 0
	for _, phase := range r.Plan.Phases {
		if rec := after.Records[phase.ID]; rec != nil && rec.State == "done" {
			continue
		}
		if phase.Kind != "bind" {
			t.Fatal("calibration refuses to execute anything except exact first pending pure bind", phase.ID)
		}
		// execute() is entered ONLY after checking Kind==bind; no Run, helper or API.
		b, e := r.execute(context.Background(), after, phase)
		if e != nil {
			t.Fatal(e)
		}
		pending = phase.ID
		pendingBytes = len(b)
		if e = checks(b, phase.Checks); e != nil {
			t.Fatal(e)
		}
		// This is a synthetic clone record, never a completion claim about the target.
		rec := after.Records[phase.ID]
		if rec == nil {
			rec = &Record{Attempt: "CPU-CLONE-PURE-BIND-ONLY"}
			after.Records[phase.ID] = rec
		}
		rec.State = "done"
		rec.Output = b
		rec.OutputSHA256 = Hash(b)
		if e = r.save(after); e != nil {
			t.Fatal("pending pure bind checkpoint still exceeds bound", e)
		}
		break
	}
	final, err := readRegular(filepath.Join(r.Dir, "state.json"), MaxJSON)
	if err != nil {
		t.Fatal(err)
	}
	rootNow, err := readRegular(statePath, MaxJSON)
	if err != nil || !bytes.Equal(original, rootNow) {
		t.Fatal("original state changed during read-only calibration (or concurrent root progress)")
	}
	if len(cold) >= len(original) || archived == 0 {
		t.Fatal("actual binding duplication not reduced")
	}
	receipt := map[string]any{"schema": "maclab.bind-output-archive-cpu-calibration/1", "actual_state_sha256": Hash(original), "actual_state_bytes": len(original), "plan_sha256": r.PlanSHA, "cold_checkpoint_bytes": len(cold), "after_pending_bind_bytes": len(final), "archived_completed_binds": archived, "pending_bind": pending, "pending_bind_output_bytes": pendingBytes, "original_hydrated_state_sha256": Hash(beforeJSON), "all_original_record_fields_and_output_hashes_equal": true, "original_unchanged": true, "helper_or_backend_executed": false, "target_actions": false}
	if out := os.Getenv("MACLAB_ARCHIVE_TEST_RECEIPT"); out != "" {
		b, _ := json.MarshalIndent(receipt, "", "  ")
		if err = os.WriteFile(out, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("actual clone %d -> %d bytes; %d archived binds; pure %s output=%d final=%d", len(original), len(cold), archived, pending, pendingBytes, len(final))
}

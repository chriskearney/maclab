package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

type sourceReplayBackend struct{ job *api.Job }

func (b *sourceReplayBackend) Upload(_ context.Context, path string) (string, error) {
	data, err := os.ReadFile(path)
	return Hash(data), err
}
func (b *sourceReplayBackend) Submit(_ context.Context, s api.JobSpec) (*api.Job, error) {
	b.job = &api.Job{ID: "j-cpu-explicit-synthetic", Spec: s, State: api.JobDone, Outcome: api.OutcomePass}
	return b.job, nil
}
func (b *sourceReplayBackend) SubmitM1(ctx context.Context, s api.JobSpec, boot string, min int, agent string) (*api.Job, error) {
	if boot == "" || min < 2700 || !shaRE.MatchString(agent) {
		return nil, fmt.Errorf("synthetic admission input invalid")
	}
	return b.Submit(ctx, s)
}
func (b *sourceReplayBackend) Job(_ context.Context, _ string) (*api.Job, error) { return b.job, nil }

// No source helper is executed. Only real Go binding/number handling/checks,
// host artifact cache and exact State serialization run. External lab traffic
// and device actions are replaced by explicitly synthetic typed outputs.
func TestFullM1SuccessGraphRepresentativeCheckpointReplay(t *testing.T) {
	planPath, fixturePath := os.Getenv("M1_REPLAY_PLAN"), os.Getenv("M1_REPLAY_OUTPUTS")
	if planPath == "" || fixturePath == "" {
		t.Skip("explicit private source fixtures required")
	}
	r, err := LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var outputs map[string]json.RawMessage
	if err = uniqueJSON(raw); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &outputs); err != nil {
		t.Fatal(err)
	}
	r.Dir, err = os.MkdirTemp("/dev/shm", "sf-workflow-full-state-replay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(r.Dir) })
	r.Backend = &sourceReplayBackend{}
	now := time.Date(2026, 10, 26, 19, 0, 0, 123456789, time.UTC)
	r.Now = func() time.Time { return now }
	s := &State{Schema: "maclab.workflow-state/1", PlanSHA256: r.PlanSHA, ID: r.Plan.ID, Device: r.Plan.Device, Created: now, Records: map[string]*Record{}}
	type sizeRow struct {
		Phase  string `json:"phase"`
		Output int    `json:"output_bytes"`
		State  int    `json:"checkpoint_bytes"`
	}
	rows := []sizeRow{}
	measureOnly := os.Getenv("M1_REPLAY_MEASURE_ONLY") == "1"
	firstBudgetRefusal := ""
	active := ""
	r.RunHelper = func(_ context.Context, _ Helper, _ []byte, _ string) ([]byte, error) {
		b, ok := outputs[active]
		if !ok {
			return nil, fmt.Errorf("missing synthetic helper output %s", active)
		}
		return b, nil
	}
	for _, p := range r.Plan.Phases {
		if p.Recovery {
			t.Fatal("unexpected recovery branch in success graph")
		}
		active = p.ID
		rec := &Record{State: "running", Attempt: strings.Repeat("a", 32), Started: now, Seconds: 1.23456789}
		if p.Mutates {
			rec.AuthorizationSHA256 = strings.Repeat("b", 64)
		}
		s.Records[p.ID] = rec
		var out []byte
		var e error
		if measureOnly && p.Kind == "helper" {
			input, er := r.value(s, Value{From: p.InputPhase})
			if er != nil {
				t.Fatal(p.ID, er)
			}
			b, _ := json.Marshal(input)
			rec.RequestSHA256 = Hash(b)
			var ok bool
			out, ok = outputs[p.ID]
			if !ok {
				t.Fatal("missing synthetic helper", p.ID)
			}
		} else {
			out, e = r.execute(context.Background(), s, p)
		}
		if e != nil {
			t.Fatalf("%s actual Go execute/binding: %v", p.ID, e)
		}
		if e = checks(out, p.Checks); e != nil {
			t.Fatalf("%s actual Go checks: %v", p.ID, e)
		}
		out, e = canonical(out)
		if e != nil {
			t.Fatal(e)
		}
		rec.Output = out
		rec.OutputSHA256 = Hash(out)
		rec.State = "done"
		rec.Finished = now.Add(time.Second)
		if e = r.save(s); e != nil {
			b, _ := json.MarshalIndent(s, "", "  ")
			if !measureOnly {
				t.Fatalf("%s actual checkpoint %d bytes: %v", p.ID, len(b)+1, e)
			}
			if firstBudgetRefusal == "" {
				firstBudgetRefusal = p.ID
			}
		}
		stateBytes, e := os.ReadFile(filepath.Join(r.Dir, "state.json"))
		if measureOnly {
			stateBytes, e = json.MarshalIndent(s, "", "  ")
			stateBytes = append(stateBytes, '\n')
		}
		if e != nil {
			t.Fatal(e)
		}
		rows = append(rows, sizeRow{p.ID, len(out), len(stateBytes)})
	}
	stateBytes, err := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	if measureOnly {
		stateBytes, err = json.MarshalIndent(s, "", "  ")
		stateBytes = append(stateBytes, '\n')
	}
	compact, _ := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately reserve room for a genuine later diagnostic/failure, while
	// preserving all existing records rather than deleting evidence to fit.
	s.Blocker = "EXPLICIT_CPU_NEGATIVE: " + strings.Repeat("E", 256*1024)
	if err = r.save(s); err != nil {
		if !measureOnly {
			t.Fatalf("256KiB failure headroom absent: success=%d; %v", len(stateBytes), err)
		}
	}
	withFailure, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
	if measureOnly {
		withFailure, _ = json.MarshalIndent(s, "", "  ")
		withFailure = append(withFailure, '\n')
	}
	compactFailure, _ := json.Marshal(s)
	s.Blocker = ""
	reopenChecked := false
	if !measureOnly {
		lock, again, openErr := r.Open()
		if openErr != nil {
			t.Fatal("actual compact checkpoint cannot reopen", openErr)
		}
		defer lock.Close()
		if len(again.Records) != len(s.Records) {
			t.Fatal("record loss on reopen")
		}
		for id, original := range s.Records {
			got := again.Records[id]
			if got == nil || got.OutputSHA256 != original.OutputSHA256 || Hash(got.Output) != original.OutputSHA256 {
				t.Fatal("evidence hash drift after reopen", id)
			}
		}
		for _, phase := range r.Plan.Phases {
			for _, v := range phase.Bind {
				if _, er := r.value(again, v); er != nil {
					t.Fatal("pointer cannot resolve after reopen", phase.ID, er)
				}
			}
		}
		reopenChecked = true
	}
	engineSource, sourceErr := os.ReadFile("workflow.go")
	if sourceErr != nil {
		t.Fatal(sourceErr)
	}
	engineCommit := os.Getenv("M1_REPLAY_ENGINE_COMMIT")
	if len(engineCommit) != 40 {
		t.Fatal("exact reviewed final engine commit required")
	}
	engineBinary := os.Getenv("M1_REPLAY_ENGINE_BINARY")
	binaryBytes, binaryErr := os.ReadFile(engineBinary)
	if binaryErr != nil {
		t.Fatal(binaryErr)
	}
	summary := map[string]any{"schema": "maclab.m1-full-checkpoint-cpu-replay/1", "source_commit": engineCommit, "actual_workflow_go_sha256": Hash(engineSource), "engine_binary": engineBinary, "engine_binary_sha256": Hash(binaryBytes), "actual_open_hash_and_pointer_roundtrip": reopenChecked, "plan_path": planPath, "plan_sha256": r.PlanSHA, "fixture_path": fixturePath, "fixture_sha256": Hash(raw), "phases": len(rows), "success_state_bytes": len(stateBytes), "with_256k_failure_bytes": len(withFailure), "state_limit_bytes": MaxJSON, "compact_state_bytes": len(compact) + 1, "compact_with256k_failure_bytes": len(compactFailure) + 1, "measurement_only": measureOnly, "first_pretty_budget_refusal": firstBudgetRefusal, "checkpoint_qualified": !measureOnly, "synthetic_helper_and_lab_outputs": true, "real_go_bind_check_save": true, "physical_evidence": false, "runtime_qualified": false, "failure_recovery_qualified": false, "rows": rows}
	receipt, _ := json.MarshalIndent(summary, "", "  ")
	dir := os.Getenv("M1_REPLAY_RESULT_DIR")
	if dir == "" {
		dir = r.Dir
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"REPLAY.json": append(receipt, '\n'), "STATE.SYNTHETIC.json": stateBytes, "STATE-WITH-FAILURE.SYNTHETIC.json": withFailure} {
		if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("all %d actual Go phase bindings/checks; %dB checkpoint, %dB with256KiBfailure; physical=false", len(rows), len(stateBytes), len(withFailure))
}

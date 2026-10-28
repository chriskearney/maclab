package workflow

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func refreshFixture(t *testing.T, kind string, mutates bool) (*Runner, Reconciliation, string, string) {
	t.Helper()
	r := fixture(t, Phase{ID: "observe", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{})}, Phase{ID: "middle", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"value": nil}), Bind: map[string]Value{"/value": {"observe", ""}}}, Phase{ID: "leaf", Kind: "bind", TimeoutSec: 2, Template: raw(map[string]any{"value": nil}), Bind: map[string]Value{"/value": {"middle", ""}}})
	r.Plan.Phases[0].Kind = kind
	r.Plan.Phases[0].Mutates = mutates
	r.Plan.Phases[0].Checks = []Check{{Pointer: "/status", Equals: raw("OK")}}
	r.PlanSHA = Hash(raw(r.Plan))
	lock, s, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	old := raw(map[string]any{"status": "OK", "observation": "old", "observed_utc": "old actual timestamp"})
	s.Records["observe"] = &Record{State: "done", Attempt: strings.Repeat("a", 32), RequestSHA256: strings.Repeat("b", 64), AuthorizationSHA256: strings.Repeat("c", 64), Output: old, OutputSHA256: Hash(old)}
	s.Blocker = "middle: failed pure binding remains pending"
	if e = r.save(s); e != nil {
		t.Fatal(e)
	}
	output := pinFile(t, filepath.Join(filepath.Dir(r.Dir), "fresh-observation.json"), []byte(`{"status":"OK","observation":"actual new bytes","mtime_ns":1793026027181000123}`))
	evidence := pinFile(t, filepath.Join(filepath.Dir(r.Dir), "root-reviewed-refresh-evidence.json"), []byte(`{"root_review":"CPU fixture only"}`))
	proof := Reconciliation{Schema: "maclab.workflow-reconciliation/1", PlanSHA256: r.PlanSHA, Device: r.Plan.Device, Phase: "observe", Attempt: strings.Repeat("a", 32), RequestSHA256: strings.Repeat("b", 64), ReviewedBy: "CPU root review", Decision: "refresh-observation", Evidence: evidence, Output: &output}
	path := filepath.Join(filepath.Dir(r.Dir), "refresh-receipt.json")
	b := raw(proof)
	os.WriteFile(path, b, 0600)
	return r, proof, path, Hash(b)
}
func rewriteRefresh(t *testing.T, path string, proof Reconciliation) string {
	t.Helper()
	b := raw(proof)
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	return Hash(b)
}
func TestRefreshReadonlyObservationRetainsFullHistoryAndOriginalFailure(t *testing.T) {
	r, p, path, hash := refreshFixture(t, "helper", false)
	lock, before, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	original := *before.Records["observe"]
	originalRaw, _ := json.Marshal(&original)
	if e = r.Reconcile(path, hash); e != nil {
		t.Fatal(e)
	}
	lock, after, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	got := after.Records["observe"]
	if got.Attempt != hash[:32] || got.Attempt == p.Attempt || got.RequestSHA256 != original.RequestSHA256 || got.AuthorizationSHA256 != original.AuthorizationSHA256 || got.OutputSHA256 != Hash(got.Output) || !bytes.Contains(got.Output, []byte("1793026027181000123")) {
		t.Fatal("new observation identity/evidence not retained")
	}
	if after.Blocker != before.Blocker {
		t.Fatal("refresh erased unrelated pending failure")
	}
	stem := "observe-" + p.Attempt + "-" + hash
	old, _ := os.ReadFile(filepath.Join(r.Dir, "observation-before-"+stem+".json"))
	receipt, _ := os.ReadFile(filepath.Join(r.Dir, "observation-refresh-"+stem+".json"))
	expectedReceipt, _ := os.ReadFile(path)
	if !bytes.Equal(old, originalRaw) || !bytes.Equal(receipt, expectedReceipt) {
		t.Fatal("exact previous record or receipt missing")
	}
	if e = r.Reconcile(path, hash); e == nil {
		t.Fatal("same old attempt could be refreshed twice")
	}
}
func TestRefreshRefusesCompletedDirectOrTransitiveConsumers(t *testing.T) {
	for _, id := range []string{"middle", "leaf"} {
		t.Run(id, func(t *testing.T) {
			r, _, path, hash := refreshFixture(t, "helper", false)
			lock, s, e := r.Open()
			if e != nil {
				t.Fatal(e)
			}
			lock.Close()
			b := raw(map[string]bool{"actual": true})
			s.Records[id] = &Record{State: "done", Output: b, OutputSHA256: Hash(b)}
			if e = r.save(s); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
			if e = r.Reconcile(path, hash); e == nil {
				t.Fatal("already consumed evidence was refreshed")
			}
			after, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed state")
			}
		})
	}
}
func TestRefreshRefusesMutatingNonHelperAndWrongAttemptRequest(t *testing.T) {
	for _, kind := range []string{"mutating", "bind", "attempt", "request", "checks", "missing-output"} {
		t.Run(kind, func(t *testing.T) {
			typ := "helper"
			if kind == "bind" {
				typ = "bind"
			}
			r, p, path, hash := refreshFixture(t, typ, kind == "mutating")
			if kind == "attempt" {
				p.Attempt = strings.Repeat("f", 32)
				hash = rewriteRefresh(t, path, p)
			}
			if kind == "request" {
				p.RequestSHA256 = strings.Repeat("f", 64)
				hash = rewriteRefresh(t, path, p)
			}
			if kind == "checks" {
				q := pinFile(t, filepath.Join(filepath.Dir(r.Dir), "wrong-output.json"), []byte(`{"status":"NOT_OK"}`))
				p.Output = &q
				hash = rewriteRefresh(t, path, p)
			}
			if kind == "missing-output" {
				p.Output = nil
				hash = rewriteRefresh(t, path, p)
			}
			before, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
			if e := r.Reconcile(path, hash); e == nil {
				t.Fatal("unsafe refresh accepted")
			}
			after, _ := os.ReadFile(filepath.Join(r.Dir, "state.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed state")
			}
		})
	}
}
func TestRefreshRefusesAlreadyAttemptedMutatingDownstream(t *testing.T) {
	r, _, path, hash := refreshFixture(t, "helper", false)
	r.Plan.Phases[1].Mutates = true
	lock, s, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
	s.Records["middle"] = &Record{State: "running", Attempt: "owned-uncertain-attempt"}
	if e = r.save(s); e != nil {
		t.Fatal(e)
	}
	if e = r.Reconcile(path, hash); e == nil {
		t.Fatal("refresh underneath uncertain side effects accepted")
	}
}
func TestRefreshExclusiveHistoryForeignAndInterruptedRetry(t *testing.T) {
	for _, foreign := range []bool{true, false} {
		t.Run(map[bool]string{true: "foreign", false: "interrupted"}[foreign], func(t *testing.T) {
			r, p, path, hash := refreshFixture(t, "helper", false)
			lock, s, e := r.Open()
			if e != nil {
				t.Fatal(e)
			}
			lock.Close()
			old, _ := json.Marshal(s.Records["observe"])
			if foreign {
				old = []byte(`{"foreign":true}`)
			}
			hist := filepath.Join(r.Dir, "observation-before-observe-"+p.Attempt+"-"+hash+".json")
			os.WriteFile(hist, old, 0600)
			e = r.Reconcile(path, hash)
			if foreign && e == nil {
				t.Fatal("foreign history overwritten")
			}
			if !foreign && e != nil {
				t.Fatal("exact crash-retained history cannot resume", e)
			}
			actual, _ := os.ReadFile(hist)
			if !bytes.Equal(actual, old) {
				t.Fatal("retained history changed")
			}
		})
	}
}
func TestRefreshUsesTypedInputAndM1AdmissionDependencies(t *testing.T) {
	for _, p := range []Phase{{ID: "submit", InputPhase: "observe"}, {ID: "submit", M1Admission: &M1SubmissionAdmission{BootID: Value{From: "observe"}}}, {ID: "submit", M1Admission: &M1SubmissionAdmission{AgentSHA256: Value{From: "observe"}}}} {
		r := &Runner{Plan: Plan{Phases: []Phase{{ID: "observe"}, p}}}
		s := &State{Records: map[string]*Record{"submit": {State: "done"}}}
		if e := r.checkObservationConsumers(s, "observe"); e == nil {
			t.Fatal("typed consumer dependency missed")
		}
	}
}

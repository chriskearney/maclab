package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/iconidentify/maclab/internal/api"
	"os"
)

// Reconciliation records independently reviewed actual evidence after an
// ambiguous operation. It is not --force, a free boolean, or an automatic retry.
// The retained file is supplied through the existing trusted operator channel.
type Reconciliation struct {
	Schema        string `json:"schema"`
	PlanSHA256    string `json:"plan_sha256"`
	Device        string `json:"device"`
	Phase         string `json:"phase"`
	Attempt       string `json:"attempt"`
	RequestSHA256 string `json:"request_sha256,omitempty"`
	ReviewedBy    string `json:"reviewed_by"`
	Decision      string `json:"decision"` // completed, proven-not-started, failed
	Evidence      Pin    `json:"evidence"`
	Output        *Pin   `json:"output,omitempty"`
}

func (r *Runner) Reconcile(path, expectedSHA string) error {
	if !shaRE.MatchString(expectedSHA) {
		return errors.New("reconciliation requires exact reviewed receipt SHA256")
	}
	b, err := readRegular(path, MaxJSON)
	if err != nil {
		return err
	}
	if Hash(b) != expectedSHA {
		return errors.New("reconciliation receipt drift")
	}
	var proof Reconciliation
	if err = Decode(b, &proof); err != nil {
		return err
	}
	if proof.Schema != "maclab.workflow-reconciliation/1" || proof.PlanSHA256 != r.PlanSHA || proof.Device != r.Plan.Device || proof.ReviewedBy == "" {
		return errors.New("reconciliation identity/reviewer mismatch")
	}
	lock, s, err := r.Open()
	if err != nil {
		return err
	}
	defer lock.Close()
	rec := s.Records[proof.Phase]
	if rec == nil || rec.State == "done" || rec.Attempt != proof.Attempt || rec.RequestSHA256 != proof.RequestSHA256 {
		return errors.New("reconciliation does not bind exact unfinished attempt/request")
	}
	var phase *Phase
	for i := range r.Plan.Phases {
		if r.Plan.Phases[i].ID == proof.Phase {
			phase = &r.Plan.Phases[i]
		}
	}
	if phase == nil {
		return errors.New("unknown phase")
	}
	if err = verifyPin(proof.Evidence); err != nil {
		return err
	}
	// Retain proof and source evidence before changing the state checkpoint.
	if err = atomicWrite(r.Dir+"/reconcile-"+proof.Phase+"-"+rec.Attempt+".json", b); err != nil {
		return err
	}
	switch proof.Decision {
	case "completed":
		if proof.Output == nil {
			return errors.New("completed needs actual bounded output pin")
		}
		if err = verifyPin(*proof.Output); err != nil {
			return err
		}
		out, err := readRegular(proof.Output.Path, MaxJSON)
		if err != nil {
			return err
		}
		if err = checks(out, phase.Checks); err != nil {
			return err
		}
		if phase.Kind == "submit" {
			var actual api.Job
			if err = Decode(out, &actual); err != nil {
				return err
			}
			if actual.ID == "" {
				return errors.New("actual reconciled job ID missing")
			}
			if err = r.checkSubmissionBinding(s, phase.ID, actual.Spec); err != nil {
				return err
			}
		}
		out, err = canonical(out)
		if err != nil {
			return err
		}
		rec.Output = out
		rec.OutputSHA256 = Hash(out)
		rec.State = "done"
		rec.Error = ""
		rec.Finished = r.now()
		rec.Seconds = rec.Finished.Sub(rec.Started).Seconds()
	case "proven-not-started":
		// Preserve original failed/running intent rather than rewriting history.
		archived, _ := json.Marshal(rec)
		if err = atomicWrite(r.Dir+"/attempt-"+proof.Phase+"-"+rec.Attempt+".json", archived); err != nil {
			return err
		}
		delete(s.Records, proof.Phase)
	case "failed":
		rec.State = "failed"
		rec.Error = "independently reconciled failure; explicit recovery required"
	default:
		return errors.New("unsupported reconciliation decision")
	}
	s.Blocker = ""
	return r.save(s)
}
func (r *Runner) Status() ([]byte, error) {
	b, err := readRegular(r.Dir+"/state.json", MaxJSON)
	if err != nil {
		return nil, err
	}
	var decoded State
	if err = Decode(b, &decoded); err != nil {
		return nil, err
	}
	s := &decoded
	if s.PlanSHA256 != r.PlanSHA || s.ID != r.Plan.ID || s.Device != r.Plan.Device || s.Records == nil {
		return nil, errors.New("state/plan identity mismatch")
	}
	for _, rec := range s.Records {
		if rec.State == "done" {
			out, e := canonical(rec.Output)
			if e != nil || Hash(out) != rec.OutputSHA256 {
				return nil, errors.New("status output digest mismatch")
			}
		}
	}
	phases := []map[string]any{}
	pending := ""
	complete := true
	now := r.now()
	for _, p := range r.Plan.Phases {
		row := map[string]any{"phase": p.ID, "kind": p.Kind, "recovery": p.Recovery, "state": "pending", "elapsed_seconds": float64(0)}
		if rec := s.Records[p.ID]; rec != nil {
			row["state"] = rec.State
			row["elapsed_seconds"] = rec.Seconds
			if rec.State == "running" {
				row["elapsed_seconds"] = now.Sub(rec.Started).Seconds()
			}
			if rec.Error != "" {
				row["blocker"] = rec.Error
			}
			row["attempt"] = rec.Attempt
		}
		if !p.Recovery && (s.Records[p.ID] == nil || s.Records[p.ID].State != "done") {
			complete = false
			if pending == "" {
				pending = p.ID
			}
		}
		phases = append(phases, row)
	}
	return json.MarshalIndent(map[string]any{"schema": "maclab.workflow-status/1", "id": s.ID, "device": s.Device, "plan_sha256": s.PlanSHA256, "complete": complete, "next_phase": pending, "blocker": s.Blocker, "elapsed_seconds": now.Sub(s.Created).Seconds(), "phases": phases}, "", "  ")
}

// PublishStatus is local-only; no status notification or group message is sent.
func PublishStatus(w *os.File, b []byte) error { _, err := fmt.Fprintln(w, string(b)); return err }

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// These are the same typed references used by execution; no phase-name policy.
func phaseReferences(p Phase) []string {
	refs := []string{}
	if p.InputPhase != "" {
		refs = append(refs, p.InputPhase)
	}
	for _, v := range p.Bind {
		refs = append(refs, v.From)
	}
	if p.M1Admission != nil {
		refs = append(refs, p.M1Admission.BootID.From, p.M1Admission.AgentSHA256.From)
	}
	return refs
}
func (r *Runner) checkObservationConsumers(s *State, id string) error {
	reached := map[string]bool{id: true}
	for changed := true; changed; {
		changed = false
		for _, p := range r.Plan.Phases {
			if reached[p.ID] {
				continue
			}
			for _, ref := range phaseReferences(p) {
				if reached[ref] {
					reached[p.ID] = true
					changed = true
					break
				}
			}
		}
	}
	for _, p := range r.Plan.Phases {
		if p.ID == id || !reached[p.ID] {
			continue
		}
		if rec := s.Records[p.ID]; rec != nil && (rec.State == "done" || p.Mutates) {
			return fmt.Errorf("observation already consumed by completed or attempted mutating downstream phase: %s", p.ID)
		}
	}
	return nil
}

// Publish history exclusively. A crash before the state update can safely reuse
// byte-identical history; a foreign file is never replaced.
func retainObservationHistory(path string, b []byte) error {
	if len(b) == 0 || len(b) > MaxJSON {
		return errors.New("observation history exceeds bound")
	}
	verify := func() error {
		f, st, e := openRegular(path)
		if e != nil {
			return e
		}
		defer f.Close()
		u, ok := st.Sys().(*syscall.Stat_t)
		if !ok || u.Uid != uint32(os.Geteuid()) || u.Nlink != 1 || st.Mode().Perm() != 0600 {
			return errors.New("foreign observation history ownership/type")
		}
		actual, e := readRegular(path, MaxJSON)
		if e != nil {
			return e
		}
		end, e := f.Stat()
		if e != nil || !same(st, end) {
			return errors.New("history inode drift")
		}
		if e = finalSame(path, st); e != nil {
			return e
		}
		if !bytes.Equal(actual, b) {
			return errors.New("existing observation history differs")
		}
		return nil
	}
	if _, e := os.Lstat(path); e == nil {
		return verify()
	} else if !os.IsNotExist(e) {
		return e
	}
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".observation-*")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	actual, e := readRegular(temp, MaxJSON)
	if e != nil || !bytes.Equal(actual, b) {
		return errors.New("history temporary readback differs")
	}
	if e = os.Link(temp, path); e != nil {
		return e
	}
	if e = os.Remove(temp); e != nil {
		return e
	}
	if e = syncDir(dir); e != nil {
		return e
	}
	return verify()
}
func (r *Runner) refreshObservation(s *State, phase *Phase, rec *Record, proof Reconciliation, receipt []byte) error {
	if rec.State != "done" || phase.Kind != "helper" || phase.Mutates || rec.OutputPin != nil {
		return errors.New("refresh requires one completed non-mutating helper observation")
	}
	if e := r.checkObservationConsumers(s, phase.ID); e != nil {
		return e
	}
	if proof.Output == nil || proof.Output.Bytes <= 0 || proof.Output.Bytes > MaxJSON {
		return errors.New("refresh needs bounded actual new observation output")
	}
	if e := verifyPin(*proof.Output); e != nil {
		return e
	}
	out, e := readRegular(proof.Output.Path, MaxJSON)
	if e != nil {
		return e
	}
	if e = checks(out, phase.Checks); e != nil {
		return e
	}
	out, e = canonical(out)
	if e != nil {
		return e
	}
	receiptHash := Hash(receipt)
	newAttempt := receiptHash[:32]
	if newAttempt == rec.Attempt {
		return errors.New("refreshed observation needs distinct receipt identity")
	}
	oldRecord, e := json.Marshal(rec)
	if e != nil {
		return e
	}
	stem := phase.ID + "-" + rec.Attempt + "-" + receiptHash
	if e = retainObservationHistory(filepath.Join(r.Dir, "observation-before-"+stem+".json"), oldRecord); e != nil {
		return e
	}
	if e = retainObservationHistory(filepath.Join(r.Dir, "observation-refresh-"+stem+".json"), receipt); e != nil {
		return e
	}
	// This is receipt reconciliation, not a replay of the original helper. The
	// original actual call/timing remains in full history, and new actual output
	// remains unchanged. Do not clear a different phase's pending failure.
	now := r.now()
	rec.Attempt = newAttempt
	rec.Started = now
	rec.Finished = now
	rec.Seconds = 0
	rec.Output = out
	rec.OutputSHA256 = Hash(out)
	rec.Error = ""
	return r.save(s)
}

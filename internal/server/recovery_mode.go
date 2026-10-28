package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/oob"
)

func effectiveRecoveryMode(requested, inherited string) string {
	if requested != "" {
		return requested
	}
	if inherited == api.RecoveryNetworkOnly {
		return inherited
	}
	return ""
}
func (v *dev) networkOnlyLocked() bool { return v.d.EffectiveRecoveryMode == api.RecoveryNetworkOnly }
func (v *dev) effectiveOOBLocked() oob.Controller {
	if v.networkOnlyLocked() {
		return nil
	}
	return v.oob
}
func (v *dev) alive() bool { v.mu.Lock(); defer v.mu.Unlock(); return v.aliveLocked() }
func (r *jobRun) networkOnly() bool {
	return r.j.EffectiveRecoveryMode == api.RecoveryNetworkOnly || r.j.Spec.RecoveryMode == api.RecoveryNetworkOnly
}
func (r *jobRun) serialEnabled() bool { return !r.networkOnly() && r.v.snapshot().OOB != nil }

// Controller operations serialize with a policy transition and use cancellable
// contexts. A captured stale controller pointer is never enough to issue a call.
func (v *dev) useOOB(ctx context.Context, fn func(oob.Controller, context.Context) error) error {
	v.oobCallMu.Lock()
	defer v.oobCallMu.Unlock()
	v.mu.Lock()
	ctl := v.effectiveOOBLocked()
	if ctl == nil {
		v.mu.Unlock()
		return errors.New("out-of-band use is unavailable under the current recovery policy")
	}
	op, cancel := context.WithCancel(ctx)
	v.oobCallCancel = cancel
	v.mu.Unlock()
	defer func() { cancel(); v.mu.Lock(); v.oobCallCancel = nil; v.mu.Unlock() }()
	return fn(ctl, op)
}
func (v *dev) armOOB(ctx context.Context, d time.Duration) error {
	return v.useOOB(ctx, func(c oob.Controller, x context.Context) error { return c.Arm(x, d) })
}
func (v *dev) resetOOB(ctx context.Context) error {
	return v.useOOB(ctx, func(c oob.Controller, x context.Context) error { return c.Reset(x) })
}
func (v *dev) statusOOB(ctx context.Context) (string, error) {
	var out string
	e := v.useOOB(ctx, func(c oob.Controller, x context.Context) error { var e error; out, e = c.Status(x); return e })
	return out, e
}
func (v *dev) writeOOB(ctx context.Context, b []byte) error {
	return v.useOOB(ctx, func(c oob.Controller, x context.Context) error { return c.Write(x, b) })
}
func (v *dev) rawOOB(ctx context.Context, w io.Writer) error {
	return v.useOOB(ctx, func(c oob.Controller, x context.Context) error { return c.Raw(x, w) })
}
func (v *dev) execOOB(ctx context.Context, a api.ExecArgs) (api.ExecResult, error) {
	var out api.ExecResult
	e := v.useOOB(ctx, func(c oob.Controller, x context.Context) error { var e error; out, e = serialExec(x, c, a); return e })
	return out, e
}

// This policy survives a failed return and controller restart. An empty legacy
// request inherits a network hold; only explicit validated serial-assisted may
// re-enable a configured route. Nothing clears or rewrites Device.OOB.
func (s *Server) beginJobRecoveryMode(ctx context.Context, v *dev, j *api.Job) error {
	v.recoveryMu.Lock()
	defer v.recoveryMu.Unlock()
	if e := validateRecoveryTransaction(v.snapshot(), j.Spec); e != nil {
		return e
	}
	if e := s.transitionRecoveryMode(ctx, v, j.Spec.RecoveryMode, "", "", j.ID); e != nil {
		return e
	}
	j.EffectiveRecoveryMode = v.snapshot().EffectiveRecoveryMode
	if err := s.store.saveJob(j); err != nil {
		return fmt.Errorf("persist effective job recovery mode: %w", err)
	}
	return nil
}
func validateRecoveryTransaction(d api.Device, spec api.JobSpec) error {
	if spec.RecoveryTransaction != "" && (spec.RecoveryTransaction != d.RecoveryTransaction || spec.Holder != d.RecoveryHolder || spec.RecoveryMode == "" || spec.RecoveryMode != d.EffectiveRecoveryMode) {
		return errors.New("job does not match selected recovery transaction")
	}
	if d.RecoveryTransaction != "" && spec.RecoveryMode != "" && spec.RecoveryTransaction == "" {
		return errors.New("explicit job mode requires selected recovery_transaction")
	}
	return nil
}
func (s *Server) transitionRecoveryMode(ctx context.Context, v *dev, requested, transaction, holder, jobID string) error {
	if !api.ValidRecoveryMode(requested) {
		return errors.New("stored job has invalid recovery_mode")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d := v.snapshot()
	mode := effectiveRecoveryMode(requested, d.EffectiveRecoveryMode)
	if requested == api.RecoverySerialAssisted {
		if d.OOB == nil {
			return errors.New("serial-assisted requested without a configured route")
		}
		ctl, e := s.cfg.OOBFactory(&d)
		if e != nil {
			return e
		}
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		status, e := ctl.Status(probe)
		cancel()
		if e != nil || strings.TrimSpace(status) == "" {
			return fmt.Errorf("explicit serial-assisted route failed fresh status validation")
		}
	}
	v.mu.Lock()
	previous := v.d.EffectiveRecoveryMode
	previousTransaction, previousHolder, previousJob := v.d.RecoveryTransaction, v.d.RecoveryHolder, v.d.RecoveryModeJob
	done := v.oobSerialDone
	v.d.EffectiveRecoveryMode = mode
	if jobID != "" {
		v.d.RecoveryModeJob = jobID
	}
	if transaction != "" {
		v.d.RecoveryTransaction = transaction
		v.d.RecoveryHolder = holder
	}
	if mode == api.RecoveryNetworkOnly && v.oobCallCancel != nil {
		v.oobCallCancel()
	}
	if err := v.s.store.saveDevice(&v.d, v.secretHash); err != nil {
		v.mu.Unlock()
		if mode == api.RecoveryNetworkOnly {
			s.attachOOB(v)
		}
		return fmt.Errorf("persist recovery policy before commands: %w", err)
	}
	v.mu.Unlock()
	if mode == api.RecoveryNetworkOnly || previous == api.RecoveryNetworkOnly {
		s.attachOOB(v)
	}
	if mode == api.RecoveryNetworkOnly {
		if done != nil {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				return errors.New("configured serial stream did not stop; no device command issued")
			}
		}
		drained := make(chan struct{})
		go func() { v.oobCallMu.Lock(); v.oobCallMu.Unlock(); close(drained) }()
		select {
		case <-drained:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return errors.New("prior controller call did not stop; no device command issued")
		}
	}
	return nil
}

var recoveryTransactionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)

func (s *Server) hRecoveryMode(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	var q api.RecoveryModeRequest
	d := json.NewDecoder(io.LimitReader(r.Body, 4097))
	d.DisallowUnknownFields()
	if e := d.Decode(&q); e != nil {
		httpErr(w, 400, "invalid recovery mode request")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		httpErr(w, 400, "extra recovery mode data")
		return
	}
	if q.Mode == "" || !api.ValidRecoveryMode(q.Mode) || q.Holder == "" || !recoveryTransactionID.MatchString(q.Transaction) {
		httpErr(w, 400, "explicit mode, holder and bounded transaction required")
		return
	}
	v.recoveryMu.Lock()
	defer v.recoveryMu.Unlock()
	current := v.snapshot()
	if current.Lease == nil || current.Lease.Holder != q.Holder || time.Until(current.Lease.Expires) < 30*time.Second || current.ActiveJob != "" || len(v.queue) > 0 {
		httpErr(w, 409, "own lease covering transition and idle device required")
		return
	}
	if e := s.transitionRecoveryMode(r.Context(), v, q.Mode, q.Transaction, q.Holder, ""); e != nil {
		httpErr(w, 409, "recovery policy transition failed; inspect current state before retry: %v", e)
		return
	}
	writeJSON(w, api.RecoveryModeSelection{Schema: 1, Device: current.Name, Mode: q.Mode, Holder: q.Holder, Transaction: q.Transaction, Quiescent: true})
}

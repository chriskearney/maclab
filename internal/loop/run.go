package loop

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

// Lab is the part of labd the harness uses; *client.Client is one.
type Lab interface {
	Device(ctx context.Context, name string) (*client.Device, error)
	Lease(ctx context.Context, name, holder string, ttl time.Duration) (*api.Lease, error)
	Release(ctx context.Context, name, holder string) error
	Submit(ctx context.Context, spec api.JobSpec) (*api.Job, error)
	Wait(ctx context.Context, id string, timeout time.Duration) (*api.Job, error)
}

// Night is one run of the loop on one Mac.
type Night struct {
	Lab    Lab
	Judge  Judge // nil: no agent, the ledger records the lab alone
	Ledger Ledger
	Device string
	Holder string
	Kernel string // artifact sha256 of the chaos kernel
	// ChaosCheck is the uploaded sha256 of the chaos-check script test.
	ChaosCheck string
	Boots      []Boot
	Seed       uint64
	// JobTimeout bounds one job, recovery included; ReadyTimeout bounds the
	// wait for the Mac to be ready before a boot.
	JobTimeout, ReadyTimeout time.Duration
	Poll                     time.Duration // how often to look at a Mac that isn't ready
	Logf                     func(format string, args ...any)
}

// Stop says why a night ended early. A night that ran every boot returns nil.
type Stop struct{ Reason string }

func (s *Stop) Error() string { return "stopped: " + s.Reason }

// Run leases the Mac, runs every boot in order, and writes one ledger entry
// per boot. It stops early on the research doc's stop rules: the Mac needs
// hands, two infra errors in a row, a healthy boot that doesn't pass, or the
// Mac not being ready in time.
func (n *Night) Run(ctx context.Context) error {
	logf := n.Logf
	if logf == nil {
		logf = log.Printf
	}
	d, err := n.Lab.Device(ctx, n.Device)
	if err != nil {
		return err
	}
	if d.Volunteer {
		return fmt.Errorf("%s is a Volunteer's Mac: week 1 runs on Lab-owned Macs only", n.Device)
	}
	if _, err := n.Lab.Lease(ctx, n.Device, n.Holder, n.JobTimeout*time.Duration(len(n.Boots)+1)); err != nil {
		return fmt.Errorf("lease %s: %w", n.Device, err)
	}
	defer n.Lab.Release(context.WithoutCancel(ctx), n.Device, n.Holder)

	infra := 0
	for _, b := range n.Boots {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		d, err := n.waitReady(ctx)
		if err != nil {
			return err
		}
		e := n.boot(ctx, b, d)
		if err := n.Ledger.Append(e); err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
		logf("boot %d/%d %-11s %-16s %s", b.Iter, len(n.Boots), b.Mode, orDash(e.Outcome), predictedNote(e))
		switch {
		case e.NeedsHands:
			return &Stop{fmt.Sprintf("%s needs hands after boot %d (%s): the lab says not to retry, so a person goes to it", n.Device, b.Iter, b.Mode)}
		case e.Outcome == api.OutcomeInfra:
			if infra++; infra == 2 {
				return &Stop{"two infra errors in a row: the lab is broken, not the kernel"}
			}
		case b.Mode.Healthy() && e.Outcome != api.OutcomePass:
			return &Stop{fmt.Sprintf("boot %d (%s) broke nothing but ended %s: every later result would be noise", b.Iter, b.Mode, orDash(e.Outcome))}
		default:
			infra = 0
		}
	}
	return nil
}

// waitReady waits for the Mac to be ready for the next boot.
func (n *Night) waitReady(ctx context.Context) (*client.Device, error) {
	deadline := time.Now().Add(n.ReadyTimeout)
	for {
		d, err := n.Lab.Device(ctx, n.Device)
		if err == nil {
			switch d.State {
			case api.StateReady:
				return d, nil
			case api.StateNeedsHands:
				return nil, &Stop{n.Device + " needs hands"}
			case api.StateLeft, api.StateNew:
				return nil, &Stop{fmt.Sprintf("%s is %s", n.Device, d.State)}
			}
		}
		if time.Now().After(deadline) {
			state := "unknown"
			if d != nil {
				state = string(d.State)
			}
			return nil, &Stop{fmt.Sprintf("%s not ready after %s (%s)", n.Device, n.ReadyTimeout, state)}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(n.Poll):
		}
	}
}

func (n *Night) boot(ctx context.Context, b Boot, d *client.Device) Entry {
	serial := d.OOB != nil
	e := Entry{Boot: b, Seed: n.Seed, Started: time.Now().UTC(), Device: n.Device, Tier: d.Tier, Serial: serial,
		Kernel: n.Kernel, Predicted: Predicted(b.Mode, serial)}
	defer func() { e.Seconds = time.Since(e.Started).Seconds() }()

	spec := api.JobSpec{Device: n.Device, Kernel: n.Kernel, Cmdline: b.Cmdline, Holder: n.Holder}
	if n.ChaosCheck != "" {
		spec.Tests = []api.TestSpec{{Name: "chaos-check", Script: n.ChaosCheck}}
	}
	j, err := n.Lab.Submit(ctx, spec)
	if err != nil {
		e.Error = "submit: " + err.Error()
		e.Outcome = api.OutcomeInfra
		return e
	}
	e.Job = j.ID
	deadline := time.Now().Add(n.JobTimeout)
	for j.State != api.JobDone && time.Now().Before(deadline) && ctx.Err() == nil {
		if j, err = n.Lab.Wait(ctx, e.Job, min(time.Until(deadline), 10*time.Minute)); err != nil {
			e.Error = "wait: " + err.Error()
			break
		}
	}
	if j != nil {
		e.Outcome, e.Summary = j.Outcome, j.Summary
		e.FellBack, e.Recovery = j.Result.FellBack, j.Result.Recovery
		if t := slices.IndexFunc(j.Result.Tests, func(t api.TestResult) bool { return t.Name == "chaos-check" }); t >= 0 {
			e.ChaosCheck = "fail"
			if j.Result.Tests[t].Passed {
				e.ChaosCheck = "pass"
			}
		}
		if j.State != api.JobDone && e.Error == "" {
			e.Error = fmt.Sprintf("job still %s after %s", j.State, n.JobTimeout)
		}
	}
	e.AsPredicted = slices.Contains(e.Predicted, e.Outcome)
	if d, err := n.Lab.Device(ctx, n.Device); err == nil {
		e.DeviceState = string(d.State)
		e.NeedsHands = d.State == api.StateNeedsHands
	}
	if n.Judge != nil && e.Job != "" {
		v, err := n.Judge.Judge(ctx, e.Job, n.Device)
		if err != nil {
			e.AgentError = err.Error()
		} else {
			e.Agent = v
			e.Score = &Score{Fault: v.Fault == b.Mode, HumanNeeded: v.HumanNeeded == e.NeedsHands}
		}
		if cj, ok := n.Judge.(CommandJudge); ok {
			for _, t := range cj.Tools {
				e.AgentInputs = append(e.AgentInputs, Input{Tool: t, Taint: "lab-evidence"})
			}
		}
	}
	return e
}

func predictedNote(e Entry) string {
	note := "as predicted"
	if !e.AsPredicted {
		note = fmt.Sprintf("NOT PREDICTED (expected %v)", e.Predicted)
	}
	if e.Score != nil {
		note += fmt.Sprintf("; judge fault %s, human %s", okWord(e.Score.Fault), okWord(e.Score.HumanNeeded))
	} else if e.AgentError != "" {
		note += "; judge failed"
	}
	return note
}

func okWord(b bool) string {
	if b {
		return "right"
	}
	return "WRONG"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// IsStop reports whether err is a stop rule rather than a failure.
func IsStop(err error) bool {
	var s *Stop
	return errors.As(err, &s)
}

package loop

import (
	"encoding/json"
	"os"
	"time"
)

// Entry is one ledger line: one Lab boot, written by the harness, never by
// the agent.
type Entry struct {
	Boot
	Seed      uint64    `json:"seed"`
	Started   time.Time `json:"started"`
	Seconds   float64   `json:"seconds"`
	Device    string    `json:"device"`
	Tier      int       `json:"tier"`
	Serial    bool      `json:"serial"`
	Kernel    string    `json:"kernel_sha256"`
	Job       string    `json:"job,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Predicted []string  `json:"predicted"`
	// AsPredicted is false for a finding worth an issue.
	AsPredicted bool     `json:"as_predicted"`
	FellBack    bool     `json:"fell_back,omitempty"`
	Recovery    []string `json:"recovery,omitempty"`
	// ChaosCheck is the chaos-check test's verdict: the boot ran this kernel
	// (and, for a marker boot, the result belongs to this boot). Empty when
	// the test never ran.
	ChaosCheck  string `json:"chaos_check,omitempty"`
	NeedsHands  bool   `json:"needs_hands"`
	DeviceState string `json:"device_state,omitempty"`
	// HumanMinutes is filled in by hand the next morning: any non-zero value
	// is a failed night.
	HumanMinutes int      `json:"human_minutes"`
	Agent        *Verdict `json:"agent,omitempty"`
	AgentError   string   `json:"agent_error,omitempty"`
	// AgentInputs is the seed of the taint ledger: what the judge could read.
	// Every input in week 1 is lab evidence, which is clean.
	AgentInputs []Input `json:"agent_inputs,omitempty"`
	Score       *Score  `json:"score,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// Input is one source an agent read, with its taint class: "lab-evidence"
// (clean) or "vendor" (code written after it can't go upstream).
type Input struct {
	Tool  string `json:"tool"`
	Taint string `json:"taint"`
}

// Score compares the judge with what was injected and what happened.
type Score struct {
	Fault       bool `json:"fault"`
	HumanNeeded bool `json:"human_needed"`
}

// Ledger appends entries to a JSON Lines file, one synced line per boot, so
// a night cut short keeps every boot it finished.
type Ledger struct{ Path string }

func (l Ledger) Append(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

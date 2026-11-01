package loop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Verdict is what the judge says a finished job shows. It is never told what
// was injected.
type Verdict struct {
	Fault            Mode     `json:"fault"` // one of Modes, or "unsure"
	LabOutcomeAgrees bool     `json:"lab_outcome_agrees"`
	HumanNeeded      bool     `json:"human_needed"`
	Evidence         []string `json:"evidence,omitempty"`
	Surprise         string   `json:"surprise,omitempty"`
	Tokens           int      `json:"tokens,omitempty"`
	CostUSD          float64  `json:"cost_usd,omitempty"`
}

// A Judge reads a finished job and says what happened.
type Judge interface {
	Judge(ctx context.Context, job, device string) (*Verdict, error)
}

// CommandJudge runs a shell command with MACLAB_JOB and MACLAB_DEVICE set and
// reads a Verdict from its output: the whole output as JSON, or else the
// last {...} in it. scripts/loop-judge.sh is the one for Claude Code with
// read-only lab tools.
type CommandJudge struct {
	Command string
	Timeout time.Duration
	// Tools lists what the command lets the agent read, for the ledger.
	Tools []string
}

func (j CommandJudge) Judge(ctx context.Context, job, device string) (*Verdict, error) {
	if j.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, j.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", j.Command)
	cmd.Env = append(os.Environ(), "MACLAB_JOB="+job, "MACLAB_DEVICE="+device)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("judge: %v: %s", err, lastLine(stderr.String()))
	}
	return parseVerdict(out.Bytes())
}

func parseVerdict(out []byte) (*Verdict, error) {
	var v Verdict
	s := strings.TrimSpace(string(out))
	if err := json.Unmarshal([]byte(s), &v); err == nil && v.Fault != "" {
		return &v, nil
	}
	end := strings.LastIndexByte(s, '}')
	for start := strings.LastIndexByte(s[:max(end, 0)], '{'); start >= 0 && end > start; start = strings.LastIndexByte(s[:start], '{') {
		v = Verdict{}
		if err := json.Unmarshal([]byte(s[start:end+1]), &v); err == nil && v.Fault != "" {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("judge: no verdict JSON in its output: %q", lastLine(s))
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

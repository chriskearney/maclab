package loop

import (
	"slices"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// A Class is the set of modes the evidence on a Mac can tell apart from the
// others, and no finer. The judge is scored on the class, since asking it to
// split modes that leave the same evidence scores the design, not the judge.
type Class string

const (
	// ClassHealthy is none and marker: every boot prints a code and a marker,
	// so a healthy boot looks the same whichever it was.
	ClassHealthy Class = "healthy"
	// ClassEarly is a boot that went down before lab-agent reached labd, on a
	// Mac without serial: panic_early, hang_early and hang_late all fall back
	// to the known-good kernel and leave no kernel log of their own.
	ClassEarly Class = "early"
)

// ClassOf is m's class on a Mac with or without a serial console. A mode in
// no shared class is a class of its own. Unsure is in none.
func ClassOf(m Mode, serial bool) Class {
	switch m {
	case None, Marker:
		return ClassHealthy
	case PanicEarly, HangEarly, HangLate:
		if !serial {
			return ClassEarly
		}
	case Unsure:
		return ""
	}
	return Class(m)
}

// JudgeRight is whether a judge's fault reading is right for a boot of
// injected: in the same class. "unsure" is right only for the early class,
// where there is honestly nothing to read, and wrong everywhere else.
func JudgeRight(fault, injected Mode, serial bool) bool {
	c := ClassOf(injected, serial)
	if fault == Unsure {
		return c == ClassEarly
	}
	return ClassOf(fault, serial) == c
}

// ScoreVerdict scores a judge's verdict on a boot.
func ScoreVerdict(v *Verdict, injected Mode, serial, needsHands bool) *Score {
	return &Score{Fault: v.Fault == injected, Class: JudgeRight(v.Fault, injected, serial),
		HumanNeeded: v.HumanNeeded == needsHands}
}

// LabScore is how maclab itself did on a boot, judge aside.
type LabScore struct {
	// AsPredicted: the outcome is one Predicted gives for the mode.
	AsPredicted bool `json:"as_predicted"`
	// NoHands: the Mac came back ready, with nobody touching it.
	NoHands bool `json:"no_hands"`
	// Logs: the lab brought back logs of the boot. For a lost boot that is
	// what lab-agent collected of it afterwards (prevboot/), the only
	// evidence a judge has of a boot without serial.
	Logs bool `json:"logs"`
}

// lostOutcomes end a job whose test kernel went down: what is known of the
// boot is what lab-agent collected after it came back (collectLost).
var lostOutcomes = []string{api.OutcomeBootFailed, api.OutcomeCrashedOrHung, api.OutcomeLostContact,
	api.OutcomePanicked, api.OutcomeHung, api.OutcomeUnknown}

// Lost is whether a finished job's test kernel went down before the job
// ended, so its logs had to come from the next boot.
func Lost(j *api.Job) bool {
	return j.Result.FellBack || slices.Contains(lostOutcomes, j.Outcome)
}

// LogsCollected is whether a finished job holds logs of its boot: for a lost
// boot, prevboot/ files (collect-status.txt, the journal, pstore); otherwise
// any log at all. It reads only the job, with no further lab calls.
func LogsCollected(j *api.Job) bool {
	if !Lost(j) {
		return len(j.Result.Logs) > 0
	}
	return slices.ContainsFunc(j.Result.Logs, func(f string) bool { return strings.HasPrefix(f, "prevboot/") })
}

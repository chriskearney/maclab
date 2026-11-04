package loop

import (
	"slices"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// A Class is the set of modes the evidence on a Mac can't tell apart. The
// judge is scored on the class, since asking it to split modes that leave
// the same evidence scores the design, not the judge.
type Class string

// ClassHealthy is none and marker: every boot prints a code and a marker, so
// a healthy boot looks the same whichever it was.
const ClassHealthy Class = "healthy"

// ClassOf is m's class. Every fault is a class of its own: even the early
// ones, which leave no kernel log without serial, differ in how long the Mac
// takes to come back (a panic=10 reboot, U-Boot's 60 s watchdog,
// watchdog.open_timeout). Unsure is in none.
func ClassOf(m Mode) Class {
	switch m {
	case None, Marker:
		return ClassHealthy
	case Unsure:
		return ""
	}
	return Class(m)
}

// JudgeRight is whether a judge's fault reading is right for a boot of
// injected: in the same class. "unsure" is never right; it is an abstention,
// counted on its own.
func JudgeRight(fault, injected Mode) bool {
	return fault != Unsure && ClassOf(fault) == ClassOf(injected)
}

// ScoreVerdict scores a judge's verdict on a boot.
func ScoreVerdict(v *Verdict, injected Mode, needsHands bool) *Score {
	return &Score{Fault: v.Fault == injected, Class: JudgeRight(v.Fault, injected), Abstained: v.Fault == Unsure,
		HumanNeeded: v.HumanNeeded == needsHands}
}

// LabelFault is what a judge that only repeats maclab's outcome label would
// say: the mode Predicted gives that outcome for, when the modes it is
// predicted for are all one class, and Unsure otherwise (boot_failed fits
// every early fault). It is the baseline the judge has to beat.
func LabelFault(outcome string, serial bool) Mode {
	var class Class
	fault := Unsure
	for _, m := range Modes {
		if !slices.Contains(Predicted(m, serial), outcome) {
			continue
		}
		if class != "" && ClassOf(m) != class {
			return Unsure
		}
		if class == "" {
			class, fault = ClassOf(m), m
		}
	}
	return fault
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

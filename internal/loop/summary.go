package loop

import (
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
)

// Row is one mode's line of a night's summary.
type Row struct {
	Mode        Mode
	Boots       int
	AsPredicted int
	// Judged is the boots the judge gave a verdict on; JudgeRight is the
	// ones it got right by class.
	Judged, JudgeRight int
	NeedsHands         int
}

// Summarize counts a ledger per mode, in Modes order, then a total row with
// Mode "total". It scores with today's rules rather than reading the
// ledger's own scores, so a ledger written before a rule changed reads the
// same as a new one: as predicted is the outcome against Predicted, and the
// judge is scored by class (JudgeRight).
func Summarize(es []Entry) []Row {
	by := map[Mode]*Row{}
	total := Row{Mode: "total"}
	for _, e := range es {
		r := by[e.Mode]
		if r == nil {
			r = &Row{Mode: e.Mode}
			by[e.Mode] = r
		}
		for _, r := range []*Row{r, &total} {
			r.Boots++
			if e.Outcome != "" && slices.Contains(Predicted(e.Mode, e.Serial), e.Outcome) {
				r.AsPredicted++
			}
			if e.Agent != nil {
				r.Judged++
				if JudgeRight(e.Agent.Fault, e.Mode, e.Serial) {
					r.JudgeRight++
				}
			}
			if e.NeedsHands {
				r.NeedsHands++
			}
		}
	}
	var rows []Row
	for _, m := range Modes {
		if r := by[m]; r != nil {
			rows = append(rows, *r)
			delete(by, m)
		}
	}
	for _, r := range by { // a mode this build doesn't know
		rows = append(rows, *r)
	}
	return append(rows, total)
}

// WriteSummary prints Summarize's table.
func WriteSummary(w io.Writer, es []Entry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "mode\tboots\tas predicted\tjudge right (class)\tneeds hands")
	for _, r := range Summarize(es) {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d/%d\t%d\n", r.Mode, r.Boots, r.AsPredicted, r.JudgeRight, r.Judged, r.NeedsHands)
	}
	return tw.Flush()
}

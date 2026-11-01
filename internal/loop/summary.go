package loop

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"text/tabwriter"
)

// Row is one mode's line of a night's summary.
type Row struct {
	Mode        Mode
	Boots       int
	AsPredicted int
	// Judged is the boots the judge gave a verdict on. Of those, JudgeClass
	// it got right by class, JudgeExact named the exact mode, and Abstained
	// it said "unsure" (never right).
	Judged, JudgeClass, JudgeExact, Abstained int
	NeedsHands                                int
}

// BaselineMode names the summary's last row: what a judge that only repeats
// maclab's outcome label (LabelFault) would score on the boots the judge
// judged.
const BaselineMode Mode = "label baseline"

// Summarize counts a ledger per mode, in Modes order (modes this build
// doesn't know after, sorted), then a total row with Mode "total" and a
// BaselineMode row. It scores with today's rules rather than reading the
// ledger's own scores, so a ledger written before a rule changed reads the
// same as a new one: as predicted is the outcome against Predicted, and the
// judge is scored by class (JudgeRight).
func Summarize(es []Entry) []Row {
	by := map[Mode]*Row{}
	total := Row{Mode: "total"}
	base := Row{Mode: BaselineMode}
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
				count(r, e.Agent.Fault, e.Mode)
			}
			if e.NeedsHands {
				r.NeedsHands++
			}
		}
		if e.Agent != nil {
			base.Boots++
			count(&base, LabelFault(e.Outcome, e.Serial), e.Mode)
		}
	}
	var rows []Row
	for _, m := range Modes {
		if r := by[m]; r != nil {
			rows = append(rows, *r)
			delete(by, m)
		}
	}
	for _, m := range slices.Sorted(maps.Keys(by)) { // modes this build doesn't know
		rows = append(rows, *by[m])
	}
	return append(rows, total, base)
}

func count(r *Row, fault, injected Mode) {
	r.Judged++
	if JudgeRight(fault, injected) {
		r.JudgeClass++
	}
	if fault == injected {
		r.JudgeExact++
	}
	if fault == Unsure {
		r.Abstained++
	}
}

// WriteSummary prints Summarize's table. The baseline row has no as
// predicted or needs hands: it only reads labels.
func WriteSummary(w io.Writer, es []Entry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "mode\tboots\tas predicted\tjudge class\tjudge exact\tabstained\tneeds hands")
	for _, r := range Summarize(es) {
		pred, hands := fmt.Sprint(r.AsPredicted), fmt.Sprint(r.NeedsHands)
		if r.Mode == BaselineMode {
			pred, hands = "-", "-"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%d/%d\t%d/%d\t%d\t%s\n", r.Mode, r.Boots, pred,
			r.JudgeClass, r.Judged, r.JudgeExact, r.Judged, r.Abstained, hands)
	}
	return tw.Flush()
}

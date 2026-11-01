package loop

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func TestClassOf(t *testing.T) {
	for m, want := range map[Mode]Class{
		None: ClassHealthy, Marker: ClassHealthy,
		// The early faults come back after different times, so each is its own.
		PanicEarly: Class(PanicEarly), HangEarly: Class(HangEarly), HangLate: Class(HangLate),
		OopsLate: Class(OopsLate), PanicLate: Class(PanicLate), Netdown: Class(Netdown),
		Unsure: "",
	} {
		if got := ClassOf(m); got != want {
			t.Errorf("ClassOf(%s) = %q, want %q", m, got, want)
		}
	}
}

func TestJudgeRight(t *testing.T) {
	for _, c := range []struct {
		fault, injected Mode
		want            bool
	}{
		{Marker, None, true}, // can't be told apart: every boot prints a marker
		{None, Marker, true},
		{Netdown, Netdown, true},
		{HangEarly, PanicEarly, false}, // the time back tells them apart
		{None, HangLate, false},
		{PanicLate, OopsLate, false},
		// unsure is an abstention, never right
		{Unsure, PanicEarly, false}, {Unsure, HangLate, false}, {Unsure, None, false},
	} {
		if got := JudgeRight(c.fault, c.injected); got != c.want {
			t.Errorf("JudgeRight(%s, %s) = %v, want %v", c.fault, c.injected, got, c.want)
		}
	}
}

func TestScoreVerdictKeepsTheExactFault(t *testing.T) {
	s := ScoreVerdict(&Verdict{Fault: Marker}, None, false)
	if s.Fault || !s.Class || s.Abstained || !s.HumanNeeded {
		t.Errorf("%+v", s)
	}
	if s := ScoreVerdict(&Verdict{Fault: None}, None, true); !s.Fault || !s.Class || s.HumanNeeded {
		t.Errorf("a judge that missed needs hands: %+v", s)
	}
	if s := ScoreVerdict(&Verdict{Fault: Unsure}, HangEarly, false); s.Fault || s.Class || !s.Abstained {
		t.Errorf("unsure: %+v", s)
	}
}

func TestLabelFault(t *testing.T) {
	for _, c := range []struct {
		outcome string
		serial  bool
		want    Mode
	}{
		{api.OutcomePass, false, None}, // none and marker: one class
		{api.OutcomeUnhealthy, false, OopsLate},
		{api.OutcomeCrashedOrHung, false, PanicLate},
		{api.OutcomeLostContact, false, Netdown},
		{api.OutcomeBootFailed, false, Unsure}, // fits every early fault
		{api.OutcomePanicked, false, Unsure},   // predicted for nothing without serial
		{api.OutcomePanicked, true, Unsure},    // panic_late and panic_early with serial
		{api.OutcomeInfra, false, Unsure},
	} {
		if got := LabelFault(c.outcome, c.serial); got != c.want {
			t.Errorf("LabelFault(%s, serial %v) = %s, want %s", c.outcome, c.serial, got, c.want)
		}
	}
}

func TestPredictedIsWhatLabdCanProduce(t *testing.T) {
	for _, serial := range []bool{false, true} {
		// The kernel lives through an oops: labd reads it booted_unhealthy.
		if got := Predicted(OopsLate, serial); !slices.Equal(got, []string{api.OutcomeUnhealthy}) {
			t.Errorf("oops_late, serial %v: %v", serial, got)
		}
		for _, m := range []Mode{HangEarly, HangLate} {
			if got := Predicted(m, serial); !slices.Equal(got, []string{api.OutcomeBootFailed}) {
				t.Errorf("%s, serial %v: %v", m, serial, got)
			}
		}
	}
	// Without serial no dying kernel's panic reaches labd.
	for _, m := range Modes {
		if slices.Contains(Predicted(m, false), api.OutcomePanicked) {
			t.Errorf("%s predicts panicked without serial", m)
		}
	}
	if got := Predicted(PanicLate, false); !slices.Equal(got, []string{api.OutcomeCrashedOrHung}) {
		t.Errorf("panic_late without serial: %v", got)
	}
	if got := Predicted(PanicLate, true); !slices.Contains(got, api.OutcomePanicked) {
		t.Errorf("panic_late with serial: %v", got)
	}
	if got := Predicted(PanicEarly, false); !slices.Equal(got, []string{api.OutcomeBootFailed}) {
		t.Errorf("panic_early without serial: %v", got)
	}
}

func TestLogsCollected(t *testing.T) {
	job := func(outcome string, fellBack bool, logs ...string) *api.Job {
		return &api.Job{Outcome: outcome, Result: api.JobResult{FellBack: fellBack, Logs: logs}}
	}
	for _, c := range []struct {
		name string
		j    *api.Job
		lost bool
		want bool
	}{
		{"a pass with boot0", job(api.OutcomePass, false, "boot0/journal.txt"), false, true},
		{"a pass with nothing", job(api.OutcomePass, false), false, false},
		{"a fallback with prevboot", job(api.OutcomeBootFailed, true, "prevboot/collect-status.txt"), true, true},
		{"a crash with only boot0", job(api.OutcomeCrashedOrHung, false, "boot0/journal.txt"), true, false},
		{"lost contact with nothing", job(api.OutcomeLostContact, true), true, false},
		{"fell back but ended infra", job(api.OutcomeInfra, true, "prevboot/journal.txt"), true, true},
	} {
		if got := Lost(c.j); got != c.lost {
			t.Errorf("%s: lost %v, want %v", c.name, got, c.lost)
		}
		if got := LogsCollected(c.j); got != c.want {
			t.Errorf("%s: logs %v, want %v", c.name, got, c.want)
		}
	}
}

// night1 is the shape of the first night's ledger: written before scores had
// classes, with the judge failing to run on the first three boots.
const night1 = `{"iter":1,"mode":"marker","serial":false,"outcome":"pass","as_predicted":true,"agent_error":"judge: exit status 126"}
{"iter":2,"mode":"panic_late","serial":false,"outcome":"crashed_or_hung","as_predicted":true,"agent_error":"judge: exit status 126"}
{"iter":4,"mode":"netdown","serial":false,"outcome":"boot_failed","as_predicted":false,"agent":{"fault":"netdown"},"score":{"fault":true,"human_needed":true}}
{"iter":5,"mode":"oops_late","serial":false,"outcome":"booted_unhealthy","as_predicted":true,"agent":{"fault":"oops_late"},"score":{"fault":true,"human_needed":true}}
{"iter":7,"mode":"panic_early","serial":false,"outcome":"boot_failed","as_predicted":true,"agent":{"fault":"unsure"},"score":{"fault":false,"human_needed":true}}

{"iter":14,"mode":"none","serial":false,"outcome":"pass","as_predicted":true,"agent":{"fault":"marker"},"score":{"fault":false,"human_needed":true}}
{"iter":15,"mode":"none","serial":false,"outcome":"pass","as_predicted":true,"agent":{"fault":"unsure"},"needs_hands":true}
{"iter":20,"mode":"panic_late","serial":false,"outcome":"panicked","as_predicted":true,"agent":{"fault":"panic_late"}}
{"iter":21,"mode":"zz_new","serial":false,"outcome":"pass"}
{"iter":22,"mode":"aa_new","serial":false,"outcome":"pass"}
`

func TestSummarize(t *testing.T) {
	es, err := ReadLedger(strings.NewReader(night1))
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{Mode: None, Boots: 2, AsPredicted: 2, Judged: 2, JudgeClass: 1, JudgeExact: 0, Abstained: 1, NeedsHands: 1},
		{Mode: Marker, Boots: 1, AsPredicted: 1},
		{Mode: OopsLate, Boots: 1, AsPredicted: 1, Judged: 1, JudgeClass: 1, JudgeExact: 1},
		// panicked without serial is rescored against today's prediction.
		{Mode: PanicLate, Boots: 2, AsPredicted: 1, Judged: 1, JudgeClass: 1, JudgeExact: 1},
		{Mode: PanicEarly, Boots: 1, AsPredicted: 1, Judged: 1, Abstained: 1},
		{Mode: Netdown, Boots: 1, AsPredicted: 0, Judged: 1, JudgeClass: 1, JudgeExact: 1},
		// modes this build doesn't know come last, sorted
		{Mode: "aa_new", Boots: 1}, {Mode: "zz_new", Boots: 1},
		{Mode: "total", Boots: 10, AsPredicted: 6, Judged: 6, JudgeClass: 4, JudgeExact: 3, Abstained: 2, NeedsHands: 1},
		// the label alone: pass reads none, booted_unhealthy oops_late;
		// boot_failed and panicked without serial fit no single class
		{Mode: BaselineMode, Boots: 6, Judged: 6, JudgeClass: 3, JudgeExact: 3, Abstained: 3},
	}
	for range 5 { // map order must not leak into the rows
		if rows := Summarize(es); !slices.Equal(rows, want) {
			t.Fatalf("rows:\n%+v\nwant\n%+v", rows, want)
		}
	}
	var b bytes.Buffer
	if err := WriteSummary(&b, es); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != len(want)+1 || !strings.HasPrefix(lines[0], "mode") ||
		strings.Join(strings.Fields(lines[len(lines)-2]), " ") != "total 10 6 4/6 3/6 2 1" ||
		strings.Join(strings.Fields(lines[len(lines)-1]), " ") != "label baseline 6 - 3/6 3/6 3 -" {
		t.Errorf("table:\n%s", b.String())
	}
}

func TestReadLedgerNamesABadLine(t *testing.T) {
	if _, err := ReadLedger(strings.NewReader("{\"iter\":1}\nnot json\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("got %v", err)
	}
}

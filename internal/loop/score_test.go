package loop

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func TestClassOf(t *testing.T) {
	for _, c := range []struct {
		m      Mode
		serial bool
		want   Class
	}{
		{None, false, ClassHealthy}, {Marker, true, ClassHealthy},
		{PanicEarly, false, ClassEarly}, {HangEarly, false, ClassEarly}, {HangLate, false, ClassEarly},
		// A serial console reads an early boot, so each is its own class.
		{PanicEarly, true, Class(PanicEarly)}, {HangEarly, true, Class(HangEarly)}, {HangLate, true, Class(HangLate)},
		{OopsLate, false, Class(OopsLate)}, {PanicLate, false, Class(PanicLate)}, {Netdown, true, Class(Netdown)},
		{Unsure, false, ""},
	} {
		if got := ClassOf(c.m, c.serial); got != c.want {
			t.Errorf("ClassOf(%s, serial %v) = %q, want %q", c.m, c.serial, got, c.want)
		}
	}
}

func TestJudgeRight(t *testing.T) {
	for _, c := range []struct {
		fault, injected Mode
		serial, want    bool
	}{
		{Marker, None, false, true}, // can't be told apart: every boot prints a marker
		{None, Marker, true, true},
		{Unsure, PanicEarly, false, true}, // nothing to read without serial: unsure is honest
		{Unsure, HangLate, false, true},
		{HangEarly, PanicEarly, false, true},
		{HangEarly, PanicEarly, true, false}, // serial tells them apart
		{Unsure, PanicEarly, true, false},
		{Unsure, None, false, false}, // unsure is wrong where there is evidence
		{Unsure, PanicLate, false, false},
		{None, HangLate, false, false},
		{PanicLate, OopsLate, false, false},
		{Netdown, Netdown, false, true},
	} {
		if got := JudgeRight(c.fault, c.injected, c.serial); got != c.want {
			t.Errorf("JudgeRight(%s, %s, serial %v) = %v, want %v", c.fault, c.injected, c.serial, got, c.want)
		}
	}
}

func TestScoreVerdictKeepsTheExactFault(t *testing.T) {
	s := ScoreVerdict(&Verdict{Fault: Marker}, None, false, false)
	if s.Fault || !s.Class || !s.HumanNeeded {
		t.Errorf("%+v", s)
	}
	if s := ScoreVerdict(&Verdict{Fault: None}, None, false, true); !s.Fault || !s.Class || s.HumanNeeded {
		t.Errorf("a judge that missed needs hands: %+v", s)
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
`

func TestSummarize(t *testing.T) {
	es, err := ReadLedger(strings.NewReader(night1))
	if err != nil {
		t.Fatal(err)
	}
	rows := Summarize(es)
	want := []Row{
		{Mode: None, Boots: 2, AsPredicted: 2, Judged: 2, JudgeRight: 1, NeedsHands: 1},
		{Mode: Marker, Boots: 1, AsPredicted: 1},
		{Mode: OopsLate, Boots: 1, AsPredicted: 1, Judged: 1, JudgeRight: 1},
		// panicked without serial is rescored against today's prediction.
		{Mode: PanicLate, Boots: 2, AsPredicted: 1, Judged: 1, JudgeRight: 1},
		{Mode: PanicEarly, Boots: 1, AsPredicted: 1, Judged: 1, JudgeRight: 1},
		{Mode: Netdown, Boots: 1, AsPredicted: 0, Judged: 1, JudgeRight: 1},
		{Mode: "total", Boots: 8, AsPredicted: 6, Judged: 6, JudgeRight: 5, NeedsHands: 1},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows:\n%+v\nwant\n%+v", rows, want)
	}
	var b bytes.Buffer
	if err := WriteSummary(&b, es); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != len(want)+1 || !strings.HasPrefix(lines[0], "mode") ||
		strings.Join(strings.Fields(lines[len(lines)-1]), " ") != "total 8 6 5/6 1" {
		t.Errorf("table:\n%s", b.String())
	}
}

func TestReadLedgerNamesABadLine(t *testing.T) {
	if _, err := ReadLedger(strings.NewReader("{\"iter\":1}\nnot json\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("got %v", err)
	}
}

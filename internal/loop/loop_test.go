package loop

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

func TestScheduleKeepsThePlanAndReplaysFromTheSeed(t *testing.T) {
	a, b := Schedule(Week1, 7), Schedule(Week1, 7)
	if len(a) != 20 {
		t.Fatalf("week 1 is 20 boots, got %d", len(a))
	}
	counts := map[Mode]int{}
	markers := map[string]bool{}
	for i, boot := range a {
		counts[boot.Mode]++
		if boot.Mode != b[i].Mode {
			t.Fatalf("boot %d: %s, then %s from the same seed", i+1, boot.Mode, b[i].Mode)
		}
		if boot.Mode == Marker {
			if markers[boot.Marker] || !strings.Contains(boot.Cmdline, "maclab_chaos.marker="+boot.Marker) {
				t.Errorf("marker boot %d: marker %q, cmdline %q", boot.Iter, boot.Marker, boot.Cmdline)
			}
			markers[boot.Marker] = true
		}
	}
	for m, n := range Week1 {
		if counts[m] != n {
			t.Errorf("%s: %d boots, plan says %d", m, counts[m], n)
		}
	}
	if !a[0].Mode.Healthy() {
		t.Errorf("first boot is %s; a healthy boot goes first", a[0].Mode)
	}
}

func TestParsePlan(t *testing.T) {
	p, err := ParsePlan("none=2, hang_late=1")
	if err != nil || p[None] != 2 || p[HangLate] != 1 {
		t.Fatalf("got %v, %v", p, err)
	}
	for _, bad := range []string{"none", "none=-1", "sleep=2", "none=x"} {
		if _, err := ParsePlan(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// fakeLab ends each job with the outcome outcome() gives its mode, read back
// from the cmdline, and can leave the Mac needing hands after one.
type fakeLab struct {
	volunteer  bool
	outcome    func(Mode) string
	handsAfter Mode
	state      api.DeviceState
	jobs       []api.JobSpec
	leased     bool
	released   bool
}

func (f *fakeLab) Device(_ context.Context, name string) (*client.Device, error) {
	d := &client.Device{Tier: 1}
	d.Name, d.Volunteer, d.State = name, f.volunteer, f.state
	if d.State == "" {
		d.State = api.StateReady
	}
	return d, nil
}

func (f *fakeLab) Lease(context.Context, string, string, time.Duration) (*api.Lease, error) {
	f.leased = true
	return &api.Lease{}, nil
}

func (f *fakeLab) Release(context.Context, string, string) error { f.released = true; return nil }

func (f *fakeLab) Submit(_ context.Context, spec api.JobSpec) (*api.Job, error) {
	f.jobs = append(f.jobs, spec)
	return &api.Job{ID: fmt.Sprintf("j%d", len(f.jobs)), Spec: spec, State: api.JobQueued}, nil
}

func (f *fakeLab) Wait(_ context.Context, id string, _ time.Duration) (*api.Job, error) {
	spec := f.jobs[len(f.jobs)-1]
	m := modeOf(spec.Cmdline)
	out := f.outcome(m)
	if m == f.handsAfter {
		f.state = api.StateNeedsHands
	}
	return &api.Job{ID: id, Spec: spec, State: api.JobDone, Outcome: out,
		Result: api.JobResult{Tests: []api.TestResult{{Name: "chaos-check", Passed: true}}}}, nil
}

func modeOf(cmdline string) Mode {
	if strings.Contains(cmdline, "modprobe.blacklist=brcmfmac") {
		return Netdown
	}
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "maclab_chaos.mode="); ok {
			return Mode(v)
		}
	}
	return None
}

func asPredicted(m Mode) string { return Predicted(m, false)[0] }

type fixedJudge struct{ fault func(job string) Mode }

func (j fixedJudge) Judge(_ context.Context, job, _ string) (*Verdict, error) {
	return &Verdict{Fault: j.fault(job)}, nil
}

func night(t *testing.T, lab *fakeLab, plan map[Mode]int) (*Night, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	return &Night{Lab: lab, Ledger: Ledger{Path: path}, Device: "m1", Holder: "lab-loop:test", Kernel: strings.Repeat("a", 64),
		ChaosCheck: strings.Repeat("b", 64), Boots: Schedule(plan, 1), Seed: 1,
		JobTimeout: time.Minute, ReadyTimeout: time.Second, Poll: time.Millisecond, Logf: t.Logf}, path
}

func readLedger(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestANightRunsEveryBootAndScoresTheJudge(t *testing.T) {
	lab := &fakeLab{outcome: asPredicted}
	n, path := night(t, lab, Week1)
	// The judge gets every boot right except the hangs, which it calls none.
	modes := map[string]Mode{}
	for i, b := range n.Boots {
		modes[fmt.Sprintf("j%d", i+1)] = b.Mode
	}
	n.Judge = fixedJudge{func(job string) Mode {
		if m := modes[job]; m != HangEarly && m != HangLate {
			return m
		}
		return None
	}}
	if err := n.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !lab.leased || !lab.released {
		t.Errorf("leased %v, released %v", lab.leased, lab.released)
	}
	es := readLedger(t, path)
	if len(es) != 20 {
		t.Fatalf("%d ledger entries, want 20", len(es))
	}
	wrong := 0
	for _, e := range es {
		if !e.AsPredicted || e.ChaosCheck != "pass" || e.Score == nil || !e.Score.HumanNeeded {
			t.Errorf("boot %d %s: %+v", e.Iter, e.Mode, e)
		}
		if e.Score != nil && !e.Score.Fault {
			wrong++
		}
	}
	if wrong != 4 {
		t.Errorf("judge wrong on %d boots, want the 4 hangs", wrong)
	}
	if spec := lab.jobs[0]; spec.Holder != "lab-loop:test" || len(spec.Tests) != 1 || spec.Tests[0].Script != strings.Repeat("b", 64) {
		t.Errorf("first job spec: %+v", spec)
	}
}

func TestNeedsHandsStopsTheNight(t *testing.T) {
	lab := &fakeLab{outcome: asPredicted, handsAfter: HangEarly}
	n, path := night(t, lab, map[Mode]int{None: 1, HangEarly: 1, HangLate: 3})
	err := n.Run(context.Background())
	if !IsStop(err) || !strings.Contains(err.Error(), "needs hands") {
		t.Fatalf("got %v", err)
	}
	es := readLedger(t, path)
	if last := es[len(es)-1]; last.Mode != HangEarly || !last.NeedsHands {
		t.Errorf("last entry %+v", last)
	}
	if len(es) == 5 {
		t.Errorf("ran every boot after the Mac needed hands")
	}
}

func TestAHealthyBootThatFailsStopsTheNight(t *testing.T) {
	lab := &fakeLab{outcome: func(Mode) string { return api.OutcomeBootFailed }}
	n, path := night(t, lab, map[Mode]int{None: 3})
	if err := n.Run(context.Background()); !IsStop(err) {
		t.Fatalf("got %v", err)
	}
	if es := readLedger(t, path); len(es) != 1 || es[0].AsPredicted {
		t.Errorf("ledger %+v", es)
	}
}

func TestTwoInfraErrorsInARowStopTheNight(t *testing.T) {
	lab := &fakeLab{outcome: func(m Mode) string {
		if m.Healthy() {
			return api.OutcomePass
		}
		return api.OutcomeInfra
	}}
	n, path := night(t, lab, map[Mode]int{None: 1, HangLate: 4})
	if err := n.Run(context.Background()); !IsStop(err) || !strings.Contains(err.Error(), "infra") {
		t.Fatalf("got %v", err)
	}
	if es := readLedger(t, path); len(es) != 3 {
		t.Errorf("%d entries, want 3 (the healthy one, then two infra errors)", len(es))
	}
}

func TestAVolunteersMacIsRefused(t *testing.T) {
	lab := &fakeLab{volunteer: true, outcome: asPredicted}
	n, _ := night(t, lab, map[Mode]int{None: 1})
	if err := n.Run(context.Background()); err == nil || lab.leased {
		t.Fatalf("got %v, leased %v", err, lab.leased)
	}
}

func TestParseVerdict(t *testing.T) {
	for _, out := range []string{
		`{"fault":"hang_late","human_needed":false}`,
		"I read the logs.\n```json\n{\"fault\": \"hang_late\", \"evidence\": [\"boot0/kernel.txt: {stuck}\"]}\n```",
	} {
		v, err := parseVerdict([]byte(out))
		if err != nil || v.Fault != HangLate {
			t.Errorf("%q: %+v, %v", out, v, err)
		}
	}
	if _, err := parseVerdict([]byte(`{"something":"else"} no verdict`)); err == nil {
		t.Error("a JSON object with no fault parsed as a verdict")
	}
}

func TestCommandJudgeGetsTheJob(t *testing.T) {
	j := CommandJudge{Command: `printf '{"fault":"none","evidence":["%s on %s"]}' "$MACLAB_JOB" "$MACLAB_DEVICE"`}
	v, err := j.Judge(context.Background(), "j42", "m1")
	if err != nil || v.Fault != None || len(v.Evidence) != 1 || v.Evidence[0] != "j42 on m1" {
		t.Fatalf("%+v, %v", v, err)
	}
	if _, err := (CommandJudge{Command: "exit 3"}).Judge(context.Background(), "j", "m1"); err == nil {
		t.Error("a failing judge gave no error")
	}
}

func TestChaosCheckScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "chaos-check.sh")
	os.WriteFile(script, ChaosCheckScript, 0o755)
	run := func(cmdline, dmesg string) error {
		os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "dmesg"), []byte(dmesg), 0o644)
		cmd := exec.Command("sh", script)
		cmd.Env = append(os.Environ(), "CMDLINE="+filepath.Join(dir, "cmdline"), "DMESG=cat "+filepath.Join(dir, "dmesg"))
		return cmd.Run()
	}
	for _, c := range []struct {
		cmdline, dmesg string
		ok             bool
	}{
		{"root=x maclab_chaos.mode=marker maclab_chaos.marker=abc123", "[ 1.2] maclab-chaos: mode=marker marker=abc123\n", true},
		{"root=x maclab_chaos.mode=marker maclab_chaos.marker=abc123", "[ 1.2] maclab-chaos: mode=marker marker=old999\n", false},
		{"root=x maclab_chaos.mode=hang_late", "[ 1.2] maclab-chaos: mode=hang_late marker=\n", true},
		{"root=x maclab_chaos.mode=none", "[ 1.2] nothing from the chaos kernel\n", false},
		{"root=x quiet", "", true},
	} {
		if err := run(c.cmdline, c.dmesg); (err == nil) != c.ok {
			t.Errorf("cmdline %q, dmesg %q: err %v, want ok=%v", c.cmdline, c.dmesg, err, c.ok)
		}
	}
}

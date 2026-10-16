package server

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
)

func TestChipFamily(t *testing.T) {
	cases := []struct {
		compatible []string
		model      string
		want       string
	}{
		{[]string{"apple,j313", "apple,t8103", "apple,arm-platform"}, "", "m1"},
		{[]string{"apple,j375d", "apple,t6002", "apple,arm-platform"}, "", "m1-pro"},
		{[]string{"apple,j413", "apple,t8112", "apple,arm-platform"}, "", "m2"},
		{[]string{"apple,j475d", "apple,t6022", "apple,arm-platform"}, "", "m2-pro"},
		{[]string{"apple,j504", "apple,t8122", "apple,arm-platform"}, "", "m3"},
		{[]string{"apple,j514c", "apple,t6031", "apple,arm-platform"}, "", "m3-pro"},
		{[]string{"apple,j604", "apple,t8132", "apple,arm-platform"}, "", ""}, // M4
		// The SoC compatible wins over the model.
		{[]string{"apple,j614s", "apple,t6040", "apple,arm-platform"}, "Apple MacBook Air (M1, 2020)", ""},
		// Agents too old to report the compatible: the model decides.
		{nil, "Apple MacBook Air (M1, 2020)", "m1"},
		{nil, "Apple MacBook Pro (14-inch, M1 Pro, 2021)", "m1-pro"},
		{nil, "Apple Mac Studio (M1 Ultra, 2022)", "m1-pro"},
		{nil, "Apple Mac mini (M2, 2023)", "m2"},
		{nil, "Apple Mac Studio (M2 Ultra, 2023)", "m2-pro"},
		{nil, "Apple MacBook Air (13-inch, M3, 2024)", "m3"},
		{nil, "Apple MacBook Pro (16-inch, M3 Max, 2023)", "m3-pro"},
		{nil, "Apple Mac Studio (M3 Ultra, 2025)", ""},
		{nil, "Apple MacBook Pro (14-inch, M4 Pro, 2024)", ""},
		{nil, "Apple MacBook Pro (14-inch, M12, 2031)", ""},
		{nil, "Simulated Mac", ""},
	}
	for _, c := range cases {
		if got := family(api.Facts{Compatible: c.compatible, DTModel: c.model}); got != c.want {
			t.Errorf("family(%v, %q) = %q, want %q", c.compatible, c.model, got, c.want)
		}
	}
}

func gateDev(name, soc string) api.Device {
	d := api.Device{Name: name}
	if soc != "" {
		d.Facts.Compatible = []string{"apple,j000", "apple," + soc, "apple,arm-platform"}
	}
	return d
}

// gateJobs builds finished jobs, newest first, from "device outcome [failing-test]".
func gateJobs(specs ...string) []*api.Job {
	var out []*api.Job
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for i, s := range specs {
		f := strings.Fields(s)
		j := &api.Job{ID: "j" + f[0] + "-" + string(rune('a'+i)), State: api.JobDone, Outcome: f[1], Updated: now.Add(-time.Duration(i) * time.Minute),
			Spec:   api.JobSpec{Device: f[0], Kernel: "k", Build: "b1015-120000-abcd"},
			Result: api.JobResult{Booted: true, BootKernel: "7.2.0-lab1", Tests: []api.TestResult{{Name: "boot-health", Passed: true}}}}
		if f[1] == api.OutcomeStageFailed {
			j.Summary, j.Result = "staging failed: the boot partition is full", api.JobResult{}
		}
		if len(f) > 2 {
			j.Result.Tests = append(j.Result.Tests, api.TestResult{Name: f[2], ExitCode: 1})
		}
		out = append(out, j)
	}
	return out
}

func gateFleet() []api.Device {
	return []api.Device{gateDev("m1air", "t8103"), gateDev("m1mini", "t8103"), gateDev("m1pro", "t6000"), gateDev("m2air", "t8112"),
		gateDev("m2pro", "t6020"), gateDev("m2max", "t6021"), gateDev("m3air", "t8122"), gateDev("m3pro", "t6030"),
		gateDev("m4mini", "t8132"), gateDev("sim", "")}
}

func gateResults(r api.GateReport) map[string]string {
	out := map[string]string{}
	for _, f := range r.Families {
		out[f.Family] = f.Result
	}
	return out
}

func TestGateRollUp(t *testing.T) {
	jobs := gateJobs(
		"m1air pass",
		"m1mini infra_error", // says nothing about the kernel: the earlier pass stands
		"m1pro canceled",
		"m2pro pass",
		"m2max panicked", // a family with one Mac passing and one failing fails
		"m2air pass",
		"m4mini pass",        // no supported family: not counted
		"m1air stage_failed", // older than its pass, which decides
		"m1mini pass",
		"m1pro tests_failed gui-smoke",
		"m2max canceled",
	)
	notDone := &api.Job{ID: "jm3pro", State: api.JobTesting, Spec: api.JobSpec{Device: "m3pro", Kernel: "k"}}
	jobs = append([]*api.Job{notDone}, jobs...)
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, familyIDs(), gateOpts{})

	want := map[string]string{"m1": "pass", "m1-pro": "fail", "m2": "pass", "m2-pro": "fail", "m3": "untested", "m3-pro": "untested"}
	if got := gateResults(r); !maps.Equal(got, want) {
		t.Fatalf("families %v, want %v", got, want)
	}
	if r.Result != api.GateFail || !slices.Equal(r.Untested, []string{"m3", "m3-pro"}) || !slices.Equal(r.Unclassified, []string{"m4mini", "sim"}) {
		t.Fatalf("result %s untested %v unclassified %v", r.Result, r.Untested, r.Unclassified)
	}
	if r.Kernel.Build != "b1015-120000-abcd" || r.Kernel.Release != "7.2.0-lab1" {
		t.Fatalf("kernel %+v", r.Kernel)
	}
	m1, m1pro, m2pro := r.Families[0], r.Families[1], r.Families[3]
	if len(m1.Runs) != 2 || m1.Runs[0].Device != "m1air" || m1.Runs[1].Device != "m1mini" || m1.Runs[1].Outcome != api.OutcomePass {
		t.Fatalf("m1 runs %+v", m1.Runs)
	}
	if len(m1pro.Runs) != 1 || m1pro.Runs[0].Outcome != api.OutcomeTestsFailed ||
		!slices.Equal(m1pro.Runs[0].Tests, []api.GateTest{{Name: "boot-health", Result: "pass"}, {Name: "gui-smoke", Result: "fail"}}) {
		t.Fatalf("m1-pro runs %+v", m1pro.Runs)
	}
	if len(m2pro.Runs) != 2 || m2pro.Runs[0].Device != "m2max" || m2pro.Runs[0].Outcome != api.OutcomePanicked {
		t.Fatalf("m2-pro: the failed run must come first: %+v", m2pro.Runs)
	}
	for _, s := range []string{"gate shut: ", "m1-pro failed (m1pro, job jm1pro-j)", "m2-pro failed (m2max, job jm2max-e)", "m3 untested", "m3-pro untested"} {
		if !strings.Contains(r.Summary, s) {
			t.Errorf("summary %q lacks %q", r.Summary, s)
		}
	}
}

func TestGateSkipsCrashTests(t *testing.T) {
	// A crash test boots the kernel only to crash it: neither its pass nor its
	// failure says anything, so the run before it decides.
	jobs := gateJobs("m1air pass", "m1air panicked", "m2air panicked", "m2air pass")
	jobs[0].Spec.Crash, jobs[2].Spec.Crash = "panic", "panic"
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m2"}, gateOpts{})
	if got := gateResults(r); got["m1"] != "fail" || got["m2"] != "pass" {
		t.Fatalf("families %v", got)
	}
}

func TestGateOpenShut(t *testing.T) {
	fleet := gateFleet()
	all := gateJobs("m1air pass", "m1pro pass", "m2air pass", "m2pro pass", "m3air pass", "m3pro pass")
	if r := rollUp(api.GateKernel{}, fleet, all, familyIDs(), gateOpts{}); r.Result != api.GatePass || len(r.Untested) != 0 {
		t.Fatalf("every family passed, but %s: %s", r.Result, r.Summary)
	}
	// No Mac of a family has run it: the gate stays shut.
	some := gateJobs("m1air pass", "m2air pass")
	if r := rollUp(api.GateKernel{}, fleet, some, familyIDs(), gateOpts{}); r.Result != api.GateFail || r.Summary != "gate shut: m1-pro untested, m2-pro untested, m3 untested, m3-pro untested" {
		t.Fatalf("%s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{}, fleet, some, []string{"m1", "m2"}, gateOpts{}); r.Result != api.GatePass || r.Summary != "gate open: passed on m1, m2" {
		t.Fatalf("required m1, m2: %s: %s", r.Result, r.Summary)
	}
	// A failure outside the required families doesn't shut the gate.
	if r := rollUp(api.GateKernel{}, fleet, gateJobs("m1air pass", "m3air hung"), []string{"m1"}, gateOpts{}); r.Result != api.GatePass {
		t.Fatalf("required m1: %s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{}, fleet, gateJobs("m1air pass", "m1mini boot_failed"), []string{"m1"}, gateOpts{}); r.Result != api.GateFail {
		t.Fatalf("one m1 failed: %s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{}, nil, nil, familyIDs(), gateOpts{}); r.Result != api.GateFail || len(r.Untested) != 6 {
		t.Fatalf("no Macs: %s, untested %v", r.Result, r.Untested)
	}
}

func TestGateStageFailed(t *testing.T) {
	jobs := gateJobs(
		"m2air stage_failed", // the family's only result: it couldn't stage
		"m1air stage_failed", // a pass on another m1 still decides m1
		"m1mini pass",
		"m2pro stage_failed", // a failure on another m2-pro still decides m2-pro
		"m2max panicked",
		"m3air pass",        // the latest run counts: this pass, not the older stage_failed
		"m3pro infra_error", // skipped: the stage_failed before it stands
		"m3pro stage_failed",
		"m3air stage_failed",
	)
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, familyIDs(), gateOpts{})
	want := map[string]string{"m1": "pass", "m1-pro": "untested", "m2": "stage_failed", "m2-pro": "fail", "m3": "pass", "m3-pro": "stage_failed"}
	if got := gateResults(r); !maps.Equal(got, want) {
		t.Fatalf("families %v, want %v", got, want)
	}
	m1, m2 := r.Families[0], r.Families[2]
	if m1.Runs[0].Device != "m1mini" || m1.Runs[1].Result != api.GateStageFailed {
		t.Fatalf("m1: the pass must come first: %+v", m1.Runs)
	}
	if run := m2.Runs[0]; run.Reason != "staging failed: the boot partition is full" || run.Outcome != api.OutcomeStageFailed {
		t.Fatalf("m2 run %+v", run)
	}
	if r.Families[3].Runs[0].Device != "m2max" {
		t.Fatalf("m2-pro: the failure must come first: %+v", r.Families[3].Runs)
	}
	// It never shuts the gate quietly: the reason is in the summary.
	r = rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m2", "m3"}, gateOpts{})
	if r.Result != api.GateFail || r.Summary != "gate shut: m2 couldn't stage on m2air (job jm2air-a: staging failed: the boot partition is full)" {
		t.Fatalf("%s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m3"}, gateOpts{}); r.Result != api.GatePass {
		t.Fatalf("m1, m3 passed despite a Mac that couldn't stage: %s: %s", r.Result, r.Summary)
	}
}

func TestGateStageFailedHidesNothing(t *testing.T) {
	// A rerun that couldn't stage says nothing about the kernel: the result
	// before it stands, a failure as much as a pass.
	jobs := gateJobs(
		"m2max stage_failed",
		"m2max panicked",
		"m2pro pass",
		"m1air stage_failed",
		"m1air pass",
	)
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m2-pro"}, gateOpts{})
	if got := gateResults(r); got["m1"] != "pass" || got["m2-pro"] != "fail" {
		t.Fatalf("families %v", got)
	}
	m1, m2pro := r.Families[0], r.Families[3]
	if len(m1.Runs) != 1 || m1.Runs[0].Outcome != api.OutcomePass {
		t.Fatalf("m1 runs %+v", m1.Runs)
	}
	if len(m2pro.Runs) != 2 || m2pro.Runs[0].Device != "m2max" || m2pro.Runs[0].Outcome != api.OutcomePanicked {
		t.Fatalf("m2-pro: the panic must stand and come first: %+v", m2pro.Runs)
	}
	if r.Result != api.GateFail || !strings.Contains(r.Summary, "m2-pro failed (m2max, job jm2max-b)") {
		t.Fatalf("%s: %s", r.Result, r.Summary)
	}
}

// A Mac that both passed and failed on the kernel is flaky, whichever came
// last: a lab retry's pass doesn't hide the failure before it. Runs that say
// nothing about the kernel make no Mac flaky.
func TestGateFlaky(t *testing.T) {
	jobs := gateJobs(
		"m1air pass", // a lab retry of the failure below
		"m1air tests_failed gui-smoke",
		"m1mini pass",
		"m2air panicked", // a failure after a pass
		"m2air pass",
		"m2max panicked", // a failing Mac decides over a flaky one
		"m2pro pass",
		"m2pro boot_failed",
		"m3air pass",
		"m3air infra_error",
		"m3air stage_failed",
		"m3air canceled",
		"m1pro pass",
	)
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, familyIDs(), gateOpts{})
	want := map[string]string{"m1": "flaky", "m1-pro": "pass", "m2": "flaky", "m2-pro": "fail", "m3": "pass", "m3-pro": "untested"}
	if got := gateResults(r); !maps.Equal(got, want) {
		t.Fatalf("families %v, want %v", got, want)
	}
	type run struct{ device, job, outcome, result, reason string }
	runs := func(l []api.GateRun) (out []run) {
		for _, r := range l {
			out = append(out, run{r.Device, r.Job, r.Outcome, r.Result, r.Reason})
		}
		return out
	}
	m1 := []run{
		{"m1air", "jm1air-b", "tests_failed", "flaky", "passed too, in job jm1air-a"},
		{"m1air", "jm1air-a", "pass", "flaky", "tests_failed too, in job jm1air-b"},
		{"m1mini", "jm1mini-c", "pass", "pass", ""},
	}
	if got := runs(r.Families[0].Runs); !slices.Equal(got, m1) {
		t.Errorf("m1 runs %+v, want %+v", got, m1)
	}
	m2pro := []run{
		{"m2max", "jm2max-f", "panicked", "fail", ""},
		{"m2pro", "jm2pro-h", "boot_failed", "flaky", "passed too, in job jm2pro-g"},
		{"m2pro", "jm2pro-g", "pass", "flaky", "boot_failed too, in job jm2pro-h"},
	}
	if got := runs(r.Families[3].Runs); !slices.Equal(got, m2pro) {
		t.Errorf("m2-pro runs %+v, want %+v", got, m2pro)
	}
	if m3 := r.Families[4].Runs; len(m3) != 1 || m3[0].Job != "jm3air-i" {
		t.Errorf("m3 runs %+v", m3)
	}
	for _, s := range []string{"m1 flaky (m1air passed in job jm1air-a, tests_failed in job jm1air-b)",
		"m2 flaky (m2air passed in job jm2air-e, panicked in job jm2air-d)", "m2-pro failed (m2max, job jm2max-f)"} {
		if !strings.Contains(r.Summary, s) {
			t.Errorf("summary %q lacks %q", r.Summary, s)
		}
	}
	if r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1"}, gateOpts{}); r.Result != api.GateFail {
		t.Errorf("a flaky family opened the gate: %s", r.Summary)
	}
	if r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1-pro", "m3"}, gateOpts{}); r.Result != api.GatePass {
		t.Errorf("m1-pro, m3: %s", r.Summary)
	}
}

// Only plain runs open the gate: the known-good cmdline, the tests every job
// on the Mac runs, and no omarchy-m-test allowances. A changed cmdline boots
// something a release doesn't, so that run counts neither way; a run that
// tested less still fails the kernel when it failed.
func TestGatePlainRuns(t *testing.T) {
	jobs := gateJobs(
		"m1air pass",         // a: --cmdline
		"m1mini pass",        // b: --omt-allow
		"m1pro tests_failed", // c: --omt-allow, and it failed even so
		"m2air panicked",     // d: --cmdline-strip: says nothing, so m2air isn't flaky
		"m2air pass",         // e: plain
		"m2pro pass",         // f: a verbose boot from the known-good cmdline is plain
		"m3air pass",         // g: boot-health didn't run
		"m3pro pass",         // h: omarchy-m-test didn't run, and every m3pro job runs it
		"m3pro pass",         // i: it did
		"m2max pass",         // j: --cmdline-base default
	)
	jobs[0].Spec.Cmdline = "initcall_debug"
	jobs[1].Spec.OMTAllow = []string{"system.failed-units"}
	jobs[2].Spec.OMTAllow = []string{"system.failed-units"}
	jobs[3].Spec.CmdlineStrip = []string{"asahi.*", "apple_dcp.*"}
	jobs[5].Spec.VerboseBoot, jobs[5].Spec.CmdlineBase = true, "known-good"
	jobs[6].Result.Tests = []api.TestResult{{Name: "gui-smoke", Passed: true}}
	jobs[8].Result.Tests = append(jobs[8].Result.Tests, api.TestResult{Name: omtTest, Passed: true})
	jobs[9].Spec.CmdlineBase = "default"
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, familyIDs(), gateOpts{omt: map[string]bool{"m3pro": true}})

	want := map[string]string{"m1": "untested", "m1-pro": "fail", "m2": "pass", "m2-pro": "pass", "m3": "untested", "m3-pro": "pass"}
	if got := gateResults(r); !maps.Equal(got, want) {
		t.Fatalf("families %v, want %v", got, want)
	}
	notCounted := map[string][]string{}
	for _, f := range r.Families {
		for _, run := range f.NotCounted {
			notCounted[f.Family] = append(notCounted[f.Family], run.Job+": "+run.NotCounted)
		}
	}
	wantNot := map[string][]string{
		"m1":     {`jm1air-a: custom cmdline: --cmdline "initcall_debug"`, "jm1mini-b: tested less than a plain run: --omt-allow system.failed-units"},
		"m2":     {`jm2air-d: custom cmdline: --cmdline-strip "asahi.* apple_dcp.*"`},
		"m2-pro": {`jm2max-j: custom cmdline: --cmdline-base "default"`},
		"m3":     {"jm3air-g: tested less than a plain run: boot-health didn't run"},
		"m3-pro": {"jm3pro-h: tested less than a plain run: omarchy-m-test didn't run"},
	}
	if !maps.EqualFunc(notCounted, wantNot, slices.Equal) {
		t.Errorf("not counted %q,\nwant %q", notCounted, wantNot)
	}
	if run := r.Families[1].Runs[0]; run.Job != "jm1pro-c" || run.Result != api.GateFail {
		t.Errorf("m1-pro: the failure with --omt-allow must count: %+v", run)
	}
	if run := r.Families[5].Runs[0]; run.Job != "jm3pro-i" {
		t.Errorf("m3-pro: the run with omarchy-m-test decides: %+v", run)
	}
	for _, s := range []string{"m1 untested (2 runs not counted)", "m3 untested (1 run not counted)"} {
		if !strings.Contains(r.Summary, s) {
			t.Errorf("summary %q lacks %q", r.Summary, s)
		}
	}
}

// A tests_failed job whose failed tests never ran (exit 126: the desktop user
// couldn't open the test script) says nothing about the kernel. One with a
// real failure among them, or a fatal kernel event, still fails.
func TestGateRunnerFailures(t *testing.T) {
	jobs := gateJobs("m1air tests_failed", "m1air pass", "m2air tests_failed", "m2air pass", "m3air tests_failed", "m3air pass")
	cant := api.TestResult{Name: omtTest, ExitCode: 126, Tail: "bash: /var/lib/maclab/jobs/j/test-omarchy-m-test.sh: Permission denied"}
	jobs[0].Result.Tests = append(jobs[0].Result.Tests, cant)
	jobs[2].Result.Tests = append(jobs[2].Result.Tests, cant, api.TestResult{Name: "gui-smoke", ExitCode: 1})
	jobs[4].Result.Tests = append(jobs[4].Result.Tests, api.TestResult{Name: "gui-terminal", ExitCode: 127})
	jobs[4].Result.KernelEvents = []api.KernelEvent{{Kind: detect.Oops, Line: "Internal error: Oops: 96000004"}}
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, familyIDs(), gateOpts{})
	if got := gateResults(r); got["m1"] != "pass" || got["m2"] != "flaky" || got["m3"] != "flaky" {
		t.Fatalf("families %v", got)
	}
	nc := r.Families[0].NotCounted
	if len(nc) != 1 || nc[0].Job != "jm1air-a" || nc[0].NotCounted != "test omarchy-m-test couldn't run (exit 126)" {
		t.Fatalf("m1 not counted %+v", nc)
	}
}

// Volunteers' Macs run agents the lab doesn't control: the gate lists their
// runs apart and counts them only when asked.
func TestGateVolunteers(t *testing.T) {
	fleet := append(gateFleet(), gateDev("naeem-omarchy", "t6031"), gateDev("visitor-air", "t8103"), gateDev("visitor-m4", "t8132"))
	for i := range fleet[len(fleet)-3:] {
		fleet[len(fleet)-3+i].Volunteer = true
	}
	jobs := gateJobs(
		"naeem-omarchy pass", // m3-pro's only result
		"visitor-air panicked",
		"visitor-air pass",
		"m1air pass",
	)
	r := rollUp(api.GateKernel{SHA256: "k"}, fleet, jobs, []string{"m1", "m3-pro"}, gateOpts{})
	if got := gateResults(r); got["m1"] != "pass" || got["m3-pro"] != "untested" {
		t.Fatalf("families %v", got)
	}
	if !slices.Equal(r.Volunteers, []string{"naeem-omarchy", "visitor-air", "visitor-m4"}) || r.VolunteersCounted ||
		!slices.Contains(r.Unclassified, "visitor-m4") {
		t.Fatalf("volunteers %v (counted %v), unclassified %v", r.Volunteers, r.VolunteersCounted, r.Unclassified)
	}
	m1, m3pro := r.Families[0], r.Families[5]
	if len(m1.Runs) != 1 || m1.Runs[0].Device != "m1air" || len(m1.NotCounted) != 2 {
		t.Fatalf("m1 runs %+v, not counted %+v", m1.Runs, m1.NotCounted)
	}
	for _, run := range append(m1.NotCounted, m3pro.NotCounted...) {
		if !run.Volunteer || run.NotCounted != "a volunteer's Mac" {
			t.Errorf("volunteer run %+v", run)
		}
	}
	if m1.NotCounted[0].Result != api.GateFlaky || len(m3pro.NotCounted) != 1 || m3pro.NotCounted[0].Device != "naeem-omarchy" {
		t.Errorf("m1 not counted %+v, m3-pro %+v", m1.NotCounted, m3pro.NotCounted)
	}
	if r.Result != api.GateFail || r.Summary != "gate shut: m3-pro untested (1 run not counted)" {
		t.Errorf("%s: %s", r.Result, r.Summary)
	}
	b, _ := json.Marshal(r)
	for _, s := range []string{`"not_counted":[{"device":"naeem-omarchy"`, `"volunteer":true,"not_counted":"a volunteer's Mac"`, `"volunteers":["naeem-omarchy"`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("record lacks %s: %s", s, b)
		}
	}

	r = rollUp(api.GateKernel{SHA256: "k"}, fleet, jobs, []string{"m3-pro"}, gateOpts{volunteers: true})
	if got := gateResults(r); got["m1"] != "flaky" || got["m3-pro"] != "pass" || !r.Families[5].Runs[0].Volunteer {
		t.Fatalf("counting volunteers: families %v, m3-pro %+v", got, r.Families[5].Runs)
	}
	if r.Result != api.GatePass || r.Summary != "gate open: passed on m3-pro; volunteers' Macs counted" || !r.VolunteersCounted {
		t.Errorf("%s: %s", r.Result, r.Summary)
	}
}

func TestGateEvidenceShape(t *testing.T) {
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), gateJobs("m1air tests_failed gui-smoke"), familyIDs(), gateOpts{})
	r.Labd, r.Generated = "labd:7700", time.Now()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Kernel   map[string]any   `json:"kernel"`
		Families []map[string]any `json:"families"`
	}
	var top map[string]any
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &top)
	keys := func(m map[string]any) []string { return slices.Sorted(maps.Keys(m)) }
	check := func(what string, m map[string]any, want ...string) {
		t.Helper()
		if got := keys(m); !slices.Equal(got, want) {
			t.Errorf("%s keys %v, want %v", what, got, want)
		}
	}
	check("record", top, "families", "generated", "kernel", "labd", "required", "result", "summary", "unclassified", "untested")
	check("kernel", rec.Kernel, "build", "release", "sha256")
	if len(rec.Families) != 6 {
		t.Fatalf("%d families", len(rec.Families))
	}
	check("family", rec.Families[0], "family", "name", "result", "runs")
	check("untested family", rec.Families[1], "family", "name", "result")
	run := rec.Families[0]["runs"].([]any)[0].(map[string]any)
	check("run", run, "device", "finished", "job", "outcome", "result", "tests")
	if top["result"] != "fail" || top["labd"] != "labd:7700" || run["device"] != "m1air" || run["result"] != "fail" {
		t.Fatalf("record %s", b)
	}
	test := run["tests"].([]any)[1].(map[string]any)
	check("test", test, "name", "result")
	if test["name"] != "gui-smoke" || test["result"] != "fail" {
		t.Fatalf("test %v", test)
	}

	b, _ = json.Marshal(rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), gateJobs("m2air stage_failed"), familyIDs(), gateOpts{}))
	var sf struct {
		Families []map[string]any `json:"families"`
	}
	json.Unmarshal(b, &sf)
	run = sf.Families[2]["runs"].([]any)[0].(map[string]any)
	check("stage_failed run", run, "device", "finished", "job", "outcome", "reason", "result")
	if sf.Families[2]["result"] != "stage_failed" || run["reason"] != "staging failed: the boot partition is full" {
		t.Fatalf("record %s", b)
	}
}

// TestGateEndpoint runs a kernel on the simulated Mac and asks labd's gate.
func TestGateEndpoint(t *testing.T) {
	l := newLab(t, false)
	l.baseline()
	k := l.artifact("krel=7.2-gate behavior=ok")
	l.expect(l.run(api.JobSpec{Kernel: k}), api.OutcomePass)
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Facts.Compatible = []string{"apple,j313", "apple,t8103", "apple,arm-platform"}
	v.mu.Unlock()

	gate := func(path string, code int) api.GateReport {
		t.Helper()
		resp, body := l.get("GET", path)
		if resp.StatusCode != code {
			t.Fatalf("GET %s: %d %s, want %d", path, resp.StatusCode, body, code)
		}
		var r api.GateReport
		if code == 200 {
			if err := json.Unmarshal([]byte(body), &r); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	r := gate("/api/gate/"+k[:12]+"?families=m1", 200)
	if r.Result != api.GatePass || r.Kernel.SHA256 != k || r.Kernel.Release != "7.2-gate" || r.Labd == "" ||
		r.Families[0].Runs[0].Device != l.name || !slices.Equal(r.Required, []string{"m1"}) {
		t.Fatalf("m1 only: %+v", r)
	}
	if r := gate("/api/gate/"+k, 200); r.Result != api.GateFail || len(r.Untested) != 5 {
		t.Fatalf("all families: %s, untested %v", r.Result, r.Untested)
	}
	// A volunteer's Mac counts only when asked.
	v.mu.Lock()
	v.d.Volunteer = true
	v.mu.Unlock()
	if r := gate("/api/gate/"+k[:12]+"?families=m1", 200); r.Result != api.GateFail || len(r.Families[0].NotCounted) != 1 || !slices.Equal(r.Volunteers, []string{l.name}) {
		t.Fatalf("a volunteer's Mac: %+v", r)
	}
	if r := gate("/api/gate/"+k[:12]+"?families=m1&volunteers=1", 200); r.Result != api.GatePass || !r.VolunteersCounted {
		t.Fatalf("counting volunteers: %+v", r)
	}
	gate("/api/gate/"+k[:12]+"?volunteers=maybe", 400)
	v.mu.Lock()
	v.d.Volunteer = false
	v.mu.Unlock()

	// Once the lab runs omarchy-m-test on the Mac, a pass without it doesn't
	// count; a run with it does.
	l.s.cfg.OMT = true
	r = gate("/api/gate/"+k[:12]+"?families=m1", 200)
	if nc := r.Families[0].NotCounted; r.Result != api.GateFail || len(nc) != 1 || nc[0].NotCounted != "tested less than a plain run: omarchy-m-test didn't run" {
		t.Fatalf("a pass without omarchy-m-test: %+v", r)
	}
	l.expect(l.run(api.JobSpec{Kernel: k}), api.OutcomePass)
	v.mu.Lock()
	v.d.Facts.Compatible = []string{"apple,j313", "apple,t8103", "apple,arm-platform"} // the reboots brought the sim's own facts back
	v.mu.Unlock()
	if r := gate("/api/gate/"+k[:12]+"?families=m1", 200); r.Result != api.GatePass {
		t.Fatalf("a pass with omarchy-m-test: %+v", r)
	}
	gate("/api/gate/"+k[:12]+"?families=m1,m4", 400)
	gate("/api/gate/abcdef0123", 404)
	gate("/api/gate/not-a-kernel", 400)
}

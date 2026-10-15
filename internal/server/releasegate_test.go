package server

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
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
		"m4mini pass", // no supported family: not counted
		"m1air tests_failed",
		"m1mini pass",
		"m1pro tests_failed gui-smoke",
		"m2max pass", // older than its panic
	)
	notDone := &api.Job{ID: "jm3pro", State: api.JobTesting, Spec: api.JobSpec{Device: "m3pro", Kernel: "k"}}
	jobs = append([]*api.Job{notDone}, jobs...)
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, familyIDs())

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
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m2"})
	if got := gateResults(r); got["m1"] != "fail" || got["m2"] != "pass" {
		t.Fatalf("families %v", got)
	}
}

func TestGateOpenShut(t *testing.T) {
	fleet := gateFleet()
	all := gateJobs("m1air pass", "m1pro pass", "m2air pass", "m2pro pass", "m3air pass", "m3pro pass")
	if r := rollUp(api.GateKernel{}, fleet, all, familyIDs()); r.Result != api.GatePass || len(r.Untested) != 0 {
		t.Fatalf("every family passed, but %s: %s", r.Result, r.Summary)
	}
	// No Mac of a family has run it: the gate stays shut.
	some := gateJobs("m1air pass", "m2air pass")
	if r := rollUp(api.GateKernel{}, fleet, some, familyIDs()); r.Result != api.GateFail || r.Summary != "gate shut: m1-pro untested, m2-pro untested, m3 untested, m3-pro untested" {
		t.Fatalf("%s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{}, fleet, some, []string{"m1", "m2"}); r.Result != api.GatePass || r.Summary != "gate open: passed on m1, m2" {
		t.Fatalf("required m1, m2: %s: %s", r.Result, r.Summary)
	}
	// A failure outside the required families doesn't shut the gate.
	if r := rollUp(api.GateKernel{}, fleet, gateJobs("m1air pass", "m3air hung"), []string{"m1"}); r.Result != api.GatePass {
		t.Fatalf("required m1: %s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{}, fleet, gateJobs("m1air pass", "m1mini boot_failed"), []string{"m1"}); r.Result != api.GateFail {
		t.Fatalf("one m1 failed: %s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{}, nil, nil, familyIDs()); r.Result != api.GateFail || len(r.Untested) != 6 {
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
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, familyIDs())
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
	r = rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m2", "m3"})
	if r.Result != api.GateFail || r.Summary != "gate shut: m2 couldn't stage on m2air (job jm2air-a: staging failed: the boot partition is full)" {
		t.Fatalf("%s: %s", r.Result, r.Summary)
	}
	if r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m3"}); r.Result != api.GatePass {
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
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), jobs, []string{"m1", "m2-pro"})
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

func TestGateEvidenceShape(t *testing.T) {
	r := rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), gateJobs("m1air tests_failed gui-smoke"), familyIDs())
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

	b, _ = json.Marshal(rollUp(api.GateKernel{SHA256: "k"}, gateFleet(), gateJobs("m2air stage_failed"), familyIDs()))
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
	gate("/api/gate/"+k[:12]+"?families=m1,m4", 400)
	gate("/api/gate/abcdef0123", 404)
	gate("/api/gate/not-a-kernel", 400)
}

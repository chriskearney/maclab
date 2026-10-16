package server

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
)

// Chip families a release must pass on, by SoC compatible in the device tree.
// M3 Ultra and M4 and later aren't supported.
var families = []struct {
	id, name string
	socs     []string
}{
	{"m1", "M1", []string{"t8103"}},
	{"m1-pro", "M1 Pro/Max/Ultra", []string{"t6000", "t6001", "t6002"}},
	{"m2", "M2", []string{"t8112"}},
	{"m2-pro", "M2 Pro/Max/Ultra", []string{"t6020", "t6021", "t6022"}},
	{"m3", "M3", []string{"t8122"}},
	{"m3-pro", "M3 Pro/Max", []string{"t6030", "t6031", "t6034"}},
}

func familyIDs() []string {
	var ids []string
	for _, f := range families {
		ids = append(ids, f.id)
	}
	return ids
}

var reChip = regexp.MustCompile(`\bM([1-3])(?: (Pro|Max|Ultra))?[,)]`)

// family is a Mac's chip family, from its SoC compatible or, for an agent too
// old to report one, from the device-tree model, e.g. "Apple MacBook Pro
// (14-inch, M1 Pro, 2021)". It is "" for a chip the gate doesn't cover.
func family(f api.Facts) string {
	for _, c := range f.Compatible {
		for _, fam := range families {
			if slices.Contains(fam.socs, strings.TrimPrefix(c, "apple,")) {
				return fam.id
			}
		}
	}
	if len(f.Compatible) > 0 {
		return ""
	}
	m := reChip.FindStringSubmatch(f.DTModel)
	switch {
	case m == nil || m[1] == "3" && m[2] == "Ultra":
		return ""
	case m[2] == "":
		return "m" + m[1]
	}
	return "m" + m[1] + "-pro"
}

// gateResult is what a finished job says about its kernel: pass, fail,
// stage_failed (it never booted), or "" for nothing: canceled, the lab
// itself failed, or no kernel was built to boot. Every other outcome
// (panicked, hung, crashed_or_hung, boot_failed, booted_unhealthy,
// tests_failed) is the kernel's failure, but see runnerFailures.
func gateResult(outcome string) string {
	switch outcome {
	case api.OutcomePass:
		return api.GatePass
	case api.OutcomeStageFailed:
		return api.GateStageFailed
	case api.OutcomeCanceled, api.OutcomeInfra, api.OutcomeBuildFailed, "":
		return ""
	}
	return api.GateFail
}

// runnerFailures says why a tests_failed job says nothing about its kernel:
// every test that failed couldn't run at all, because bash couldn't open its
// script (scriptUnopened), and the kernel logged nothing fatal. It is "" when
// any failure may be the kernel's. Other trouble running a test (a script
// that didn't download, no desktop session, a tool that didn't install) is
// recorded just like a kernel's failure, so it still counts.
func runnerFailures(j *api.Job) string {
	if j.Outcome != api.OutcomeTestsFailed {
		return ""
	}
	for _, e := range j.Result.KernelEvents {
		if detect.Fatal(e.Kind) {
			return ""
		}
	}
	var why []string
	for _, t := range j.Result.Tests {
		if t.Passed {
			continue
		}
		e := scriptUnopened(t)
		if e == "" {
			return ""
		}
		why = append(why, fmt.Sprintf("test %s couldn't run (exit %d: bash couldn't open its script: %s)", t.Name, t.ExitCode, e))
	}
	return strings.Join(why, ", ")
}

// scriptUnopened is bash's error when test t never ran because bash couldn't
// open its script, or "". The agent runs every test as bash <job
// dir>/test-<name>.sh, as the desktop user for a GUI test (omarchy-m-test
// among them), who may not be able to reach the job's directory. Then bash's
// own error for that path is the last thing the test printed, and it exited
// 126 for "Permission denied" or 127 for "No such file or directory". A test
// that ran and exited 126 or 127 itself, say for a binary it couldn't execute
// (Exec format error) or a command it couldn't find, failed like any other.
func scriptUnopened(t api.TestResult) string {
	want := map[int]string{126: "Permission denied", 127: "No such file or directory"}[t.ExitCode]
	if want == "" || t.TimedOut {
		return ""
	}
	tail := strings.TrimSpace(t.Tail)
	last := strings.TrimSpace(tail[strings.LastIndex(tail, "\n")+1:])
	rest, ok := strings.CutPrefix(last, "bash: ")
	if !ok {
		return ""
	}
	if script, ok := strings.CutSuffix(rest, ": "+want); ok && path.Base(script) == "test-"+t.Name+".sh" {
		return want
	}
	return ""
}

// builtinNames are the names job j ran builtin test b under: a test is the
// builtin whatever the job called it.
func builtinNames(j *api.Job, b string) []string {
	var names []string
	for _, t := range testsFor(j.Spec) {
		if t.Builtin == b {
			names = append(names, t.Name)
		}
	}
	return names
}

// omtCompared says whether job j's omarchy-m-test run was compared with a
// known-good run of it on the Mac. One with nothing to compare with checked
// nothing about the kernel: it has no regressions because it had no
// reference. A job from before labd recorded the reference's job has only
// compared_to, which names it this way only after a comparison.
func omtCompared(j *api.Job) bool {
	o := j.Result.OMT
	return o != nil && (o.BaselineJob != "" || strings.HasPrefix(o.ComparedTo, "known-good run "))
}

// customCmdline says how a job changed the Mac's known-good cmdline, or "".
// A verbose boot is no change here: a Mac with a serial console always
// boots verbose.
func customCmdline(s api.JobSpec) string {
	var why []string
	if s.Cmdline != "" {
		why = append(why, fmt.Sprintf("--cmdline %q", s.Cmdline))
	}
	if s.CmdlineBase != "" && s.CmdlineBase != "known-good" {
		why = append(why, fmt.Sprintf("--cmdline-base %q", s.CmdlineBase))
	}
	if len(s.CmdlineStrip) > 0 {
		why = append(why, fmt.Sprintf("--cmdline-strip %q", strings.Join(s.CmdlineStrip, " ")))
	}
	return strings.Join(why, " ")
}

// lessTested says how a job checked less than a plain run on its Mac, or "":
// omarchy-m-test allowances, or a test that every job there runs (boot-health,
// and omarchy-m-test when omt) missing. Tests are known by their builtin.
func lessTested(j *api.Job, omt bool) string {
	var why []string
	if len(j.Spec.OMTAllow) > 0 {
		why = append(why, "--omt-allow "+strings.Join(j.Spec.OMTAllow, ","))
	}
	want := []string{"boot-health"}
	if omt {
		want = append(want, omtTest)
	}
	for _, b := range want {
		names := builtinNames(j, b)
		if !slices.ContainsFunc(j.Result.Tests, func(t api.TestResult) bool { return t.Passed && slices.Contains(names, t.Name) }) {
			why = append(why, b+" didn't run")
		}
	}
	return strings.Join(why, ", ")
}

// gatePrecedence orders run results by how much they decide a family: a
// failure on any Mac decides it, then a Mac that both passed and failed,
// then a pass; a Mac that couldn't stage the kernel decides only when no
// other Mac has a result.
var gatePrecedence = []string{api.GateFail, api.GateFlaky, api.GatePass, api.GateStageFailed}

// gateOpts are a gate's choices besides the required families.
type gateOpts struct {
	// volunteers counts volunteers' Macs (enrolled with ./volunteer), whose
	// agents the lab doesn't control. Otherwise their runs are not counted.
	volunteers bool
	// omt names the Macs whose jobs all run omarchy-m-test now: it decides for
	// jobs that didn't record whether theirs did.
	omt map[string]bool
	// exclude names jobs set aside for this query, say a failure the lab
	// caused that reads as the kernel's: they are listed, not counted.
	exclude map[string]bool
}

// gateMac is a Mac as the gate takes it for a job: what the job recorded of
// it when it was submitted, or for an older job the Mac as labd has it now.
// One name may be more than one Mac over time (lab forget, then enroll
// again), and a job is judged by the one it ran on.
type gateMac struct {
	name, family string
	volunteer    bool
}

// gateRun is job j's line in a gate report, with the result res.
func gateRun(j *api.Job, res string) api.GateRun {
	r := api.GateRun{Device: j.Spec.Device, Job: j.ID, Outcome: j.Outcome, Result: res, Finished: j.Updated}
	if res == api.GateStageFailed {
		r.Reason = j.Summary
	}
	for _, t := range j.Result.Tests {
		tr := api.GateTest{Name: t.Name, Result: api.GatePass}
		if !t.Passed {
			tr.Result = api.GateFail
		}
		r.Tests = append(r.Tests, tr)
	}
	return r
}

// rollUp judges a kernel from each Mac's plain runs on it (jobs come newest
// first). A plain run boots the Mac's known-good cmdline and runs at least
// the tests every job on that Mac runs, with no omarchy-m-test allowances,
// and its omarchy-m-test, where the Mac runs it, was compared with a
// known-good run. A run with a changed cmdline boots something a release
// doesn't, so it counts neither way. A run that tested less counts when it
// failed, since it failed even so, but not when it passed. Canceled and
// infra_error jobs say nothing about the kernel, nor do tests_failed jobs
// whose failed tests couldn't run at all, nor crash tests, which crash it on
// purpose, nor the jobs o.exclude sets aside.
//
// A job is judged by its Mac as it was when the job was submitted: its chip
// family, whether it was a volunteer's and whether its jobs ran
// omarchy-m-test. A job from before labd recorded that is judged by the Mac
// as it is now. A Mac labd no longer has (lab forget) doesn't count: its runs
// are listed as not counted under its family, or under the report when its
// jobs didn't record their family.
//
// A Mac fails when it failed on the kernel and never passed, passes when it
// passed and never failed, and is flaky when it did both: a retry's pass
// doesn't hide an earlier failure, and a flaky Mac doesn't pass. A run that
// couldn't stage the kernel says nothing about it, so it counts only for a
// Mac with no pass or failure. A family fails when any of its Macs failed,
// is flaky when any is flaky, passes when at least one passed, is
// stage_failed when its only results are Macs that couldn't stage the kernel,
// and is untested when none of its Macs has a result. Volunteers' Macs count
// only with o.volunteers, and Macs labd no longer has don't count. Runs that
// don't count are listed per family, with the reason. The gate opens only
// when every required family passed.
func rollUp(k api.GateKernel, devs []api.Device, jobs []*api.Job, required []string, o gateOpts) api.GateReport {
	rep := api.GateReport{Kernel: k, Required: required, VolunteersCounted: o.volunteers}
	cur := map[string]api.Device{}
	for _, d := range devs {
		cur[d.Name] = d
		if family(d.Facts) == "" {
			rep.Unclassified = append(rep.Unclassified, d.Name)
		}
		if d.Volunteer {
			rep.Volunteers = append(rep.Volunteers, d.Name)
		}
	}
	type mac struct {
		pass, fail, unstaged *api.Job      // its newest counted pass, failure and couldn't-stage run
		skipped              []api.GateRun // its runs that don't count
	}
	macs := map[gateMac]*mac{}
	var order []gateMac // the Mac with the newest run first
	for _, j := range jobs {
		res, d := gateResult(j.Outcome), j.Spec.Device
		if j.State != api.JobDone || res == "" || j.Spec.Crash != "" {
			continue // says nothing about the kernel
		}
		if rep.Kernel.Build == "" {
			rep.Kernel.Build = j.Spec.Build
		}
		if rep.Kernel.Release == "" && j.Result.Booted {
			rep.Kernel.Release = j.Result.BootKernel
		}
		key, omt := gateMac{name: d}, false
		if at := j.DeviceAtSubmit; at != nil {
			key.family, key.volunteer, omt = at.Family, at.Volunteer, at.OMT
		} else if now, ok := cur[d]; ok {
			key.family, key.volunteer, omt = family(now.Facts), now.Volunteer, o.omt[d]
		}
		m := macs[key]
		if m == nil {
			m = &mac{}
			macs[key] = m
			order = append(order, key)
		}
		why := ""
		if o.exclude[j.ID] {
			why = "excluded (lab gate --exclude)"
		}
		if why == "" && res == api.GateFail {
			why = runnerFailures(j)
		}
		if c := customCmdline(j.Spec); why == "" && c != "" {
			why = "custom cmdline: " + c
		}
		if l := lessTested(j, omt); why == "" && res == api.GatePass && l != "" {
			why = "tested less than a plain run: " + l
		}
		if why == "" && res == api.GatePass && omt && !omtCompared(j) {
			why = "no OMT reference: omarchy-m-test had no known-good run on " + d + " to compare with (lab baseline makes one)"
		}
		switch {
		case why != "":
			r := gateRun(j, res)
			r.NotCounted, r.Excluded = why, o.exclude[j.ID]
			m.skipped = append(m.skipped, r)
		case res == api.GatePass && m.pass == nil:
			m.pass = j
		case res == api.GateFail && m.fail == nil:
			m.fail = j
		case res == api.GateStageFailed && m.unstaged == nil:
			m.unstaged = j
		}
	}
	runs, skipped := map[string][]api.GateRun{}, map[string][]api.GateRun{}
	for _, key := range order {
		m, f := macs[key], key.family
		_, here := cur[key.name]
		if f == "" && here {
			// no supported family: listed as unclassified
			if !slices.Contains(rep.Unclassified, key.name) {
				rep.Unclassified = append(rep.Unclassified, key.name)
			}
			continue
		}
		var counted []api.GateRun
		switch {
		case m.pass != nil && m.fail != nil:
			fail, pass := gateRun(m.fail, api.GateFlaky), gateRun(m.pass, api.GateFlaky)
			fail.Reason = "passed too, in job " + m.pass.ID
			pass.Reason = fmt.Sprintf("%s too, in job %s", m.fail.Outcome, m.fail.ID)
			counted = []api.GateRun{fail, pass}
		case m.fail != nil:
			counted = []api.GateRun{gateRun(m.fail, api.GateFail)}
		case m.pass != nil:
			counted = []api.GateRun{gateRun(m.pass, api.GatePass)}
		case m.unstaged != nil:
			counted = []api.GateRun{gateRun(m.unstaged, api.GateStageFailed)}
		}
		for i := range counted {
			counted[i].Volunteer = key.volunteer
			switch {
			case !here:
				counted[i].NotCounted = "device gone: labd no longer has " + key.name + " (lab forget)"
			case key.volunteer && !o.volunteers:
				counted[i].NotCounted = "a volunteer's Mac"
			}
		}
		for i := range m.skipped {
			m.skipped[i].Volunteer = key.volunteer
		}
		switch {
		case f == "":
			// gone, and no family to list its runs under
			rep.NotCounted = append(rep.NotCounted, counted...)
			rep.NotCounted = append(rep.NotCounted, m.skipped...)
			continue
		case !here || key.volunteer && !o.volunteers:
			skipped[f] = append(skipped[f], counted...)
		default:
			runs[f] = append(runs[f], counted...)
		}
		skipped[f] = append(skipped[f], m.skipped...)
	}
	byID := map[string]api.GateFamily{}
	for _, f := range families {
		l := runs[f.id]
		slices.SortStableFunc(l, func(a, b api.GateRun) int {
			return slices.Index(gatePrecedence, a.Result) - slices.Index(gatePrecedence, b.Result)
		})
		fr := api.GateFamily{Family: f.id, Name: f.name, Result: api.GateUntested, Runs: l, NotCounted: skipped[f.id]}
		if len(l) > 0 {
			fr.Result = l[0].Result
		} else {
			rep.Untested = append(rep.Untested, f.id)
		}
		byID[f.id] = fr
		rep.Families = append(rep.Families, fr)
	}
	var why []string
	for _, f := range required {
		switch fr := byID[f]; fr.Result {
		case api.GateFail:
			why = append(why, fmt.Sprintf("%s failed (%s, job %s)", f, fr.Runs[0].Device, fr.Runs[0].Job))
		case api.GateFlaky:
			// a flaky Mac's failure comes first, then its pass
			r, p := fr.Runs[0], fr.Runs[1]
			why = append(why, fmt.Sprintf("%s flaky (%s passed in job %s, %s in job %s)", f, r.Device, p.Job, r.Outcome, r.Job))
		case api.GateUntested:
			if n := len(fr.NotCounted); n > 0 {
				why = append(why, fmt.Sprintf("%s untested (%d %s not counted)", f, n, plural(n, "run", "runs")))
			} else {
				why = append(why, f+" untested")
			}
		case api.GateStageFailed:
			r := fr.Runs[0]
			why = append(why, fmt.Sprintf("%s couldn't stage on %s (job %s: %s)", f, r.Device, r.Job, r.Reason))
		}
	}
	rep.Result, rep.Summary = api.GatePass, "gate open: passed on "+strings.Join(required, ", ")
	if len(why) > 0 {
		rep.Result, rep.Summary = api.GateFail, "gate shut: "+strings.Join(why, ", ")
	}
	if o.volunteers && len(rep.Volunteers) > 0 {
		rep.Summary += "; volunteers' Macs counted"
	}
	rep.Excluded = slices.Sorted(maps.Keys(o.exclude))
	if len(rep.Excluded) > 0 {
		rep.Summary += "; excluded " + strings.Join(rep.Excluded, ", ")
	}
	return rep
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

var reKernelPrefix = regexp.MustCompile(`^[0-9a-f]{6,64}$`)

// gateKernel resolves a build id, or a kernel artifact's sha256 or a prefix of
// it that a job has run.
func (s *Server) gateKernel(id string) (api.GateKernel, int, error) {
	if b, err := s.getBuild(id); err == nil {
		if b.Artifact == "" {
			return api.GateKernel{}, 409, fmt.Errorf("build %s is %s and has no kernel", b.ID, b.State)
		}
		return api.GateKernel{SHA256: b.Artifact, Build: b.ID, Release: b.Release}, 200, nil
	}
	if !reKernelPrefix.MatchString(id) {
		return api.GateKernel{}, 400, errors.New("give a build id, or a kernel sha256 or at least 6 characters of it")
	}
	if len(id) == 64 {
		return api.GateKernel{SHA256: id}, 200, nil
	}
	rows, err := s.store.db.Query(`SELECT DISTINCT json_extract(data, '$.spec.kernel') FROM jobs
		WHERE json_extract(data, '$.spec.kernel') LIKE ? || '%'`, id)
	if err != nil {
		return api.GateKernel{}, 500, err
	}
	defer rows.Close()
	var shas []string
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return api.GateKernel{}, 500, err
		}
		shas = append(shas, sha)
	}
	switch len(shas) {
	case 0:
		return api.GateKernel{}, 404, fmt.Errorf("no job has run a kernel %s...", id)
	case 1:
		return api.GateKernel{SHA256: shas[0]}, 200, nil
	}
	return api.GateKernel{}, 400, fmt.Errorf("%s is ambiguous: %s", id, strings.Join(shas, ", "))
}

// hGate reports whether a kernel passed on every required chip family:
// ?families=m1,m2 narrows the requirement from all of them, ?volunteers=1
// counts volunteers' Macs, and ?exclude=j1,j2 sets those jobs of the kernel
// aside for this query, say a failure the lab caused (an access point that
// went down mid-test reads as crashed_or_hung). Nothing is kept: the next
// query without it counts them again.
func (s *Server) hGate(w http.ResponseWriter, r *http.Request) {
	required := familyIDs()
	if v := r.URL.Query().Get("families"); v != "" {
		required = nil
		for _, f := range strings.Split(v, ",") {
			f = strings.TrimSpace(f)
			if !slices.Contains(familyIDs(), f) {
				httpErr(w, 400, "unknown chip family %q (known: %s)", f, strings.Join(familyIDs(), ", "))
				return
			}
			if !slices.Contains(required, f) {
				required = append(required, f)
			}
		}
	}
	o := gateOpts{omt: map[string]bool{}}
	if v := r.URL.Query().Get("volunteers"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			httpErr(w, 400, "volunteers=%q: give 1 to count volunteers' Macs, 0 not to", v)
			return
		}
		o.volunteers = b
	}
	k, code, err := s.gateKernel(r.PathValue("kernel"))
	if err != nil {
		httpErr(w, code, "%v", err)
		return
	}
	jobs, err := s.store.kernelJobs(k.SHA256)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if v := r.URL.Query().Get("exclude"); v != "" {
		o.exclude = map[string]bool{}
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id == "" {
				continue
			}
			if !slices.ContainsFunc(jobs, func(j *api.Job) bool { return j.ID == id }) {
				httpErr(w, 400, "can't exclude %s: it is no finished job of kernel %s", id, short(k.SHA256))
				return
			}
			o.exclude[id] = true
		}
	}
	var devs []api.Device
	for _, v := range s.allDevs() {
		d := v.snapshot()
		devs = append(devs, d)
		o.omt[d.Name] = s.omtWanted(d, api.JobSpec{})
	}
	rep := rollUp(k, devs, jobs, required, o)
	rep.Labd, rep.Generated = r.Host, time.Now().UTC()
	writeJSON(w, rep)
}

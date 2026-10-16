package server

import (
	"errors"
	"fmt"
	"net/http"
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
// every test that failed couldn't run at all, its shell exiting 126 or 127
// (not executable, not found), as omarchy-m-test does when the desktop user
// can't reach the job's directory, and the kernel logged nothing fatal. It
// is "" when any failure may be the kernel's. Other trouble running a test
// (a script that didn't download, no desktop session, a tool that didn't
// install) is recorded just like a kernel's failure, so it still counts.
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
		switch {
		case t.Passed:
		case !t.TimedOut && (t.ExitCode == 126 || t.ExitCode == 127):
			why = append(why, fmt.Sprintf("test %s couldn't run (exit %d)", t.Name, t.ExitCode))
		default:
			return ""
		}
	}
	return strings.Join(why, ", ")
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
// and omarchy-m-test when omt) missing.
func lessTested(j *api.Job, omt bool) string {
	var why []string
	if len(j.Spec.OMTAllow) > 0 {
		why = append(why, "--omt-allow "+strings.Join(j.Spec.OMTAllow, ","))
	}
	want := []string{"boot-health"}
	if omt {
		want = append(want, omtTest)
	}
	for _, w := range want {
		if !slices.ContainsFunc(j.Result.Tests, func(t api.TestResult) bool { return t.Name == w && t.Passed }) {
			why = append(why, w+" didn't run")
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
	// omt names the Macs whose jobs all run omarchy-m-test.
	omt map[string]bool
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
// the tests every job on that Mac runs, with no omarchy-m-test allowances. A
// run with a changed cmdline boots something a release doesn't, so it
// counts neither way. A run that tested less counts when it failed, since it
// failed even so, but not when it passed. Canceled and infra_error jobs say
// nothing about the kernel, nor do tests_failed jobs whose failed tests
// couldn't run at all, nor crash tests, which crash it on purpose.
//
// A Mac fails when it failed on the kernel and never passed, passes when it
// passed and never failed, and is flaky when it did both: a retry's pass
// doesn't hide an earlier failure, and a flaky Mac doesn't pass. A run that
// couldn't stage the kernel says nothing about it, so it counts only for a
// Mac with no pass or failure. A family fails when any of its Macs failed,
// is flaky when any is flaky, passes when at least one passed, is
// stage_failed when its only results are Macs that couldn't stage the kernel,
// and is untested when none of its Macs has a result. Volunteers' Macs count
// only with o.volunteers. Runs that don't count are listed per family, with
// the reason. The gate opens only when every required family passed.
func rollUp(k api.GateKernel, devs []api.Device, jobs []*api.Job, required []string, o gateOpts) api.GateReport {
	rep := api.GateReport{Kernel: k, Required: required, VolunteersCounted: o.volunteers}
	fam, vol := map[string]string{}, map[string]bool{}
	for _, d := range devs {
		if f := family(d.Facts); f != "" {
			fam[d.Name] = f
		} else {
			rep.Unclassified = append(rep.Unclassified, d.Name)
		}
		if d.Volunteer {
			vol[d.Name] = true
			rep.Volunteers = append(rep.Volunteers, d.Name)
		}
	}
	type mac struct {
		pass, fail, unstaged *api.Job      // its newest counted pass, failure and couldn't-stage run
		skipped              []api.GateRun // its runs that don't count
	}
	macs := map[string]*mac{}
	var order []string // the Mac with the newest run first
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
		m := macs[d]
		if m == nil {
			m = &mac{}
			macs[d] = m
			order = append(order, d)
		}
		why := ""
		if res == api.GateFail {
			why = runnerFailures(j)
		}
		if c := customCmdline(j.Spec); why == "" && c != "" {
			why = "custom cmdline: " + c
		}
		if l := lessTested(j, o.omt[d]); why == "" && res == api.GatePass && l != "" {
			why = "tested less than a plain run: " + l
		}
		switch {
		case why != "":
			r := gateRun(j, res)
			r.NotCounted = why
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
	for _, d := range order {
		m, f := macs[d], fam[d]
		if f == "" {
			continue // no supported family: listed as unclassified
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
		if vol[d] {
			for i := range counted {
				counted[i].Volunteer = true
				if !o.volunteers {
					counted[i].NotCounted = "a volunteer's Mac"
				}
			}
			for i := range m.skipped {
				m.skipped[i].Volunteer = true
			}
		}
		if vol[d] && !o.volunteers {
			skipped[f] = append(skipped[f], counted...)
		} else {
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
// ?families=m1,m2 narrows the requirement from all of them, and
// ?volunteers=1 counts volunteers' Macs.
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

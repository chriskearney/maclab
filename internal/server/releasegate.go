package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
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
// stage_failed (it never booted), or "" for nothing (canceled, or the lab
// itself failed).
func gateResult(outcome string) string {
	switch outcome {
	case api.OutcomePass:
		return api.GatePass
	case api.OutcomeStageFailed:
		return api.GateStageFailed
	case api.OutcomeCanceled, api.OutcomeInfra, "":
		return ""
	}
	return api.GateFail
}

// gatePrecedence orders run results by how much they decide a family: a
// failure on any Mac decides it, then a pass; a Mac that couldn't stage the
// kernel decides only when no other Mac has a result.
var gatePrecedence = []string{api.GateFail, api.GatePass, api.GateStageFailed}

// rollUp judges a kernel from each Mac's latest pass or failure on it (jobs
// come newest first). A Mac that couldn't stage the kernel says nothing about
// it, so that run counts only when the Mac has no pass or failure on the
// kernel; crash tests boot the kernel only to crash it, so they don't count at
// all. A family fails when any of its Macs' latest runs failed,
// passes when at least one passed and none failed, is stage_failed when its
// only results are Macs that couldn't stage the kernel, and is untested when
// none of its Macs has a result. The gate opens only when every required
// family passed.
func rollUp(k api.GateKernel, devs []api.Device, jobs []*api.Job, required []string) api.GateReport {
	rep := api.GateReport{Kernel: k, Required: required}
	fam := map[string]string{}
	for _, d := range devs {
		if f := family(d.Facts); f != "" {
			fam[d.Name] = f
		} else {
			rep.Unclassified = append(rep.Unclassified, d.Name)
		}
	}
	runs := map[string][]api.GateRun{}
	add := func(j *api.Job, res string) {
		if rep.Kernel.Build == "" {
			rep.Kernel.Build = j.Spec.Build
		}
		if rep.Kernel.Release == "" && j.Result.Booted {
			rep.Kernel.Release = j.Result.BootKernel
		}
		f := fam[j.Spec.Device]
		if f == "" {
			return
		}
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
		runs[f] = append(runs[f], r)
	}
	decided := map[string]bool{}      // the Mac's latest pass or failure is in
	unstaged := map[string]*api.Job{} // its latest couldn't-stage run, if it has nothing else
	for _, j := range jobs {
		res, d := gateResult(j.Outcome), j.Spec.Device
		switch {
		case j.State != api.JobDone || res == "" || j.Spec.Crash != "" || decided[d]:
			// says nothing about the kernel, or the Mac already has its result
		case res == api.GateStageFailed:
			if unstaged[d] == nil {
				unstaged[d] = j
			}
		default:
			decided[d] = true
			add(j, res)
		}
	}
	for _, j := range jobs {
		if d := j.Spec.Device; unstaged[d] == j && !decided[d] {
			add(j, api.GateStageFailed)
		}
	}
	byID := map[string]api.GateFamily{}
	for _, f := range families {
		l := runs[f.id]
		slices.SortStableFunc(l, func(a, b api.GateRun) int {
			return slices.Index(gatePrecedence, a.Result) - slices.Index(gatePrecedence, b.Result)
		})
		fr := api.GateFamily{Family: f.id, Name: f.name, Result: api.GateUntested, Runs: l}
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
		case api.GateUntested:
			why = append(why, f+" untested")
		case api.GateStageFailed:
			r := fr.Runs[0]
			why = append(why, fmt.Sprintf("%s couldn't stage on %s (job %s: %s)", f, r.Device, r.Job, r.Reason))
		}
	}
	rep.Result, rep.Summary = api.GatePass, "gate open: passed on "+strings.Join(required, ", ")
	if len(why) > 0 {
		rep.Result, rep.Summary = api.GateFail, "gate shut: "+strings.Join(why, ", ")
	}
	return rep
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
// ?families=m1,m2 narrows the requirement from all of them.
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
		devs = append(devs, v.snapshot())
	}
	rep := rollUp(k, devs, jobs, required)
	rep.Labd, rep.Generated = r.Host, time.Now().UTC()
	writeJSON(w, rep)
}

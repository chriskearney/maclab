package server

// omarchy-m-test (github.com/maralcbr/omarchy-m-testing) checks every hardware
// feature of a Mac under Omarchy and writes a signed report. The lab runs it
// in the desktop session after a boot, compares the report with the same
// Mac's report on its known-good kernel, and can publish known-good reports
// to omarchy-m-testing.org.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// omtPackagingChecks look for the running kernel among the installed packages
// and in /boot. A lab boot runs a kernel that is neither, so they fail for
// every lab kernel and say nothing about it. boot.chain runs Omarchy's boot
// check, which wants the installed linux-aurora running (Limine Macs).
var omtPackagingChecks = map[string]bool{"boot.files": true, "boot.kernel-package": true, "boot.chain": true}

const (
	omtTest     = "omarchy-m-test"
	omtFile     = "test-" + omtTest + "/omt-report.json" // omtReportFile(omtTest)
	omtMinAgent = "0.3.0"                                // first agent with the builtin test
)

// omtReportFile is where a job keeps the report of its omarchy-m-test run
// named name: the agent uploads a test's files under test-<name>/. The test
// is the builtin omarchy-m-test whatever its name in the job.
func omtReportFile(name string) string { return "test-" + name + "/omt-report.json" }

// omtReport is the part of a report the lab reads; the file itself is kept whole.
type omtReport struct {
	Tool struct {
		Version string `json:"version"`
	} `json:"tool"`
	Catalogue int `json:"catalogue_version"`
	Machine   struct {
		Kernel string `json:"kernel"`
	} `json:"machine"`
	Inventory struct {
		Unclaimed []struct {
			Compatible string `json:"compatible"`
			Count      int    `json:"count"` // its nodes no driver claimed
			Outcome    string `json:"outcome"`
		} `json:"unclaimed"`
	} `json:"inventory"`
	Checks []struct {
		ID             string   `json:"id"`
		Status         string   `json:"status"`
		Evidence       []string `json:"evidence"`
		Classification struct {
			Outcome string `json:"outcome"`
		} `json:"classification"`
	} `json:"checks"`
}

// omtBaseline is the known-good report a Mac's other runs are compared with.
type omtBaseline struct {
	Job       string            `json:"job"`
	Time      time.Time         `json:"time"`
	Kernel    string            `json:"kernel"`
	Tool      string            `json:"tool"`
	Status    map[string]string `json:"status"`              // check id -> pass, fail or skip
	Unclaimed []string          `json:"unclaimed,omitempty"` // compatibles of the device-tree nodes no driver claimed
	// UnclaimedNodes counts those nodes per compatible. References from
	// before it was kept have only Unclaimed.
	UnclaimedNodes map[string]int `json:"unclaimed_nodes,omitempty"`
}

func (s *Server) omtBaselinePath(device string) string {
	return filepath.Join(s.cfg.DataDir, "baselines", device+".omt.json")
}

func (s *Server) omtBaseline(device string) *omtBaseline {
	b, err := os.ReadFile(s.omtBaselinePath(device))
	if err != nil {
		return nil
	}
	var base omtBaseline
	if json.Unmarshal(b, &base) != nil {
		return nil
	}
	return &base
}

// omtWanted says whether a job on this Mac runs omarchy-m-test without being asked:
// it needs a desktop user and an agent that carries the test.
func (s *Server) omtWanted(d api.Device, spec api.JobSpec) bool {
	return s.cfg.OMT && spec.Crash == "" && d.Facts.GUIUser != "" && versionAtLeast(d.Facts.AgentVersion, omtMinAgent)
}

func omtSpec() api.TestSpec {
	return api.TestSpec{Name: omtTest, Builtin: omtTest, GUI: true, TimeoutSec: 900}
}

// omtResult reads the report a finished omarchy-m-test left in the job,
// compares it with the Mac's known-good report, and records it as the new
// baseline when this run was on the known-good kernel.
func (r *jobRun) omtResult(tr *api.TestResult) {
	j := r.j
	file := omtReportFile(tr.Name)
	path := filepath.Join(r.s.jobDir(j.ID), file)
	data, err := os.ReadFile(path)
	if err != nil {
		if tr.Passed {
			tr.Passed, tr.Error = false, "omarchy-m-test wrote no report"
		}
		return
	}
	var rep omtReport
	if err := json.Unmarshal(data, &rep); err != nil {
		tr.Passed, tr.Error = false, "omarchy-m-test report is not JSON: "+err.Error()
		return
	}
	res := &api.OMTResult{Report: file, Tool: rep.Tool.Version, Catalogue: rep.Catalogue, Kernel: rep.Machine.Kernel,
		KnownGood: j.Spec.Kernel == "" && j.Spec.Source == ""}
	status := map[string]string{}
	byID := map[string]api.OMTCheck{}
	for _, c := range rep.Checks {
		status[c.ID] = c.Status
		ev := ""
		if len(c.Evidence) > 0 {
			ev = c.Evidence[0]
		}
		chk := api.OMTCheck{ID: c.ID, Outcome: c.Classification.Outcome, Evidence: ev}
		byID[c.ID] = chk
		switch c.Status {
		case "pass":
			res.Pass++
		case "fail":
			res.Fail++
			res.Fails = append(res.Fails, chk)
		default:
			res.Skip++
		}
	}
	var unclaimed []string
	for _, u := range rep.Inventory.Unclaimed {
		unclaimed = append(unclaimed, u.Compatible)
	}
	sort.Strings(unclaimed)
	nodes := unclaimedNodes(rep)
	if r.ir != nil {
		// an installed run is judged against the frozen pre-install report and
		// never becomes a reference
		res.KnownGood = false
		r.ir.omt(tr, res, data)
		r.s.updateJob(j, func(j *api.Job) { j.Result.OMT = res })
		r.ev("omarchy-m-test %s: %d pass, %d fail, %d skipped; %s vs %s", res.Tool, res.Pass, res.Fail, res.Skip, r.ir.res.OMT, res.ComparedTo)
		return
	}
	base := r.s.omtBaseline(j.Spec.Device)
	switch {
	case res.KnownGood:
		res.ComparedTo = "this is the known-good run: later runs are compared with it"
		if base != nil {
			res.Regressions, res.Fixed = omtDiff(base.Status, status, byID)
			nr, nf := omtNodes(base, status, rep)
			res.Regressions, res.Fixed = append(res.Regressions, nr...), append(res.Fixed, nf...)
			res.ComparedTo, res.BaselineJob = "the previous known-good run "+base.Job, base.Job
		}
	case base == nil:
		res.ComparedTo = "no known-good run of omarchy-m-test on this Mac yet (lab baseline makes one)"
	default:
		res.Regressions, res.Fixed = omtDiff(base.Status, status, byID)
		nr, nf := omtNodes(base, status, rep)
		res.Regressions, res.Fixed = append(res.Regressions, nr...), append(res.Fixed, nf...)
		kept := res.Regressions[:0]
		for _, c := range res.Regressions {
			if omtPackagingChecks[c.ID] {
				res.LabBoot = append(res.LabBoot, c)
			} else {
				kept = append(kept, c)
			}
		}
		res.Regressions = kept
		res.Regressions, res.Allowed = omtAllowed(res.Regressions, j.Spec.OMTAllow, rep)
		res.ComparedTo, res.BaselineJob = "known-good run "+base.Job+" on "+base.Kernel, base.Job
		if base.Tool != res.Tool {
			res.ComparedTo += fmt.Sprintf(" (omarchy-m-test %s then, %s now)", base.Tool, res.Tool)
		}
	}
	r.s.updateJob(j, func(j *api.Job) { j.Result.OMT = res })
	r.ev("omarchy-m-test %s: %d pass, %d fail, %d skipped; %d regressed, %d fixed vs %s",
		res.Tool, res.Pass, res.Fail, res.Skip, len(res.Regressions), len(res.Fixed), res.ComparedTo)
	var changed []string
	for _, c := range res.Regressions {
		changed = append(changed, c.ID+" regressed")
	}
	for _, c := range res.Fixed {
		changed = append(changed, c.ID+" fixed")
	}
	if len(changed) > 0 {
		r.ev("omarchy-m-test: %s", strings.Join(changed, ", "))
	}
	if j.Spec.Mesa != nil {
		res.Reference = "staged Mesa diagnostic: kept existing installed-desktop reference"
		r.s.updateJob(j, func(j *api.Job) { j.Result.OMT = res })
	} else if res.KnownGood {
		// A known-good kernel can't regress against itself in a way that blames
		// the kernel, so the test isn't failed. But a pass that turned into a
		// fail says something else changed (boot.bin, firmware, a cable), and a
		// run like that must not become the reference later runs are judged by.
		kg := r.v.snapshot().KnownGood
		switch {
		case j.Spec.Baseline:
			// lab baseline is how a person sets the references on purpose
			r.omtRef, _ = json.MarshalIndent(omtBaseline{Job: j.ID, Time: time.Now(), Kernel: res.Kernel, Tool: res.Tool, Status: status,
				Unclaimed: unclaimed, UnclaimedNodes: nodes}, "", "  ")
			res.Reference = "a baseline: becomes the reference if it passes"
		case len(res.Regressions) > 0:
			res.Reference = fmt.Sprintf("kept %s: %s regressed since", base.Job, strings.Join(omtIDs(res.Regressions), ", "))
		case kg == "" || res.Kernel != kg:
			res.Reference = fmt.Sprintf("not a reference: ran on %s, the known-good kernel is %q", res.Kernel, kg)
		case j.Spec.Cmdline != "" || len(j.Spec.CmdlineStrip) > 0 || (j.Spec.CmdlineBase != "" && j.Spec.CmdlineBase != "known-good"):
			res.Reference = "not a reference: the job changed the known-good cmdline"
		default:
			r.omtRef, _ = json.MarshalIndent(omtBaseline{Job: j.ID, Time: time.Now(), Kernel: res.Kernel, Tool: res.Tool, Status: status,
				Unclaimed: unclaimed, UnclaimedNodes: nodes}, "", "  ")
			res.Reference = "becomes the reference if the job passes"
		}
		r.s.updateJob(j, func(j *api.Job) { j.Result.OMT = res })
		return
	}
	if len(res.Regressions) > 0 {
		tr.Passed = false
		tr.Error = fmt.Sprintf("%d regressed from the known-good kernel: %s", len(res.Regressions), strings.Join(omtIDs(res.Regressions), ", "))
	}
}

// omtIDs lists the ids of the checks.
func omtIDs(cs []api.OMTCheck) []string {
	ids := make([]string, len(cs))
	for i, c := range cs {
		ids[i] = c.ID
	}
	return ids
}

// omtAllowed moves the regressions a job said to expect out of the way. A
// plain check id allows that check; "hardware.drivers:<compatible>" allows the
// driver check only when every node left unbound is one of the named ones, and
// allows that node's own regression (omtNodes).
func omtAllowed(regressed []api.OMTCheck, allow []string, rep omtReport) (kept, allowed []api.OMTCheck) {
	ids, compat := map[string]bool{}, map[string]bool{}
	for _, a := range allow {
		if c, ok := strings.CutPrefix(a, "hardware.drivers:"); ok {
			compat[c] = true
		} else {
			ids[a] = true
		}
	}
	for _, c := range regressed {
		ok := ids[c.ID]
		if node, isNode := strings.CutPrefix(c.ID, "hardware.drivers:"); isNode {
			ok = ids["hardware.drivers"] || compat[node]
		} else if !ok && c.ID == "hardware.drivers" && len(compat) > 0 && len(rep.Inventory.Unclaimed) > 0 {
			ok = true
			for _, u := range rep.Inventory.Unclaimed {
				ok = ok && compat[u.Compatible]
			}
		}
		if ok {
			allowed = append(allowed, c)
		} else {
			kept = append(kept, c)
		}
	}
	return kept, allowed
}

// omtDiff lists the checks that went from pass to fail, and from fail to pass.
// Skips on either side compare as nothing: a skip says nothing about the kernel.
func omtDiff(before, after map[string]string, byID map[string]api.OMTCheck) (regressed, fixed []api.OMTCheck) {
	ids := make([]string, 0, len(after))
	for id := range after {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		switch {
		case before[id] == "pass" && after[id] == "fail":
			regressed = append(regressed, byID[id])
		case before[id] == "fail" && after[id] == "pass":
			fixed = append(fixed, byID[id])
		}
	}
	return
}

// unclaimedNodes counts a report's unclaimed device-tree nodes per
// compatible. A report that gives no count lists each one as one node.
func unclaimedNodes(rep omtReport) map[string]int {
	n := map[string]int{}
	for _, u := range rep.Inventory.Unclaimed {
		n[u.Compatible] += max(u.Count, 1)
	}
	return n
}

// omtNodes compares the device-tree nodes no driver claims, compatible by
// compatible, when hardware.drivers fails on both runs and omtDiff sees no
// change. More nodes of a compatible unclaimed now than on the known-good run
// (none then, or 3 against 1) regress as "hardware.drivers:<compatible>";
// fewer are fixed. A reference from before the lab counted nodes has only
// their compatibles: then a compatible regresses only if it wasn't unclaimed
// at all, and is fixed only once none is.
func omtNodes(base *omtBaseline, status map[string]string, rep omtReport) (regressed, fixed []api.OMTCheck) {
	if base.Status["hardware.drivers"] != "fail" || status["hardware.drivers"] != "fail" ||
		len(base.Unclaimed) == 0 || len(rep.Inventory.Unclaimed) == 0 {
		return nil, nil
	}
	var evidence []string
	for _, c := range rep.Checks {
		if c.ID == "hardware.drivers" {
			evidence = c.Evidence
		}
	}
	counted := base.UnclaimedNodes != nil
	before := map[string]int{}
	for _, c := range base.Unclaimed {
		before[c] = 1
	}
	for c, n := range base.UnclaimedNodes {
		before[c] = n
	}
	now := unclaimedNodes(rep)
	seen := map[string]bool{}
	for _, u := range rep.Inventory.Unclaimed {
		c := u.Compatible
		if seen[c] {
			continue
		}
		seen[c] = true
		if b := before[c]; b > 0 && (!counted || now[c] <= b) {
			continue
		}
		chk := api.OMTCheck{ID: "hardware.drivers:" + c, Outcome: u.Outcome}
		for _, e := range evidence {
			if strings.HasPrefix(e, "unclaimed: "+c+" ") {
				chk.Evidence = e
			}
		}
		if b := before[c]; b > 0 {
			chk.Evidence = strings.TrimSuffix(fmt.Sprintf("%d nodes unclaimed, %d on the known-good kernel; %s", now[c], b, chk.Evidence), "; ")
		}
		regressed = append(regressed, chk)
	}
	seen = map[string]bool{}
	for _, c := range base.Unclaimed {
		if seen[c] {
			continue
		}
		seen[c] = true
		switch n, b := now[c], before[c]; {
		case n == 0:
			fixed = append(fixed, api.OMTCheck{ID: "hardware.drivers:" + c, Evidence: "claimed by a driver now"})
		case counted && n < b:
			fixed = append(fixed, api.OMTCheck{ID: "hardware.drivers:" + c, Evidence: fmt.Sprintf("%d of its %d nodes claimed by a driver now", b-n, b)})
		}
	}
	return regressed, fixed
}

// publishOMT uploads a job's report to omarchy-m-testing.org, the way
// `omarchy-m-test` itself does after its upload prompt. Only a run on the
// Mac's known-good kernel qualifies: the site names a report's build from the
// installed packages, and a lab kernel isn't one, so it would be filed under
// the wrong kernel.
func (s *Server) publishOMT(ctx context.Context, j *api.Job) (string, error) {
	res := j.Result.OMT
	switch {
	case j.Spec.Mesa != nil:
		return "", errors.New("staged Mesa diagnostics are private and never published")
	case s.cfg.OMTSite == "":
		return "", errors.New("publishing is off (labd --omt-site)")
	case res == nil:
		return "", errors.New("this job has no omarchy-m-test report")
	case res.Published != "":
		return res.Published, nil
	case !res.KnownGood:
		return "", fmt.Errorf("ran on lab kernel %s, which the installed packages don't describe; only known-good runs are published", res.Kernel)
	}
	// A baseline makes the kernel it booted the known-good one, but only once it
	// finishes, after this upload; until then compare with what it booted.
	if j.Spec.Baseline {
		if res.Kernel != j.Result.BootKernel {
			return "", fmt.Errorf("report names kernel %s but the baseline booted %s", res.Kernel, j.Result.BootKernel)
		}
	} else if v := s.dev(j.Spec.Device); v == nil {
		// lab forget dropped the Mac, and its known-good kernel with it
		return "", fmt.Errorf("%s was forgotten (lab forget), so there is no known-good kernel to check the report against", j.Spec.Device)
	} else if kg := v.snapshot().KnownGood; kg != "" && res.Kernel != kg {
		return "", fmt.Errorf("report names kernel %s but the known-good kernel is %s", res.Kernel, kg)
	}
	body, err := os.ReadFile(filepath.Join(s.jobDir(j.ID), res.Report))
	if err != nil {
		return "", err
	}
	site := strings.TrimRight(s.cfg.OMTSite, "/")
	req, _ := http.NewRequestWithContext(ctx, "POST", site+"/api/v1/reports", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "maclab (github.com/iconidentify/maclab)")
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var reply struct {
		ReportURL   string   `json:"report_url"`
		DeletionURL string   `json:"deletion_url"`
		Error       string   `json:"error"`
		Details     []string `json:"details"`
	}
	json.Unmarshal(out, &reply)
	if resp.StatusCode != http.StatusCreated {
		msg := reply.Error
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		if len(reply.Details) > 0 {
			msg += " (" + strings.Join(reply.Details, "; ") + ")"
		}
		return "", fmt.Errorf("%s: %s", resp.Status, msg)
	}
	// The deletion link takes the report down again; it stays with the job, not in the API.
	os.WriteFile(filepath.Join(s.jobDir(j.ID), "omt-published.json"), out, 0o600)
	return reply.ReportURL, nil
}

// omtPublish publishes a job's report and records the outcome on the job.
func (s *Server) omtPublish(ctx context.Context, j *api.Job) (string, error) {
	url, err := s.publishOMT(ctx, j)
	s.updateJob(j, func(j *api.Job) {
		if j.Result.OMT == nil {
			return
		}
		if err != nil {
			j.Result.OMT.PublishNote = err.Error()
		} else {
			j.Result.OMT.Published, j.Result.OMT.PublishNote = url, ""
		}
	})
	return url, err
}

// omtScheduler re-runs omarchy-m-test on each Mac's known-good kernel once
// every OMTEvery, publishing the result if that's on: the reference that lab
// kernels are compared with stays fresh, and so does the site.
func (s *Server) omtScheduler() {
	if s.cfg.OMTEvery <= 0 {
		return
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		for _, v := range s.allDevs() {
			d := v.snapshot()
			if d.State != api.StateReady || d.ActiveJob != "" || !s.omtWanted(d, api.JobSpec{}) {
				continue
			}
			if l := d.Lease; l != nil && time.Now().Before(l.Expires) {
				continue
			}
			if base := s.omtBaseline(d.Name); base != nil && time.Since(base.Time) < s.cfg.OMTEvery {
				continue
			}
			if open, _ := s.store.jobs(d.Name, 1, true); len(open) > 0 {
				continue
			}
			j, _, err := s.Submit(api.JobSpec{Device: d.Name, Holder: "maclab-omt", Publish: s.cfg.OMTPublish})
			if err != nil {
				s.log.Printf("%s: scheduled omarchy-m-test: %v", d.Name, err)
				continue
			}
			s.log.Printf("%s: scheduled omarchy-m-test on the known-good kernel: job %s", d.Name, j.ID)
		}
	}
}

// versionAtLeast compares dotted version numbers.
func versionAtLeast(have, want string) bool {
	h, w := strings.Split(have, "."), strings.Split(want, ".")
	for i := range w {
		var a, b int
		if i < len(h) {
			a, _ = strconv.Atoi(h[i])
		}
		b, _ = strconv.Atoi(w[i])
		if a != b {
			return a > b
		}
	}
	return true
}

// promoteOMT makes a known-good run the reference once the whole job passed:
// a failed test, an unhealthy boot or a failed restore keeps the old one.
func (r *jobRun) promoteOMT(outcome string) {
	j := r.j
	if outcome != api.OutcomePass {
		r.ev("omarchy-m-test reference kept: the job ended %s", outcome)
		r.s.updateJob(j, func(j *api.Job) {
			if j.Result.OMT != nil {
				j.Result.OMT.Reference = "kept the previous reference: the job ended " + outcome
			}
		})
		return
	}
	if err := writeFileAtomic(r.s.omtBaselinePath(j.Spec.Device), r.omtRef); err != nil {
		r.ev("omarchy-m-test reference: %v", err)
		return
	}
	r.ev("omarchy-m-test reference is now this run")
	r.s.updateJob(j, func(j *api.Job) {
		if j.Result.OMT != nil {
			j.Result.OMT.Reference = "became the reference"
		}
	})
}

// writeFileAtomic replaces path with data, never leaving a partial file, and
// syncs the file and its directory.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

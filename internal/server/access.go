package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/iconidentify/maclab/internal/api"
)

// A Volunteer's Mac has an Access level, chosen by its Volunteer on the Mac:
// at Qualification (the default) labd takes no lab exec and no Maintainer's
// script for it, and lab-agent refuses them whatever labd sends. Its screen
// and live journal are watched only while a job or lease holds it inside its
// window. Scope (see mayDo) is where labd decides these. Every Maintainer
// action reaching it lands in its Audit log, which the Mac reports to labd
// for a copy. Lab-owned Macs have none of this.

// errAccessLevel matches lab-agent refusing or stopping a command because
// the Mac's Access level doesn't allow it.
var errAccessLevel = errors.New("the Mac's Access level doesn't allow it")

// accessCut is the outcome of a job cut short (what says when) because the
// Volunteer lowered the Access level: incomplete, as when the window closes.
// lab-agent stopped it by itself.
func accessCut(what string) (string, string) {
	return api.OutcomeIncomplete, "the Volunteer lowered the Mac's Access level to Qualification " + what
}

// syncAccessLocked takes the Access level and publishing opt-in a check-in
// carried as labd's copy, and says whether they changed. Lowering the level
// ends a lease at once. Only a Volunteer's Mac has them. Caller holds v.mu.
func (v *dev) syncAccessLocked(ci api.Checkin) bool {
	if !v.d.IsVolunteer() || ci.AccessLevel == "" {
		return false
	}
	if v.d.AccessLevel == ci.AccessLevel && v.d.Publish == ci.Publish {
		return false
	}
	lowered := v.d.AccessLevel == api.AccessFull && ci.AccessLevel != api.AccessFull
	v.d.AccessLevel, v.d.Publish = ci.AccessLevel, ci.Publish
	if l := v.d.Lease; lowered && l != nil && v.s.now().Before(l.Expires) {
		v.s.log.Printf("%s: its Volunteer lowered the Access level; %s's lease ends", v.d.Name, l.Holder)
		v.d.Lease = &api.Lease{Holder: l.Holder, Expires: v.s.now()}
	}
	return true
}

// needsFull is why a job spec needs a Volunteer's Mac at Full, or "": a
// Maintainer's script, as root or in the Volunteer's session.
func needsFull(spec api.JobSpec) string {
	if spec.Mesa != nil {
		return "staged Mesa packages"
	}
	for _, t := range spec.Tests {
		switch {
		case t.MaintainerScript() && t.GUI:
			return "test " + t.Name + " is a --gui-script"
		case t.MaintainerScript():
			return "test " + t.Name + " is a --script"
		}
	}
	return ""
}

// heldLocked is whether a job or lease holds the Mac now. Caller holds v.mu.
func (v *dev) heldLocked() bool {
	return v.d.ActiveJob != "" || (v.d.Lease != nil && v.s.now().Before(v.d.Lease.Expires))
}

// ---- labd's copy of each Mac's Audit log ----

func (s *Server) auditPath(name string) string {
	return filepath.Join(s.cfg.DataDir, "audit", name+".jsonl")
}

// readAuditCopy reads labd's copy of a Mac's Audit log.
func (s *Server) readAuditCopy(name string) ([]api.AuditEntry, error) {
	b, err := os.ReadFile(s.auditPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []api.AuditEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e api.AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// auditHaveLocked is how much of the Mac's Audit log labd's copy holds, in
// bytes of the Mac's log. Caller holds v.auditMu.
func (v *dev) auditHaveLocked() int64 {
	if v.auditHave < 0 {
		v.auditHave = 0
		if es, err := v.s.readAuditCopy(v.d.Name); err == nil && len(es) > 0 {
			v.auditHave = es[len(es)-1].End
		}
	}
	return v.auditHave
}

// auditHaveNow is auditHaveLocked for callers not holding v.auditMu.
func (v *dev) auditHaveNow() int64 {
	v.auditMu.Lock()
	defer v.auditMu.Unlock()
	return v.auditHaveLocked()
}

// copyAudit adds the entries a report carried to labd's copy, each once.
func (v *dev) copyAudit(es []api.AuditEntry) {
	if len(es) == 0 {
		return
	}
	v.auditMu.Lock()
	defer v.auditMu.Unlock()
	have := v.auditHaveLocked()
	var b bytes.Buffer
	for _, e := range es {
		if e.End <= have {
			continue
		}
		line, _ := json.Marshal(e)
		b.Write(append(line, '\n'))
		have = e.End
	}
	if b.Len() == 0 {
		return
	}
	p := v.s.auditPath(v.d.Name)
	err := os.MkdirAll(filepath.Dir(p), 0o755)
	var f *os.File
	if err == nil {
		f, err = os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	}
	if err == nil {
		_, err = f.Write(b.Bytes())
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		v.s.log.Printf("%s: Audit log copy: %v", v.d.Name, err)
		return
	}
	v.auditHave = have
}

// hAudit is labd's copy of a Volunteer Mac's Audit log, for Maintainers.
func (s *Server) hAudit(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	es, err := s.readAuditCopy(v.d.Name)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if es == nil {
		es = []api.AuditEntry{}
	}
	writeJSON(w, es)
}

// hAgentPublished lists a Volunteer's Mac's published omarchy-m-test reports
// with their deletion links, for `lab-agent publish on`.
func (s *Server) hAgentPublished(w http.ResponseWriter, r *http.Request) {
	v := agentDev(r)
	jobs, err := s.store.jobs(v.snapshot().Name, 1000, false)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	out := []api.Published{}
	for i := len(jobs) - 1; i >= 0; i-- { // oldest first
		j := jobs[i]
		if j.Result.OMT == nil || j.Result.OMT.Published == "" {
			continue
		}
		var reply struct {
			DeletionURL string `json:"deletion_url"`
		}
		b, _ := os.ReadFile(filepath.Join(s.jobDir(j.ID), "omt-published.json"))
		json.Unmarshal(b, &reply)
		out = append(out, api.Published{Job: j.ID, ReportURL: j.Result.OMT.Published, DeletionURL: reply.DeletionURL})
	}
	writeJSON(w, out)
}

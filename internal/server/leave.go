package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// hLeave is lab-agent uninstall saying, before it undoes anything, that the
// Mac is leaving the lab. Without it, labd would read the stopped agent as a
// Mac that hung: it would reset the Mac through its out-of-band controller,
// twice, and then ask a human to power cycle it.
func (s *Server) hLeave(w http.ResponseWriter, r *http.Request) {
	var req api.LeaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		httpErr(w, 400, "%v", err)
		return
	}
	why := orStr(req.Reason, "lab-agent uninstall")
	if len(why) > 200 {
		why = why[:200]
	}
	v := agentDev(r)
	if req.Undo {
		if _, err := s.rejoin(v, why); err != nil {
			httpErr(w, 404, "%v", err)
			return
		}
		writeJSON(w, api.LeaveResponse{Name: v.snapshot().Name, Back: true})
		return
	}
	canceled, err := s.leave(v, why)
	switch {
	case errors.Is(err, errForgotten):
		httpErr(w, 404, "%v", err)
		return
	case err != nil:
		httpErr(w, 500, "%v", err)
		return
	}
	writeJSON(w, api.LeaveResponse{Name: v.snapshot().Name, Canceled: canceled})
}

// leave takes v out of the pool: it goes to StateLeft, which only lab forget,
// an undo from uninstall or lab reset (rejoin) moves it out of, so no
// automatic recovery resets it and no alert asks for hands. Its running job
// is canceled, ending without a restore, and its queued jobs are canceled
// before they start. It returns the canceled jobs.
func (s *Server) leave(v *dev, why string) ([]string, error) {
	v.mu.Lock()
	if v.forgotten {
		v.mu.Unlock()
		return nil, errForgotten
	}
	name := v.d.Name
	if v.d.State != api.StateLeft {
		v.leftBy = why
		v.setStateLocked(api.StateLeft, why+" ran at "+s.now().Format(time.DateTime)+"; `lab forget "+name+"` takes it out of the lab, `lab reset "+name+"` puts it back")
	}
	v.mu.Unlock()
	s.log.Printf("%s is leaving the lab: %s", name, why)

	open, err := s.store.jobs(name, 1000, true)
	if err != nil {
		return nil, err
	}
	var canceled []string
	for _, j := range open {
		canceled = append(canceled, j.ID)
		s.mu.Lock()
		cancel := s.cancels[j.ID]
		s.mu.Unlock()
		if cancel != nil {
			cancel() // runJob ends it, with the reason from v.leaving
			continue
		}
		s.updateJob(j, func(j *api.Job) {
			j.State, j.Outcome, j.Canceled = api.JobDone, api.OutcomeCanceled, true
			j.Summary = "canceled before it started: " + name + " left the lab (" + why + ")"
		})
	}
	return canceled, nil
}

// rejoin puts a Mac that left the lab back in it, idle, as if it had never
// left; the jobs canceled then stay canceled. why is what brings it back:
// lab-agent uninstall stopping before it stopped the agent (LeaveRequest.Undo),
// or an admin's lab reset. It says whether the Mac had left.
func (s *Server) rejoin(v *dev, why string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.forgotten {
		return false, errForgotten
	}
	if v.d.State != api.StateLeft {
		return false, nil
	}
	// setStateLocked keeps a Mac that left where it is: this is the way out.
	v.leftBy = ""
	v.d.State, v.d.StateReason, v.d.Action = v.idleStateLocked(), "", nil
	v.saveLocked()
	v.publishLocked()
	v.bump()
	s.log.Printf("%s is back in the lab: %s", v.d.Name, why)
	return true, nil
}

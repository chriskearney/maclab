package server

// A Mac's enrollment ends from either side: its Volunteer runs
// `sudo lab-agent leave`, or a Maintainer ends it in labd. Either way the Mac
// is gone from labd at once, its device secret with it, and a job running on
// it ends incomplete. When a Maintainer ends it, labd remembers whose secret
// it was and who ended it, so a Mac that checks in again with that secret
// learns it was ended, not just revoked, and cleans up.

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// endedHeader carries, on the 401 an ended Mac's old secret gets, the
// Maintainer who ended its enrollment.
const endedHeader = api.EndedHeader

var errMacGone = errors.New("the Mac is no longer enrolled")

// goneReason is why the Mac left the lab, or "" while it is enrolled.
func (v *dev) goneReason() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.goneWhy
}

// endEnrollment removes v from labd for reason, revoking its device secret.
// by is the Maintainer who ended it, or "" when the Mac left on its own; a
// Maintainer's name is kept with the secret for the Mac to learn. It is false
// when the Mac was not enrolled any more.
func (s *Server) endEnrollment(v *dev, by, reason string) bool {
	v.mu.Lock()
	name, id, secretHash, e := v.d.Name, v.d.ID, v.secretHash, v.d.Enrollment
	// As lab forget does: nothing still holding v may write its row back.
	if v.forgotten {
		v.mu.Unlock()
		return false
	}
	v.forgotten = true
	v.mu.Unlock()
	s.mu.Lock()
	if s.devs[name] != v {
		s.mu.Unlock()
		return false
	}
	// The record of who ended it is written before the Mac disappears, so its
	// secret is never unknown without an answer to why.
	if by != "" {
		if err := s.store.addEnded(secretHash, name, by, s.now()); err != nil {
			s.log.Printf("record that %s ended %s's enrollment: %v", by, name, err)
		}
	}
	delete(s.devs, name)
	s.mu.Unlock()
	if err := s.store.deleteDevice(id); err != nil {
		s.log.Printf("delete device %s: %v", name, err)
	}

	v.mu.Lock()
	v.goneWhy = reason
	v.d.Lease = nil
	active := v.d.ActiveJob
	if v.oobStop != nil {
		v.oobStop()
		v.oobStop, v.oob, v.serialUp = nil, nil, false
	}
	close(v.stop)
	v.bump()
	v.mu.Unlock()
	s.log.Printf("%s: enrollment ended: %s", name, reason)

	// The job holding the Mac ends incomplete (see runJob); the ones queued
	// behind it have no Mac to run on.
	s.mu.Lock()
	cancel := s.cancels[active]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if jobs, err := s.store.jobs(name, 1000, true); err == nil {
		for _, j := range jobs {
			if j.ID != active {
				s.updateJobByID(j.ID, func(j *api.Job) {
					j.State, j.Outcome, j.Summary = api.JobDone, api.OutcomeCanceled, "canceled: "+reason
				})
			}
		}
	}

	if by != "" && e.IsVolunteer() {
		s.notify(Notification{Device: name, Title: fmt.Sprintf("Enrollment of %s ended by %s", name, by),
			Body:     fmt.Sprintf("The Maintainer %s ended your Mac's enrollment in the lab. Its lab-agent removes the lab from your Mac at its next check-in; `sudo lab-agent log` records it.", by),
			Priority: "high", Volunteer: true, MacTopic: s.macTopicURL(e)})
	}
	return true
}

// hEndEnrollment is a Maintainer ending a Mac's enrollment.
func (s *Server) hEndEnrollment(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v := s.dev(name)
	by := maintainerName(r)
	if v == nil || !s.endEnrollment(v, by, "the Maintainer "+by+" ended its enrollment") {
		httpErr(w, 404, "no device %q", name)
		return
	}
	w.Write([]byte("enrollment ended\n"))
}

// hAgentLeave is a Mac telling labd its Volunteer has left the lab.
func (s *Server) hAgentLeave(w http.ResponseWriter, r *http.Request) {
	v := agentDev(r)
	s.endEnrollment(v, "", "its Volunteer left the lab")
	w.Write([]byte("left\n"))
}

// ended answers a request carrying the secret of a Mac whose enrollment a
// Maintainer ended: 401, with the Maintainer's name for the Mac to read.
func (s *Server) ended(w http.ResponseWriter, secret string) bool {
	by, err := s.store.endedBy(hashSecret(secret))
	if err != nil {
		return false
	}
	w.Header().Set(endedHeader, by)
	httpErr(w, 401, "enrollment ended by %s", by)
	return true
}

func (st *store) addEnded(secretHash, name, by string, at time.Time) error {
	_, err := st.db.Exec(`INSERT OR REPLACE INTO ended(secret_hash,name,maintainer,at) VALUES(?,?,?,?)`, secretHash, name, by, at.Unix())
	return err
}

// endedBy is the Maintainer who ended the enrollment the secret belonged to.
func (st *store) endedBy(secretHash string) (string, error) {
	var by string
	err := st.db.QueryRow(`SELECT maintainer FROM ended WHERE secret_hash=?`, secretHash).Scan(&by)
	return by, err
}

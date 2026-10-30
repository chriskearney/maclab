package server

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

type Notification struct {
	Device   string
	Title    string
	Body     string
	Priority string // urgent, high, default, low
	// MacTopic, when set, makes this a Volunteer's notice: it is posted to
	// that topic alone, never to the lab-wide topic or --notify-cmd, which
	// are the Maintainers'. A Volunteer Mac without a topic gets none.
	MacTopic  string
	Volunteer bool
}

// ntfyPriorities is how a Notification's priority reads to ntfy; default sends neither.
var ntfyPriorities = map[string]struct{ priority, tag string }{
	"urgent": {"urgent", "rotating_light"},
	"high":   {"high", "warning"},
	"low":    {"low", "information_source"},
}

func (s *Server) notify(n Notification) {
	s.log.Printf("NOTIFY [%s] %s: %s", n.Priority, n.Title, strings.ReplaceAll(n.Body, "\n", " | "))
	s.mu.Lock()
	for _, f := range s.notifyHooks {
		f(n)
	}
	s.mu.Unlock()
	topic := s.cfg.NtfyURL
	if n.Volunteer {
		topic = n.MacTopic
	}
	if topic != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", topic, strings.NewReader(n.Body))
			req.Header.Set("Title", n.Title)
			p := ntfyPriorities[n.Priority]
			req.Header.Set("Priority", p.priority)
			req.Header.Set("Tags", p.tag)
			if resp, err := http.DefaultClient.Do(req); err != nil {
				s.log.Printf("ntfy: %v", err)
			} else {
				resp.Body.Close()
			}
		}()
	}
	if s.cfg.NotifyCmd != "" && !n.Volunteer {
		go func() {
			cmd := exec.Command("sh", "-c", s.cfg.NotifyCmd)
			cmd.Env = append(os.Environ(), "MACLAB_TITLE="+n.Title, "MACLAB_BODY="+n.Body, "MACLAB_PRIORITY="+n.Priority, "MACLAB_DEVICE="+n.Device)
			if out, err := cmd.CombinedOutput(); err != nil {
				s.log.Printf("notify-cmd: %v: %s", err, out)
			}
		}()
	}
}

// tellVolunteerJobStarting tells a Volunteer, on their Mac's own topic, that a
// job is about to take their Mac: its id, who asked, how long it can take at
// most, and a request not to reboot until the done notice. Only when the
// Volunteer asked (`notify --jobs on`); a Lab-owned Mac has no Volunteer to tell.
func (r *jobRun) tellVolunteerJobStarting() {
	d := r.v.snapshot()
	if !d.IsVolunteer() || !d.JobNotices {
		return
	}
	minutes := int(math.Ceil(r.expectedLength().Minutes()))
	who := ""
	if r.j.Maintainer != "" {
		who = " for " + r.j.Maintainer
	}
	r.s.notify(Notification{Device: d.Name, Volunteer: true, MacTopic: r.s.macTopicURL(d.Enrollment), Priority: "default",
		Title: fmt.Sprintf("job %s is starting on %s", r.j.ID, d.Name),
		Body: fmt.Sprintf("Job %s%s is starting on %s. The Mac will reboot for it, and the job takes at most about %d min. "+
			"Please do not reboot or shut it down until you get the done notice. To stop it: sudo lab-agent pause.", r.j.ID, who, d.Name, max(minutes, 1))})
	r.volunteerTold = true
}

// volunteerDoneNotice is the notice that ends the heads-up: how the job ended
// and that the Mac is free.
func (s *Server) volunteerDoneNotice(d api.Device, id, outcome string) Notification {
	return Notification{Device: d.Name, Volunteer: true, MacTopic: s.macTopicURL(d.Enrollment), Priority: "default",
		Title: fmt.Sprintf("job %s on %s is done: %s", id, d.Name, outcome),
		Body:  fmt.Sprintf("Job %s ended (%s). The lab is finished with your Mac for now: you can reboot or use it.", id, outcome)}
}

// tellVolunteerJobDone sends the done notice after a start notice. While the
// Mac still needs hands or is being recovered it would not be true, so it waits
// (dev.owedDone) and goes when the Mac is back.
func (r *jobRun) tellVolunteerJobDone(outcome string) {
	if !r.volunteerTold {
		return
	}
	d := r.v.snapshot()
	n := r.s.volunteerDoneNotice(d, r.j.ID, outcome)
	if d.State == api.StateNeedsHands || d.State == api.StateRecovering {
		r.v.mu.Lock()
		r.v.owedDone = &n
		r.v.mu.Unlock()
		return
	}
	r.s.notify(n)
}

// sendOwedDoneLocked sends a done notice that waited for the Mac to be back.
func (v *dev) sendOwedDoneLocked() {
	if v.owedDone == nil || v.d.State == api.StateNeedsHands || v.d.State == api.StateRecovering || v.d.State == api.StateOffline {
		return
	}
	n := *v.owedDone
	v.owedDone = nil
	v.s.notify(n)
}

// tellVolunteerJobEndedByRestart closes the heads-up for a job labd lost by
// restarting while it held a Volunteer's Mac: the start notice went, and no
// job is left that could send the done one. A job that had not yet reached the
// Mac (queued, building) never sent a start notice.
func (s *Server) tellVolunteerJobEndedByRestart(j *api.Job, outcome string) {
	switch j.State {
	case api.JobStaging, api.JobBooting, api.JobTesting, api.JobCollecting, api.JobRestoring:
	default:
		return
	}
	v := s.devs[j.Spec.Device]
	if v == nil {
		return
	}
	d := v.snapshot()
	if d.IsVolunteer() && d.JobNotices {
		s.notify(s.volunteerDoneNotice(d, j.ID, outcome))
	}
}

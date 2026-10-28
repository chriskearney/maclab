package server

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
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

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
	if s.cfg.NtfyURL != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", s.cfg.NtfyURL, strings.NewReader(n.Body))
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
	if s.cfg.NotifyCmd != "" {
		go func() {
			cmd := exec.Command("sh", "-c", s.cfg.NotifyCmd)
			cmd.Env = append(os.Environ(), "MACLAB_TITLE="+n.Title, "MACLAB_BODY="+n.Body, "MACLAB_PRIORITY="+n.Priority, "MACLAB_DEVICE="+n.Device)
			if out, err := cmd.CombinedOutput(); err != nil {
				s.log.Printf("notify-cmd: %v: %s", err, out)
			}
		}()
	}
}

package agent

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// tailnet joins this Mac to the lab's tailnet. Commands and the reachability
// check are swappable so tests never touch the real tailscaled.
type tailnet struct {
	run   func(ctx context.Context, name string, args ...string) ([]byte, error)
	reach func(ctx context.Context, url string) error
	say   func(format string, args ...any)
}

func newTailnet(say func(string, ...any)) tailnet {
	return tailnet{
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		reach: reachable,
		say:   say,
	}
}

// join runs `tailscale up` with a hand-made auth key, tagged tag:maclab with
// Tailscale SSH on, then checks labd answers at server over the tailnet. The
// key is never printed or stored: the tailnet remembers the Mac.
func (t tailnet) join(ctx context.Context, key, hostname, server string) error {
	hide := func(b []byte) string { return strings.TrimSpace(strings.ReplaceAll(string(b), key, "<auth key>")) }
	if out, err := t.run(ctx, "systemctl", "enable", "--now", "tailscaled.service"); err != nil {
		return fmt.Errorf("start tailscaled (is tailscale installed? pacman -S tailscale): %v: %s", err, hide(out))
	}
	t.say("tailscaled enabled and running")
	out, err := t.run(ctx, "tailscale", "up", "--auth-key="+key, "--advertise-tags=tag:maclab", "--ssh", "--hostname="+hostname)
	if err != nil {
		return fmt.Errorf("tailscale up: %v: %s", err, hide(out))
	}
	t.say("joined the tailnet as %s (tag:maclab, Tailscale SSH on)", hostname)
	if server == "" {
		return nil
	}
	if err := t.reach(ctx, server); err != nil {
		return fmt.Errorf("labd at %s is not reachable over the tailnet: %w", server, err)
	}
	t.say("labd reachable at %s", server)
	return nil
}

// reachable waits up to 30 seconds for labd to answer at all: routes to a
// new tailnet peer take a moment.
func reachable(ctx context.Context, server string) error {
	c := &http.Client{Timeout: 5 * time.Second}
	var err error
	for range 10 {
		var resp *http.Response
		if resp, err = c.Get(strings.TrimSuffix(server, "/") + "/api/auth"); err == nil {
			resp.Body.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return err
}

// tailnetHostname names the Mac after its lab name when setup ran before;
// on a first setup the name only arrives with enrollment, after the join.
func tailnetHostname(cfg *Config) string {
	if cfg != nil && cfg.Name != "" {
		return "maclab-" + cfg.Name
	}
	h, _ := os.Hostname()
	return h
}

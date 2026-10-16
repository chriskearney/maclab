package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

const testKey = "tskey-auth-kTEST123-SECRETSECRET"

type fakeTailnet struct {
	cmds    [][]string
	said    []string
	reached []string
	upOut   string // tailscale up's output
	upErr   error
	reach   error
}

func (f *fakeTailnet) tailnet() tailnet {
	return tailnet{
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			f.cmds = append(f.cmds, append([]string{name}, args...))
			if name == "tailscale" {
				return []byte(f.upOut), f.upErr
			}
			return nil, nil
		},
		reach: func(ctx context.Context, url string) error { f.reached = append(f.reached, url); return f.reach },
		say:   func(format string, a ...any) { f.said = append(f.said, fmt.Sprintf(format, a...)) },
	}
}

func TestTailnetJoin(t *testing.T) {
	f := &fakeTailnet{}
	if err := f.tailnet().join(context.Background(), testKey, "maclab-m1air", "http://100.100.1.1:7770"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "enable", "--now", "tailscaled.service"},
		{"tailscale", "up", "--auth-key=" + testKey, "--advertise-tags=tag:maclab", "--ssh", "--hostname=maclab-m1air"},
	}
	if !reflect.DeepEqual(f.cmds, want) {
		t.Errorf("commands:\n got %q\nwant %q", f.cmds, want)
	}
	if !reflect.DeepEqual(f.reached, []string{"http://100.100.1.1:7770"}) {
		t.Errorf("reachability checked at %q", f.reached)
	}
	if len(f.said) != 3 {
		t.Errorf("want one line per step, got %q", f.said)
	}
	for _, l := range f.said {
		if strings.Contains(l, "SECRET") {
			t.Errorf("auth key printed: %q", l)
		}
	}
}

func TestTailnetJoinFailuresHideKey(t *testing.T) {
	f := &fakeTailnet{upOut: "backend error: invalid key: " + testKey + " not valid", upErr: errors.New("exit status 1")}
	err := f.tailnet().join(context.Background(), testKey, "h", "http://labd:7770")
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "invalid key") {
		t.Errorf("tailscale up failure: %v", err)
	}
	if len(f.reached) != 0 {
		t.Error("checked labd after a failed join")
	}

	f = &fakeTailnet{reach: errors.New("connection refused")}
	err = f.tailnet().join(context.Background(), testKey, "h", "http://labd:7770")
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("unreachable labd: %v", err)
	}

	f = &fakeTailnet{}
	if err := f.tailnet().join(context.Background(), testKey, "h", ""); err != nil || len(f.reached) != 0 {
		t.Errorf("no server to check: %v, reached %q", err, f.reached)
	}
}

func TestTailnetHostname(t *testing.T) {
	if got := tailnetHostname(&Config{Name: "m1air"}); got != "maclab-m1air" {
		t.Errorf("enrolled Mac: %q", got)
	}
	h, _ := os.Hostname()
	if got := tailnetHostname(nil); got != h {
		t.Errorf("first setup: %q, want the hostname %q", got, h)
	}
}

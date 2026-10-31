package agent

// Moving an enrolled Mac to labd's new URL: when labd moves, with its data,
// to another address (from a LAN host to https://maclab.example.com, say),
// each Mac keeps its enrollment and only learns where labd is now. Move
// changes nothing but that: no bootloader, known-good kernel, watchdog,
// journal, getty or enrollment, which only setup touches.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
)

// MoveOptions is where an enrolled Mac's labd is now.
type MoveOptions struct {
	ConfigPath string // agent.json; "" is ConfigPath
	Server     string // labd's new URL
	// CAFile is PEM certificates for the new labd's https, kept in agent.json
	// as server_ca; empty trusts the system's roots only.
	CAFile string
	// AllowPlainHTTP allows a new labd at an http:// URL on another machine,
	// on purpose; recorded in agent.json.
	AllowPlainHTTP bool
	// NoCheck skips asking the new labd whether it knows this Mac, for a move
	// staged before the new labd answers (the agent keeps trying until it
	// does). The URL and the CA are checked either way.
	NoCheck bool
	// Restart restarts lab-agent.service so it reads the new address; nil is
	// systemctl. InAgent says whether move runs inside lab-agent.service
	// (through lab exec), where restarting the service would kill move
	// before it answered; nil reads /proc/self/cgroup.
	Restart func() error
	InAgent func() bool
	Log     func(format string, args ...any)
}

// Move points this Mac's lab-agent at labd's new URL. It asks the new labd,
// with the Mac's own device secret, whether it knows this Mac, then replaces
// agent.json's server, server_ca and allow_plain_http, and nothing else, in
// one rename, and restarts lab-agent. A refused move leaves agent.json as it
// was.
func Move(ctx context.Context, o MoveOptions) error {
	path := o.ConfigPath
	if path == "" {
		path = ConfigPath
	}
	say := o.Log
	if say == nil {
		say = func(string, ...any) {}
	}
	inAgent := o.InAgent
	if inAgent == nil {
		inAgent = insideAgentUnit
	}
	if inAgent() {
		return errors.New("run lab-agent move in a terminal on the Mac or over SSH, not through the lab: it restarts lab-agent.service, which would end this command before labd heard back. Nothing was changed")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("this Mac isn't enrolled: there is no labd to move from (lab-agent setup enrolls it)")
	} else if err != nil {
		return err
	}
	var cfg Config
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Secret == "" || cfg.DeviceID == "" {
		return fmt.Errorf("%s holds no enrollment to move", path)
	}
	server := strings.TrimRight(o.Server, "/")
	if err := labhttp.CheckServer(server, o.AllowPlainHTTP); err != nil {
		return err
	}
	var caPEM []byte
	if o.CAFile != "" {
		if caPEM, err = labhttp.ReadCAFile(o.CAFile); err != nil {
			return err
		}
	}
	policy := labhttp.Policy{CAPEM: caPEM, AllowPlainHTTP: o.AllowPlainHTTP}
	if !o.NoCheck {
		if err := knowsThisMac(ctx, server, cfg, policy); err != nil {
			return err
		}
		say("labd at %s knows this Mac as %s", server, cfg.Name)
	}

	set := func(k string, v any) {
		b, _ := json.Marshal(v)
		fields[k] = b
	}
	set("server", server)
	if len(caPEM) > 0 {
		set("server_ca", string(caPEM))
	} else {
		delete(fields, "server_ca")
	}
	set("allow_plain_http", o.AllowPlainHTTP)
	b, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return err
	}
	if err := replaceFile(path, b); err != nil {
		return err
	}
	say("agent.json now names labd at %s (was %s); this Mac keeps its enrollment as %s", server, cfg.Server, cfg.Name)
	restart := o.Restart
	if restart == nil {
		restart = func() error { return run("systemctl", "restart", "lab-agent.service") }
	}
	if err := restart(); err != nil {
		return err
	}
	say("lab-agent restarted; the move is done when this Mac checks in to %s", server)
	return nil
}

// insideAgentUnit is whether this process runs in lab-agent.service's
// cgroup: lab exec's commands do.
func insideAgentUnit() bool {
	b, _ := os.ReadFile("/proc/self/cgroup")
	return strings.Contains(string(b), "/lab-agent.service")
}

// run runs a command, its output going into the error.
func run(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// knowsThisMac asks labd at server, with the Mac's device secret, for the
// Mac's enrollment: labd must know the secret, and as the same kind of Mac.
func knowsThisMac(ctx context.Context, server string, cfg Config, p labhttp.Policy) error {
	c, err := p.Client(15 * time.Second)
	if err != nil {
		return err
	}
	var live api.AgentEnrollment
	err = getJSON(ctx, c, server+"/api/agent/enrollment", cfg.Secret, &live)
	var se *statusError
	switch {
	case errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden || se.Code == http.StatusNotFound):
		return fmt.Errorf("labd at %s doesn't know this Mac (%d): is labd's data there yet? Nothing was changed", server, se.Code)
	case err != nil:
		return fmt.Errorf("labd at %s: %v%s. Nothing was changed", server, err, certTimeHint(err, time.Now()))
	case cfg.Enrollment.Kind != "" && live.Kind != cfg.Enrollment.Kind:
		return fmt.Errorf("labd at %s knows this Mac's secret as a %s Mac, not %s. Nothing was changed", server, live.Kind, cfg.Enrollment.Kind)
	}
	return nil
}

// replaceFile writes b to path in one rename, durably, keeping it private.
func replaceFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
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
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

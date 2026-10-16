package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// tailnet joins this Mac to the lab's tailnet. Commands and the reachability
// check are swappable so tests never touch the real tailscaled.
type tailnet struct {
	run   func(ctx context.Context, name string, args ...string) ([]byte, error)
	reach func(ctx context.Context, url string) error
	say   func(format string, args ...any)
	tmp   string // where the key file goes; "" is the system's temp directory
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

const labTag = "tag:maclab"

// join runs `tailscale up` with a hand-made auth key, tagged tag:maclab with
// Tailscale SSH on, checks the Mac really is on labd's tailnet with that
// tag, then checks labd answers at server over the tailnet. The key reaches
// tailscale in a file only root can read, never in argv, and is never
// printed or stored: the tailnet remembers the Mac.
func (t tailnet) join(ctx context.Context, key, hostname, server string) error {
	hide := func(b []byte) string { return strings.TrimSpace(strings.ReplaceAll(string(b), key, "<auth key>")) }
	if out, err := t.run(ctx, "systemctl", "enable", "--now", "tailscaled.service"); err != nil {
		return fmt.Errorf("start tailscaled (is tailscale installed? pacman -S tailscale): %v: %s", err, hide(out))
	}
	t.say("tailscaled enabled and running")

	// A node that is logged in keeps its login, and ignores a new key,
	// unless told to re-authenticate. When tailscaled can't say, re-auth
	// anyway: on a node that never logged in it changes nothing.
	before, err := t.status(ctx)
	loggedIn := err != nil || before.loggedIn()

	out, err := t.up(ctx, key, hostname, loggedIn)
	if err != nil && strings.Contains(string(out), "--accept-risk=") {
		return fmt.Errorf("tailscale up won't re-join from this shell: it runs over Tailscale SSH, which re-joining may cut halfway through setup. Run setup from the console or over plain SSH: %s", hide(out))
	}
	if err != nil {
		return fmt.Errorf("tailscale up: %v: %s", err, hide(out))
	}

	after, err := t.status(ctx)
	if err != nil {
		return fmt.Errorf("check the join: %w", err)
	}
	if err := checkJoined(before, after, server); err != nil {
		return err
	}
	if before != nil && before.loggedIn() && before.tailnetName() != after.tailnetName() {
		t.say("joined tailnet %s as %s (tag:maclab, Tailscale SSH on), leaving tailnet %s", after.tailnetName(), hostname, before.tailnetName())
	} else {
		t.say("joined tailnet %s as %s (tag:maclab, Tailscale SSH on)", after.tailnetName(), hostname)
	}
	if server == "" {
		return nil
	}
	if err := t.reach(ctx, server); err != nil {
		return fmt.Errorf("labd at %s is not reachable over the tailnet: %w", server, err)
	}
	t.say("labd reachable at %s", server)
	return nil
}

// up runs tailscale up, handing it the key in a file only root can read,
// which is gone again when up returns. When tailscale refuses because the
// Mac has other settings this join doesn't name, up runs it again with
// --reset: setup owns the Mac's tailnet settings, and an old tailnet's exit
// node or routes mean nothing on a new one.
func (t tailnet) up(ctx context.Context, key, hostname string, reauth bool) ([]byte, error) {
	f, err := os.CreateTemp(t.tmp, "maclab-tskey-*") // mode 0600
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(key + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("write the auth key for tailscale: %w", err)
	}
	args := []string{"up", "--auth-key=file:" + f.Name(), "--advertise-tags=" + labTag, "--ssh", "--hostname=" + hostname, "--timeout=2m"}
	if reauth {
		args = append(args, "--force-reauth")
	}
	out, err := t.run(ctx, "tailscale", args...)
	if err == nil || !strings.Contains(string(out), "requires mentioning all") {
		return out, err
	}
	reset := resetSettings(string(out))
	if out, err = t.run(ctx, "tailscale", append(args, "--reset")...); err == nil {
		if len(reset) == 0 {
			t.say("tailscale settings this setup doesn't name went back to their defaults")
		} else {
			t.say("tailscale settings this setup doesn't name went back to their defaults: %s",
				strings.ReplaceAll(strings.Join(reset, " "), key, "<auth key>"))
		}
	}
	return out, err
}

// tsStatus is the part of `tailscale status --json` join looks at.
type tsStatus struct {
	BackendState   string
	HaveNodeKey    bool
	Self           *tsPeer
	MagicDNSSuffix string // older tailscale; newer has CurrentTailnet
	CurrentTailnet *struct{ Name, MagicDNSSuffix string }
	Peer           map[string]*tsPeer
}

type tsPeer struct {
	PublicKey    string
	TailscaleIPs []netip.Addr
	Tags         []string
}

func (t tailnet) status(ctx context.Context) (*tsStatus, error) {
	out, err := t.run(ctx, "tailscale", "status", "--json")
	if err != nil {
		return nil, fmt.Errorf("tailscale status: %v: %s", err, bytes.TrimSpace(out))
	}
	// The output can open with a warning on stderr, such as a CLI and
	// tailscaled version mismatch; the JSON follows it.
	var st tsStatus
	if i := bytes.IndexByte(out, '{'); i < 0 {
		return nil, fmt.Errorf("tailscale status: no JSON in %q", bytes.TrimSpace(out))
	} else if err := json.NewDecoder(bytes.NewReader(out[i:])).Decode(&st); err != nil {
		return nil, fmt.Errorf("tailscale status: %w", err)
	}
	return &st, nil
}

func (s *tsStatus) loggedIn() bool {
	switch s.BackendState {
	case "Running", "Starting", "Stopped", "NeedsMachineAuth":
		return true
	}
	return s.HaveNodeKey
}

func (s *tsStatus) magicDNSSuffix() string {
	if s.CurrentTailnet != nil && s.CurrentTailnet.MagicDNSSuffix != "" {
		return s.CurrentTailnet.MagicDNSSuffix
	}
	return s.MagicDNSSuffix
}

func (s *tsStatus) tailnetName() string {
	if s.CurrentTailnet != nil && s.CurrentTailnet.Name != "" {
		return s.CurrentTailnet.Name
	}
	if d := s.magicDNSSuffix(); d != "" {
		return d
	}
	return "(unnamed)"
}

// checkJoined reports what is wrong with the Mac's tailnet login after a
// join: tailscale up can succeed and leave the Mac where it was, untagged,
// or on a tailnet labd isn't on.
func checkJoined(before, after *tsStatus, server string) error {
	if after.BackendState != "Running" {
		return fmt.Errorf("tailscale is %s after joining, not Running (a key that isn't pre-approved needs the Mac approved in the admin console)", after.BackendState)
	}
	if after.Self == nil {
		return fmt.Errorf("tailscale status names no node for this Mac")
	}
	if before != nil && before.loggedIn() && before.Self != nil && before.Self.PublicKey != "" && before.Self.PublicKey == after.Self.PublicKey {
		return fmt.Errorf("tailscale kept this Mac's old login on tailnet %s and did not use the new key", after.tailnetName())
	}
	if !slices.Contains(after.Self.Tags, labTag) {
		return fmt.Errorf("joined tailnet %s, but this Mac is tagged %v, not %s: make the auth key tagged %s", after.tailnetName(), after.Self.Tags, labTag, labTag)
	}
	if on, known := after.hasServer(server); known && !on {
		return fmt.Errorf("joined tailnet %s, but labd's %s is not on it: make the auth key in labd's tailnet, and check its policy lets %s reach labd", after.tailnetName(), server, labTag)
	}
	return nil
}

// hasServer says whether labd's URL names a node on this tailnet; known is
// false when the URL isn't a tailnet address or MagicDNS name, which says
// nothing about the tailnet.
func (s *tsStatus) hasServer(server string) (on, known bool) {
	u, err := url.Parse(server)
	if err != nil || server == "" {
		return false, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !inTailnetRange(ip) {
			return false, false
		}
		nodes := []*tsPeer{s.Self}
		for _, p := range s.Peer {
			nodes = append(nodes, p)
		}
		for _, n := range nodes {
			if n != nil && slices.Contains(n.TailscaleIPs, ip) {
				return true, true
			}
		}
		return false, true
	}
	if !strings.HasSuffix(host, ".ts.net") {
		return false, false
	}
	suffix := strings.TrimSuffix(strings.ToLower(s.magicDNSSuffix()), ".")
	return suffix != "" && strings.HasSuffix(host, "."+suffix), true
}

// Tailscale hands out 100.64.0.0/10 and fd7a:115c:a1e0::/48, as labd knows too.
var tailnetRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

func inTailnetRange(ip netip.Addr) bool {
	for _, n := range tailnetRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// resetSettings picks the settings tailscale up named in its refusal to
// drop them silently, leaving out the ones join passes itself.
func resetSettings(out string) []string {
	ours := map[string]bool{"auth-key": true, "advertise-tags": true, "ssh": true, "hostname": true,
		"timeout": true, "force-reauth": true, "reset": true, "accept-risk": true}
	for l := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "tailscale" || f[1] != "up" {
			continue
		}
		var reset []string
		for _, a := range f[2:] {
			name, _, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			if strings.HasPrefix(a, "--") && !ours[name] {
				reset = append(reset, a)
			}
		}
		return reset
	}
	return nil
}

// AuthKey is the Tailscale auth key setup joins with: the contents of file,
// a line read from stdin when arg is "-", else arg itself. A key given as
// arg comes with a warning: ps, /proc and sudo's journal entry show it.
func AuthKey(arg, file string, stdin io.Reader) (key, warning string, err error) {
	from := file
	switch {
	case arg != "" && file != "":
		return "", "", fmt.Errorf("give --tailscale-authkey or --tailscale-authkey-file, not both")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", "", fmt.Errorf("read the auth key: %w", err)
		}
		key = string(b)
	case arg == "-":
		from = "stdin"
		l, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", "", fmt.Errorf("read the auth key from stdin: %w", err)
		}
		key = l
	case arg != "":
		return arg, "--tailscale-authkey with a key shows it in the process list and in sudo's journal entry, " +
			"which tailnet viewers of labd can read; next time use --tailscale-authkey-file <path> or --tailscale-authkey - (stdin)", nil
	default:
		return "", "", nil
	}
	if key = strings.TrimSpace(key); key == "" {
		return "", "", fmt.Errorf("no auth key in %s", from)
	}
	if strings.ContainsAny(key, " \t\r\n") {
		return "", "", fmt.Errorf("the auth key in %s is more than one word", from)
	}
	return key, "", nil
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

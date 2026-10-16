package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const testKey = "tskey-auth-kTEST123-SECRETSECRET"

type fakeOut struct {
	out string
	err error
}

// fakeTailnet stands in for systemctl and the tailscale CLI. statuses and
// ups are answered in order, the last one repeating.
type fakeTailnet struct {
	cmds     [][]string
	said     []string
	steps    []string // commands run and lines said, in order
	reached  []string
	statuses []fakeOut // tailscale status --json
	ups      []fakeOut // tailscale up
	logout   fakeOut   // tailscale logout
	keys     []string  // what each --auth-key=file: held when tailscale ran
	reach    error
	tmp      string
	t        *testing.T
}

func next(outs []fakeOut, n int) fakeOut {
	if len(outs) == 0 {
		return fakeOut{}
	}
	return outs[min(n, len(outs)-1)]
}

func (f *fakeTailnet) tailnet() tailnet {
	nStatus, nUp := 0, 0
	return tailnet{
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			f.cmds = append(f.cmds, append([]string{name}, args...))
			f.steps = append(f.steps, "run: "+name+" "+args[0])
			if name != "tailscale" {
				return nil, nil
			}
			switch args[0] {
			case "logout":
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return []byte(f.logout.out), f.logout.err
			case "status":
				o := next(f.statuses, nStatus)
				nStatus++
				return []byte(o.out), o.err
			case "up":
				for _, a := range args {
					if path, ok := strings.CutPrefix(a, "--auth-key=file:"); ok {
						fi, err := os.Stat(path)
						if err != nil {
							f.t.Fatalf("tailscale up: key file: %v", err)
						}
						if fi.Mode().Perm() != 0o600 {
							f.t.Errorf("key file mode %v, want 0600", fi.Mode().Perm())
						}
						b, _ := os.ReadFile(path)
						f.keys = append(f.keys, string(b))
					}
				}
				o := next(f.ups, nUp)
				nUp++
				return []byte(o.out), o.err
			}
			return nil, fmt.Errorf("unexpected tailscale %q", args)
		},
		reach: func(ctx context.Context, url string) error { f.reached = append(f.reached, url); return f.reach },
		say: func(format string, a ...any) {
			f.said = append(f.said, fmt.Sprintf(format, a...))
			f.steps = append(f.steps, "say: "+f.said[len(f.said)-1])
		},
		tmp: f.tmp,
	}
}

func newFake(t *testing.T) *fakeTailnet { return &fakeTailnet{t: t, tmp: t.TempDir()} }

// status is a `tailscale status --json` answer.
type status struct {
	state, tailnet, dnsSuffix, nodeKey string
	tags                               []string
	peers                              []string // tailnet IPs of the other nodes
}

func (s status) json() string {
	peers := map[string]any{}
	for i, ip := range s.peers {
		peers[fmt.Sprintf("nodekey:peer%d", i)] = map[string]any{"PublicKey": fmt.Sprintf("nodekey:peer%d", i), "TailscaleIPs": []string{ip}}
	}
	self := map[string]any{"PublicKey": s.nodeKey, "TailscaleIPs": []string{"100.101.1.2"}}
	if s.tags != nil {
		self["Tags"] = s.tags
	}
	st := map[string]any{"BackendState": s.state, "Self": self, "Peer": peers}
	if s.state != "NeedsLogin" && s.state != "NoState" {
		st["HaveNodeKey"] = true
		st["CurrentTailnet"] = map[string]any{"Name": s.tailnet, "MagicDNSSuffix": s.dnsSuffix}
	}
	b, _ := json.Marshal(st)
	return string(b)
}

var (
	loggedOut = status{state: "NeedsLogin"}
	labNet    = status{state: "Running", tailnet: "lab@github", dnsSuffix: "tail1234.ts.net", nodeKey: "nodekey:new",
		tags: []string{"tag:maclab"}, peers: []string{"100.100.1.1"}}
	otherNet = status{state: "Running", tailnet: "someone@github", dnsSuffix: "tail9999.ts.net", nodeKey: "nodekey:old",
		peers: []string{"100.90.0.1"}}
)

func outs(ss ...status) (o []fakeOut) {
	for _, s := range ss {
		o = append(o, fakeOut{out: s.json()})
	}
	return o
}

// commands is what join ran, "keyFile" standing for the --auth-key=file:
// argument, whose path is random.
func (f *fakeTailnet) commands() [][]string {
	var got [][]string
	for _, c := range f.cmds {
		c = slices.Clone(c)
		for i, a := range c {
			if strings.HasPrefix(a, "--auth-key=file:") {
				c[i] = "keyFile"
			}
		}
		got = append(got, c)
	}
	return got
}

// upCmds is the tailscale up commands join ran.
func (f *fakeTailnet) upCmds() [][]string {
	var got [][]string
	for _, c := range f.commands() {
		if len(c) > 1 && c[0] == "tailscale" && c[1] == "up" {
			got = append(got, c)
		}
	}
	return got
}

func noKey(t *testing.T, f *fakeTailnet, err error) {
	t.Helper()
	for _, c := range f.cmds {
		if strings.Contains(strings.Join(c, " "), "SECRET") {
			t.Errorf("auth key in argv: %q", c)
		}
	}
	for _, l := range f.said {
		if strings.Contains(l, "SECRET") {
			t.Errorf("auth key printed: %q", l)
		}
	}
	if err != nil && strings.Contains(err.Error(), "SECRET") {
		t.Errorf("auth key in the error: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(f.tmp, "*")); len(left) > 0 {
		t.Errorf("key file left behind: %q", left)
	}
}

func TestTailnetJoin(t *testing.T) {
	f := newFake(t)
	f.statuses = outs(loggedOut, labNet)
	err := f.tailnet().join(context.Background(), testKey, "maclab-m1air", "http://100.100.1.1:7770")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "enable", "--now", "tailscaled.service"},
		{"tailscale", "status", "--json"},
		{"tailscale", "up", "keyFile", "--advertise-tags=tag:maclab", "--ssh", "--hostname=maclab-m1air", "--timeout=2m"},
		{"tailscale", "status", "--json"},
	}
	if got := f.commands(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
	if !reflect.DeepEqual(f.keys, []string{testKey + "\n"}) {
		t.Errorf("tailscale read %q from the key file", f.keys)
	}
	if !reflect.DeepEqual(f.reached, []string{"http://100.100.1.1:7770"}) {
		t.Errorf("reachability checked at %q", f.reached)
	}
	if len(f.said) != 3 || !strings.Contains(f.said[1], "joined tailnet lab@github as maclab-m1air") {
		t.Errorf("want one line per step, got %q", f.said)
	}
	noKey(t, f, err)
}

// A Mac already logged in ignores a new key without --force-reauth, so a
// rerun to move it to another tailnet would do nothing.
func TestTailnetRejoinForcesReauth(t *testing.T) {
	f := newFake(t)
	f.statuses = outs(otherNet, labNet)
	err := f.tailnet().join(context.Background(), testKey, "maclab-m1air", "http://100.100.1.1:7770")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"tailscale", "up", "keyFile", "--advertise-tags=tag:maclab", "--ssh", "--hostname=maclab-m1air", "--timeout=2m", "--force-reauth"}}
	if got := f.upCmds(); !reflect.DeepEqual(got, want) {
		t.Errorf("tailscale up:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(strings.Join(f.said, "\n"), "joined tailnet lab@github as maclab-m1air (tag:maclab, Tailscale SSH on), leaving tailnet someone@github") {
		t.Errorf("said %q", f.said)
	}
	noKey(t, f, err)

	// tailscaled can't say whether it's logged in: re-auth all the same.
	f = newFake(t)
	f.statuses = []fakeOut{{out: "failed to connect to local tailscaled", err: errors.New("exit status 1")}, {out: labNet.json()}}
	if err := f.tailnet().join(context.Background(), testKey, "h", ""); err != nil {
		t.Fatal(err)
	}
	if up := f.upCmds(); len(up) != 1 || up[0][len(up[0])-1] != "--force-reauth" {
		t.Errorf("tailscale up with no status: %q", up)
	}
}

// refusal is tailscale up refusing to drop the settings in cmd silently.
func refusal(cmd string) fakeOut {
	return fakeOut{out: "Error: changing settings via 'tailscale up' requires mentioning all\n" +
		"non-default flags. To proceed, either re-run your command with --reset or\n" +
		"use the command below to explicitly mention the current value of\n" +
		"all non-default settings:\n\n\t" + cmd + "\n\n", err: errors.New("exit status 1")}
}

// tailscale up refuses to drop settings the command doesn't name; join says
// which ones --reset will drop, then runs it again with --reset.
func TestTailnetJoinResetsUnnamedSettings(t *testing.T) {
	f := newFake(t)
	f.statuses = outs(otherNet, labNet)
	f.ups = []fakeOut{refusal("tailscale up --accept-routes --advertise-tags=tag:maclab --auth-key=file:/tmp/maclab-tskey-1 --exit-node=100.90.0.1 --hostname=h --ssh"), {}}
	err := f.tailnet().join(context.Background(), testKey, "h", "")
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"tailscale", "up", "keyFile", "--advertise-tags=tag:maclab", "--ssh", "--hostname=h", "--timeout=2m", "--force-reauth"}
	if got, want := f.upCmds(), [][]string{base, append(slices.Clone(base), "--reset")}; !reflect.DeepEqual(got, want) {
		t.Errorf("tailscale up:\n got %q\nwant %q", got, want)
	}
	if len(f.keys) != 2 || f.keys[1] != testKey+"\n" {
		t.Errorf("the retry read %q from the key file", f.keys)
	}
	said := strings.Join(f.said, "\n")
	if !strings.Contains(said, "back to their defaults: --accept-routes --exit-node=100.90.0.1") || strings.Contains(said, "auth-key") ||
		strings.Contains(said, "shields-up") {
		t.Errorf("said %q", f.said)
	}
	// Said before the settings go, not after.
	steps := strings.Join(f.steps, "\n")
	if i, j := strings.Index(steps, "back to their defaults"), strings.LastIndex(steps, "run: tailscale up"); i < 0 || i > j {
		t.Errorf("told what --reset drops only after running it:\n%s", steps)
	}
	noKey(t, f, err)

	// tailscale named nothing it can parse: say --reset drops whatever there is.
	f = newFake(t)
	f.statuses = outs(otherNet, labNet)
	f.ups = []fakeOut{refusal(""), {}}
	if err := f.tailnet().join(context.Background(), testKey, "h", ""); err != nil {
		t.Fatal(err)
	}
	if said := strings.Join(f.said, "\n"); !strings.Contains(said, "every setting this setup doesn't name back to its default") {
		t.Errorf("said %q", f.said)
	}
}

// --shields-up only ever closes the Mac: --reset never drops it, and join
// says it kept it.
func TestTailnetJoinKeepsShieldsUp(t *testing.T) {
	for _, flag := range []string{"--shields-up", "--shields-up=true"} {
		f := newFake(t)
		f.statuses = outs(otherNet, labNet)
		f.ups = []fakeOut{refusal("tailscale up --advertise-tags=tag:maclab --exit-node=100.90.0.1 --hostname=h " + flag + " --ssh"), {}}
		err := f.tailnet().join(context.Background(), testKey, "h", "")
		if err != nil {
			t.Fatal(err)
		}
		up := f.upCmds()
		if len(up) != 2 || !slices.Contains(up[1], "--reset") || !slices.Contains(up[1], "--shields-up") {
			t.Errorf("%s: tailscale up %q", flag, up)
		}
		said := strings.Join(f.said, "\n")
		if !strings.Contains(said, "back to their defaults: --exit-node=100.90.0.1\n") || !strings.Contains(said, "keeping --shields-up") {
			t.Errorf("%s: said %q", flag, f.said)
		}
		noKey(t, f, err)
	}
	f := newFake(t)
	f.statuses = outs(otherNet, labNet)
	f.ups = []fakeOut{refusal("tailscale up --exit-node=100.90.0.1 --shields-up=false"), {}}
	if err := f.tailnet().join(context.Background(), testKey, "h", ""); err != nil {
		t.Fatal(err)
	}
	if up := f.upCmds(); len(up) != 2 || slices.Contains(up[1], "--shields-up") {
		t.Errorf("shields down: tailscale up %q", up)
	}
}

func TestTailnetJoinVerifies(t *testing.T) {
	untagged := labNet
	untagged.tags = nil
	stuck := otherNet // tailscale up returned, and nothing changed
	elsewhere := labNet
	elsewhere.peers = []string{"100.77.0.5"}
	awaiting := labNet
	awaiting.state = "NeedsMachineAuth"
	cases := []struct {
		name          string
		before, after status
		server, want  string
	}{
		{"kept the old login", otherNet, stuck, "", "kept this Mac's old login"},
		{"not tagged", loggedOut, untagged, "", "make the auth key tagged tag:maclab"},
		{"labd's IP is elsewhere", loggedOut, elsewhere, "http://100.100.1.1:7770", "labd's http://100.100.1.1:7770 is not on it"},
		{"labd's name is elsewhere", loggedOut, labNet, "http://labd.tail9999.ts.net:7770", "is not on it"},
		{"not running", loggedOut, awaiting, "", "NeedsMachineAuth"},
	}
	for _, c := range cases {
		f := newFake(t)
		f.statuses = outs(c.before, c.after)
		err := f.tailnet().join(context.Background(), testKey, "h", c.server)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if len(f.reached) != 0 {
			t.Errorf("%s: checked labd after a bad join", c.name)
		}
		// A Mac that fails the check doesn't stay on that tailnet with
		// Tailscale SSH on.
		if cmds := f.commands(); !reflect.DeepEqual(cmds[len(cmds)-1], []string{"tailscale", "logout"}) {
			t.Errorf("%s: not logged out after a bad join: %q", c.name, cmds)
		}
		if err == nil || !strings.Contains(err.Error(), "now logged out of that tailnet") {
			t.Errorf("%s: the error doesn't say the Mac was logged out: %v", c.name, err)
		}
		noKey(t, f, err)
	}

	// tailscale status fails after the join: log out all the same.
	f := newFake(t)
	f.statuses = []fakeOut{{out: loggedOut.json()}, {out: "failed to connect to local tailscaled", err: errors.New("exit status 1")}}
	err := f.tailnet().join(context.Background(), testKey, "h", "")
	if err == nil || !strings.Contains(err.Error(), "check the join") || !strings.Contains(err.Error(), "now logged out of that tailnet") {
		t.Errorf("no status after the join: %v", err)
	}

	// The logout fails too: say so, and how to do it by hand.
	f = newFake(t)
	f.statuses = outs(loggedOut, untagged)
	f.logout = fakeOut{out: "tailscaled not responding", err: errors.New("exit status 1")}
	err = f.tailnet().join(context.Background(), testKey, "h", "")
	if err == nil || !strings.Contains(err.Error(), "make the auth key tagged") || !strings.Contains(err.Error(), "sudo tailscale logout") {
		t.Errorf("logout failed: %v", err)
	}

	// The check failed because setup was stopped (a dropped SSH session):
	// the logout still runs.
	f = newFake(t)
	f.statuses = outs(loggedOut)
	ctx, cancel := context.WithCancel(context.Background())
	tn := f.tailnet()
	run := tn.run
	tn.run = func(c context.Context, name string, args ...string) ([]byte, error) {
		if name == "tailscale" && args[0] == "status" && len(f.upCmds()) > 0 {
			cancel()
			return nil, c.Err()
		}
		return run(c, name, args...)
	}
	if err := tn.join(ctx, testKey, "h", ""); err == nil || !strings.Contains(err.Error(), "now logged out of that tailnet") {
		t.Errorf("stopped during the check: %v", err)
	}

	for _, server := range []string{"http://labd.tail1234.ts.net:7770", "http://10.1.1.5:7770", "http://labd:7770", "http://[fd7a:115c:a1e0::5]:7770"} {
		f := newFake(t)
		v6 := labNet
		v6.peers = append(v6.peers, "fd7a:115c:a1e0::5")
		f.statuses = outs(loggedOut, v6)
		if err := f.tailnet().join(context.Background(), testKey, "h", server); err != nil {
			t.Errorf("labd at %s: %v", server, err)
		}
	}
}

func TestTailnetJoinFailuresHideKey(t *testing.T) {
	f := newFake(t)
	f.ups = []fakeOut{{out: "backend error: invalid key: " + testKey + " not valid", err: errors.New("exit status 1")}}
	err := f.tailnet().join(context.Background(), testKey, "h", "http://labd:7770")
	if err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Errorf("tailscale up failure: %v", err)
	}
	if len(f.reached) != 0 {
		t.Error("checked labd after a failed join")
	}
	if strings.Contains(err.Error(), "logged out") {
		t.Errorf("a failed tailscale up changed nothing, yet the Mac was logged out: %v", err)
	}
	noKey(t, f, err)

	f = newFake(t)
	f.statuses = outs(otherNet)
	f.ups = []fakeOut{{out: "You are connected over Tailscale; this action may result in your SSH session disconnecting.\n" +
		"To skip this warning, use --accept-risk=lose-ssh\nContinue? [y/N] ", err: errors.New("exit status 1")}}
	if err := f.tailnet().join(context.Background(), testKey, "h", ""); err == nil || !strings.Contains(err.Error(), "from the console or over plain SSH") {
		t.Errorf("refused over Tailscale SSH: %v", err)
	}

	f = newFake(t)
	f.statuses = outs(loggedOut, labNet)
	f.reach = errors.New("connection refused")
	err = f.tailnet().join(context.Background(), testKey, "h", "http://labd:7770")
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("unreachable labd: %v", err)
	}
	// The Mac joined as it should: labd may only be slow to answer.
	for _, c := range f.commands() {
		if slices.Equal(c, []string{"tailscale", "logout"}) {
			t.Errorf("logged out after a good join that couldn't reach labd: %q", f.commands())
		}
	}

	f = newFake(t)
	f.statuses = outs(loggedOut, labNet)
	if err := f.tailnet().join(context.Background(), testKey, "h", ""); err != nil || len(f.reached) != 0 {
		t.Errorf("no server to check: %v, reached %q", err, f.reached)
	}
}

func TestTailscaleStatusAfterWarning(t *testing.T) {
	f := newFake(t)
	f.statuses = []fakeOut{{out: "Warning: client version \"1.90.1\" != tailscaled server version \"1.88.0\"\n" + labNet.json()}}
	st, err := f.tailnet().status(context.Background())
	if err != nil || st.tailnetName() != "lab@github" || !st.loggedIn() {
		t.Errorf("status after a warning: %+v, %v", st, err)
	}
}

func TestAuthKey(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	os.WriteFile(file, []byte(testKey+"\n"), 0o600)
	if k, err := AuthKey("", file, nil); k != testKey || err != nil {
		t.Errorf("from a file: %q, %v", k, err)
	}
	if k, err := AuthKey("-", "", strings.NewReader("  "+testKey+"\nmore\n")); k != testKey || err != nil {
		t.Errorf("from stdin: %q, %v", k, err)
	}
	if k, err := AuthKey("-", "", strings.NewReader(testKey)); k != testKey || err != nil {
		t.Errorf("from stdin with no newline: %q, %v", k, err)
	}
	if k, err := AuthKey("", "", nil); k != "" || err != nil {
		t.Errorf("no key: %q, %v", k, err)
	}
	// A key on the command line is in ps and sudo's journal by now.
	if k, err := AuthKey(testKey, "", nil); k != "" || err == nil || !strings.Contains(err.Error(), "process list") ||
		!strings.Contains(err.Error(), "--tailscale-authkey-file") || !strings.Contains(err.Error(), "Revoke it") {
		t.Errorf("on the command line: %q, %v", k, err)
	}
	// So is one in a file other users may read.
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		open := filepath.Join(dir, fmt.Sprintf("key-%o", mode))
		os.WriteFile(open, []byte(testKey+"\n"), 0o600)
		os.Chmod(open, mode)
		if k, err := AuthKey("", open, nil); k != "" || err == nil || !strings.Contains(err.Error(), "can be read by other users") {
			t.Errorf("a key file with mode %04o: %q, %v", mode, k, err)
		}
	}
	for _, mode := range []os.FileMode{0o400, 0o600, 0o620} {
		closed := filepath.Join(dir, fmt.Sprintf("key-%o", mode))
		os.WriteFile(closed, []byte(testKey+"\n"), 0o600)
		os.Chmod(closed, mode)
		if k, err := AuthKey("", closed, nil); k != testKey || err != nil {
			t.Errorf("a key file with mode %04o: %q, %v", mode, k, err)
		}
	}
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	two := filepath.Join(dir, "two")
	os.WriteFile(two, []byte("# key\n"+testKey+"\n"), 0o600)
	for name, c := range map[string]struct {
		arg, file string
		stdin     string
	}{
		"both":             {"-", file, ""},
		"key and file":     {testKey, file, ""},
		"empty file":       {"", empty, ""},
		"two words":        {"", two, ""},
		"missing file":     {"", filepath.Join(dir, "nope"), ""},
		"nothing on stdin": {"-", "", ""},
		"on the cmdline":   {testKey, "", ""},
	} {
		k, err := AuthKey(c.arg, c.file, strings.NewReader(c.stdin))
		if err == nil || k != "" {
			t.Errorf("%s: %q, %v", name, k, err)
		} else if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: the key in the error: %v", name, err)
		}
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

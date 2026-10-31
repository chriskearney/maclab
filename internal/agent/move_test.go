package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/testpki"
)

// A Mac enrolled with the old labd: everything setup wrote, plus a field a
// later lab-agent might add, which a move must keep as it is.
const oldAgentJSON = `{
  "server": "http://10.1.1.55:7770",
  "device_id": "d-abc123",
  "name": "m3pro",
  "secret": "dev_the_secret",
  "gui_user": "chrisk",
  "work_dir": "/var/lib/maclab",
  "enrollment": {"kind": "lab-owned"},
  "http_timeout_sec": 300,
  "a_later_field": {"kept": true}
}`

type moveFixture struct {
	dir, cfg string
	ca       *testpki.CA
	srv      *httptest.Server
	hits     atomic.Int32
	restarts atomic.Int32
}

// newMoveFixture is an agent.json in a private directory, next to a file a
// move must not touch, and a new labd at https://127.0.0.1:<port>/maclab
// that knows the Mac's secret as a Lab-owned Mac.
func newMoveFixture(t *testing.T) *moveFixture {
	t.Helper()
	f := &moveFixture{dir: t.TempDir(), ca: testpki.NewCA(t)}
	f.cfg = filepath.Join(f.dir, "agent.json")
	os.WriteFile(f.cfg, []byte(oldAgentJSON), 0o600)
	os.WriteFile(filepath.Join(f.dir, "left.json"), []byte(`{"untouched":true}`), 0o600)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if r.URL.Path != "/maclab/api/agent/enrollment" || r.Header.Get("Authorization") != "Bearer dev_the_secret" {
			http.Error(w, "unknown device secret", 401)
			return
		}
		json.NewEncoder(w).Encode(api.AgentEnrollment{Enrollment: api.Enrollment{Kind: api.KindLabOwned}})
	}))
	f.srv.TLS = f.ca.Leaf("127.0.0.1").ServerTLS()
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *moveFixture) caFile(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(p, f.ca.PEM, 0o600)
	return p
}

func (f *moveFixture) opts(server, ca string) MoveOptions {
	return MoveOptions{ConfigPath: f.cfg, Server: server, CAFile: ca, Restart: func() error { f.restarts.Add(1); return nil },
		InAgent: func() bool { return false }}
}

func (f *moveFixture) fields(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, _ := os.ReadFile(f.cfg)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The move checks the new labd with the Mac's own secret, then changes
// server, server_ca and allow_plain_http and nothing else, in one rename,
// and restarts lab-agent once.
func TestMoveChangesOnlyWhereLabdIs(t *testing.T) {
	f := newMoveFixture(t)
	before := f.fields(t)
	newURL := f.srv.URL + "/maclab/"
	if err := Move(context.Background(), f.opts(newURL, f.caFile(t))); err != nil {
		t.Fatal(err)
	}
	after := f.fields(t)
	same := func(a, b json.RawMessage) bool {
		var x, y bytes.Buffer
		return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && x.String() == y.String()
	}
	for k, v := range before {
		if k == "server" {
			continue
		}
		if !same(after[k], v) {
			t.Errorf("%s changed: %s -> %s", k, v, after[k])
		}
	}
	var server, ca string
	var plain bool
	json.Unmarshal(after["server"], &server)
	json.Unmarshal(after["server_ca"], &ca)
	json.Unmarshal(after["allow_plain_http"], &plain)
	if server != strings.TrimRight(newURL, "/") || ca != string(f.ca.PEM) || plain || len(after) != len(before)+2 {
		t.Errorf("after the move: %v", after)
	}
	if f.hits.Load() != 1 || f.restarts.Load() != 1 {
		t.Errorf("%d requests to the new labd, %d restarts", f.hits.Load(), f.restarts.Load())
	}
	st, _ := os.Stat(f.cfg)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("agent.json mode %v", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(f.dir)
	if len(ents) != 2 {
		t.Errorf("files beside agent.json: %v", ents)
	}
	if b, _ := os.ReadFile(filepath.Join(f.dir, "left.json")); string(b) != `{"untouched":true}` {
		t.Errorf("another file changed: %s", b)
	}
	// The moved config is the same Mac, reaching the new labd.
	cfg, err := LoadConfig(f.cfg)
	if err != nil || cfg.DeviceID != "d-abc123" || cfg.Secret != "dev_the_secret" || cfg.GUIUser != "chrisk" || cfg.HTTPTimeoutSec != 300 {
		t.Fatalf("the moved config: %+v %v", cfg, err)
	}
	if p, legacy := cfg.transportPolicy(); legacy || p.AllowPlainHTTP || len(p.CAPEM) == 0 {
		t.Errorf("the moved policy: %+v legacy=%v", p, legacy)
	}
}

// A move the new labd can't confirm, or that the policy refuses, changes
// nothing: agent.json stays byte for byte, and lab-agent isn't restarted.
func TestARefusedMoveChangesNothing(t *testing.T) {
	f := newMoveFixture(t)
	orig, _ := os.ReadFile(f.cfg)
	other := testpki.NewCA(t)
	otherCA := filepath.Join(t.TempDir(), "other.pem")
	os.WriteFile(otherCA, other.PEM, 0o600)
	junk := filepath.Join(t.TempDir(), "junk.pem")
	os.WriteFile(junk, []byte("junk"), 0o600)
	for name, o := range map[string]MoveOptions{
		"a labd that doesn't know the Mac": f.opts(f.srv.URL+"/elsewhere", f.caFile(t)),
		"an untrusted certificate":         f.opts(f.srv.URL+"/maclab", otherCA),
		"no CA for a private certificate":  f.opts(f.srv.URL+"/maclab", ""),
		"a junk CA file":                   f.opts(f.srv.URL+"/maclab", junk),
		"plain http to another machine":    f.opts("http://10.9.9.9:7770", ""),
		"a URL with credentials":           f.opts("https://u:p@maclab.example.com", ""),
		"no URL":                           f.opts("", ""),
	} {
		hitsBefore := f.hits.Load()
		if err := Move(context.Background(), o); err == nil {
			t.Errorf("%s: moved", name)
		}
		if b, _ := os.ReadFile(f.cfg); string(b) != string(orig) {
			t.Errorf("%s: agent.json changed", name)
		}
		if strings.HasPrefix(name, "plain") || strings.HasPrefix(name, "a URL") || strings.HasPrefix(name, "a junk") {
			if f.hits.Load() != hitsBefore {
				t.Errorf("%s: a request was sent", name)
			}
		}
	}
	if f.restarts.Load() != 0 {
		t.Errorf("restarted %d times", f.restarts.Load())
	}
	ents, _ := os.ReadDir(f.dir)
	if len(ents) != 2 {
		t.Errorf("left behind: %v", ents)
	}
}

// A labd that knows the secret as another kind of Mac is not this Mac's.
func TestMoveRefusesALabdThatKnowsTheMacAsAnotherKind(t *testing.T) {
	f := newMoveFixture(t)
	os.WriteFile(f.cfg, []byte(strings.Replace(oldAgentJSON, `"kind": "lab-owned"`, `"kind": "volunteer"`, 1)), 0o600)
	if err := Move(context.Background(), f.opts(f.srv.URL+"/maclab", f.caFile(t))); err == nil || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("a different kind: %v", err)
	}
}

// --no-check stages a move before the new labd answers: the URL and CA are
// still checked, nothing is asked of labd, and lab-agent keeps trying.
// A Mac that isn't enrolled has nothing to move.
func TestMoveWithoutCheckAndWithoutEnrollment(t *testing.T) {
	f := newMoveFixture(t)
	o := f.opts("https://maclab.example.com", "")
	o.NoCheck = true
	if err := Move(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	var server string
	json.Unmarshal(f.fields(t)["server"], &server)
	if server != "https://maclab.example.com" || f.hits.Load() != 0 || f.restarts.Load() != 1 {
		t.Errorf("staged move: %s, %d requests, %d restarts", server, f.hits.Load(), f.restarts.Load())
	}
	o.ConfigPath = filepath.Join(t.TempDir(), "none.json")
	if err := Move(context.Background(), o); err == nil || !strings.Contains(err.Error(), "isn't enrolled") {
		t.Errorf("not enrolled: %v", err)
	}
	gone := filepath.Join(t.TempDir(), "agent.json")
	os.WriteFile(gone, []byte(`{"server":"http://127.0.0.1:7770"}`), 0o600)
	o.ConfigPath = gone
	if err := Move(context.Background(), o); err == nil {
		t.Error("a config without an enrollment was moved")
	}
}

// setup no longer moves an enrolled Mac: given another server without a
// token, it stops before anything and names lab-agent move.
func TestSetupLeavesMovingToMove(t *testing.T) {
	cfg := &Config{Server: "http://10.1.1.55:7770", DeviceID: "d-1", Secret: "dev_s"}
	if err := refuseMoveInSetup(cfg, "", "https://maclab.example.com"); err == nil || !strings.Contains(err.Error(), "lab-agent move --server https://maclab.example.com") {
		t.Errorf("a move through setup: %v", err)
	}
	for name, c := range map[string]struct {
		cfg           *Config
		token, server string
	}{
		"the same server":      {cfg, "", "http://10.1.1.55:7770/"},
		"no server given":      {cfg, "", ""},
		"enrolling with token": {cfg, "enr_x", "https://maclab.example.com"},
		"not enrolled":         {nil, "", "https://maclab.example.com"},
	} {
		if err := refuseMoveInSetup(c.cfg, c.token, c.server); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Through lab exec (inside lab-agent.service) move would end with the service
// it restarts, before labd heard back: it refuses before reading or writing
// anything, and asks for a terminal or SSH.
func TestMoveRefusesToRunInsideLabAgent(t *testing.T) {
	f := newMoveFixture(t)
	orig, _ := os.ReadFile(f.cfg)
	o := f.opts(f.srv.URL+"/maclab", f.caFile(t))
	o.InAgent = func() bool { return true }
	err := Move(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "over SSH") || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("move inside lab-agent: %v", err)
	}
	if b, _ := os.ReadFile(f.cfg); string(b) != string(orig) || f.hits.Load() != 0 || f.restarts.Load() != 0 {
		t.Errorf("it acted: config changed=%v, %d requests, %d restarts", string(b) != string(orig), f.hits.Load(), f.restarts.Load())
	}
}

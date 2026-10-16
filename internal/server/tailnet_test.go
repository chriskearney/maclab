package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func TestTailnetRoles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peers := map[string]*TailnetPeer{
		"100.64.0.1":         {Login: "Admin@github", Node: "laptop"},
		"100.64.0.2":         {Login: "visitor@github", Node: "phone"},
		"100.64.0.3":         {Login: "tagged-devices", Node: "maclab-m1air", Tags: []string{"tag:maclab"}},
		"fd7a:115c:a1e0::10": {Login: "visitor@github", Node: "phone"},
	}
	calls := map[string]int{}
	whois := func(ctx context.Context, ip string) (*TailnetPeer, error) {
		calls[ip]++
		if p := peers[ip]; p != nil {
			return p, nil
		}
		return nil, fmt.Errorf("no match for IP")
	}
	trust, _ := ParseTrust("10.1.1.0/24")
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "adm_secret", Trust: trust,
		Tailscale: true, Admins: ParseAdmins("admin@github, other@github"), WhoIs: whois}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	try := func(method, path, remote, token string) int {
		r := httptest.NewRequest(method, path, strings.NewReader("{}"))
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	const (
		admin   = "100.64.0.1:40000"
		viewer  = "100.64.0.2:40000"
		tagged  = "100.64.0.3:40000"
		unknown = "100.64.0.9:40000"
		past    = 404 // through auth, then no such Mac
	)
	cases := []struct {
		name, method, path, remote, token string
		want                              int
	}{
		{"admin lists Macs", "GET", "/api/devices", admin, "", 200},
		{"admin submits a job", "POST", "/api/jobs", admin, "", past},
		{"viewer lists Macs", "GET", "/api/devices", viewer, "", 200},
		{"viewer over IPv6", "GET", "/api/jobs", "[fd7a:115c:a1e0::10]:1", "", 200},
		{"viewer reads builds", "GET", "/api/builds", viewer, "", 200},
		{"viewer submits a job", "POST", "/api/jobs", viewer, "", 403},
		{"viewer enrolls a Mac", "POST", "/api/enroll-tokens", viewer, "", 403},
		{"viewer resets a Mac", "POST", "/api/devices/m/reset", viewer, "", 403},
		{"viewer runs a command", "POST", "/api/devices/m/exec", viewer, "", 403},
		{"viewer takes a screenshot", "POST", "/api/devices/m/screenshot", viewer, "", 403},
		{"viewer opens the console", "GET", "/api/devices/m/console", viewer, "", 403},
		{"viewer reads the serial log", "GET", "/api/devices/m/serial", viewer, "", 403},
		{"viewer releases a lease", "DELETE", "/api/devices/m/lease", viewer, "", 403},
		{"viewer with the token", "POST", "/api/jobs", viewer, "adm_secret", past},
		{"tagged device only looks", "GET", "/api/devices", tagged, "", 200},
		{"tagged device can't change", "POST", "/api/jobs", tagged, "", 403},
		{"unknown tailnet address", "GET", "/api/devices", unknown, "", 401},
		{"off the tailnet", "GET", "/api/devices", "192.168.7.3:5000", "", 401},
		{"trusted network still admin", "POST", "/api/jobs", "10.1.1.42:1", "", past},
		{"token from anywhere", "POST", "/api/jobs", "192.168.7.3:5000", "adm_secret", past},
		{"agents keep device secrets", "POST", "/api/agent/checkin", admin, "", 401},
	}
	for _, c := range cases {
		if got := try(c.method, c.path, c.remote, c.token); got != c.want {
			t.Errorf("%s: %s %s got %d, want %d", c.name, c.method, c.path, got, c.want)
		}
	}
	if calls["100.64.0.2"] != 1 || calls["100.64.0.9"] != 1 {
		t.Errorf("whois answers must be cached: %v", calls)
	}
	if calls["192.168.7.3"] != 0 || calls["10.1.1.42"] != 0 {
		t.Errorf("whois asked about an address off the tailnet: %v", calls)
	}

	auth := func(remote string, token ...string) (out struct {
		TokenRequired bool `json:"token_required"`
		Role, Login   string
	}) {
		r := httptest.NewRequest("GET", "/api/auth", nil)
		r.RemoteAddr = remote
		for _, tok := range token {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if a := auth(viewer); a.TokenRequired || a.Role != "viewer" || a.Login != "visitor@github" {
		t.Errorf("viewer's /api/auth: %+v", a)
	}
	if a := auth(viewer, "adm_secret"); a.Role != "admin" {
		t.Errorf("viewer's /api/auth with the token: %+v", a)
	}
	if a := auth(viewer, "nope"); a.Role != "viewer" {
		t.Errorf("viewer's /api/auth with a wrong token: %+v", a)
	}
	if a := auth(admin); a.TokenRequired || a.Role != "admin" {
		t.Errorf("admin's /api/auth: %+v", a)
	}
	if a := auth("192.168.7.3:5000"); !a.TokenRequired || a.Role != "" {
		t.Errorf("outsider's /api/auth: %+v", a)
	}
}

// ./volunteer: any tailnet peer gets a token for its own Mac, under a free
// name and labelled with its login, and downloads the lab's lab-agent.
func TestVolunteer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	whois := func(ctx context.Context, ip string) (*TailnetPeer, error) {
		if ip == "100.64.0.2" {
			return &TailnetPeer{Login: "visitor@github", Node: "omarchy"}, nil
		}
		return nil, fmt.Errorf("no match for IP")
	}
	bin := filepath.Join(t.TempDir(), "lab-agent-linux-arm64")
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "adm_secret", Tailscale: true, WhoIs: whois, AgentBinary: bin},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	const peer = "100.64.0.2:40000"
	do := func(method, path, remote, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	volunteer := func(body string) (resp api.EnrollTokenResponse) {
		w := do("POST", "/api/volunteer", peer, body)
		if w.Code != 200 {
			t.Fatalf("volunteer %s: %d %s", body, w.Code, w.Body)
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		return resp
	}

	first := volunteer(`{"name":"Naeem-omarchy","model":"desktop"}`)
	if first.Name != "naeem-omarchy" || !strings.HasPrefix(first.Token, "enr_") {
		t.Fatalf("first volunteer: %+v", first)
	}
	if w := do("POST", "/api/agent/enroll", peer, `{"token":"`+first.Token+`"}`); w.Code != 200 {
		t.Fatalf("enroll with the volunteer's token: %d %s", w.Code, w.Body)
	}
	var d api.Device
	json.Unmarshal(do("GET", "/api/devices/naeem-omarchy", peer, "").Body.Bytes(), &d)
	if d.Label != "visitor@github" || d.Model != api.ModelDesktop {
		t.Errorf("the volunteer's Mac: label %q, model %q", d.Label, d.Model)
	}
	for body, want := range map[string]string{
		`{"name":"naeem-omarchy"}`:      "naeem-omarchy-2",
		`{"name":"  Ünïcode__host!! "}`: "n-code-host",
		`{}`:                            "mac",
		`{"name":"` + strings.Repeat("a", 40) + `"}`: strings.Repeat("a", 28),
	} {
		if got := volunteer(body).Name; got != want {
			t.Errorf("volunteer %s: name %q, want %q", body, got, want)
		}
	}
	if w := do("POST", "/api/volunteer", "192.168.7.3:5000", `{}`); w.Code != 401 {
		t.Errorf("off the tailnet: %d", w.Code)
	}

	if w := do("GET", "/api/volunteer/lab-agent", peer, ""); w.Code != 404 {
		t.Errorf("no lab-agent built: %d", w.Code)
	}
	if err := os.WriteFile(bin, []byte("ELF agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if w := do("GET", "/api/volunteer/lab-agent", peer, ""); w.Code != 200 || w.Body.String() != "ELF agent" {
		t.Errorf("download lab-agent: %d %q", w.Code, w.Body)
	}
	if w := do("GET", "/api/volunteer/lab-agent", "192.168.7.3:5000", ""); w.Code != 401 {
		t.Errorf("lab-agent off the tailnet: %d", w.Code)
	}
}

// Device views leave the controller's token out: it resets the Mac.
func TestDeviceViewHidesOOBToken(t *testing.T) {
	v := &dev{d: api.Device{Name: "m", OOB: &api.OOBConfig{URL: "http://oobd:7780", Token: "secret"}}}
	if o := v.viewLocked().OOB; o == nil || o.Token != "" || o.URL == "" {
		t.Fatalf("view oob %+v", o)
	}
	if v.d.OOB.Token != "secret" {
		t.Fatal("the view changed labd's own copy of the token")
	}
}

func TestTailscaleOffByDefault(t *testing.T) {
	asked := false
	s := &Server{cfg: Config{AdminToken: "adm_secret", WhoIs: func(context.Context, string) (*TailnetPeer, error) {
		asked = true
		return &TailnetPeer{Login: "admin@github"}, nil
	}, Admins: []string{"admin@github"}}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.1:1"
	if a, _ := s.access(r); a != noAccess || asked {
		t.Errorf("without --tailscale a tailnet peer got %v (whois asked: %v)", a, asked)
	}
}

func TestParseWhoIs(t *testing.T) {
	user := `{"Node":{"ID":1,"Name":"laptop.tail1234.ts.net.","ComputedName":"laptop","Addresses":["100.64.0.1/32"]},
		"UserProfile":{"ID":2,"LoginName":"someone@github","DisplayName":"Someone"}}`
	p, err := parseWhoIs([]byte(user))
	if err != nil || p.Login != "someone@github" || p.Node != "laptop" || len(p.Tags) != 0 {
		t.Errorf("user node: %+v, %v", p, err)
	}
	tagged := `{"Node":{"ComputedName":"maclab-m1air","Tags":["tag:maclab"]},"UserProfile":{"LoginName":"tagged-devices"}}`
	p, err = parseWhoIs([]byte(tagged))
	if err != nil || p.Node != "maclab-m1air" || len(p.Tags) != 1 {
		t.Errorf("tagged node: %+v, %v", p, err)
	}
	if _, err := parseWhoIs([]byte(`{}`)); err == nil {
		t.Error("an answer naming no one accepted")
	}
}

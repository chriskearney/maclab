package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret",
		Tailscale: true, WhoIs: whois}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	try := func(method, path, remote, token string) int {
		r := httptest.NewRequest(method, labdAt+path, strings.NewReader("{}"))
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
		{"admin lists Macs", "GET", "/api/devices", admin, "adm_secret", 200},
		{"admin submits a job", "POST", "/api/jobs", admin, "adm_secret", past},
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
		{"trusted network still admin", "POST", "/api/jobs", "10.1.1.42:1", "adm_secret", past},
		{"token from anywhere", "POST", "/api/jobs", "192.168.7.3:5000", "adm_secret", past},
		{"agents keep device secrets", "POST", "/api/agent/checkin", admin, "", 401},
		{"viewer reads a release", "GET", "/api/installed/aurora-1", viewer, "", 200},
		{"viewer can't leave the frozen stores", "GET", "/api/installed/..%2F..%2F..%2Fetc", viewer, "", 404},
		{"nor can an admin", "GET", "/api/installed/..%2F..%2F..%2Fetc", admin, "adm_secret", 404},
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
		r := httptest.NewRequest("GET", labdAt+"/api/auth", nil)
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
	if a := auth(admin, "adm_secret"); a.TokenRequired || a.Role != "admin" {
		t.Errorf("admin's /api/auth: %+v", a)
	}
	if a := auth("192.168.7.3:5000"); !a.TokenRequired || a.Role != "" {
		t.Errorf("outsider's /api/auth: %+v", a)
	}

	// The live stream leaves serial lines out for viewers: they carry the
	// console, which only admins may see.
	stream := func(remote string, token ...string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = remote
			for _, tok := range token {
				r.Header.Set("Authorization", "Bearer "+tok)
			}
			h.ServeHTTP(w, r)
		}))
		defer srv.Close()
		res, err := http.Get(srv.URL + "/api/stream")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		rd := bufio.NewReader(res.Body)
		if l, err := rd.ReadString('\n'); err != nil || !strings.HasPrefix(l, ": maclab stream") {
			t.Fatalf("stream for %s opened with %q, %v", remote, l, err)
		}
		s.hub.publish("serial", "m", map[string]any{"device": "m", "line": "root@m:~# cat secret"})
		s.hub.publish("job", "m", map[string]any{"device": "m", "id": "end"})
		var got strings.Builder
		for !strings.Contains(got.String(), `"end"`) {
			l, err := rd.ReadString('\n')
			if err != nil {
				t.Fatalf("stream for %s: %v after %q", remote, err, got.String())
			}
			got.WriteString(l)
		}
		return got.String()
	}
	if got := stream(viewer); strings.Contains(got, "event: serial") || strings.Contains(got, "secret") {
		t.Errorf("a viewer's stream carried a serial line:\n%s", got)
	}
	if got := stream(admin, "adm_secret"); !strings.Contains(got, "event: serial") {
		t.Errorf("an admin's stream lost the serial line:\n%s", got)
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
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret", Tailscale: true, WhoIs: whois, AgentBinary: bin},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	const peer = "100.64.0.2:40000"
	do := func(method, path, remote, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, labdAt+path, strings.NewReader(body))
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asked := false
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret", WhoIs: func(context.Context, string) (*TailnetPeer, error) {
		asked = true
		return &TailnetPeer{Login: "admin@github"}, nil
	}}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
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

func TestWhoisFailuresExpireSoon(t *testing.T) {
	calls, up := 0, false
	s := &Server{log: log.New(io.Discard, "", 0), cfg: Config{Tailscale: true, WhoIs: func(context.Context, string) (*TailnetPeer, error) {
		calls++
		if !up {
			return nil, fmt.Errorf("Failed to connect to local Tailscale daemon")
		}
		return &TailnetPeer{Login: "admin@github", Node: "laptop"}, nil
	}}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.1:1"
	ip := netip.MustParseAddr("100.64.0.1")
	age := func(d time.Duration) {
		e := s.whoCache[ip]
		e.at = e.at.Add(-d)
		s.whoCache[ip] = e
	}
	if p := s.tailnetPeer(r); p != nil || calls != 1 {
		t.Fatalf("tailscaled down: %+v after %d calls", p, calls)
	}
	if s.tailnetPeer(r); calls != 1 {
		t.Errorf("a failure right away asked again: %d calls", calls)
	}
	up = true
	age(whoisFailTTL + time.Second)
	if p := s.tailnetPeer(r); p == nil || calls != 2 {
		t.Fatalf("tailscaled back %v later: %+v after %d calls", whoisFailTTL+time.Second, p, calls)
	}
	age(whoisFailTTL + time.Second)
	if s.tailnetPeer(r); calls != 2 {
		t.Errorf("an answer was not kept: %d calls", calls)
	}
	age(whoisTTL)
	if s.tailnetPeer(r); calls != 3 {
		t.Errorf("an answer was kept past %v: %d calls", whoisTTL, calls)
	}
}

func TestWhoisSingleFlight(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	s := &Server{log: log.New(io.Discard, "", 0), cfg: Config{Tailscale: true, WhoIs: func(context.Context, string) (*TailnetPeer, error) {
		calls.Add(1)
		<-release
		return &TailnetPeer{Login: "admin@github", Node: "laptop"}, nil
	}}}
	var wg sync.WaitGroup
	got := make([]*TailnetPeer, 20)
	for i := range got {
		wg.Go(func() {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "100.64.0.1:" + fmt.Sprint(40000+i)
			got[i] = s.tailnetPeer(r)
		})
	}
	time.Sleep(50 * time.Millisecond) // let the burst pile up on the first lookup
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("a burst of %d requests ran %d lookups", len(got), n)
	}
	for i, p := range got {
		if p == nil || p.Login != "admin@github" {
			t.Errorf("request %d got %+v", i, p)
		}
	}
	if len(s.whoCalls) != 0 {
		t.Errorf("lookups left in flight: %v", s.whoCalls)
	}
}

// A lookup that panics is kept as a failure, for whoisFailTTL, not as an
// answer for whoisTTL: a real admin is locked out for seconds, not a minute.
func TestWhoisPanicExpiresSoon(t *testing.T) {
	calls, broken := 0, true
	s := &Server{log: log.New(io.Discard, "", 0), cfg: Config{Tailscale: true, WhoIs: func(context.Context, string) (*TailnetPeer, error) {
		calls++
		if broken {
			panic("whois blew up")
		}
		return &TailnetPeer{Login: "admin@github", Node: "laptop"}, nil
	}}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.1:1"
	ip := netip.MustParseAddr("100.64.0.1")
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
		}()
		s.tailnetPeer(r)
	}()
	if e := s.whoCache[ip]; e.p != nil || e.ttl != whoisFailTTL {
		t.Errorf("after a panic: cached %+v for %v, want nobody for %v", e.p, e.ttl, whoisFailTTL)
	}
	if len(s.whoCalls) != 0 {
		t.Errorf("the panicked lookup is still in flight: %v", s.whoCalls)
	}
	broken = false
	e := s.whoCache[ip]
	e.at = e.at.Add(-(whoisFailTTL + time.Second))
	s.whoCache[ip] = e
	if p := s.tailnetPeer(r); p == nil || calls != 2 {
		t.Errorf("%v after the panic: %+v after %d calls", whoisFailTTL+time.Second, p, calls)
	}
}

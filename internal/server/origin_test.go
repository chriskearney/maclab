package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// labdAt is where the tests' browsers and scripts reach labd: by an IP
// address, which is always one of labd's own names.
const labdAt = "http://10.1.1.5:7770"

// A page on another site, open in a browser on a trusted network, can't
// change the lab through it; labd's own UI, the CLI, agents and builders
// can.
func TestSameOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trust, _ := ParseTrust("10.1.1.0/24")
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "adm_secret", BuilderToken: "bld", Trust: trust,
		AllowHosts: []string{"labd", "labd.tail1234.ts.net"}}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	try := func(method, url, origin, site, token string) int {
		t.Helper()
		r := httptest.NewRequest(method, url, strings.NewReader(`{"command":"id"}`))
		r.RemoteAddr = "10.1.1.42:50000"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	const (
		exec = "http://labd:7770/api/devices/m1air/exec"
		past = 404 // through the check, then no such Mac
	)
	cases := []struct {
		name, method, url, origin, site, token string
		want                                   int
	}{
		{"another site's page", "POST", exec, "http://evil.example", "cross-site", "", 403},
		{"another site, Origin only", "POST", exec, "http://evil.example", "", "", 403},
		{"another site, with the token", "POST", exec, "http://evil.example", "", "adm_secret", 403},
		{"another port on labd's host", "POST", exec, "http://labd:8080", "same-site", "", 403},
		{"labd's host, default port", "POST", exec, "http://labd", "", "", 403},
		{"a sandboxed frame", "POST", exec, "null", "cross-site", "", 403},
		{"a sibling subdomain, no Origin", "DELETE", "http://labd:7770/api/devices/m1air/lease", "", "same-site", "", 403},
		{"another site, no Origin", "PATCH", "http://labd:7770/api/devices/m1air", "", "cross-site", "", 403},
		{"labd's own UI", "POST", exec, "http://labd:7770", "same-origin", "", past},
		{"labd's own UI, Origin only", "POST", exec, "http://labd:7770", "", "", past},
		{"the UI under another case", "POST", exec, "http://LabD:7770", "", "", past},
		{"the UI by IPv6 address", "POST", "http://[fd7a:115c:a1e0::5]:7770/api/devices/m1air/exec", "http://[fd7a:115c:a1e0::5]:7770", "same-origin", "", past},
		{"the UI behind https", "POST", "https://labd.tail1234.ts.net/api/devices/m1air/exec", "https://labd.tail1234.ts.net", "same-origin", "", past},
		{"the UI, Host with the default port", "POST", "https://labd.tail1234.ts.net:443/api/devices/m1air/exec", "https://labd.tail1234.ts.net", "", "", past},
		{"typed into the address bar", "POST", exec, "", "none", "", past},
		{"the CLI, curl, scripts", "POST", exec, "", "", "", past},
		{"the CLI with the token", "POST", exec, "", "", "adm_secret", past},
		{"another site may still look", "GET", "http://labd:7770/api/devices", "http://evil.example", "cross-site", "", 200},
		{"and ask about CORS", "OPTIONS", exec, "http://evil.example", "cross-site", "", 405},

		// Agents and builders send neither header, and get the same check:
		// a page can't post check-ins, enrollments or builds either.
		{"an agent's check-in", "POST", "http://labd:7770/api/agent/checkin", "", "", "dev_unknown", 401},
		{"a page posting a check-in", "POST", "http://labd:7770/api/agent/checkin", "http://evil.example", "cross-site", "dev_unknown", 403},
		{"a page enrolling a Mac", "POST", "http://labd:7770/api/agent/enroll", "http://evil.example", "cross-site", "", 403},
		{"a builder's poll", "POST", "http://labd:7770/api/builder/poll", "", "", "nope", 401},
		{"a page posting to the builder API", "POST", "http://labd:7770/api/builder/poll", "", "cross-site", "bld", 403},
	}
	for _, c := range cases {
		if got := try(c.method, c.url, c.origin, c.site, c.token); got != c.want {
			t.Errorf("%s: %s %s (Origin %q, Sec-Fetch-Site %q) got %d, want %d", c.name, c.method, c.url, c.origin, c.site, got, c.want)
		}
	}
}

// A page whose site points its own name at labd's address once it is open
// (DNS rebinding) sends labd that name as Host, and its Origin agrees: on a
// trusted network, or as a tailnet peer, labd answers it only on a Host of
// labd's own. A token, a device secret or the builder token works on any.
func TestDNSRebinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trust, _ := ParseTrust("10.1.1.0/24")
	whois := func(_ context.Context, ip string) (*TailnetPeer, error) {
		return &TailnetPeer{Login: "admin@github", Node: "laptop"}, nil
	}
	tsLookups := 0
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "adm_secret", BuilderToken: "bld", Trust: trust,
		Tailscale: true, Admins: []string{"admin@github"}, WhoIs: whois, AllowHosts: []string{"Lab.Example.LAN."},
		TailnetNames: func(context.Context) ([]string, error) {
			tsLookups++
			return parseStatusNames([]byte(`{"Self":{"DNSName":"i9beef.tail1234.ts.net."}}`))
		}}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.store.addTokenForTest("m1air")
	h := s.Handler()
	type answer struct {
		code int
		body string
	}
	try := func(method, url, remote, origin, token, body string) answer {
		t.Helper()
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		r.RemoteAddr = remote
		if origin != "" {
			r.Header.Set("Origin", origin)
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return answer{w.Code, w.Body.String()}
	}
	const (
		lan     = "10.1.1.42:50000"
		tailnet = "100.64.0.1:40000"
		exec    = "/api/devices/m1air/exec"
		past    = 404 // in, then no such Mac
	)
	host, _ := os.Hostname()
	short, _, _ := strings.Cut(strings.ToLower(host), ".")
	cases := []struct {
		name, method, url, remote, origin, token string
		want                                     int
	}{
		{"a rebound page runs a command", "POST", "http://evil.example:7770" + exec, lan, "http://evil.example:7770", "", 403},
		{"a rebound page reads the Macs", "GET", "http://evil.example:7770/api/devices", lan, "http://evil.example:7770", "", 403},
		{"a rebound page reads a job", "GET", "http://evil.example:7770/api/jobs/j1", lan, "", "", 403},
		{"a rebound page on the default port", "GET", "http://evil.example/api/devices", lan, "", "", 403},
		{"a rebound page from a tailnet admin", "POST", "http://evil.example:7770" + exec, tailnet, "http://evil.example:7770", "", 403},
		{"a rebound page watches the stream", "GET", "http://evil.example:7770/api/stream", lan, "", "", 403},
		{"by IPv4 address", "POST", "http://10.1.1.5:7770" + exec, lan, "http://10.1.1.5:7770", "", past},
		{"by IPv4 address, no port", "GET", "http://10.1.1.5/api/devices", lan, "", "", 200},
		{"by IPv6 address", "POST", "http://[fd00::5]:7770" + exec, lan, "http://[fd00::5]:7770", "", past},
		{"by IPv6 address, no port", "GET", "http://[::1]/api/devices", lan, "", "", 200},
		{"by localhost", "POST", "http://localhost:7770" + exec, lan, "http://localhost:7770", "", past},
		{"by its host name", "POST", "http://" + short + ":7770" + exec, lan, "http://" + short + ":7770", "", past},
		{"by its host name, in capitals", "GET", "http://" + strings.ToUpper(short) + ":7770/api/devices", lan, "", "", 200},
		{"by its .local name", "GET", "http://" + short + ".local:7770/api/devices", lan, "", "", 200},
		{"by an --allow-host name", "POST", "http://lab.example.lan:7770" + exec, lan, "http://lab.example.lan:7770", "", past},
		{"by its MagicDNS name", "POST", "http://i9beef.tail1234.ts.net:7770" + exec, tailnet, "http://i9beef.tail1234.ts.net:7770", "", past},
		{"by its MagicDNS short name", "GET", "http://i9beef:7770/api/devices", tailnet, "", "", 200},
		{"the token, by any name", "POST", "http://evil.example:7770" + exec, lan, "", "adm_secret", past},
		{"the token from outside, by any name", "GET", "http://evil.example:7770/api/devices", "192.168.7.3:5000", "", "adm_secret", 200},
		{"outside, no token: no access anyway", "GET", "http://evil.example:7770/api/devices", "192.168.7.3:5000", "", "", 401},
		{"the builder, by any name", "GET", "http://evil.example:7770/api/builder/artifacts/" + strings.Repeat("a", 64), lan, "", "bld", 404},
		{"the UI's files, by any name", "GET", "http://evil.example:7770/", lan, "", "", 200},
	}
	for _, c := range cases {
		if got := try(c.method, c.url, c.remote, c.origin, c.token, `{"command":"id"}`); got.code != c.want {
			t.Errorf("%s: %s %s from %s got %d %s, want %d", c.name, c.method, c.url, c.remote, got.code, got.body, c.want)
		}
	}
	if tsLookups != 1 {
		t.Errorf("looked up the MagicDNS names %d times, want once", tsLookups)
	}
	got := try("GET", "http://evil.example:7770/api/devices", lan, "", "", "")
	if want := "refused: this request asked for labd as evil.example:7770"; !strings.HasPrefix(got.body, want) || !strings.Contains(got.body, "--allow-host evil.example;") {
		t.Errorf("the refusal says %q", got.body)
	}
	// The UI asks /api/auth first, and shows why it needs a token.
	var a struct {
		TokenRequired bool   `json:"token_required"`
		Refused       string `json:"refused"`
	}
	json.Unmarshal([]byte(try("GET", "http://evil.example:7770/api/auth", lan, "", "", "").body), &a)
	if !a.TokenRequired || !strings.Contains(a.Refused, "--allow-host evil.example") {
		t.Errorf("/api/auth by a rebound name: %+v", a)
	}
	a.TokenRequired, a.Refused = true, ""
	json.Unmarshal([]byte(try("GET", "http://10.1.1.5:7770/api/auth", lan, "", "", "").body), &a)
	if a.TokenRequired || a.Refused != "" {
		t.Errorf("/api/auth by address: %+v", a)
	}

	// Agents enroll, check in and report by whatever name they were given.
	got = try("POST", "http://evil.example:7770/api/agent/enroll", lan, "", "", `{"token":"`+tok+`"}`)
	var enr api.EnrollResponse
	if json.Unmarshal([]byte(got.body), &enr); got.code != 200 || enr.Secret == "" {
		t.Fatalf("enroll by any name: %d %s", got.code, got.body)
	}
	if got := try("POST", "http://evil.example:7770/api/agent/report", lan, "", enr.Secret, `{}`); got.code != 200 {
		t.Errorf("an agent's report by any name: %d %s", got.code, got.body)
	}
	if got := try("POST", "http://evil.example:7770/api/agent/checkin?wait_ms=1", lan, "", enr.Secret, `{"boot_id":"b1"}`); got.code != 200 {
		t.Errorf("an agent's check-in by any name: %d %s", got.code, got.body)
	}
}

// --allow-host takes host names, with a port or a trailing dot dropped.
func TestParseAllowHost(t *testing.T) {
	if got, err := ParseAllowHost("Labd.LAN., i9beef:7770"); err != nil || !slices.Equal(got, []string{"labd.lan", "i9beef"}) {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"http://labd", "*.lan", "labd/ui", "-labd"} {
		if _, err := ParseAllowHost(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

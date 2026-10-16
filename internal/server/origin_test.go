package server

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
)

// A page on another site, open in a browser on a trusted network, can't
// change the lab through it; labd's own UI, the CLI, agents and builders
// can.
func TestSameOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trust, _ := ParseTrust("10.1.1.0/24")
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "adm_secret", BuilderToken: "bld", Trust: trust}, log.New(io.Discard, "", 0))
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

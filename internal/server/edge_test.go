package server

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// edgeServer is a labd served as https://chonkbase.net/maclab behind a
// reverse proxy in 10.2.0.0/16.
func edgeServer(t *testing.T) http.Handler {
	t.Helper()
	pub, err := ParsePublicURL("https://chonkbase.net/maclab")
	if err != nil {
		t.Fatal(err)
	}
	proxies, _ := ParseTrustedProxies("10.2.0.0/16")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret",
		PublicURL: pub, TrustedProxies: proxies}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

const (
	viaProxy = "10.2.3.4:5000"   // the ingress controller
	direct   = "192.0.2.9:40000" // anyone else reaching the pod
)

var fromIngress = map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "chonkbase.net"}

func edgeDo(h http.Handler, method, path, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	// The proxy talks plain http to labd, keeping the Host.
	r := httptest.NewRequest(method, "http://chonkbase.net"+path, strings.NewReader(`{}`))
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func with(m map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

// labd serves everything under its public URL's path, once; nothing outside
// it, not /maclabx, and no X-Forwarded-Prefix changes that.
func TestPrefixIsServedExactlyOnce(t *testing.T) {
	h := edgeServer(t)
	tok := with(fromIngress, "Authorization", "Bearer adm_secret")
	for _, c := range []struct {
		name, path string
		hdr        map[string]string
		want       int
	}{
		{"the UI", "/maclab/", fromIngress, 200},
		{"the UI without its slash", "/maclab", fromIngress, 200},
		{"its script", "/maclab/ui/app.js", fromIngress, 200},
		{"the API", "/maclab/api/devices", tok, 200},
		{"the API outside the prefix", "/api/devices", tok, 404},
		{"the UI outside the prefix", "/", fromIngress, 404},
		{"a sibling path", "/maclabx/api/devices", tok, 404},
		{"a sibling path's UI", "/maclab-old/", fromIngress, 404},
		{"the prefix twice", "/maclab/maclab/api/devices", tok, 404},
		{"a forwarded prefix", "/other/api/devices", with(tok, "X-Forwarded-Prefix", "/other"), 404},
		{"a forwarded prefix inside", "/maclab/api/devices", with(tok, "X-Forwarded-Prefix", "/other"), 200},
	} {
		if w := edgeDo(h, "GET", c.path, viaProxy, c.hdr); w.Code != c.want {
			t.Errorf("%s: GET %s = %d, want %d: %s", c.name, c.path, w.Code, c.want, w.Body)
		}
	}
	w := edgeDo(h, "GET", "/maclab/", viaProxy, fromIngress)
	if !strings.Contains(w.Body.String(), `<base href="/maclab/">`) {
		t.Errorf("the UI's page doesn't name its base:\n%s", w.Body)
	}
	page := strings.Replace(w.Body.String(), `<base href="/maclab/">`, "", 1)
	for _, p := range []string{`src="/`, `href="/`} {
		if strings.Contains(page, p) {
			t.Errorf("the UI's page has a URL from the root (%s), which would leave the prefix", p)
		}
	}
	js := edgeDo(h, "GET", "/maclab/ui/app.js", viaProxy, fromIngress).Body.String()
	for _, p := range []string{"'/api/", "`/api/", `"/api/`, "'/ui/", "`/ui/", `"/ui/`, "location.origin"} {
		if strings.Contains(js, p) {
			t.Errorf("app.js still has %q, which would leave the prefix", p)
		}
	}
}

// Forwarded scheme and host count only from the trusted proxies, and must
// name the public URL; anyone else's are ignored.
func TestForwardedOriginIsCheckedAndOnlyFromTrustedProxies(t *testing.T) {
	h := edgeServer(t)
	tok := with(fromIngress, "Authorization", "Bearer adm_secret")
	for _, c := range []struct {
		name, remote string
		hdr          map[string]string
		want         int
	}{
		{"the public URL", viaProxy, tok, 200},
		{"its default port named", viaProxy, with(tok, "X-Forwarded-Host", "chonkbase.net:443"), 200},
		{"the host in another case", viaProxy, with(tok, "X-Forwarded-Host", "ChonkBase.NET"), 200},
		{"plain http forwarded", viaProxy, with(tok, "X-Forwarded-Proto", "http"), 421},
		{"no scheme forwarded", viaProxy, map[string]string{"X-Forwarded-Host": "chonkbase.net", "Authorization": "Bearer adm_secret"}, 421},
		{"another host forwarded", viaProxy, with(tok, "X-Forwarded-Host", "evil.example"), 421},
		{"another port forwarded", viaProxy, with(tok, "X-Forwarded-Host", "chonkbase.net:8443"), 421},
		{"not from the proxy: headers ignored", direct, with(tok, "X-Forwarded-Host", "evil.example", "X-Forwarded-Proto", "gopher"), 200},
	} {
		w := edgeDo(h, "GET", "/maclab/api/devices", c.remote, c.hdr)
		if w.Code != c.want {
			t.Errorf("%s: %d, want %d: %s", c.name, w.Code, c.want, w.Body)
		}
		if w.Code == 421 && !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("%s: the refusal isn't sandboxed", c.name)
		}
	}
}

// A browser's Origin must be the very origin labd was reached at: scheme,
// host and port.
func TestBrowserOriginMustMatchSchemeHostAndPort(t *testing.T) {
	h := edgeServer(t)
	tok := with(fromIngress, "Authorization", "Bearer adm_secret")
	for _, c := range []struct {
		name, remote string
		hdr          map[string]string
		refused      bool
	}{
		{"labd's own page", viaProxy, with(tok, "Origin", "https://chonkbase.net"), false},
		{"labd's own page, default port named", viaProxy, with(tok, "Origin", "https://chonkbase.net:443"), false},
		{"an http page on labd's host", viaProxy, with(tok, "Origin", "http://chonkbase.net"), true},
		{"another port", viaProxy, with(tok, "Origin", "https://chonkbase.net:8443"), true},
		{"a subdomain", viaProxy, with(tok, "Origin", "https://evil.chonkbase.net"), true},
		{"another site", viaProxy, with(tok, "Origin", "https://evil.example"), true},
		{"a sandboxed frame", viaProxy, with(tok, "Origin", "null"), true},
		{"a sibling site, no Origin", viaProxy, with(tok, "Sec-Fetch-Site", "same-site"), true},
		// Not through the proxy, labd was reached at http://chonkbase.net:
		// the https page is another origin, forwarded headers or not.
		{"an https page, reaching the pod directly", direct, with(tok, "Origin", "https://chonkbase.net"), true},
	} {
		w := edgeDo(h, "POST", "/maclab/api/jobs", c.remote, c.hdr)
		if refused := w.Code == 403 && strings.Contains(w.Body.String(), "refused: a"); refused != c.refused {
			t.Errorf("%s: %d %s, want refused=%v", c.name, w.Code, w.Body, c.refused)
		}
	}
}

// Every answer is nosniff and no-referrer; API answers, uploaded job files and
// screens included, are sandboxed, so an uploaded page runs no script on
// labd's origin; the UI can't be framed; https answers carry HSTS.
func TestEveryAnswerCarriesTheSecurityHeaders(t *testing.T) {
	h := edgeServer(t)
	tok := with(fromIngress, "Authorization", "Bearer adm_secret")
	for _, c := range []struct {
		path    string
		sandbox bool
	}{
		{"/maclab/", false},
		{"/maclab/ui/app.js", false},
		{"/maclab/api/devices", true},
		{"/maclab/api/jobs/nope/files/evil.html", true},
		{"/maclab/api/devices/nope/screens/x.jpg", true},
		{"/nowhere", true},
	} {
		w := edgeDo(h, "GET", c.path, viaProxy, tok)
		hd := w.Header()
		if hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: %v", c.path, hd)
		}
		csp := hd.Get("Content-Security-Policy")
		if strings.Contains(csp, "sandbox") != c.sandbox || (!c.sandbox && !strings.Contains(csp, "frame-ancestors 'none'")) {
			t.Errorf("%s: Content-Security-Policy %q", c.path, csp)
		}
		if !strings.HasPrefix(hd.Get("Strict-Transport-Security"), "max-age=") {
			t.Errorf("%s: no HSTS over https", c.path)
		}
	}
	if w := edgeDo(h, "GET", "/maclab/", direct, nil); w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS on a plain http answer")
	}
}

func TestPublicURLAndTrustedProxiesRefuseWhatTheyCantMean(t *testing.T) {
	for _, bad := range []string{"ftp://lab", "https://", "lab.example.com/maclab", "https://u:p@lab/maclab", "https://lab/maclab?x=1",
		"https://lab/maclab#x", "https://lab/a/../b", "https://lab/a b", "https://lab/%2e%2e", "https://lab/.hidden"} {
		if _, err := ParsePublicURL(bad); err == nil {
			t.Errorf("--public-url %q was taken", bad)
		}
	}
	u, err := ParsePublicURL("https://ChonkBase.NET:443/maclab/")
	if err != nil || u.String() != "https://chonkbase.net/maclab" {
		t.Errorf("a public URL: %v %v", u, err)
	}
	if _, err := ParseTrustedProxies("10.2.0.0/16, 127.0.0.1"); err != nil {
		t.Error(err)
	}
	if _, err := ParseTrustedProxies("ingress-nginx"); err == nil {
		t.Error("a name was taken as a proxy")
	}
	proxies := []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}
	pub, _ := ParsePublicURL("https://chonkbase.net/maclab")
	for name, cfg := range map[string]Config{
		"a proxy without a public URL": {TrustedProxies: proxies},
		"a proxy with Tailscale":       {TrustedProxies: proxies, PublicURL: pub, Tailscale: true, WhoIs: func(context.Context, string) (*TailnetPeer, error) { return nil, nil }},
	} {
		cfg.DataDir, cfg.FirstMaintainer, cfg.FirstMaintainerToken = t.TempDir(), "ada", "adm_secret"
		if _, err := New(context.Background(), cfg, log.New(io.Discard, "", 0)); err == nil {
			t.Errorf("%s: labd started", name)
		}
	}
}

// A relayed request's TCP peer is the relay: with --tailscale on, no request
// carrying forwarding headers is judged by the relay's tailnet identity.
func TestForwardedRequestsNeverGetTailnetIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret", Tailscale: true,
		WhoIs: func(context.Context, string) (*TailnetPeer, error) {
			return &TailnetPeer{Login: "proxy@github", Node: "proxy"}, nil
		}},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	get := func(hdr ...string) int {
		r := httptest.NewRequest("GET", labdAt+"/api/devices", nil)
		r.RemoteAddr = "100.64.0.2:40000"
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := get(); c != 200 {
		t.Fatalf("a tailnet person directly: %d", c)
	}
	for _, hd := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-Ip"} {
		if c := get(hd, "203.0.113.7"); c != 401 {
			t.Errorf("relayed with %s: %d, want 401", hd, c)
		}
	}
}

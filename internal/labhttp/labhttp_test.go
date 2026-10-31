package labhttp

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/testpki"
)

// tlsServer serves h over TLS with a certificate for hosts signed by ca.
func tlsServer(t *testing.T, ca *testpki.CA, h http.Handler, hosts ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = ca.Leaf(hosts...).ServerTLS()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := c.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

func TestTrustedCertificateWorks(t *testing.T) {
	ca := testpki.NewCA(t)
	srv := tlsServer(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			w.WriteHeader(401)
		}
	}), "127.0.0.1")
	c, err := Policy{CAPEM: ca.PEM}.Client(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := get(t, c, srv.URL); err != nil || resp.StatusCode != 200 {
		t.Fatalf("labd with a certificate from the given CA: %v %v", resp, err)
	}
}

// Without the CA, with a certificate for another name, or with a certificate
// not valid yet, the handshake fails before the request (and its token) is
// sent.
func TestUntrustedCertificatesFailBeforeTheTokenIsSent(t *testing.T) {
	ca, other := testpki.NewCA(t), testpki.NewCA(t)
	var got atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.Add(1) })
	cases := []struct {
		name   string
		srv    *httptest.Server
		policy Policy
		time   bool
	}{
		{"system roots only", tlsServer(t, ca, h, "127.0.0.1"), Policy{}, false},
		{"another CA", tlsServer(t, ca, h, "127.0.0.1"), Policy{CAPEM: other.PEM}, false},
		{"a certificate for another name", tlsServer(t, ca, h, "labd.example.com"), Policy{CAPEM: ca.PEM}, false},
	}
	future := httptest.NewUnstartedServer(h)
	future.TLS = ca.LeafValid(time.Now().Add(time.Hour), time.Now().Add(48*time.Hour), "127.0.0.1").ServerTLS()
	future.StartTLS()
	defer future.Close()
	cases = append(cases, struct {
		name   string
		srv    *httptest.Server
		policy Policy
		time   bool
	}{"a certificate not valid yet (a clock behind)", future, Policy{CAPEM: ca.PEM}, true})

	for _, c := range cases {
		cl, err := c.policy.Client(5 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = get(t, cl, c.srv.URL)
		if err == nil {
			t.Errorf("%s: the request went through", c.name)
			continue
		}
		if CertTimeError(err) != c.time {
			t.Errorf("%s: CertTimeError = %v for %v", c.name, !c.time, err)
		}
	}
	if n := got.Load(); n != 0 {
		t.Errorf("%d requests reached a server the client must not trust", n)
	}
}

// A redirect is never followed: neither to plain http on the same host nor to
// another host, so the token goes nowhere else.
func TestRedirectsAreNeverFollowed(t *testing.T) {
	ca := testpki.NewCA(t)
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	for _, to := range []string{other.URL + "/api/devices", "http://127.0.0.1:1/api/devices"} {
		srv := tlsServer(t, ca, http.RedirectHandler(to, http.StatusFound), "127.0.0.1")
		c, _ := Policy{CAPEM: ca.PEM, AllowPlainHTTP: true}.Client(5 * time.Second)
		if _, err := get(t, c, srv.URL+"/api/devices"); !errors.Is(err, ErrRedirect) {
			t.Errorf("redirect to %s: %v, want ErrRedirect", to, err)
		}
	}
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the redirect target got %d requests", n)
	}
}

type countingRT struct{ n atomic.Int32 }

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

// Plain http leaves this machine only on purpose; the check comes before
// anything is sent. Names are never taken as private: only loopback
// addresses and localhost.
func TestPlainHTTPReachesOnlyLoopbackUnlessAllowed(t *testing.T) {
	for _, c := range []struct {
		url   string
		allow bool
		ok    bool
	}{
		{"http://127.0.0.1:7770/api/devices", false, true},
		{"http://[::1]:7770/api/devices", false, true},
		{"http://localhost:7770/api/devices", false, true},
		{"http://LOCALHOST/api/devices", false, true},
		{"http://10.1.1.55:7770/api/devices", false, false},
		{"http://100.64.0.1:7770/api/devices", false, false},
		{"http://labd.local:7770/api/devices", false, false},
		{"http://labd.tail1234.ts.net:7770/api/devices", false, false},
		{"http://labd:7770/api/devices", false, false},
		{"http://localhost.example.com/api/devices", false, false},
		{"http://lab.example.com/api/devices", false, false},
		{"http://10.1.1.55:7770/api/devices", true, true},
		{"https://lab.example.com/api/devices", false, true},
		{"ftp://lab.example.com/", true, false},
		{"https://user:pass@lab.example.com/maclab", false, false},
		{"http://user@127.0.0.1:7770/", false, false},
	} {
		base := &countingRT{}
		g := &guard{base: base, allowPlain: c.allow}
		u, _ := url.Parse(c.url)
		_, err := g.RoundTrip(&http.Request{Method: "GET", URL: u, Header: http.Header{"Authorization": {"Bearer t"}}})
		if (err == nil) != c.ok || (base.n.Load() == 1) != c.ok {
			t.Errorf("%s allow=%v: err %v, sent %d, want ok=%v", c.url, c.allow, err, base.n.Load(), c.ok)
		}
		if !c.ok && strings.HasPrefix(c.url, "http:") && !strings.Contains(c.url, "@") && !errors.Is(err, ErrPlainHTTP) {
			t.Errorf("%s: %v, want ErrPlainHTTP", c.url, err)
		}
	}
}

func TestCheckServerWantsAWholeURL(t *testing.T) {
	for _, s := range []string{"labd.example.com", "labd:7770", "", "https://"} {
		if CheckServer(s, true) == nil {
			t.Errorf("%q passed", s)
		}
	}
	if err := CheckServer("https://labd.example.com", false); err != nil {
		t.Error(err)
	}
}

func TestReadCAFileRefusesAFileWithoutCertificates(t *testing.T) {
	p := t.TempDir() + "/ca.pem"
	writeFile(t, p, "not a certificate")
	if _, err := ReadCAFile(p); err == nil {
		t.Error("a file without a certificate was taken")
	}
	ca := testpki.NewCA(t)
	writeFile(t, p, string(ca.PEM))
	if b, err := ReadCAFile(p); err != nil || len(b) == 0 {
		t.Errorf("a CA certificate: %v", err)
	}
	if _, err := (Policy{CAPEM: []byte("junk")}).Transport(); err == nil {
		t.Error("a junk CA was taken")
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Requests go straight to labd, whatever the environment says about proxies.
func TestEnvironmentProxiesAreNotUsed(t *testing.T) {
	var viaProxy atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { viaProxy.Add(1) }))
	defer proxy.Close()
	labd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer labd.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	c, _ := Policy{AllowPlainHTTP: true}.Client(5 * time.Second)
	if _, err := get(t, c, labd.URL); err != nil {
		t.Fatal(err)
	}
	if n := viaProxy.Load(); n != 0 {
		t.Errorf("%d requests went through the environment's proxy", n)
	}
}

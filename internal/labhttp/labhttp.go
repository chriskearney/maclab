// Package labhttp is how Maclab's programs talk to labd: the lab CLI and its
// MCP server, lab-agent and lab-builder all use one policy, so a labd URL
// means the same thing to each of them.
//
//   - https:// is verified against the system's roots, plus a private CA or
//     labd's own certificate when one is given (Policy.CAPEM). Verification
//     is never turned off.
//   - http:// reaches loopback only (127.0.0.0/8, ::1, localhost) unless the
//     caller opted in to plain http on purpose (Policy.AllowPlainHTTP): every
//     request carries a token or a device secret, which plain http would
//     show to the network.
//   - Redirects are never followed. labd never redirects an API request, and
//     a redirect would carry the token to wherever it points.
//   - No proxy from the environment (HTTP_PROXY and the like) is used, and a
//     URL may not carry credentials of its own: requests go straight to the
//     labd URL given, with the token in the Authorization header only.
package labhttp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Policy is how a client reaches labd.
type Policy struct {
	// CAPEM is extra trust for https: PEM certificates added to the system's
	// roots, such as a private CA or labd's own self-signed certificate.
	CAPEM []byte
	// AllowPlainHTTP lets http:// URLs reach hosts other than loopback.
	AllowPlainHTTP bool
}

// ErrPlainHTTP is a request refused before it was sent: plain http to a host
// other than loopback, without the opt-in.
var ErrPlainHTTP = errors.New("plain http outside this machine")

// ErrRedirect is labd's answer being a redirect, which clients don't follow.
var ErrRedirect = errors.New("labd answered with a redirect")

// Transport is an http.RoundTripper with p's trust, which refuses plain http
// as p says before anything is sent. Clients sharing one Transport share its
// connections.
func (p Policy) Transport() (http.RoundTripper, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(p.CAPEM) > 0 && !roots.AppendCertsFromPEM(p.CAPEM) {
		return nil, errors.New("the CA file holds no PEM certificate")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	t.ForceAttemptHTTP2 = true
	t.Proxy = nil
	return &guard{base: t, allowPlain: p.AllowPlainHTTP}, nil
}

// Client is an http.Client over rt that never follows a redirect. timeout 0
// is none.
func Client(rt http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{Transport: rt, Timeout: timeout, CheckRedirect: refuseRedirect}
}

// Client is a Client over a new Transport with p.
func (p Policy) Client(timeout time.Duration) (*http.Client, error) {
	rt, err := p.Transport()
	if err != nil {
		return nil, err
	}
	return Client(rt, timeout), nil
}

func refuseRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("%w to %s: Maclab clients never follow one, so check the labd URL", ErrRedirect, req.URL.Redacted())
}

// guard checks each request's URL before its base transport sends it.
type guard struct {
	base       http.RoundTripper
	allowPlain bool
}

func (g *guard) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := CheckURL(r.URL, g.allowPlain); err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	return g.base.RoundTrip(r)
}

// CheckURL is why a client won't send a request to u, or nil: only http and
// https, and http only to loopback unless allowPlain.
func CheckURL(u *url.URL, allowPlain bool) error {
	if u.User != nil {
		return fmt.Errorf("labd URL %s carries credentials: give the token separately", u.Redacted())
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowPlain || Loopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %s is plain http, which would show the token to the network. Use https://, "+
			"or opt in to plain http on purpose (--allow-plain-http, or MACLAB_ALLOW_PLAIN_HTTP=1)", ErrPlainHTTP, u.Redacted())
	default:
		return fmt.Errorf("labd URL %s: want https:// (or http:// on this machine)", u.Redacted())
	}
}

// CheckServer is CheckURL for a labd URL as a user gave it.
func CheckServer(raw string, allowPlain bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("labd URL %q: %v", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("labd URL %q: give the whole URL, such as https://labd.example.com", raw)
	}
	return CheckURL(u, allowPlain)
}

// Loopback reports whether host, a URL's host name, is this machine by its
// literal address or the name localhost. Nothing is resolved.
func Loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ReadCAFile reads a PEM file of CA certificates for Policy.CAPEM, refusing
// one that holds none.
func ReadCAFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("CA file: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("CA file %s holds no PEM certificate", path)
	}
	return b, nil
}

// CertTimeError reports whether err is a certificate that isn't valid at this
// machine's time: expired, or not valid yet. Right after a reboot a Mac's
// clock can be decades behind until NTP sets it, and every https request
// fails this way until then.
func CertTimeError(err error) bool {
	var inv x509.CertificateInvalidError
	return errors.As(err, &inv) && inv.Reason == x509.Expired
}

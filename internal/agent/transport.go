package agent

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/iconidentify/maclab/internal/labhttp"
)

// How lab-agent reaches labd: labhttp's policy, from what setup recorded in
// agent.json.
//
//   - server_ca is the PEM of the CA (or labd certificate) setup was given
//     with --ca-file, trusted besides the system's roots.
//   - allow_plain_http is whether an http:// labd on another machine is
//     allowed (setup --allow-plain-http); setup always writes it.
//
// An agent.json without allow_plain_http was written by a lab-agent from
// before https support, every one of which talked plain http to labd. Such a
// Mac keeps doing so, with a warning: lab-agent has no self-update, and a
// new binary refusing the URL its Mac was set up with would leave the Mac
// unreachable until someone ran setup at it. That is the one exception to
// "plain http reaches loopback only"; setup turns it into an explicit choice.

// transportPolicy is cfg's labhttp policy, and whether it allows plain http
// only because agent.json predates the choice.
func (c *Config) transportPolicy() (p labhttp.Policy, legacy bool) {
	p.CAPEM = []byte(c.ServerCA)
	switch {
	case c.AllowPlainHTTP != nil:
		p.AllowPlainHTTP = *c.AllowPlainHTTP
	case plainRemote(c.Server):
		p.AllowPlainHTTP, legacy = true, true
	}
	return p, legacy
}

// plainRemote is whether server is an http:// URL to another machine.
func plainRemote(server string) bool {
	u, err := url.Parse(server)
	return err == nil && u.Scheme == "http" && !labhttp.Loopback(u.Hostname())
}

// legacyPlainWarning is what lab-agent logs when it uses plain http only
// because agent.json predates the choice.
func legacyPlainWarning(server string) string {
	return fmt.Sprintf("WARNING: labd %s is plain http, so this Mac's device secret crosses the network unencrypted. "+
		"agent.json predates that being a choice; run `sudo lab-agent setup --server https://...` to move to https, "+
		"or `sudo lab-agent setup --allow-plain-http` to keep plain http on purpose", server)
}

// transport is the RoundTripper every request of cfg's goes through. A CA
// that can't be read makes every request fail, never fall back to less.
func (c *Config) transport() http.RoundTripper {
	p, _ := c.transportPolicy()
	rt, err := p.Transport()
	if err != nil {
		return failing{fmt.Errorf("agent.json server_ca: %w", err)}
	}
	return rt
}

// client is an http.Client for cfg's requests, timeout 0 being none.
func (c *Config) client(timeout time.Duration) *http.Client {
	return labhttp.Client(c.transport(), timeout)
}

type failing struct{ err error }

func (f failing) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		r.Body.Close()
	}
	return nil, f.err
}

// certTimeHint is added to an error reaching labd when labd's certificate
// isn't valid at this Mac's time: right after a reboot a Mac's clock can be
// decades behind until NTP sets it. Verification stays on; lab-agent just
// keeps trying.
func certTimeHint(err error, now time.Time) string {
	if !labhttp.CertTimeError(err) {
		return ""
	}
	return fmt.Sprintf(" (labd's certificate isn't valid at this Mac's clock, %s: waiting for the time to be set, e.g. by NTP)", now.UTC().Format(time.RFC3339))
}

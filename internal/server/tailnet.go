package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// TailnetPeer is who tailscaled says is behind a tailnet address.
type TailnetPeer struct {
	Login string   // e.g. someone@github; "tagged-devices" for a tagged node
	Node  string   // the machine's name on the tailnet
	Tags  []string // set for tagged devices, which act for no person
}

type access int

const (
	noAccess access = iota
	viewAccess
	adminAccess
)

// Tailscale hands out 100.64.0.0/10 and fd7a:115c:a1e0::/48; anything else
// never reaches whois.
var tailnetRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

func inTailnet(ip netip.Addr) bool {
	for _, n := range tailnetRanges {
		if n.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// whoisTTL keeps labd from running the tailscale CLI on every request.
// whoisFailTTL is much shorter: a failed lookup (tailscaled restarting, a
// timeout) must not lock a real admin out for long.
const (
	whoisTTL     = time.Minute
	whoisFailTTL = 5 * time.Second
)

type whoisEntry struct {
	p   *TailnetPeer
	at  time.Time
	ttl time.Duration
}

// whoisCall is a lookup in flight; requests from the same address wait for it
// instead of starting their own.
type whoisCall struct {
	done chan struct{}
	p    *TailnetPeer
}

// access decides what a request may do. The admin token and a trusted network
// give admin. With Tailscale on, a tailnet peer whose login is in Admins is an
// admin and any other peer, tagged devices included, a viewer. who names the
// tailnet peer, for error messages. Without the token, a request gets in only
// when it asked for labd by one of its own names (see ownHost).
func (s *Server) access(r *http.Request) (a access, who string) {
	a, who, _ = s.accessHost(r)
	return a, who
}

// accessHost is access, and says whether the request has no access only
// because it asked for labd by a name that isn't labd's own (foreign): its
// network or its tailnet login would have let it in.
func (s *Server) accessHost(r *http.Request) (a access, who string, foreign bool) {
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.AdminToken)) == 1 {
		return adminAccess, "", false
	}
	if a, who = s.tokenless(r); a != noAccess && !s.ownHost(r.Host) {
		return noAccess, "", true
	}
	return a, who, false
}

// tokenless is the access a request gets without the admin token. With
// Tailscale on, a trusted network gives nothing to traffic that may be from
// the tailnet, as far as labd can tell (see mayBeTailnet): a tailnet peer
// address is judged by its identity, and a proxied request gets no trust at
// all.
func (s *Server) tokenless(r *http.Request) (access, string) {
	if s.trusted(r) && !(s.cfg.Tailscale && mayBeTailnet(r)) {
		return adminAccess, ""
	}
	if !s.cfg.Tailscale {
		return noAccess, ""
	}
	p := s.tailnetPeer(r)
	if p == nil {
		return noAccess, ""
	}
	if len(p.Tags) > 0 {
		return viewAccess, p.Node
	}
	for _, a := range s.cfg.Admins {
		if strings.EqualFold(a, p.Login) {
			return adminAccess, p.Login
		}
	}
	return viewAccess, p.Login
}

// serveHeaders are what tailscale serve sets on a request it proxies, besides
// X-Forwarded-For: the identity of a tailnet user, or Funnel's marker for
// internet traffic. Tagged nodes get none of them.
var serveHeaders = []string{"Tailscale-User-Login", "Tailscale-User-Name", "Tailscale-User-Profile-Pic",
	"Tailscale-Headers-Info", "Tailscale-App-Capabilities", "Tailscale-Funnel-Request"}

// mayBeTailnet reports whether a request may have come from the tailnet, as
// far as labd can tell: it came from a tailnet address, or through an HTTP
// proxy. tailscale serve and Funnel proxy from 127.0.0.1 or this host's own
// address, so only headers give them away: serve's own, and the
// X-Forwarded-For it always sets. Any X-Forwarded-* or Forwarded header
// counts, whatever it says: labd can't tell which proxy set it, or where that
// proxy's client came from. Faking one only loses a client access. Raw TCP
// forwarding (tailscale serve --tcp or --tls-terminated-tcp, Funnel's TCP
// mode) sets no header at all, and labd can't tell it from a local client.
func mayBeTailnet(r *http.Request) bool {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil && inTailnet(ap.Addr()) {
		return true
	}
	for _, h := range serveHeaders {
		if len(r.Header.Values(h)) > 0 {
			return true
		}
	}
	for h := range r.Header {
		if strings.EqualFold(h, "Forwarded") || len(h) > len("X-Forwarded-") && strings.EqualFold(h[:len("X-Forwarded-")], "X-Forwarded-") {
			return true
		}
	}
	return false
}

// warnTrustedNetworks says, for each trusted network, what tailnet traffic
// gets admin through it anyway: labd only sees a local or LAN address.
func warnTrustedNetworks(cfg Config, logger *log.Logger) {
	if !cfg.Tailscale {
		return
	}
	for _, n := range cfg.Trust {
		logger.Printf("warning: --trust %s with --tailscale: tailnet traffic that reaches labd through %s gets admin with no token "+
			"(a subnet router into it, Tailscale SSH onto a machine in it, tailscale serve --tcp or Funnel TCP forwarding from this host). "+
			"labd refuses trust to requests carrying a proxy's headers (X-Forwarded-*, Forwarded, tailscale serve's), "+
			"but can't tell the rest from local traffic", n, n)
	}
}

// tailnetPeer asks tailscaled who connected, by the TCP peer address only.
// Answers are cached for whoisTTL, failures ("nobody") for whoisFailTTL, and
// concurrent requests from one address share one lookup.
func (s *Server) tailnetPeer(r *http.Request) *TailnetPeer {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || s.cfg.WhoIs == nil {
		return nil
	}
	ip := ap.Addr().Unmap()
	if !inTailnet(ip) {
		return nil
	}
	s.whoMu.Lock()
	if e, ok := s.whoCache[ip]; ok && time.Since(e.at) < e.ttl {
		s.whoMu.Unlock()
		return e.p
	}
	if c, ok := s.whoCalls[ip]; ok {
		s.whoMu.Unlock()
		<-c.done
		return c.p
	}
	c := &whoisCall{done: make(chan struct{})}
	if s.whoCalls == nil {
		s.whoCalls = map[netip.Addr]*whoisCall{}
	}
	s.whoCalls[ip] = c
	s.whoMu.Unlock()

	// A lookup is a failure until it returns an answer: one that panics is
	// kept for whoisFailTTL too, not whoisTTL.
	ttl := whoisFailTTL
	defer func() {
		s.whoMu.Lock()
		if s.whoCache == nil {
			s.whoCache = map[netip.Addr]whoisEntry{}
		}
		s.whoCache[ip] = whoisEntry{c.p, time.Now(), ttl}
		delete(s.whoCalls, ip)
		s.whoMu.Unlock()
		close(c.done)
	}()
	// Not the request's context: a client hanging up must not fail the lookup
	// for everyone waiting on it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := s.cfg.WhoIs(ctx, ip.String())
	if err != nil {
		s.log.Printf("tailscale whois %s: %v", ip, err)
		return nil
	}
	c.p, ttl = p, whoisTTL
	return p
}

// tailscaleWhoIs asks the local tailscaled through its CLI.
func tailscaleWhoIs(ctx context.Context, ip string) (*TailnetPeer, error) {
	out, err := exec.CommandContext(ctx, tailscaleCLI(), "whois", "--json", ip).Output()
	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
		return nil, fmt.Errorf("%v: %s", err, bytes.TrimSpace(ee.Stderr))
	} else if err != nil {
		return nil, err
	}
	return parseWhoIs(out)
}

func parseWhoIs(b []byte) (*TailnetPeer, error) {
	var w struct {
		Node struct {
			ComputedName string
			Tags         []string
		}
		UserProfile struct{ LoginName string }
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("tailscale whois: %w", err)
	}
	if w.UserProfile.LoginName == "" && len(w.Node.Tags) == 0 {
		return nil, fmt.Errorf("tailscale whois: no login and no tags")
	}
	return &TailnetPeer{Login: w.UserProfile.LoginName, Node: w.Node.ComputedName, Tags: w.Node.Tags}, nil
}

// tailscaleCLI is tailscale on PATH, else the macOS app's copy.
func tailscaleCLI() string {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	if runtime.GOOS == "darwin" {
		return "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
	}
	return "tailscale"
}

// ParseAdmins turns "a@github, b@github" into logins.
func ParseAdmins(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
}

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
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

// access decides what a request may do. A Maintainer's token gives admin,
// and who is that Maintainer's name. With Tailscale on, any tailnet peer,
// tagged devices included, is a viewer, and who names the peer, for error
// messages. Without a token, a request gets in only when it asked for labd
// by one of its own names (see ownHost).
func (s *Server) access(r *http.Request) (a access, who string) {
	a, who, _ = s.accessHost(r)
	return a, who
}

// accessHost is access, and says whether the request has no access only
// because it asked for labd by a name that isn't labd's own (foreign): its
// tailnet login would have let it look.
func (s *Server) accessHost(r *http.Request) (a access, who string, foreign bool) {
	if name, err := s.store.maintainerByToken(hashSecret(bearer(r))); err == nil {
		return adminAccess, name, false
	}
	if a, who = s.tokenless(r); a != noAccess && !s.ownHost(r.Host) {
		return noAccess, "", true
	}
	return a, who, false
}

// tokenless is the access a request gets without a Maintainer's token: with
// Tailscale on, a tailnet peer may look, judged by its identity; nothing
// else gets in.
func (s *Server) tokenless(r *http.Request) (access, string) {
	if !s.cfg.Tailscale {
		return noAccess, ""
	}
	// A relayed request's TCP peer is the relay, not the person: a proxy on
	// the tailnet would otherwise lend everyone behind it its own identity.
	if forwarded(r) || s.fromTrustedProxy(r) {
		return noAccess, ""
	}
	p := s.tailnetPeer(r)
	if p == nil {
		return noAccess, ""
	}
	if len(p.Tags) > 0 {
		return viewAccess, p.Node
	}
	return viewAccess, p.Login
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

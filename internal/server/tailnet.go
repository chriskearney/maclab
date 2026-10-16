package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
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

// whoisTTL keeps labd from running the tailscale CLI on every request.
const whoisTTL = time.Minute

type whoisEntry struct {
	p  *TailnetPeer
	at time.Time
}

// access decides what a request may do. The admin token and a trusted network
// give admin. With Tailscale on, a tailnet peer whose login is in Admins is an
// admin and any other peer, tagged devices included, a viewer. who names the
// tailnet peer, for error messages.
func (s *Server) access(r *http.Request) (a access, who string) {
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.AdminToken)) == 1 {
		return adminAccess, ""
	}
	return s.tokenless(r)
}

// tokenless is the access a request gets without the admin token.
func (s *Server) tokenless(r *http.Request) (access, string) {
	if s.trusted(r) {
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

// tailnetPeer asks tailscaled who connected, by the TCP peer address only.
// Answers, including "nobody", are cached for whoisTTL.
func (s *Server) tailnetPeer(r *http.Request) *TailnetPeer {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || s.cfg.WhoIs == nil {
		return nil
	}
	ip := ap.Addr().Unmap()
	in := false
	for _, n := range tailnetRanges {
		in = in || n.Contains(ip)
	}
	if !in {
		return nil
	}
	s.whoMu.Lock()
	e, ok := s.whoCache[ip]
	s.whoMu.Unlock()
	if ok && time.Since(e.at) < whoisTTL {
		return e.p
	}
	// Not the request's context: a client hanging up must not cache "nobody".
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := s.cfg.WhoIs(ctx, ip.String())
	if err != nil {
		s.log.Printf("tailscale whois %s: %v", ip, err)
		p = nil
	}
	s.whoMu.Lock()
	if s.whoCache == nil {
		s.whoCache = map[netip.Addr]whoisEntry{}
	}
	s.whoCache[ip] = whoisEntry{p, time.Now()}
	s.whoMu.Unlock()
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

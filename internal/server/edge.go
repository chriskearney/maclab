package server

// The edge is what labd does with every request before any route: the
// prefix labd lives under, which external origin the request came through,
// and the headers every answer carries.
//
//   - Config.PublicURL is the one URL people and Macs use, such as
//     https://chonkbase.net/maclab. Its path is labd's prefix: labd serves
//     everything under it, and the reverse proxy in front passes the path on
//     unchanged. A request outside it gets 404.
//   - Config.TrustedProxies are the reverse proxies labd sits behind. Only
//     from them does labd read X-Forwarded-Proto and X-Forwarded-Host, and
//     those must name the public URL's scheme and host, or the request gets
//     421. Nothing forwarded is ever an identity: a caller is still known by
//     their token alone.
//   - Every answer says nosniff and no-referrer, and no page may frame labd.
//     API answers, which include files Macs uploaded, are sandboxed, so an
//     uploaded page can't run script with labd's origin, where the browser
//     keeps a Maintainer's token. Over https the browser is told to stay on
//     https (HSTS).

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// rePublicPath is a prefix's path: segments of safe characters.
var rePublicPath = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*$`)

// ParsePublicURL checks a --public-url: https (or http) scheme://host[:port]
// and an optional path prefix, nothing else.
func ParsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("--public-url %q: %v", raw, err)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, fmt.Errorf("--public-url %q: want https://host[/prefix]", raw)
	case u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return nil, fmt.Errorf("--public-url %q: give scheme://host[:port][/prefix] only", raw)
	case !rePublicPath.MatchString(u.Path) || strings.Contains(u.Path, "/.") || u.RawPath != "":
		return nil, fmt.Errorf("--public-url %q: the prefix must be plain path segments, such as /maclab", raw)
	}
	u.Host = canonHost(u.Scheme, u.Host)
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}, nil
}

// ParseTrustedProxies turns --trusted-proxy values (CIDRs or addresses,
// comma separated) into prefixes.
func ParseTrustedProxies(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("--trusted-proxy %q: give a CIDR such as 10.42.0.0/16, or an address", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// canonHost is host[:port] in lower case, without the scheme's default port.
func canonHost(scheme, host string) string {
	host = strings.ToLower(host)
	if h, p, err := net.SplitHostPort(host); err == nil && p == map[string]string{"http": "80", "https": "443"}[scheme] {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return host
}

// basePath is labd's prefix, "" when it serves at the root.
func (s *Server) basePath() string {
	if s.cfg.PublicURL == nil {
		return ""
	}
	return s.cfg.PublicURL.Path
}

// fromTrustedProxy reports whether r's TCP peer is one of the trusted
// reverse proxies.
func (s *Server) fromTrustedProxy(r *http.Request) bool {
	if len(s.cfg.TrustedProxies) == 0 {
		return false
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// forwarded reports whether r says a proxy relayed it. A browser connecting
// to labd itself sends none of these.
func forwarded(r *http.Request) bool {
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip"} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// externalOrigin is the origin r came to: scheme://host[:port] as the
// browser saw it. From a trusted proxy that is the public URL's, once the
// forwarded scheme and host are checked against it; otherwise it is the
// connection's own scheme and the Host header. ok is false for a proxied
// request naming another origin.
func (s *Server) externalOrigin(r *http.Request) (origin string, ok bool) {
	if s.fromTrustedProxy(r) {
		pub := s.cfg.PublicURL
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "http"
		}
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		if pub == nil || !strings.EqualFold(proto, pub.Scheme) || canonHost(pub.Scheme, host) != pub.Host {
			return "", false
		}
		return pub.Scheme + "://" + pub.Host, true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + canonHost(scheme, r.Host), true
}

// sameOriginAs reports whether a browser's Origin header names origin.
func sameOriginAs(o, origin string) bool {
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" {
		return false
	}
	return u.Scheme+"://"+canonHost(u.Scheme, u.Host) == origin
}

// edge wraps the API and UI: the prefix, the proxy check, the browser check
// and the headers every answer carries.
func (s *Server) edge(h http.Handler) http.Handler {
	base := s.basePath()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Referrer-Policy", "no-referrer")
		origin, ok := s.externalOrigin(r)
		if !ok {
			hdr.Set("Content-Security-Policy", "sandbox; default-src 'none'")
			httpErr(w, http.StatusMisdirectedRequest, "this is labd at %s: the proxy in front of it forwarded a request for another address", s.cfg.PublicURL.Redacted())
			return
		}
		if strings.HasPrefix(origin, "https://") {
			hdr.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if base != "" {
			rest, found := strings.CutPrefix(r.URL.Path, base)
			// A path the router would clean (//, /./, /../) gets 404, not
			// its redirect: that would name a path outside the prefix.
			if !found || (rest != "" && rest[0] != '/') || (rest != "" && path.Clean(rest) != strings.TrimSuffix(rest, "/") && path.Clean(rest) != rest) {
				hdr.Set("Content-Security-Policy", "sandbox; default-src 'none'")
				http.NotFound(w, r)
				return
			}
			r = stripPrefix(r, base, rest)
			w = &prefixedRedirects{ResponseWriter: w, base: base}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hdr.Set("Content-Security-Policy", "sandbox; default-src 'none'; frame-ancestors 'none'")
		} else {
			hdr.Set("Content-Security-Policy", "frame-ancestors 'none'")
		}
		if !s.sameOriginOK(w, r, origin) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// prefixedRedirects puts labd's prefix back in front of the path a redirect
// names: the router and file server below it know only the stripped path,
// and a redirect to /ui/ would otherwise leave labd for its neighbours.
type prefixedRedirects struct {
	http.ResponseWriter
	base string
}

func (p *prefixedRedirects) WriteHeader(code int) {
	if code >= 300 && code < 400 {
		if loc := p.Header().Get("Location"); strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") {
			p.Header().Set("Location", p.base+loc)
		}
	}
	p.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the writer below (flushing a
// stream, its deadlines).
func (p *prefixedRedirects) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// Flush flushes, for the handlers that ask the writer itself.
func (p *prefixedRedirects) Flush() {
	if f, ok := p.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// stripPrefix is r with base taken off its path once; rest is what follows
// it, "" for the prefix itself, which serves the UI.
func stripPrefix(r *http.Request, base, rest string) *http.Request {
	r2 := new(http.Request)
	*r2 = *r
	r2.URL = new(url.URL)
	*r2.URL = *r.URL
	if rest == "" {
		rest = "/"
	}
	r2.URL.Path = rest
	r2.URL.RawPath = ""
	if r.URL.RawPath != "" {
		if rp, found := strings.CutPrefix(r.URL.RawPath, base); found {
			r2.URL.RawPath = rp
		}
	}
	return r2
}

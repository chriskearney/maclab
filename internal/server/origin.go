package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// sameOrigin refuses a request that can change something (any method but
// GET, HEAD and OPTIONS) when a browser sent it from another site's page.
// labd gives admin by the network a browser is on (--trust, a tailnet login
// in --admins) as well as by token, so without this any page open in a
// browser there could POST to /api/devices/{name}/exec. Browsers name the
// sending page's origin in Origin on such requests, and newer ones say in
// Sec-Fetch-Site how it relates to labd; a page can set neither. labd's own
// UI is served from the origin it calls, so its Origin names the host it
// asked. The lab CLI, agents, builders and curl send neither header and are
// let through: what guards them is the token, device secret or network
// they come with.
func sameOrigin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			h.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && !originIsHost(origin, r.Host) {
			httpErr(w, 403, "refused: a page from %s asked labd at %s to change something. Use labd's own UI at its address, or the lab CLI", origin, r.Host)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); origin == "" && (site == "cross-site" || site == "same-site") {
			httpErr(w, 403, "refused: a %s page asked labd at %s to change something. Use labd's own UI at its address, or the lab CLI", site, r.Host)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// originIsHost reports whether origin (scheme://host[:port]) names the same
// host and port as a request's Host header. A port left out is the
// scheme's default in both.
func originIsHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false // "null", from a sandboxed frame or a redirect, among them
	}
	def := map[string]string{"http": "80", "https": "443"}[u.Scheme]
	oPort := u.Port()
	if oPort == "" {
		oPort = def
	}
	hName, hPort, err := net.SplitHostPort(host)
	if err != nil {
		hName, hPort = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), def
	}
	return strings.EqualFold(u.Hostname(), hName) && oPort == hPort
}

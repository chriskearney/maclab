package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
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

// A request that gets in without a token, by the network it comes from
// (--trust) or its tailnet login, counts only when its Host names labd
// itself (ownHost). A web page whose site points its own name at labd's
// address once the page is open (DNS rebinding) is served from that name,
// so its Origin and Host agree and sameOrigin lets it through; but its Host
// is that name, not one of labd's. Requests with the admin token, a device
// secret or the builder token are let in whatever their Host: a page can't
// send those.

// ownHost reports whether host, a request's Host header, names labd: an IP
// address, localhost, this machine's own names (localNames), a name given
// with --allow-host, or with --tailscale this machine's MagicDNS names. No
// browser sends an empty Host.
func (s *Server) ownHost(host string) bool {
	name := hostName(host)
	if name == "" || name == "localhost" {
		return true
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return true
	}
	return slices.Contains(s.hosts, name) || slices.Contains(s.tailnetHosts(), name)
}

// hostName is the name in a Host header: without its port or an IPv6
// address's brackets, in lower case, without a trailing dot.
func hostName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

var reHostName = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$`)

// ParseAllowHost turns an --allow-host value, "labd.lan" or a list of them
// split by commas, into host names.
func ParseAllowHost(v string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		h := hostName(f)
		if strings.Contains(f, "/") || !reHostName.MatchString(h) {
			return nil, fmt.Errorf("--allow-host %q: give a host name, such as labd.lan", f)
		}
		out = append(out, h)
	}
	return out, nil
}

// localNames are this machine's own names: its host name as os.Hostname
// has it, short and fully qualified (as the resolver names it, if it can
// within two seconds), and the short name under .local, as mDNS gives it.
// They are looked up once.
var localNames = sync.OnceValue(func() []string {
	h, err := os.Hostname()
	if err != nil {
		return nil
	}
	h = hostName(h)
	short, _, _ := strings.Cut(h, ".")
	names := []string{h, short, short + ".local"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c, err := net.DefaultResolver.LookupCNAME(ctx, short); err == nil {
		names = append(names, hostName(c))
	}
	slices.Sort(names)
	return slices.Compact(names)
})

// tailnetNamesTTL is how long labd keeps its MagicDNS names: they change
// only when the machine is renamed on the tailnet.
const tailnetNamesTTL = time.Minute

// tailnetHosts are this machine's MagicDNS names, with --tailscale. They are
// looked up only when a request needs them, at most once a tailnetNamesTTL,
// and a failed lookup keeps the names labd had.
func (s *Server) tailnetHosts() []string {
	if s.cfg.TailnetNames == nil {
		return nil
	}
	s.tsMu.Lock()
	defer s.tsMu.Unlock()
	if time.Since(s.tsAt) < tailnetNamesTTL {
		return s.tsNames
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names, err := s.cfg.TailnetNames(ctx)
	if err != nil {
		s.log.Printf("tailscale status: %v; labd answers to the MagicDNS names it had: %s", err, orStr(strings.Join(s.tsNames, ", "), "none"))
	} else {
		s.tsNames = names
	}
	s.tsAt = time.Now()
	return s.tsNames
}

// tailscaleNames asks the local tailscaled for this machine's MagicDNS
// name, e.g. labd.tail1234.ts.net, and its short form, labd.
func tailscaleNames(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, tailscaleCLI(), "status", "--json").Output()
	if err != nil {
		return nil, err
	}
	return parseStatusNames(out)
}

func parseStatusNames(b []byte) ([]string, error) {
	var st struct{ Self struct{ DNSName string } }
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("tailscale status: %w", err)
	}
	name := hostName(st.Self.DNSName)
	if name == "" {
		return nil, nil // MagicDNS off
	}
	short, _, _ := strings.Cut(name, ".")
	return slices.Compact([]string{name, short}), nil
}

// foreignHost answers a request that the network it came from, or its
// tailnet login, would have let in, but that asked for labd by a name
// labd doesn't know as its own.
func foreignHost(w http.ResponseWriter, r *http.Request) {
	httpErr(w, 403, "%s", hostRefusal(r.Host))
}

func hostRefusal(host string) string {
	name := hostName(host)
	return fmt.Sprintf("refused: this request asked for labd as %s, a name labd doesn't know as its own, and without a token only requests "+
		"to labd's own names get in (a web page can point a name its site owns at labd's address). If %s is labd's, run labd with --allow-host %s; "+
		"or open labd by its IP address or host name, or use the admin token", host, name, name)
}

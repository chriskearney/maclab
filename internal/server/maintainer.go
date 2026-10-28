package server

// Maintainers are the named people with their own access to labd. Each has a
// token, shown once when they're added; labd keeps only its hash. Every
// Maintainer route resolves its token to a name, and what labd records (jobs,
// Promotions, Maintainer changes) carries that name.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/iconidentify/maclab/internal/api"
)

var reMaintainer = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func newMaintainerToken() string { return "mnt_" + randHex(20) }

// firstMaintainer makes Config.FirstMaintainer a Maintainer, holding
// Config.FirstMaintainerToken, when labd has none yet: on a fresh labd, and
// on the first start after an upgrade from the single admin token.
func (s *Server) firstMaintainer() error {
	if n, err := s.store.countMaintainers(); err != nil || n > 0 {
		return err
	}
	if !reMaintainer.MatchString(s.cfg.FirstMaintainer) {
		return fmt.Errorf("labd has no Maintainer yet: name the first one with labd --maintainer <name> (%q isn't a name)", s.cfg.FirstMaintainer)
	}
	if s.cfg.FirstMaintainerToken == "" {
		return fmt.Errorf("labd has no Maintainer yet, and %s is empty: delete it to make a new token", firstTokenPath(s.cfg.DataDir))
	}
	s.log.Printf("first Maintainer: %s; log in with `lab login <labd-url> \"$(cat %s)\"`", s.cfg.FirstMaintainer, firstTokenPath(s.cfg.DataDir))
	return s.store.addMaintainer(api.Maintainer{Name: s.cfg.FirstMaintainer, Added: s.now()}, hashSecret(s.cfg.FirstMaintainerToken))
}

// FirstMaintainerToken reads the first Maintainer's token from the data
// directory, creating it on a fresh labd. It is the file the single admin
// token lived in, so `lab login`, the UI and MCP keep working after an upgrade.
func FirstMaintainerToken(dataDir string) (token string, created bool, err error) {
	p := firstTokenPath(dataDir)
	b, err := os.ReadFile(p)
	if err == nil {
		return strings.TrimSpace(string(b)), false, nil
	}
	if !os.IsNotExist(err) {
		return "", false, err
	}
	token = newMaintainerToken()
	return token, true, os.WriteFile(p, []byte(token), 0o600)
}

func firstTokenPath(dataDir string) string { return filepath.Join(dataDir, "admin.token") }

type maintainerKey struct{}

// maintainerConns are the open requests of each Maintainer, so removing one
// also ends their streams, console and waits.
type maintainerConns struct {
	mu   sync.Mutex
	next int
	by   map[string]map[int]context.CancelFunc
}

func (c *maintainerConns) add(name string, cancel context.CancelFunc) (done func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.by == nil {
		c.by = map[string]map[int]context.CancelFunc{}
	}
	if c.by[name] == nil {
		c.by[name] = map[int]context.CancelFunc{}
	}
	c.next++
	id := c.next
	c.by[name][id] = cancel
	return func() {
		c.mu.Lock()
		delete(c.by[name], id)
		c.mu.Unlock()
		cancel()
	}
}

func (c *maintainerConns) end(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cancel := range c.by[name] {
		cancel()
	}
	delete(c.by, name)
}

// maintainer admits a request carrying a Maintainer's token and passes on
// their name (see maintainerName). The request ends when they're removed.
// A tailnet viewer may only look, and is told so.
func (s *Server) maintainer(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch a, who, foreign := s.accessHost(r); {
		case a == adminAccess:
			s.asMaintainer(w, r, who, h)
		case a == viewAccess:
			httpErr(w, 403, "%s may only look; this needs a Maintainer's token", who)
		case foreign:
			foreignHost(w, r)
		default:
			httpErr(w, 401, "not a Maintainer's token")
		}
	}
}

// viewer guards read-only endpoints, which tailnet viewers may use too.
func (s *Server) viewer(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch a, who, foreign := s.accessHost(r); {
		case a == adminAccess:
			s.asMaintainer(w, r, who, h)
		case a == viewAccess:
			h(w, r)
		case foreign:
			foreignHost(w, r)
		default:
			httpErr(w, 401, "not a Maintainer's token")
		}
	}
}

// asMaintainer serves r for the Maintainer name until it ends or they're
// removed.
func (s *Server) asMaintainer(w http.ResponseWriter, r *http.Request, name string, h http.HandlerFunc) {
	ctx, cancel := context.WithCancel(context.WithValue(r.Context(), maintainerKey{}, name))
	defer s.conns.add(name, cancel)()
	h(w, r.WithContext(ctx))
}

// maintainerName is the Maintainer who made a request on a Maintainer route.
func maintainerName(r *http.Request) string {
	return maintainerOf(r.Context())
}

// maintainerOf is the Maintainer a request's context acts for; "" for labd.
func maintainerOf(ctx context.Context) string {
	name, _ := ctx.Value(maintainerKey{}).(string)
	return name
}

func (s *Server) hMaintainers(w http.ResponseWriter, r *http.Request) {
	ms, err := s.store.maintainers()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	writeJSON(w, ms)
}

func (s *Server) hAddMaintainer(w http.ResponseWriter, r *http.Request) {
	var req api.MaintainerRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || !reMaintainer.MatchString(req.Name) {
		httpErr(w, 400, "a Maintainer's name is letters, digits, dots, dashes and underscores")
		return
	}
	m := api.NewMaintainer{Maintainer: api.Maintainer{Name: req.Name, Added: s.now(), AddedBy: maintainerName(r)}, Token: newMaintainerToken()}
	if err := s.store.addMaintainer(m.Maintainer, hashSecret(m.Token)); err != nil {
		if s.store.hasMaintainer(req.Name) {
			httpErr(w, 409, "%s is already a Maintainer", req.Name)
			return
		}
		httpErr(w, 500, "%v", err)
		return
	}
	s.log.Printf("Maintainer %s added by %s", m.Name, m.AddedBy)
	writeJSON(w, m)
}

func (s *Server) hRemoveMaintainer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	removed, err := s.store.removeMaintainer(name)
	switch {
	case err != nil:
		httpErr(w, 500, "%v", err)
	case removed:
		s.conns.end(name)
		s.log.Printf("Maintainer %s removed by %s", name, maintainerName(r))
		writeJSON(w, map[string]string{"removed": name})
	case s.store.hasMaintainer(name):
		httpErr(w, 409, "%s is the last Maintainer; add another first", name)
	default:
		httpErr(w, 404, "no Maintainer %s", name)
	}
}

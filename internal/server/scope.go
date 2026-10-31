package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// Scope is what a request's caller may see and do. A Maintainer sees the
// whole fleet. A person on the tailnet without a Maintainer's token sees
// only the Macs they volunteered, while those stay enrolled. A Mac sees only
// itself, through its own routes (see agent). A Volunteer's Mac must never
// reach another Mac, a Volunteer's or Lab-owned, and this is where that
// holds. What a caller may do to a Mac (mayDo) keeps a Volunteer's Mac's
// Access level, Availability window and held rules in one place too.
//
// Every route says who may reach it (reach), and labd registers no route
// that doesn't, so a new route can't forget to ask.

// caller is who made a request on a route people may reach.
type caller struct {
	maintainer string // a Maintainer's name, by their token
	login      string // a person's tailnet login, without a token
	mac        string // a Mac's name, by its device secret
	labd       bool   // labd itself (see labdItself)
}

type personKey struct{}

// callerOf is who made r.
func callerOf(r *http.Request) caller { return callerOfCtx(r.Context()) }

// callerOfCtx is who a request's context acts for; the zero caller when
// nobody is named, which Scope refuses everything (see labdItself).
func callerOfCtx(ctx context.Context) caller {
	c := caller{maintainer: maintainerOf(ctx)}
	c.login, _ = ctx.Value(personKey{}).(string)
	if v, ok := ctx.Value(ctxKey{}).(*dev); ok {
		c.mac = v.d.Name
	}
	return c
}

// sees reports whether c may see the Mac called name, its jobs and its
// events. name "" is the fleet's own: builds and the like, Maintainers' only.
func (s *Server) sees(c caller, name string) bool {
	if c.maintainer != "" {
		return true
	}
	if c.login == "" || name == "" {
		return false
	}
	v := s.dev(name)
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return s.seesLocked(c, v)
}

// seesLocked is sees for a person and a Mac whose v.mu the caller holds.
func (s *Server) seesLocked(c caller, v *dev) bool {
	return c.login != "" && !v.forgotten && v.d.State != api.StateLeft && v.volunteeredBy != "" && strings.EqualFold(v.volunteeredBy, c.login)
}

// seenMacs names the Macs c sees.
func (s *Server) seenMacs(c caller) []string {
	var names []string
	for _, v := range s.allDevs() {
		if s.sees(c, v.d.Name) {
			names = append(names, v.d.Name)
		}
	}
	return names
}

// reach is who may reach a route.
type reach int

const (
	unset       reach = iota // refused at registration
	anyone                   // no credential: /api/auth, enrolling with a token
	ownMac                   // a Mac, by its device secret; it only touches itself
	builder                  // the builder, by its token
	maintainers              // a Maintainer's token: the fleet's own, and every change
	people                   // Maintainers, and any person on the tailnet: ./volunteer
	macNamed                 // the Mac in {name}: whoever sees it
	jobNamed                 // the job in {id}: whoever sees its Mac
	scoped                   // a list or the stream: the handler keeps to what the caller sees
)

// letsPeopleIn reports whether a person without a Maintainer's token may
// reach a route at all: the reaches from people on, in the order above.
func (r reach) letsPeopleIn() bool { return r >= people }

type route struct {
	pattern string
	reach   reach
	h       http.HandlerFunc
}

// register adds rt to m behind what its reach asks for.
func (s *Server) register(m *http.ServeMux, rt route) {
	h := rt.h
	switch rt.reach {
	case anyone:
	case ownMac:
		h = s.agent(h)
	case builder:
		h = s.builderAuth(h)
	case maintainers:
		h = s.maintainer(h)
	case people, scoped:
		h = s.viewer(h)
	case macNamed:
		h = s.viewer(s.macInScope(h))
	case jobNamed:
		h = s.viewer(s.jobInScope(h))
	default:
		panic(fmt.Sprintf("route %s says nothing about who may reach it", rt.pattern))
	}
	m.HandleFunc(rt.pattern, h)
}

// macInScope answers 404 for a Mac the caller doesn't see, as if it weren't
// there: names of other Macs stay unknown.
func (s *Server) macInScope(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, name := callerOf(r), r.PathValue("name")
		if !s.sees(c, name) {
			if s.dev(name) != nil {
				s.log.Printf("%s asked for %s %s, a Mac they don't see", c.login, r.Method, r.URL.Path)
			}
			httpErr(w, 404, "no device %q", name)
			return
		}
		h(w, r)
	}
}

// jobInScope answers 404 for a job on a Mac the caller doesn't see.
func (s *Server) jobInScope(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, id := callerOf(r), r.PathValue("id")
		if c.maintainer == "" {
			if j, err := s.store.job(id); err != nil || !s.sees(c, j.Spec.Device) {
				s.log.Printf("%s asked for %s %s, a job they don't see", c.login, r.Method, r.URL.Path)
				httpErr(w, 404, "no job %s", id)
				return
			}
		}
		h(w, r)
	}
}

// asPerson serves r for a person's tailnet login.
func asPerson(w http.ResponseWriter, r *http.Request, login string, h http.HandlerFunc) {
	h(w, r.WithContext(context.WithValue(r.Context(), personKey{}, login)))
}

// errNotSeen is what a caller gets for a Mac they don't see: as if it
// weren't there.
var errNotSeen = errors.New("no such Mac")

// labdItself is labd acting on its own, for a job no Maintainer submitted.
var labdItself = caller{labd: true}

// callerFor is the caller a job acts as: its Maintainer, or labd itself.
func callerFor(maintainer string) caller {
	if maintainer == "" {
		return labdItself
	}
	return caller{maintainer: maintainer}
}

// action is something a caller asks to do on a Mac.
type action struct {
	kind actionKind
	what string // named in a refusal
}

type actionKind int

const (
	kindFull   actionKind = iota + 1 // needs a Volunteer's Mac at Access level Full
	kindWatch                        // its screen or live journal
	kindLease                        // holding it for a Maintainer
	kindUpload                       // a file added to one of its jobs
)

var (
	actExec     = action{kindFull, "lab exec"}
	actMesa     = action{kindFull, "staged Mesa packages"}
	actRecovery = action{kindFull, "recovery-policy overrides"}
	actWatch    = action{kindWatch, "its screen or live journal"}
	actLease    = action{kindLease, "a lease"}
	actUpload   = action{kindUpload, "files added to its jobs"}
)

// actScript is running a Maintainer's script on a Mac; why says which (see
// needsFull).
func actScript(why string) action { return action{kindFull, "Maintainer's script (" + why + ")"} }

// mayDo is why c may not do a on v, or nil when it may. A Mac c doesn't see
// is errNotSeen. A person may only watch their own Mac; a Mac may only add
// files to its own jobs; Maintainers and labd do the rest, as far as a
// Volunteer's Mac's Access level and Availability window allow.
func (s *Server) mayDo(c caller, v *dev, a action) error {
	if v == nil {
		return errNotSeen
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return s.mayDoLocked(c, v, a)
}

// mayDoLocked is mayDo for callers already holding v.mu.
func (s *Server) mayDoLocked(c caller, v *dev, a action) error {
	if v == nil {
		return errNotSeen
	}
	d := &v.d
	switch {
	case c.maintainer != "" || c.labd:
	case c.mac != "":
		if a.kind == kindUpload && c.mac == d.Name {
			return nil
		}
		return fmt.Errorf("a Mac may not ask for %s on %s", a.what, d.Name)
	case c.login != "":
		if !s.seesLocked(c, v) {
			return errNotSeen
		}
		if a.kind != kindWatch {
			return fmt.Errorf("only a Maintainer may ask for %s on %s", a.what, d.Name)
		}
	default:
		return errNotSeen
	}
	switch a.kind {
	case kindFull:
		return refuseBelowFull(d, a)
	case kindWatch:
		if d.IsVolunteer() && (!v.heldLocked() || v.openUntilLocked().IsZero()) {
			return fmt.Errorf("%s is a Volunteer's Mac: at any Access level its screen and live journal are shown only while a job or lease holds it inside its Availability window", d.Name)
		}
	case kindLease:
		if d.IsVolunteer() && v.openUntilLocked().IsZero() {
			return fmt.Errorf("%s's Availability window is closed: a lease on a Volunteer's Mac lasts only inside it", d.Name)
		}
	case kindUpload:
		return fmt.Errorf("only a Mac adds files to its own jobs")
	}
	return nil
}

// refuseBelowFull is why a, which only Access level Full allows, can't run
// on a Volunteer's Mac at Qualification, or nil. validateMesa asks it of a
// job's copy of the Mac, whoever submitted the job.
func refuseBelowFull(d *api.Device, a action) error {
	if d.AllowsAnything() {
		return nil
	}
	return fmt.Errorf("%s is a Volunteer's Mac at Access level Qualification, which allows no %s; only its Volunteer can raise it (sudo lab-agent access full)", d.Name, a.what)
}

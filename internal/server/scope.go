package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// Scope is what a request's caller may see. A Maintainer sees the whole
// fleet. A person on the tailnet without a Maintainer's token sees only the
// Macs they volunteered, while those stay enrolled. A Mac sees only itself,
// through its own routes (see agent). A Volunteer's Mac must never reach
// another Mac, a Volunteer's or Lab-owned, and this is where that holds.
//
// Every route says who may reach it (reach), and labd registers no route
// that doesn't, so a new route can't forget to ask.

// caller is who made a request on a route people may reach.
type caller struct {
	maintainer string // a Maintainer's name, by their token
	login      string // a person's tailnet login, without a token
}

type personKey struct{}

// callerOf is who made r.
func callerOf(r *http.Request) caller {
	login, _ := r.Context().Value(personKey{}).(string)
	return caller{maintainer: maintainerName(r), login: login}
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
	return !v.forgotten && v.d.State != api.StateLeft && v.volunteeredBy != "" && strings.EqualFold(v.volunteeredBy, c.login)
}

// seesJob reports whether c may read job j: a Maintainer may read any; a
// person only one their Mac ran in its current enrollment. A forgotten Mac's
// name can be taken again, by anyone, and the old enrollment's jobs stay with
// the Maintainers.
func (s *Server) seesJob(c caller, j *api.Job) bool {
	if c.maintainer != "" {
		return true
	}
	if !s.sees(c, j.Spec.Device) {
		return false
	}
	v := s.dev(j.Spec.Device)
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return j.DeviceID != "" && j.DeviceID == v.d.ID
}

// seenEnrollments is the enrollments (Device.ID) of the Macs c sees, or of
// the one Mac named if name isn't "".
func (s *Server) seenEnrollments(c caller, name string) []string {
	var ids []string
	for _, v := range s.allDevs() {
		if (name == "" || v.d.Name == name) && s.sees(c, v.d.Name) {
			v.mu.Lock()
			ids = append(ids, v.d.ID)
			v.mu.Unlock()
		}
	}
	return ids
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
	invited                  // someone joining with an enrollment token (enr_...), see joinToken
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
	case invited:
		h = s.joinToken(h)
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

// jobInScope answers 404 for a job the caller may not read (seesJob).
func (s *Server) jobInScope(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, id := callerOf(r), r.PathValue("id")
		if c.maintainer == "" {
			if j, err := s.store.job(id); err != nil || !s.seesJob(c, j) {
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

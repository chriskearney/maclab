package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/window"
)

// Scope, through its interface: who may see which Mac, its jobs and its
// events. No HTTP and no tailscaled: callers and Macs are plain values.
func TestScope(t *testing.T) {
	s := &Server{devs: map[string]*dev{}}
	add := func(name, by string, state api.DeviceState, forgotten bool) {
		s.devs[name] = &dev{s: s, d: api.Device{Name: name, State: state}, volunteeredBy: by, forgotten: forgotten}
	}
	add("lab", "", api.StateReady, false)                // Lab-owned
	add("mine", "visitor@github", api.StateReady, false) // the visitor's
	add("theirs", "other@github", api.StateReady, false) // another Volunteer's
	add("old", "visitor@github", api.StateLeft, false)   // left by lab-agent uninstall
	add("gone", "visitor@github", api.StateReady, true)  // ended, still held by a request
	add("unlinked", "", api.StateReady, false)           // a Volunteer's, enrolled without a login

	var (
		maintainer = caller{maintainer: "ada"}
		visitor    = caller{login: "Visitor@GitHub"} // logins compare case-insensitively
		other      = caller{login: "other@github"}
		nobody     = caller{}
	)
	all := []string{"lab", "mine", "theirs", "old", "gone", "unlinked", "", "no-such-mac"}
	for _, c := range []struct {
		name string
		who  caller
		sees []string // device names, "" for fleet-wide events
	}{
		{"a Maintainer sees the whole fleet", maintainer, all},
		{"a Volunteer sees only their own enrolled Macs", visitor, []string{"mine"}},
		{"another Volunteer sees only theirs", other, []string{"theirs"}},
		{"nobody sees nothing", nobody, nil},
	} {
		for _, name := range all {
			want := slices.Contains(c.sees, name)
			if got := s.sees(c.who, name); got != want {
				t.Errorf("%s: sees(%q) = %v, want %v", c.name, name, got, want)
			}
		}
	}
}

// Every route says who may reach it, and only the routes named here let a
// person without a Maintainer's token in. A new route a person may reach
// changes this list on purpose.
func TestRoutesDeclareReach(t *testing.T) {
	s, err := New(context.Background(), Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	var people []string
	for _, rt := range s.routes() {
		if rt.reach == unset {
			t.Errorf("%s declares no reach", rt.pattern)
		}
		if rt.reach.letsPeopleIn() {
			people = append(people, rt.pattern)
		}
	}
	want := []string{
		"GET /api/devices",
		"GET /api/devices/{name}",
		"GET /api/devices/{name}/oob",
		"GET /api/stream",
		"GET /api/devices/{name}/screen",
		"GET /api/devices/{name}/screens",
		"GET /api/devices/{name}/screens/{file}",
		"GET /api/devices/{name}/logs",
		"POST /api/volunteer",
		"GET /api/volunteer/lab-agent",
		"GET /api/jobs",
		"GET /api/jobs/{id}",
		"GET /api/jobs/{id}/wait",
		"GET /api/jobs/{id}/files/{name...}",
	}
	if !slices.Equal(people, want) {
		t.Errorf("routes a person may reach:\n got %q\nwant %q", people, want)
	}
	defer func() {
		if recover() == nil {
			t.Error("a route without a reach was registered")
		}
	}()
	s.register(http.NewServeMux(), route{pattern: "GET /api/new", h: func(http.ResponseWriter, *http.Request) {}})
}

// A person on the tailnet, through labd's routes: their own Mac, its jobs and
// its events, and nothing of another Volunteer's Mac or a Lab-owned one. A
// tagged device gets nothing without a token; a Maintainer sees everything.
func TestPersonSeesOnlyTheirOwnMacs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peers := map[string]*TailnetPeer{
		"100.64.0.2": {Login: "Visitor@github", Node: "laptop"},
		"100.64.0.3": {Login: "tagged-devices", Node: "lab", Tags: []string{"tag:maclab"}},
		"100.64.0.4": {Login: "other@github", Node: "phone"},
	}
	whois := func(_ context.Context, ip string) (*TailnetPeer, error) {
		if p := peers[ip]; p != nil {
			return p, nil
		}
		return nil, fmt.Errorf("no match for IP")
	}
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret", Tailscale: true, WhoIs: whois},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	const (
		visitor = "100.64.0.2:40000"
		tagged  = "100.64.0.3:40000"
		other   = "100.64.0.4:40000"
	)
	do := func(method, path, remote, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, labdAt+path, strings.NewReader(body))
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var secret string // the last enrolled Mac's device secret
	enroll := func(token string) {
		t.Helper()
		w := do("POST", "/api/agent/enroll", other, "", `{"token":"`+token+`"}`)
		var resp api.EnrollResponse
		if json.Unmarshal(w.Body.Bytes(), &resp); w.Code != 200 || resp.Secret == "" {
			t.Fatalf("enroll: %d %s", w.Code, w.Body)
		}
		secret = resp.Secret
	}
	volunteer := func(remote, name string) {
		t.Helper()
		var resp api.EnrollTokenResponse
		w := do("POST", "/api/volunteer", remote, "", `{"name":"`+name+`"}`)
		if json.Unmarshal(w.Body.Bytes(), &resp); w.Code != 200 {
			t.Fatalf("volunteer %s: %d %s", name, w.Code, w.Body)
		}
		enroll(resp.Token)
	}
	volunteer(visitor, "mine")
	volunteer(other, "theirs")
	tok, _ := s.store.addTokenForTest("lab")
	enroll(tok)
	for _, d := range []string{"mine", "theirs", "lab"} {
		if err := s.store.saveJob(&api.Job{ID: "j-" + d, Spec: api.JobSpec{Device: d}, State: api.JobDone, Created: s.now()}); err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(s.jobDir("j-"+d), 0o755)
		os.WriteFile(filepath.Join(s.jobDir("j-"+d), "journal"), []byte("journal of "+d), 0o644)
	}

	names := func(remote, token string) (out []string) {
		var ds []api.Device
		json.Unmarshal(do("GET", "/api/devices", remote, token, "").Body.Bytes(), &ds)
		for _, d := range ds {
			out = append(out, d.Name)
		}
		return out
	}
	jobs := func(remote, token, query string) (out []string) {
		var js []api.Job
		json.Unmarshal(do("GET", "/api/jobs"+query, remote, token, "").Body.Bytes(), &js)
		for _, j := range js {
			out = append(out, j.ID)
		}
		slices.Sort(out)
		return out
	}
	if got := names(visitor, ""); !slices.Equal(got, []string{"mine"}) {
		t.Errorf("the visitor lists %q, want only their own Mac", got)
	}
	if got := names(other, ""); !slices.Equal(got, []string{"theirs"}) {
		t.Errorf("the other Volunteer lists %q, want only theirs", got)
	}
	if got := names(visitor, "adm_secret"); !slices.Equal(got, []string{"lab", "mine", "theirs"}) {
		t.Errorf("a Maintainer lists %q, want the whole fleet", got)
	}
	if got := jobs(visitor, "", ""); !slices.Equal(got, []string{"j-mine"}) {
		t.Errorf("the visitor's jobs: %q", got)
	}
	if got := jobs(visitor, "", "?device=lab"); len(got) != 0 {
		t.Errorf("the visitor's jobs on the Lab-owned Mac: %q", got)
	}
	if got := jobs(visitor, "adm_secret", ""); len(got) != 3 {
		t.Errorf("a Maintainer's jobs: %q", got)
	}

	for _, c := range []struct {
		name, path, remote, token string
		want                      int
	}{
		{"their own Mac", "/api/devices/mine", visitor, "", 200},
		{"another Volunteer's Mac", "/api/devices/theirs", visitor, "", 404},
		{"a Lab-owned Mac", "/api/devices/lab", visitor, "", 404},
		{"a Lab-owned Mac's live logs", "/api/devices/lab/logs", visitor, "", 404},
		{"another Volunteer's screens", "/api/devices/theirs/screens", visitor, "", 404},
		{"another Volunteer's latest screen", "/api/devices/theirs/screen", visitor, "", 404},
		{"a Lab-owned Mac's controller", "/api/devices/lab/oob", visitor, "", 404},
		{"their own job", "/api/jobs/j-mine", visitor, "", 200},
		{"their own job's journal", "/api/jobs/j-mine/files/journal", visitor, "", 200},
		{"another Volunteer's job", "/api/jobs/j-theirs", visitor, "", 404},
		{"another Volunteer's journal", "/api/jobs/j-theirs/files/journal", visitor, "", 404},
		{"waiting on a Lab-owned Mac's job", "/api/jobs/j-lab/wait", visitor, "", 404},
		{"a job that isn't there", "/api/jobs/j-none", visitor, "", 404},
		{"builds", "/api/builds", visitor, "", 403},
		{"builders", "/api/builders", visitor, "", 403},
		{"a Release's Installed runs", "/api/installed/aurora-1", visitor, "", 403},
		{"recovery capabilities", "/api/recovery", visitor, "", 403},
		{"a tagged device lists Macs", "/api/devices", tagged, "", 401},
		{"a tagged device reads a job", "/api/jobs/j-lab", tagged, "", 401},
		{"a Mac's device secret lists Macs", "/api/devices", "10.1.1.42:1", secret, 401},
		{"a Mac's device secret reads a job", "/api/jobs/j-lab", "10.1.1.42:1", secret, 401},
		{"a Maintainer reads any Mac", "/api/devices/lab", visitor, "adm_secret", 200},
		{"a Maintainer reads any journal", "/api/jobs/j-theirs/files/journal", visitor, "adm_secret", 200},
	} {
		if w := do("GET", c.path, c.remote, c.token, ""); w.Code != c.want {
			t.Errorf("%s: GET %s got %d %s, want %d", c.name, c.path, w.Code, w.Body, c.want)
		}
	}

	// The stream carries the visitor's own Mac's events, none of another
	// Mac's, and no builds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = visitor
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	res, err := http.Get(srv.URL + "/api/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	rd := bufio.NewReader(res.Body)
	if l, err := rd.ReadString('\n'); err != nil || !strings.HasPrefix(l, ": maclab stream") {
		t.Fatalf("stream opened with %q, %v", l, err)
	}
	s.hub.publish("job", "theirs", map[string]any{"device": "theirs", "id": "their-secret"})
	s.hub.publish("job", "lab", map[string]any{"device": "lab", "id": "lab-secret"})
	s.hub.publish("build", "", map[string]any{"id": "build-secret"})
	s.hub.publish("job", "mine", map[string]any{"device": "mine", "id": "end"})
	var got strings.Builder
	for !strings.Contains(got.String(), `"end"`) {
		l, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("stream: %v after %q", err, got.String())
		}
		got.WriteString(l)
	}
	if strings.Contains(got.String(), "secret") {
		t.Errorf("the visitor's stream carried another Mac's or the fleet's events:\n%s", got.String())
	}
}

// Scope's actions, through its interface: who may do what on which Mac. The
// Access level, Availability window and held rules are a Volunteer's Mac's;
// a Lab-owned Mac has none of them.
func TestScopeActions(t *testing.T) {
	s := &Server{devs: map[string]*dev{}}
	open := &window.Settings{OpenUntil: s.now().Add(time.Hour)}
	add := func(name string, d api.Device) {
		d.Name = name
		s.devs[name] = &dev{s: s, d: d, volunteeredBy: d.VolunteeredBy}
	}
	vol := func(level string, w *window.Settings, job string) api.Device {
		return api.Device{Kind: api.KindVolunteer, VolunteeredBy: "visitor@github", AccessLevel: level, Window: w, ActiveJob: job}
	}
	add("lab", api.Device{Kind: api.KindLabOwned})
	add("full", vol(api.AccessFull, open, ""))
	add("held", vol(api.AccessQualification, open, "j1"))       // Qualification, held, window open
	add("held-closed", vol(api.AccessQualification, nil, "j1")) // held, window closed
	add("free", vol(api.AccessQualification, open, ""))         // window open, not held
	add("theirs", api.Device{Kind: api.KindVolunteer, VolunteeredBy: "other@github", AccessLevel: api.AccessFull, Window: open, ActiveJob: "j2"})
	add("full-held", vol(api.AccessFull, open, "j3"))  // Full, held, window open
	add("full-closed", vol(api.AccessFull, nil, "j4")) // Full, held, window closed

	var (
		maintainer = caller{maintainer: "ada"}
		self       = labdItself
		visitor    = caller{login: "visitor@github"}
		heldMac    = caller{mac: "held"}
	)
	macs := []string{"lab", "full", "held", "held-closed", "free", "theirs", "full-held", "full-closed"}
	for _, c := range []struct {
		name string
		who  caller
		a    action
		may  []string
	}{
		{"a Maintainer runs lab exec where the Access level allows it", maintainer, actExec, []string{"lab", "full", "theirs", "full-held", "full-closed"}},
		{"labd runs a Maintainer's script for a job", self, actScript("test t is a --script"), []string{"lab", "full", "theirs", "full-held", "full-closed"}},
		{"Mesa packages need Full", maintainer, actMesa, []string{"lab", "full", "theirs", "full-held", "full-closed"}},
		{"recovery overrides need Full", maintainer, actRecovery, []string{"lab", "full", "theirs", "full-held", "full-closed"}},
		{"a Maintainer watches a held Mac inside its window", maintainer, actWatch, []string{"lab", "held", "theirs", "full-held"}},
		{"a Volunteer watches only their own held Mac", visitor, actWatch, []string{"held", "full-held"}},
		{"a Maintainer leases inside the window", maintainer, actLease, []string{"lab", "full", "held", "free", "theirs", "full-held"}},
		{"a Volunteer runs no lab exec, even on their own Mac", visitor, actExec, nil},
		{"a Volunteer takes no lease", visitor, actLease, nil},
		{"a Mac adds files only to its own jobs", heldMac, actUpload, []string{"held"}},
		{"a Maintainer adds no files to a Mac's job", maintainer, actUpload, nil},
		{"a Mac runs nothing on another Mac", heldMac, actExec, nil},
		{"a Mac watches nothing", heldMac, actWatch, nil},
		{"nobody does anything", caller{}, actWatch, nil},
	} {
		for _, name := range macs {
			want := slices.Contains(c.may, name)
			if err := s.mayDo(c.who, s.devs[name], c.a); (err == nil) != want {
				t.Errorf("%s: on %s got %v, want allowed=%v", c.name, name, err, want)
			}
		}
	}
	if err := s.mayDo(maintainer, nil, actExec); !errors.Is(err, errNotSeen) {
		t.Errorf("a Mac that isn't there: %v", err)
	}
	if err := s.mayDo(visitor, s.devs["theirs"], actWatch); !errors.Is(err, errNotSeen) {
		t.Errorf("another Volunteer's Mac must look absent: %v", err)
	}
	if err := s.mayDo(maintainer, s.devs["held"], actScript("test t is a --script")); err == nil || !strings.Contains(err.Error(), "test t is a --script") {
		t.Errorf("a script refusal names the script: %v", err)
	}
}

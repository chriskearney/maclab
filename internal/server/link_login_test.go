package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// volunteerLogin takes a tailnet login, user@github or an email, and
// nothing else: a typo or a pasted secret would show a Mac to someone else.
func TestVolunteerLogin(t *testing.T) {
	for raw, want := range map[string]string{
		"ada@github":                    "ada@github",
		" Ada@GitHub ":                  "ada@github",
		"ada@passkey":                   "ada@passkey",
		"ada.lovelace+lab@example.org":  "ada.lovelace+lab@example.org",
		"a_b@mail.example.co.uk":        "a_b@mail.example.co.uk",
		"first-last@sub-domain.example": "first-last@sub-domain.example",
	} {
		if got, err := volunteerLogin(raw); err != nil || got != want {
			t.Errorf("volunteerLogin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"", "ada", "ada@", "@github", "ada@@github", "ada@git@hub", "ada lovelace@github", "ada@github.", "ada@.github",
		"ada@-github", "ada@github/x", "<ada>@github", "ada@github\nbob@github", "tagged-devices",
		"enr_0123456789abcdef0123456789abcdef", "adm_secret", "dev_0123456789abcdef0123456789abcdef0123456789abcdef",
		"bld_x@github", "mnt_x@github", "ENR_x@github", "tskey-auth-kAbCdEf@github",
		"0123456789abcdef0123456789abcdef@github", strings.Repeat("a", 65) + "@github",
	} {
		if got, err := volunteerLogin(raw); err == nil {
			t.Errorf("volunteerLogin(%q) = %q, want it refused", raw, got)
		}
	}
}

// A Maintainer links a Volunteer's Mac to a tailnet login, at enrollment or
// later, and unlinks it: that login, and only that one, sees the Mac while
// it is linked. A person can't link, a bad login is refused, and linked Macs
// don't count toward the person's own ./volunteer limit.
func TestMaintainerLinksVolunteerLogin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peers := map[string]*TailnetPeer{
		"100.64.0.2": {Login: "Visitor@github", Node: "laptop"},
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
		other   = "100.64.0.4:40000"
		admin   = "adm_secret"
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
	enroll := func(token string) {
		t.Helper()
		if w := do("POST", "/api/agent/enroll", other, "", enrollJSON(token)); w.Code != 200 {
			t.Fatalf("enroll: %d %s", w.Code, w.Body)
		}
	}
	tokenFor := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		return do("POST", "/api/enroll-tokens", visitor, admin, body)
	}
	maintainerMac := func(name, login string) {
		t.Helper()
		var resp api.EnrollTokenResponse
		w := tokenFor(`{"name":"` + name + `","volunteer_name":"Visitor","contact":"v@example.org","volunteer_login":"` + login + `"}`)
		if json.Unmarshal(w.Body.Bytes(), &resp); w.Code != 200 {
			t.Fatalf("token for %s: %d %s", name, w.Code, w.Body)
		}
		enroll(resp.Token)
		s.store.saveJob(&api.Job{ID: "j-" + name, Spec: api.JobSpec{Device: name}, DeviceID: s.dev(name).d.ID, State: api.JobDone, Created: s.now()})
	}
	volunteer := func(remote, body string) *httptest.ResponseRecorder {
		t.Helper()
		var resp api.EnrollTokenResponse
		w := do("POST", "/api/volunteer", remote, "", body)
		if json.Unmarshal(w.Body.Bytes(), &resp); w.Code == 200 {
			enroll(resp.Token)
		}
		return w
	}
	names := func(remote string) (out []string) {
		var ds []api.Device
		json.Unmarshal(do("GET", "/api/devices", remote, "", "").Body.Bytes(), &ds)
		for _, d := range ds {
			out = append(out, d.Name)
		}
		slices.Sort(out)
		return out
	}
	patch := func(remote, token, name, body string) *httptest.ResponseRecorder {
		t.Helper()
		return do("PATCH", "/api/devices/"+name, remote, token, body)
	}
	seesMac := func(remote, name string) bool {
		t.Helper()
		dev, job := do("GET", "/api/devices/"+name, remote, "", ""), do("GET", "/api/jobs/j-"+name, remote, "", "")
		if (dev.Code == 200) != (job.Code == 200) {
			t.Errorf("%s: the Mac answers %d, its job %d", name, dev.Code, job.Code)
		}
		return dev.Code == 200 && slices.Contains(names(remote), name)
	}

	// Linked at enrollment: the login, in any case, sees the Mac; nobody else.
	maintainerMac("linked", "Visitor@GitHub")
	if d := s.dev("linked").d; d.LinkedLogin != "visitor@github" || d.VolunteeredBy != "" {
		t.Errorf("linked: LinkedLogin %q, VolunteeredBy %q", d.LinkedLogin, d.VolunteeredBy)
	}
	if !seesMac(visitor, "linked") {
		t.Error("the linked Volunteer doesn't see their Mac")
	}
	if seesMac(other, "linked") {
		t.Error("another person sees a Mac linked to someone else")
	}

	// Bad logins and logins without a Volunteer are refused; no token is made.
	for _, body := range []string{
		`{"name":"bad","volunteer_name":"V","contact":"c","volunteer_login":"visitor"}`,
		`{"name":"bad","volunteer_name":"V","contact":"c","volunteer_login":"enr_0123456789abcdef0123456789abcdef"}`,
		`{"name":"bad","volunteer_name":"V","contact":"c","volunteer_login":"adm_secret"}`,
		`{"name":"bad","volunteer_name":"V","contact":"c","volunteer_login":"visitor@github visitor@github"}`,
		`{"name":"bad","volunteer_login":"visitor@github"}`, // a Lab-owned Mac's token
	} {
		if w := tokenFor(body); w.Code != 400 {
			t.Errorf("token %s: %d %s, want 400", body, w.Code, w.Body)
		}
	}

	// Linked later, and unlinked.
	maintainerMac("later", "")
	if seesMac(visitor, "later") || seesMac(other, "later") {
		t.Fatal("an unlinked Maintainer-made Mac is seen by a person")
	}
	if w := patch(visitor, admin, "later", `{"volunteer_login":"other@github"}`); w.Code != 200 {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}
	if !seesMac(other, "later") || seesMac(visitor, "later") {
		t.Error("after linking later to other@github, only they should see it")
	}
	for _, login := range []string{"other", "dev_0123456789abcdef0123456789abcdef0123456789abcdef", "a@b@c"} {
		if w := patch(visitor, admin, "later", `{"volunteer_login":"`+login+`"}`); w.Code != 400 {
			t.Errorf("link to %q: %d %s, want 400", login, w.Code, w.Body)
		}
	}
	if got := s.dev("later").d.LinkedLogin; got != "other@github" {
		t.Errorf("a refused link changed the Mac's login to %q", got)
	}
	if w := patch(visitor, admin, "later", `{"volunteer_login":""}`); w.Code != 200 {
		t.Fatalf("unlink: %d %s", w.Code, w.Body)
	}
	if seesMac(other, "later") {
		t.Error("an unlinked Mac is still seen by the login it was linked to")
	}
	if w := do("GET", "/api/jobs/j-later/files/journal", other, "", ""); w.Code != 404 {
		t.Errorf("an unlinked Mac's journal: %d, want 404", w.Code)
	}

	// A person can't link or unlink, not even to their own login.
	for _, c := range []struct{ remote, name, body string }{
		{visitor, "later", `{"volunteer_login":"visitor@github"}`},
		{visitor, "linked", `{"volunteer_login":""}`},
		{other, "linked", `{"volunteer_login":"other@github"}`},
	} {
		if w := patch(c.remote, "", c.name, c.body); w.Code != 403 {
			t.Errorf("a person's PATCH %s %s: %d %s, want 403", c.name, c.body, w.Code, w.Body)
		}
	}
	if w := do("POST", "/api/enroll-tokens", other, "", `{"name":"sneak","volunteer_name":"O","contact":"c","volunteer_login":"other@github"}`); w.Code != 403 {
		t.Errorf("a person asks for a Maintainer's token: %d, want 403", w.Code)
	}
	if got := s.dev("linked").d.LinkedLogin; got != "visitor@github" {
		t.Errorf("a person changed linked's login to %q", got)
	}
	// ./volunteer takes no login from its body: the Mac is its asker's alone.
	if w := volunteer(other, `{"name":"own","volunteer_login":"visitor@github"}`); w.Code != 200 {
		t.Fatalf("volunteer: %d %s", w.Code, w.Body)
	}
	if d := s.dev("own").d; d.LinkedLogin != "" || d.VolunteeredBy != "other@github" {
		t.Errorf("own: LinkedLogin %q, VolunteeredBy %q", d.LinkedLogin, d.VolunteeredBy)
	}

	// Only a Volunteer's Mac, and not one a person volunteered, is linked.
	tok, _ := s.store.addTokenForTest("lab")
	enroll(tok)
	if w := patch(visitor, admin, "lab", `{"volunteer_login":"visitor@github"}`); w.Code != 409 {
		t.Errorf("link a Lab-owned Mac: %d %s, want 409", w.Code, w.Body)
	}
	if w := patch(visitor, admin, "own", `{"volunteer_login":"visitor@github"}`); w.Code != 409 {
		t.Errorf("link a Mac other@github volunteered: %d %s, want 409", w.Code, w.Body)
	}
	if got := names(visitor); !slices.Equal(got, []string{"linked"}) {
		t.Errorf("the visitor lists %q, want only linked", got)
	}

	// Linked Macs are outside the person's own limit: with three linked, they
	// still volunteer three of their own, and no more.
	maintainerMac("linked-2", "visitor@github")
	maintainerMac("linked-3", "visitor@github")
	for i := range maxVolunteerMacs {
		if w := volunteer(visitor, fmt.Sprintf(`{"name":"mine-%d"}`, i)); w.Code != 200 {
			t.Fatalf("volunteer mine-%d with linked Macs: %d %s", i, w.Code, w.Body)
		}
	}
	if w := volunteer(visitor, `{"name":"one-too-many"}`); w.Code != 409 {
		t.Errorf("a fourth Mac of their own: %d %s, want 409", w.Code, w.Body)
	}
	if got := names(visitor); len(got) != 6 {
		t.Errorf("the visitor lists %q, want 3 linked and 3 of their own", got)
	}

	// A forgotten linked Mac takes its link with it: its name, taken again,
	// is nobody's until a Maintainer links it, and the old jobs stay hidden.
	if code, err := s.forget(s.dev("linked"), "", true); code != 200 {
		t.Fatalf("forget linked: %d %v", code, err)
	}
	if slices.Contains(names(visitor), "linked") {
		t.Error("the visitor still lists a forgotten Mac")
	}
	var resp api.EnrollTokenResponse
	json.Unmarshal(tokenFor(`{"name":"linked","volunteer_name":"Other","contact":"o@example.org"}`).Body.Bytes(), &resp)
	enroll(resp.Token)
	if w := do("GET", "/api/devices/linked", visitor, "", ""); w.Code != 404 {
		t.Errorf("the visitor sees a new, unlinked Mac under a forgotten linked Mac's name: %d", w.Code)
	}
	// Linked to the same person again, the new Mac is theirs; the old one's
	// jobs stay with the Maintainers.
	if w := patch(visitor, admin, "linked", `{"volunteer_login":"visitor@github"}`); w.Code != 200 {
		t.Fatalf("link the new linked: %d %s", w.Code, w.Body)
	}
	if w := do("GET", "/api/devices/linked", visitor, "", ""); w.Code != 200 {
		t.Errorf("the visitor doesn't see the new Mac linked to them: %d", w.Code)
	}
	for _, path := range []string{"/api/jobs/j-linked", "/api/jobs/j-linked/files/journal"} {
		if w := do("GET", path, visitor, "", ""); w.Code != 404 {
			t.Errorf("the forgotten linked Mac's history: GET %s got %d, want 404", path, w.Code)
		}
	}
	if w := do("GET", "/api/jobs/j-linked", visitor, admin, ""); w.Code != 200 {
		t.Errorf("a Maintainer reads the forgotten Mac's job: %d, want 200", w.Code)
	}
}

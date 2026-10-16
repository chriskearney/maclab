package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// volunteerLab is a labd under --tailscale whose tailnet has a tagged lab Mac
// at 100.64.0.3 and a person at every other 100.64.x.y, user-x-y@github.
func volunteerLab(t *testing.T) (*Server, func(method, path, remote, token, body string) *httptest.ResponseRecorder) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	whois := func(ctx context.Context, ip string) (*TailnetPeer, error) {
		if ip == "100.64.0.3" {
			return &TailnetPeer{Login: "tagged-devices", Node: "maclab-m1air", Tags: []string{"tag:maclab"}}, nil
		}
		var a, b int
		if _, err := fmt.Sscanf(ip, "100.64.%d.%d", &a, &b); err != nil {
			return nil, fmt.Errorf("no match for IP")
		}
		return &TailnetPeer{Login: fmt.Sprintf("User-%d-%d@github", a, b), Node: "omarchy"}, nil
	}
	trust, _ := ParseTrust("10.1.1.0/24")
	s, err := New(ctx, Config{DataDir: t.TempDir(), AdminToken: "adm_secret", Trust: trust, Tailscale: true, WhoIs: whois},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	return s, func(method, path, remote, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
}

func volunteerTokens(t *testing.T, s *Server) (n int) {
	t.Helper()
	if err := s.store.db.QueryRow(`SELECT count(*) FROM tokens`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A tailnet viewer holds one unused volunteer token at a time, and only so
// many viewers hold one at once. Tagged devices get none, and a request
// can't be large.
func TestVolunteerLimits(t *testing.T) {
	s, do := volunteerLab(t)
	ask := func(remote, token, body string) (int, api.EnrollTokenResponse) {
		t.Helper()
		w := do("POST", "/api/volunteer", remote, token, body)
		var resp api.EnrollTokenResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}
	enroll := func(token string) int {
		return do("POST", "/api/agent/enroll", "100.64.9.9:1", "", `{"token":"`+token+`"}`).Code
	}
	peer := func(i int) string { return fmt.Sprintf("100.64.1.%d:40000", i) }

	// The request is a name and a model: anything larger is turned away.
	if code, _ := ask(peer(0), "", `{"name":"`+strings.Repeat("a", 5000)+`"}`); code != 413 {
		t.Errorf("a 5 KB request: %d, want 413", code)
	}
	if code, _ := ask("100.64.0.3:40000", "", `{"name":"m1air"}`); code != 403 {
		t.Errorf("a tagged lab Mac got a token: %d", code)
	}
	if n := volunteerTokens(t, s); n != 0 {
		t.Fatalf("%d tokens after two refusals", n)
	}

	// Asking again replaces the token: only the newest one enrolls.
	_, first := ask(peer(0), "", `{"name":"omarchy"}`)
	code, second := ask(peer(0), "", `{"name":"omarchy"}`)
	if code != 200 || first.Token == "" || second.Token == first.Token {
		t.Fatalf("asking twice: %d %+v %+v", code, first, second)
	}
	if n := volunteerTokens(t, s); n != 1 {
		t.Fatalf("one volunteer holds %d tokens", n)
	}
	if code := enroll(first.Token); code != 403 {
		t.Errorf("the replaced token enrolled: %d", code)
	}

	// Up to maxVolunteerTokens people hold one at once; then newcomers wait.
	for i := 1; i < maxVolunteerTokens; i++ {
		if code, _ := ask(peer(i), "", `{}`); code != 200 {
			t.Fatalf("volunteer %d: %d", i, code)
		}
	}
	if code, _ := ask(peer(maxVolunteerTokens), "", `{}`); code != 429 {
		t.Fatalf("volunteer %d of %d: %d, want 429", maxVolunteerTokens+1, maxVolunteerTokens, code)
	}
	if code, _ := ask(peer(1), "", `{}`); code != 200 {
		t.Errorf("a volunteer who holds a token can't replace it when the lab is full: %d", code)
	}
	// Admins aren't held to it, by token or from a trusted network.
	if code, _ := ask("100.64.0.3:40000", "adm_secret", `{}`); code != 200 {
		t.Errorf("admin token from a tagged device: %d", code)
	}
	if code, _ := ask("10.1.1.42:1", "", `{}`); code != 200 {
		t.Errorf("admin on a trusted network: %d", code)
	}

	// Using a token frees its place, and so does its expiry.
	if code := enroll(second.Token); code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	if code, _ := ask(peer(maxVolunteerTokens), "", `{}`); code != 200 {
		t.Errorf("after one enrolled: %d", code)
	}
	if code, _ := ask(peer(maxVolunteerTokens+1), "", `{}`); code != 429 {
		t.Errorf("full again: %d", code)
	}
	if _, err := s.store.db.Exec(`UPDATE tokens SET expires=1 WHERE requester=?`, "user-1-2@github"); err != nil {
		t.Fatal(err)
	}
	if code, _ := ask(peer(maxVolunteerTokens+1), "", `{}`); code != 200 {
		t.Errorf("after one expired: %d", code)
	}
}

// A Mac enrolled with a volunteer token is a volunteer's, whatever the
// request said; one enrolled with an admin's token isn't.
func TestVolunteerDevicesMarked(t *testing.T) {
	_, do := volunteerLab(t)
	mint := func(path, remote, token, body string) string {
		t.Helper()
		w := do("POST", path, remote, token, body)
		var resp api.EnrollTokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); w.Code != 200 || err != nil {
			t.Fatalf("%s from %s: %d %s", path, remote, w.Code, w.Body)
		}
		return resp.Token
	}
	device := func(token string) api.Device {
		t.Helper()
		w := do("POST", "/api/agent/enroll", "100.64.9.9:1", "", `{"token":"`+token+`"}`)
		var e api.EnrollResponse
		if err := json.Unmarshal(w.Body.Bytes(), &e); w.Code != 200 || err != nil {
			t.Fatalf("enroll: %d %s", w.Code, w.Body)
		}
		var d api.Device
		json.Unmarshal(do("GET", "/api/devices/"+e.Name, "10.1.1.42:1", "", "").Body.Bytes(), &d)
		return d
	}
	if d := device(mint("/api/volunteer", "100.64.1.1:1", "", `{"name":"viewer","volunteer":false}`)); !d.Volunteer || d.Label != "User-1-1@github" {
		t.Errorf("a viewer's Mac: volunteer %v, label %q", d.Volunteer, d.Label)
	}
	if d := device(mint("/api/volunteer", "10.1.1.42:1", "", `{"name":"admins"}`)); !d.Volunteer {
		t.Error("a Mac an admin enrolled through ./volunteer isn't marked a volunteer's")
	}
	if d := device(mint("/api/enroll-tokens", "10.1.1.42:1", "", `{"name":"labmac"}`)); d.Volunteer {
		t.Error("a lab Mac enrolled with lab enroll is marked a volunteer's")
	}
}

// Tokens and devices stored before the volunteer flag existed read as a
// lab Mac's.
func TestTokensFromBeforeVolunteers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labd.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE devices (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, secret_hash TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE tokens (token_hash TEXT PRIMARY KEY, name TEXT NOT NULL, label TEXT, model TEXT, expires INTEGER NOT NULL);
INSERT INTO tokens VALUES ('old', 'm1air', 'left desk', 'laptop', 9999999999);
INSERT INTO devices VALUES ('d-1', 'm2air', 'x', '{"id":"d-1","name":"m2air","label":"right desk","model":"laptop","state":"ready"}');`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	tok, err := st.takeToken("old")
	if err != nil || tok.Name != "m1air" || tok.Volunteer {
		t.Fatalf("old token: %+v, %v", tok, err)
	}
	rows, err := st.devices()
	if err != nil || len(rows) != 1 || rows[0].d.Volunteer {
		t.Fatalf("old device: %+v, %v", rows, err)
	}
	if _, err := openStore(path); err != nil {
		t.Fatalf("opening it again: %v", err)
	}
}

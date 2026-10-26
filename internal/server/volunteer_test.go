package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
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
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret", Tailscale: true, WhoIs: whois},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	return s, func(method, path, remote, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, labdAt+path, strings.NewReader(body))
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
	// Maintainers aren't held to it, with their token from anywhere.
	if code, _ := ask("100.64.0.3:40000", "adm_secret", `{}`); code != 200 {
		t.Errorf("admin token from a tagged device: %d", code)
	}
	if code, _ := ask("10.1.1.42:1", "adm_secret", `{}`); code != 200 {
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
		json.Unmarshal(do("GET", "/api/devices/"+e.Name, "10.1.1.42:1", "adm_secret", "").Body.Bytes(), &d)
		return d
	}
	if d := device(mint("/api/volunteer", "100.64.1.1:1", "", `{"name":"viewer","volunteer":false}`)); !d.Volunteer || d.Label != "User-1-1@github" {
		t.Errorf("a viewer's Mac: volunteer %v, label %q", d.Volunteer, d.Label)
	}
	if d := device(mint("/api/volunteer", "10.1.1.42:1", "adm_secret", `{"name":"admins"}`)); !d.Volunteer {
		t.Error("a Mac an admin enrolled through ./volunteer isn't marked a volunteer's")
	}
	if d := device(mint("/api/enroll-tokens", "10.1.1.42:1", "adm_secret", `{"name":"labmac"}`)); d.Volunteer {
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
	tok, err := st.token("old", time.Now())
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

// One tailnet login puts at most maxVolunteerMacs Macs in the lab, however
// many tokens it asks for one after another; lab forget frees a place.
func TestVolunteerMacLimit(t *testing.T) {
	s, do := volunteerLab(t)
	const (
		person = "100.64.1.1:40000" // user-1-1@github
		login  = "user-1-1@github"
		lan    = "10.1.1.42:1"
	)
	ask := func(remote string, token ...string) (int, string, api.EnrollTokenResponse) {
		t.Helper()
		w := do("POST", "/api/volunteer", remote, strings.Join(token, ""), `{"name":"omarchy"}`)
		var resp api.EnrollTokenResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, w.Body.String(), resp
	}
	enroll := func(token string) (int, string) {
		t.Helper()
		w := do("POST", "/api/agent/enroll", "100.64.9.9:1", "", `{"token":"`+token+`"}`)
		return w.Code, w.Body.String()
	}
	var names []string
	for i := range maxVolunteerMacs {
		code, body, tok := ask(person)
		if code != 200 {
			t.Fatalf("Mac %d: %d %s", i+1, code, body)
		}
		if code, body := enroll(tok.Token); code != 200 {
			t.Fatalf("enroll Mac %d: %d %s", i+1, code, body)
		}
		names = append(names, tok.Name)
	}
	// The Macs' tokens stay until each first checks in; the refusal adds none.
	before := volunteerTokens(t, s)
	code, body, _ := ask(person)
	if code != 409 || !strings.Contains(body, "volunteered 3 Macs already") || !strings.Contains(body, names[0]) {
		t.Errorf("Mac %d: %d %s", maxVolunteerMacs+1, code, body)
	}
	if n := volunteerTokens(t, s); n != before {
		t.Errorf("the refusal left %d tokens", n-before)
	}
	if code, body, _ := ask("100.64.1.2:40000"); code != 200 {
		t.Errorf("someone else: %d %s", code, body)
	}
	if code, body, _ := ask(lan, "adm_secret"); code != 200 {
		t.Errorf("an admin: %d %s", code, body)
	}
	rows, err := s.store.devices()
	if err != nil {
		t.Fatal(err)
	}
	stored := 0
	for _, r := range rows {
		if r.d.VolunteeredBy == login {
			stored++
		}
	}
	if stored != maxVolunteerMacs {
		t.Errorf("%d of the person's %d Macs are stored as theirs", stored, maxVolunteerMacs)
	}

	// lab forget frees a place.
	if w := do("DELETE", "/api/devices/"+names[0], lan, "adm_secret", ""); w.Code != 200 {
		t.Fatalf("forget %s: %d %s", names[0], w.Code, w.Body)
	}
	code, body, tok := ask(person)
	if code != 200 {
		t.Fatalf("after lab forget: %d %s", code, body)
	}
	// A Mac enrolled with a token handed out moments earlier, while this
	// one was handed out, still counts: the token can't make a fourth.
	s.mu.Lock()
	s.devs["raced"] = newDev(s, api.Device{Name: "raced", VolunteeredBy: login}, "")
	s.mu.Unlock()
	if code, body := enroll(tok.Token); code != 409 || !strings.Contains(body, "volunteered 3 Macs already") {
		t.Errorf("a token that would make a fourth Mac: %d %s", code, body)
	}
	if s.dev(tok.Name) != nil {
		t.Errorf("%s enrolled anyway", tok.Name)
	}
}

// filler reads as n bytes of one character, made as they are read.
type filler struct {
	n     int64
	chunk []byte
}

func fill(n int64, c byte) *filler { return &filler{n, bytes.Repeat([]byte{c}, 32<<10)} }

func (f *filler) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, io.EOF
	}
	n := copy(p[:min(int64(len(p)), f.n)], f.chunk)
	f.n -= int64(n)
	return n, nil
}

// Enrollments, check-ins and reports have size limits real agents are far
// below; uploads go elsewhere and have none.
func TestAgentBodyLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	// post sends body, of length bytes if length > 0, else of a length it
	// doesn't say.
	post := func(path, secret string, body io.Reader, length ...int64) (int, string) {
		t.Helper()
		r := httptest.NewRequest("POST", labdAt+path, body)
		r.ContentLength = -1
		for _, n := range length {
			r.ContentLength = n
		}
		if secret != "" {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	// huge is a JSON body with a string of n bytes in it.
	huge := func(prefix string, n int64, suffix string) io.Reader {
		return io.MultiReader(strings.NewReader(prefix), fill(n, 'a'), strings.NewReader(suffix))
	}
	// The facts of a Mac with plenty to say: a long command line and many
	// preflight problems and warnings.
	facts := api.Facts{Hostname: "omarchy", Machine: "aarch64", DTModel: "Apple MacBook Air (13-inch, M2, 2022)",
		Compatible: []string{"apple,j413", "apple,t8112", "apple,arm-platform"}, Bootloader: "limine", Initramfs: "mkinitcpio",
		Watchdog: true, PanicTimeout: 10, GUIUser: "omarchy", AgentVersion: "0.9.0"}
	for i := range 20 {
		facts.Problems = append(facts.Problems, fmt.Sprintf("problem %d: /boot has %d MB free; a lab kernel and its initramfs need 200 MB, so clear old kernels out first", i, i))
		facts.Warnings = append(facts.Warnings, fmt.Sprintf("warning %d: journald keeps the journal in memory only, so a lab boot that fails takes its journal with it", i))
	}
	enrollBody, _ := json.Marshal(api.EnrollRequest{Token: "enr_test_m1", Facts: facts})
	checkin, _ := json.Marshal(api.Checkin{BootID: "b1", Kernel: "6.17.0-asahi", Cmdline: strings.Repeat("x", 4096), Facts: &facts,
		Health: api.Health{Uptime: 100, SystemState: "running"}, Running: []string{"c1", "c2"}})
	if len(enrollBody) > enrollBodyMax/16 || len(checkin) > checkinBodyMax/16 {
		t.Errorf("a full enrollment is %d bytes and a full check-in %d: less headroom than wanted", len(enrollBody), len(checkin))
	}

	tok, err := s.store.addTokenForTest("m1")
	if err != nil {
		t.Fatal(err)
	}
	if code, body := post("/api/agent/enroll", "", huge(`{"token":"`+tok+`","facts":{"hostname":"`, enrollBodyMax, `"}}`)); code != 413 {
		t.Errorf("an enrollment over %d bytes: %d %s", enrollBodyMax, code, body)
	}
	code, body := post("/api/agent/enroll", "", bytes.NewReader(enrollBody))
	var e api.EnrollResponse
	if json.Unmarshal([]byte(body), &e); code != 200 || e.Secret == "" {
		t.Fatalf("enroll after the refusal, with the same token: %d %s", code, body)
	}

	if code, body := post("/api/agent/checkin", e.Secret, bytes.NewReader(checkin)); code != 200 {
		t.Errorf("a full check-in: %d %s", code, body)
	}
	if code, body := post("/api/agent/checkin", e.Secret, huge(`{"boot_id":"b1","facts":{"hostname":"`, checkinBodyMax, `"}}`)); code != 413 {
		t.Errorf("a check-in over %d bytes: %d %s", checkinBodyMax, code, body)
	}
	if d := s.dev("m1").snapshot(); d.Facts.Hostname != "omarchy" {
		t.Errorf("the refused check-in's facts were kept: hostname of %d bytes", len(d.Facts.Hostname))
	}

	// The largest real report: an exec's whole output, 1 MB per stream, all
	// control characters, which JSON writes six bytes each.
	junk := strings.Repeat("\x01", 1<<20)
	out, _ := json.Marshal(api.ExecResult{Stdout: junk, Stderr: junk, Via: "agent"})
	rep, _ := json.Marshal(api.Report{Results: []api.CommandResult{{ID: "c1", OK: true, Output: out}}})
	if code, body := post("/api/agent/report", e.Secret, bytes.NewReader(rep)); code != 200 {
		t.Errorf("a report of %d bytes: %d %s", len(rep), code, body)
	}
	// One that says it's too large is turned away unread; one that doesn't
	// say is cut off where it passes the limit, as check-ins are above.
	if code, body := post("/api/agent/report", e.Secret, fill(reportBodyMax+1, ' '), reportBodyMax+1); code != 413 {
		t.Errorf("a report over %d bytes: %d %s", reportBodyMax, code, body)
	}

	if err := s.store.saveJob(&api.Job{ID: "j1016-120000-ab12", Spec: api.JobSpec{Device: "m1"}, State: api.JobTesting}); err != nil {
		t.Fatal(err)
	}
	if code, body := post("/api/agent/upload?job=j1016-120000-ab12&name=boot0/journal.txt", e.Secret, fill(reportBodyMax+1, 'j')); code != 200 {
		t.Errorf("an upload larger than any report: %d %s", code, body)
	}
	if fi, err := os.Stat(filepath.Join(s.jobDir("j1016-120000-ab12"), "boot0", "journal.txt")); err != nil || fi.Size() != reportBodyMax+1 {
		t.Errorf("the upload: %v, %v", fi, err)
	}
}

func TestVolunteerLabRunsVolunteerCommands(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	if _, err := l.volunteer("no-such-command"); err == nil || !strings.Contains(err.Error(), `"no-such-command"`) {
		t.Fatalf("an unknown Volunteer command: %v", err)
	}
}

func TestEncryptedMacWaitsForItsPassword(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.sim.Encrypted = true
	before := l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	l.sim.PowerCycle()
	time.Sleep(time.Second) // several reboot delays
	if d := l.s.dev(l.name).snapshot(); d.BootID != before.BootID {
		t.Fatal("an encrypted Mac booted without its disk password")
	}
	l.sim.TypePassword()
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" && d.BootID != before.BootID })
}

func TestRollbackReturnsTheMacToItsSnapshot(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true})
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	l.sim.Snapshot()
	l.sim.DefaultKernel = "7.3-installed" // what an installer leaves behind
	l.sim.PowerCycle()
	l.waitDevice(func(d api.Device) bool { return d.Kernel == "7.3-installed" })
	if err := l.sim.Rollback(); err != nil {
		t.Fatal(err)
	}
	l.sim.PowerCycle()
	l.waitDevice(func(d api.Device) bool { return d.Kernel == agent.SimKnownGood })
}

func TestLabBootThatLosesTheNetworkNeverChecksIn(t *testing.T) {
	l := newLabWith(t, labConfig{volunteer: true, oob: true})
	l.openForTheLab(time.Now())
	l.baseline()
	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-offline behavior=no-network")})
	if j.Result.Booted || j.Outcome == api.OutcomePass {
		t.Fatalf("a Lab boot with no network reached labd: %s %+v", j.Outcome, j.Result)
	}
	l.waitDevice(func(d api.Device) bool { return d.State == api.StateReady && d.Kernel == agent.SimKnownGood })
}

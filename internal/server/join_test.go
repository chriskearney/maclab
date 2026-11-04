package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// joinLab is a labd at https://chonkbase.net/maclab with a lab-agent to hand
// out, driven by requests straight to its Handler, and its log.
type joinLab struct {
	t    *testing.T
	s    *Server
	h    http.Handler
	logs *strings.Builder
	mu   sync.Mutex
}

func newJoinLab(t *testing.T) *joinLab {
	t.Helper()
	agentBin := filepath.Join(t.TempDir(), "lab-agent-linux-arm64")
	os.WriteFile(agentBin, []byte("\x7fELF lab-agent for the test"), 0o755)
	pub, _ := ParsePublicURL("https://chonkbase.net/maclab")
	proxies, _ := ParseTrustedProxies("10.2.0.0/16")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	j := &joinLab{t: t, logs: &strings.Builder{}}
	s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "adm_secret",
		PublicURL: pub, TrustedProxies: proxies, AgentBinary: agentBin}, log.New(lockedWriter{j}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	j.s, j.h = s, s.Handler()
	return j
}

type lockedWriter struct{ j *joinLab }

func (w lockedWriter) Write(b []byte) (int, error) {
	w.j.mu.Lock()
	defer w.j.mu.Unlock()
	return w.j.logs.Write(b)
}

func (j *joinLab) do(method, path, bearer, body string) (int, string) {
	r := httptest.NewRequest(method, "http://chonkbase.net/maclab"+path, strings.NewReader(body))
	r.RemoteAddr = viaProxy
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "chonkbase.net")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	j.h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// invite has a Maintainer make an enrollment token for name, as lab enroll does.
func (j *joinLab) invite(name string) api.EnrollTokenResponse {
	j.t.Helper()
	code, body := j.do("POST", "/api/enroll-tokens", "adm_secret", `{"name":"`+name+`"}`)
	var t api.EnrollTokenResponse
	if json.Unmarshal([]byte(body), &t); code != 200 || t.Token == "" {
		j.t.Fatalf("invite %s: %d %s", name, code, body)
	}
	return t
}

func (j *joinLab) enroll(token, key, terms string) (int, api.EnrollResponse) {
	b, _ := json.Marshal(api.EnrollRequest{Token: token, ActivationKey: key, TermsSHA256: terms})
	code, body := j.do("POST", "/api/agent/enroll", "", string(b))
	var e api.EnrollResponse
	json.Unmarshal([]byte(body), &e)
	return code, e
}

const keyA, keyB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// The token is good for one activation. The Mac that used it may enroll again
// with its own activation key until its first check-in (the answer never
// reached it); a copy of the token on another Mac is worth nothing.
func TestEnrollmentTokenActivatesOneMacOnce(t *testing.T) {
	j := newJoinLab(t)
	tok := j.invite("fresh").Token
	first, a := j.enroll(tok, keyA, termsSum())
	if first != 200 || a.DeviceID == "" {
		t.Fatalf("first activation: %d", first)
	}
	for name, key := range map[string]string{"another Mac's key": keyB, "no key (an older lab-agent)": ""} {
		if code, _ := j.enroll(tok, key, termsSum()); code != 403 {
			t.Errorf("the used token with %s: %d, want 403", name, code)
		}
	}
	code, again := j.enroll(tok, keyA, termsSum())
	if code != 200 || again.DeviceID != a.DeviceID || again.Secret == a.Secret {
		t.Fatalf("the same activation again: %d %+v (first %+v)", code, again, a)
	}
	// The first secret was replaced; the new one checks in, which spends the token.
	ci, _ := json.Marshal(api.Checkin{BootID: "b1", Kernel: "7.2"})
	if code, _ := j.do("POST", "/api/agent/checkin", a.Secret, string(ci)); code != 401 {
		t.Errorf("the replaced secret checks in: %d", code)
	}
	if code, body := j.do("POST", "/api/agent/checkin", again.Secret, string(ci)); code != 200 {
		t.Fatalf("check-in: %d %s", code, body)
	}
	if code, _ := j.enroll(tok, keyA, termsSum()); code != 403 {
		t.Errorf("the same activation after the first check-in: %d, want 403", code)
	}
	// A token for a name taken by a Mac that never checked in is refused up
	// front, with what to do.
	j.invite("pending")
	if code, _ := j.enroll(j.invite("pending2").Token, keyA, termsSum()); code != 200 {
		t.Fatal("pending2")
	}
	if code, body := j.do("POST", "/api/enroll-tokens", "adm_secret", `{"name":"pending2"}`); code != 409 || !strings.Contains(body, "lab forget pending2") {
		t.Errorf("a new token for a Mac that never checked in: %d %s", code, body)
	}
}

// Two Macs racing with one token: exactly one gets it.
func TestOneOfTwoRacingEnrollmentsWins(t *testing.T) {
	j := newJoinLab(t)
	tok := j.invite("race").Token
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = j.enroll(tok, strings.Repeat(string(rune('c'+i)), 64), termsSum())
		}()
	}
	wg.Wait()
	won := 0
	for _, c := range codes {
		if c == 200 {
			won++
		} else if c != 403 && c != 409 {
			t.Errorf("a losing enrollment got %d", c)
		}
	}
	if won != 1 {
		t.Errorf("%d enrollments won: %v", won, codes)
	}
}

// labd takes only an enrollment whose owner accepted its current terms, and a
// refused one leaves the token unused.
func TestEnrollmentNeedsTheCurrentTerms(t *testing.T) {
	j := newJoinLab(t)
	tok := j.invite("terms").Token
	for _, bad := range []string{"", strings.Repeat("0", 64), strings.ToUpper(termsSum())} {
		if code, _ := j.enroll(tok, keyA, bad); code != 409 {
			t.Errorf("terms %q: %d, want 409", bad, code)
		}
	}
	code, e := j.enroll(tok, keyA, termsSum())
	if code != 200 {
		t.Fatalf("with the terms: %d", code)
	}
	_, body := j.do("GET", "/api/devices/terms", "adm_secret", "")
	var d api.Device
	json.Unmarshal([]byte(body), &d)
	if d.ID != e.DeviceID || d.TermsSHA256 != termsSum() || d.TermsAccepted.IsZero() {
		t.Errorf("the Mac's record of the terms: %+v", d)
	}
	// An operator's own terms replace the built-in ones, and their sha256 is the version.
	if text, sum := (&Server{cfg: Config{Terms: "Our lab. Our rules.\n"}}).terms(); text != "Our lab. Our rules.\n" || sum == termsSum() || len(sum) != 64 {
		t.Errorf("own terms: %q %s", text, sum)
	}
}

// The join routes answer to an unexpired enrollment token in the
// Authorization header, and to nothing else: not a Maintainer's token, not a
// device secret, not a token in the URL.
func TestJoinRoutesTakeOnlyAnEnrollmentTokenInTheHeader(t *testing.T) {
	j := newJoinLab(t)
	tok := j.invite("joiner").Token
	code, body := j.do("GET", "/api/join/terms", tok, "")
	var terms api.JoinTerms
	if json.Unmarshal([]byte(body), &terms); code != 200 || terms.SHA256 != termsSum() || terms.Text != DefaultTerms {
		t.Fatalf("terms: %d %s", code, body)
	}
	if code, body := j.do("GET", "/api/join/lab-agent", tok, ""); code != 200 || !strings.HasPrefix(body, "\x7fELF") {
		t.Fatalf("lab-agent: %d", code)
	}
	_, e := j.enroll(j.invite("enrolled").Token, keyA, termsSum())
	for name, bearer := range map[string]string{"no token": "", "a Maintainer's token": "adm_secret", "a device secret": e.Secret, "a made-up token": "enr_00000000000000000000000000000000"} {
		for _, p := range []string{"/api/join/terms", "/api/join/lab-agent"} {
			if code, _ := j.do("GET", p, bearer, ""); code != 401 {
				t.Errorf("%s on %s: %d, want 401", name, p, code)
			}
		}
	}
	if code, _ := j.do("GET", "/api/join/terms?token="+tok, "", ""); code != 401 {
		t.Errorf("a token in the URL: %d, want 401", code)
	}
	// The enrollment token reaches nothing a Maintainer or a Mac does.
	for _, p := range []string{"/api/devices", "/api/jobs", "/api/agent/enrollment", "/api/volunteer/lab-agent"} {
		if code, _ := j.do("GET", p, tok, ""); code != 401 {
			t.Errorf("an enrollment token on %s: %d, want 401", p, code)
		}
	}
}

// A Maintainer revokes an invite: unused, it stops working, and so do the
// join routes.
func TestRevokedInviteIsRefused(t *testing.T) {
	j := newJoinLab(t)
	tok := j.invite("revoked").Token
	if code, body := j.do("DELETE", "/api/enroll-tokens/revoked", "adm_secret", ""); code != 200 || !strings.Contains(body, `"revoked":1`) {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if code, _ := j.enroll(tok, keyA, termsSum()); code != 403 {
		t.Errorf("enrolling with a revoked token: %d", code)
	}
	if code, _ := j.do("GET", "/api/join/terms", tok, ""); code != 401 {
		t.Errorf("terms with a revoked token: %d", code)
	}
	if code, _ := j.do("DELETE", "/api/enroll-tokens/revoked", tok, ""); code != 401 {
		t.Errorf("an enrollment token revoking: %d", code)
	}
}

// The one-liner a Maintainer gets: the public URL with its prefix, the token
// in a shell variable sent in the Authorization header, never in a URL,
// https only, the download checked against labd's lab-agent sha256, the token
// handed to setup on stdin; and labd never logs the token.
func TestJoinCommandKeepsTheTokenOutOfURLsAndLogs(t *testing.T) {
	j := newJoinLab(t)
	t1 := j.invite("one-liner")
	cmd, tok := t1.JoinCommand, t1.Token
	sum := j.s.agentSHA256()
	for _, want := range []string{
		" T='" + tok + "'", "U='https://chonkbase.net/maclab'", "--proto '=https' --tlsv1.2",
		`printf 'Authorization: Bearer %s\n' "$T" | curl`, "-H @-", `"$U/api/join/lab-agent"`, "echo '" + sum + "  '",
		"sha256sum -c --quiet", `printf '%s\n' "$T" | sudo "$D/lab-agent" setup --server "$U" --token-stdin`,
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("the one-liner lacks %q:\n%s", want, cmd)
		}
	}
	if strings.Count(cmd, tok) != 1 || strings.Contains(cmd, "?") || strings.Contains(cmd, "--token ") || strings.Contains(cmd, "--allow-plain-http") {
		t.Errorf("the token is used more than once, or in a URL or on a command line, or plain http is allowed:\n%s", cmd)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sum) {
		t.Errorf("lab-agent sha256 %q", sum)
	}
	// The whole join, then: no token in labd's log.
	j.do("GET", "/api/join/terms", tok, "")
	j.do("GET", "/api/join/lab-agent", tok, "")
	j.enroll(tok, keyA, termsSum())
	j.enroll(tok, keyB, termsSum())
	j.do("DELETE", "/api/enroll-tokens/one-liner", "adm_secret", "")
	j.mu.Lock()
	logs := j.logs.String()
	j.mu.Unlock()
	if strings.Contains(logs, tok) || strings.Contains(logs, keyA) {
		t.Errorf("labd logged the token or activation key:\n%s", logs)
	}
	// Without a lab-agent to hand out there is no one-liner.
	j.s.cfg.AgentBinary = filepath.Join(t.TempDir(), "none")
	if t2 := j.invite("no-agent"); t2.JoinCommand != "" {
		t.Errorf("a one-liner without a lab-agent: %s", t2.JoinCommand)
	}
}

// Over plain http (a test or LAN labd), the one-liner says so: curl isn't held
// to https and setup must allow plain http. An address that isn't safe in
// single quotes gets no one-liner at all.
func TestJoinCommandForPlainHTTPAndUnsafeURLs(t *testing.T) {
	agentBin := filepath.Join(t.TempDir(), "lab-agent")
	os.WriteFile(agentBin, []byte("x"), 0o755)
	s := &Server{cfg: Config{AgentBinary: agentBin}}
	r := httptest.NewRequest("POST", "http://10.1.1.55:7770/api/enroll-tokens", nil)
	cmd := s.joinCommand(r, "enr_0123456789abcdef0123456789abcdef")
	if !strings.Contains(cmd, "U='http://10.1.1.55:7770'") || strings.Contains(cmd, "--proto") || !strings.HasSuffix(cmd, "--allow-plain-http") {
		t.Errorf("plain http one-liner:\n%s", cmd)
	}
	r.Host = "evil.example';rm -rf ~;'"
	if cmd := s.joinCommand(r, "enr_0123456789abcdef0123456789abcdef"); cmd != "" {
		t.Errorf("a one-liner for an unsafe host: %s", cmd)
	}
	if cmd := s.joinCommand(httptest.NewRequest("POST", "http://10.1.1.55:7770/", nil), "enr_x';id;'"); cmd != "" {
		t.Errorf("a one-liner for an unsafe token: %s", cmd)
	}
}

// The one-liner itself, run by bash with stand-ins for curl and sudo that
// record what they were given: the token reaches both on stdin, and no
// process's arguments, while the download is checked against its sha256.
func TestJoinCommandRunsWithTheTokenInNoArguments(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	for _, tool := range []string{"mktemp", "sha256sum", "chmod", "cat"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("no " + tool)
		}
	}
	j := newJoinLab(t)
	t1 := j.invite("argv")
	bin := t.TempDir()
	rec := t.TempDir()
	agent, _ := os.ReadFile(j.s.cfg.AgentBinary)
	os.WriteFile(filepath.Join(rec, "agent"), agent, 0o600)
	// curl: record argv and stdin, write the agent where -o says.
	os.WriteFile(filepath.Join(bin, "curl"), []byte(`#!/bin/bash
printf '%s\n' "$@" > "$REC/curl.argv"
cat > "$REC/curl.stdin"
while [ $# -gt 0 ]; do if [ "$1" = -o ]; then cp "$REC/agent" "$2"; fi; shift; done
`), 0o755)
	os.WriteFile(filepath.Join(bin, "sudo"), []byte(`#!/bin/bash
printf '%s\n' "$@" > "$REC/sudo.argv"
cat > "$REC/sudo.stdin"
`), 0o755)
	path := bin
	for _, tool := range []string{"mktemp", "sha256sum", "chmod", "cat", "cp"} {
		p, _ := exec.LookPath(tool)
		path += ":" + filepath.Dir(p)
	}
	cmd := exec.Command(bash, "-c", t1.JoinCommand)
	cmd.Env = []string{"PATH=" + path, "REC=" + rec, "USER=owner", "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the one-liner: %v\n%s", err, out)
	}
	read := func(f string) string { b, _ := os.ReadFile(filepath.Join(rec, f)); return string(b) }
	if strings.Contains(read("curl.argv"), t1.Token) || strings.Contains(read("sudo.argv"), t1.Token) {
		t.Errorf("the token is in a command's arguments:\ncurl %q\nsudo %q", read("curl.argv"), read("sudo.argv"))
	}
	if read("curl.stdin") != "Authorization: Bearer "+t1.Token+"\n" || read("sudo.stdin") != t1.Token+"\n" {
		t.Errorf("stdin: curl %q, sudo %q", read("curl.stdin"), read("sudo.stdin"))
	}
	if !strings.Contains(read("curl.argv"), "https://chonkbase.net/maclab/api/join/lab-agent") || !strings.Contains(read("sudo.argv"), "--token-stdin") {
		t.Errorf("curl %q sudo %q", read("curl.argv"), read("sudo.argv"))
	}
	// A download that isn't labd's lab-agent never runs.
	os.WriteFile(filepath.Join(rec, "agent"), []byte("#!/bin/sh\necho pwned\n"), 0o600)
	os.Remove(filepath.Join(rec, "sudo.argv"))
	cmd = exec.Command(bash, "-c", t1.JoinCommand)
	cmd.Env = []string{"PATH=" + path, "REC=" + rec, "USER=owner", "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
	if err := cmd.Run(); err == nil {
		t.Error("the one-liner went on with a wrong download")
	}
	if _, err := os.Stat(filepath.Join(rec, "sudo.argv")); err == nil {
		t.Error("sudo ran with a wrong download")
	}
}

// An enrollment is the one body anyone may send before labd knows who they
// are: one that trickles in is cut off at its deadline, not held open.
func TestASlowEnrollmentBodyIsCutOff(t *testing.T) {
	old := enrollBodyTimeout
	enrollBodyTimeout = 300 * time.Millisecond
	defer func() { enrollBodyTimeout = old }()
	j := newJoinLab(t)
	srv := httptest.NewServer(j.h)
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	fmt.Fprintf(c, "POST /maclab/api/agent/enroll HTTP/1.1\r\nHost: chonkbase.net\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, _ := io.ReadAll(c)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the slow body held the connection %s", took)
	}
	if len(b) > 0 && !strings.Contains(string(b), " 400 ") && !strings.Contains(string(b), " 408 ") {
		t.Errorf("answer to a slow body: %q", b)
	}
}

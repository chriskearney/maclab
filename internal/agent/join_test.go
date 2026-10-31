package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
	"github.com/iconidentify/maclab/internal/testpki"
)

func testTerms(text string) *api.JoinTerms {
	h := sha256.Sum256([]byte(text))
	return &api.JoinTerms{SHA256: hex.EncodeToString(h[:]), Text: text}
}

type fakeTTY struct {
	in  *strings.Reader
	out bytes.Buffer
}

func (f *fakeTTY) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) { return f.out.Write(p) }

// The owner accepts by typing yes, having been shown the terms; anything
// else, no answer, or no terminal at all stops setup. Acceptance given
// beforehand must name these very terms.
func TestTheTermsMustBeAcceptedExplicitly(t *testing.T) {
	terms := testTerms("Joining hands the lab your Mac.\n")
	for _, c := range []struct {
		answer string
		ok     bool
	}{
		{"yes\n", true},
		{"  yes  \n", true},
		{"no\n", false},
		{"y\n", false},
		{"YES PLEASE\n", false},
		{"\n", false},
		{"", false}, // the terminal closed
	} {
		tty := &fakeTTY{in: strings.NewReader(c.answer)}
		err := acceptTerms(terms, "https://lab.example.com/maclab", "", tty)
		if (err == nil) != c.ok {
			t.Errorf("answer %q: %v", c.answer, err)
		}
		if !c.ok && !errors.Is(err, errTermsDeclined) {
			t.Errorf("answer %q: %v, want declined", c.answer, err)
		}
		if !strings.Contains(tty.out.String(), "Joining hands the lab your Mac.") || !strings.Contains(tty.out.String(), terms.SHA256) {
			t.Errorf("the terms weren't shown with their sha256: %q", tty.out.String())
		}
	}
	if err := acceptTerms(terms, "https://lab", "", nil); err == nil || !strings.Contains(err.Error(), "--accept-terms "+terms.SHA256) {
		t.Errorf("no terminal: %v", err)
	}
	if err := acceptTerms(terms, "https://lab", strings.Repeat("0", 64), nil); err == nil {
		t.Error("acceptance of other terms was taken")
	}
	if err := acceptTerms(terms, "https://lab", strings.ToUpper(terms.SHA256), nil); err != nil {
		t.Errorf("acceptance of these terms: %v", err)
	}
}

// labd's terms are taken only when their text is the one their sha256 names.
func TestFetchTermsChecksTheirHash(t *testing.T) {
	var answer api.JoinTerms
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.RawQuery != "" {
			t.Errorf("a query: %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(answer)
	}))
	defer srv.Close()
	answer = *testTerms("terms")
	if got, err := FetchTerms(context.Background(), srv.URL+"/maclab", "enr_x", labhttp.Policy{}); err != nil || got.Text != "terms" {
		t.Fatalf("good terms: %v %v", got, err)
	}
	if auth != "Bearer enr_x" {
		t.Errorf("the token went as %q", auth)
	}
	answer.Text = "other terms"
	if _, err := FetchTerms(context.Background(), srv.URL, "enr_x", labhttp.Policy{}); err == nil {
		t.Error("terms not matching their sha256 were taken")
	}
	if _, err := FetchTerms(context.Background(), "http://10.1.1.55:7770", "enr_x", labhttp.Policy{}); !errors.Is(err, labhttp.ErrPlainHTTP) {
		t.Errorf("plain http to another machine: %v", err)
	}
}

// Setup run again after an interruption enrolls with the same activation key
// for the same token; another token gets its own; the key is private to root
// and goes once the Mac is set up.
func TestActivationKeyIsKeptForTheSameToken(t *testing.T) {
	dir := t.TempDir()
	k1, err := activationKey(dir, "enr_one")
	if err != nil || len(k1) < 32 {
		t.Fatal(k1, err)
	}
	if k2, _ := activationKey(dir, "enr_one"); k2 != k1 {
		t.Error("a second run for the same token made a new key")
	}
	if k3, _ := activationKey(dir, "enr_two"); k3 == k1 {
		t.Error("another token got the same key")
	}
	st, err := os.Stat(filepath.Join(dir, activationFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the key file: %v %v", st, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, activationFile))
	if strings.Contains(string(b), "enr_two") {
		t.Error("the token itself is in the key file")
	}
	activationDone(dir)
	if _, err := os.Stat(filepath.Join(dir, activationFile)); !os.IsNotExist(err) {
		t.Error("the key outlived setup")
	}
}

func TestReadTokenTakesTheFirstLine(t *testing.T) {
	if tok, err := ReadToken(strings.NewReader("enr_abc\nmore\n")); err != nil || tok != "enr_abc" {
		t.Errorf("%q %v", tok, err)
	}
	if tok, err := ReadToken(strings.NewReader("enr_abc")); err != nil || tok != "enr_abc" {
		t.Errorf("without a newline: %q %v", tok, err)
	}
	if _, err := ReadToken(strings.NewReader("\n")); err == nil {
		t.Error("an empty token was taken")
	}
}

// applyServer records the CA and the plain-http choice, nothing else.
func TestApplyServerRecordsOnlyTheTransportChoice(t *testing.T) {
	cfg := &Config{Server: "https://maclab.example.com", DeviceID: "d-1", Name: "m3pro", Secret: "dev_secret",
		Enrollment: api.AgentEnrollment{Enrollment: api.Enrollment{Kind: api.KindLabOwned}}}
	before := *cfg
	applyServer(cfg, []byte("PEM"), false)
	if cfg.Server != before.Server || cfg.ServerCA != "PEM" || cfg.AllowPlainHTTP == nil || *cfg.AllowPlainHTTP {
		t.Fatalf("after: %+v", cfg)
	}
	if cfg.DeviceID != before.DeviceID || cfg.Secret != before.Secret || cfg.Name != before.Name || cfg.Enrollment != before.Enrollment {
		t.Fatalf("the enrollment changed: %+v", cfg)
	}
}

// An agent.json from before https support (no allow_plain_http) keeps its
// plain http, with a warning; one that says no is held to it, refused before
// anything is sent.
func TestOldAgentConfigKeepsPlainHTTPWithAWarning(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "agent.json")
	os.WriteFile(old, []byte(`{"server":"http://10.1.1.55:7770","device_id":"d-1","name":"m3pro","secret":"dev_s","enrollment":{"kind":"lab"}}`), 0o600)
	cfg, err := LoadConfig(old)
	if err != nil {
		t.Fatal(err)
	}
	if p, legacy := cfg.transportPolicy(); !p.AllowPlainHTTP || !legacy {
		t.Fatalf("an old agent.json: %+v legacy=%v", p, legacy)
	}
	var logs bytes.Buffer
	New(cfg, NewSim(t.TempDir()), log.New(&logs, "", 0))
	if !strings.Contains(logs.String(), "WARNING") || !strings.Contains(logs.String(), "--allow-plain-http") {
		t.Errorf("no warning: %q", logs.String())
	}
	no := false
	cfg.AllowPlainHTTP = &no
	if p, legacy := cfg.transportPolicy(); p.AllowPlainHTTP || legacy {
		t.Fatalf("an explicit no: %+v %v", p, legacy)
	}
	if _, err := cfg.client(time.Second).Get("http://10.1.1.55:7770/api/agent/enrollment"); !errors.Is(err, labhttp.ErrPlainHTTP) {
		t.Errorf("plain http after an explicit no: %v", err)
	}
	// A loopback labd needs no opt-in, and https needs none either.
	for _, s := range []string{"http://127.0.0.1:7770", "https://chonkbase.net/maclab"} {
		c := &Config{Server: s}
		if _, legacy := c.transportPolicy(); legacy {
			t.Errorf("%s counted as a legacy plain-http config", s)
		}
	}
	// A CA that can't be read makes every request fail, never fall back.
	bad := &Config{Server: "https://chonkbase.net", ServerCA: "junk"}
	if _, err := bad.client(time.Second).Get("https://chonkbase.net/"); err == nil || !strings.Contains(err.Error(), "server_ca") {
		t.Errorf("a junk CA: %v", err)
	}
}

// Right after a reboot a Mac's clock can be decades behind, so labd's
// certificate looks not valid yet: check-ins fail with verification on,
// lab-agent says why and keeps trying.
func TestCheckinsBeforeTheClockIsSetFailClosedAndSayWhy(t *testing.T) {
	ca := testpki.NewCA(t)
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	srv.TLS = ca.LeafValid(time.Now().Add(time.Hour), time.Now().Add(48*time.Hour), "127.0.0.1").ServerTLS()
	srv.StartTLS()
	defer srv.Close()
	var logs safeBuf
	no := false
	a := New(&Config{Server: srv.URL, DeviceID: "d-1", Name: "m", Secret: "dev_s", WorkDir: t.TempDir(), ServerCA: string(ca.PEM), AllowPlainHTTP: &no},
		NewSim(t.TempDir()), log.New(&logs, "", 0))
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	a.Run(ctx)
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests got through", n)
	}
	if !strings.Contains(logs.String(), "isn't valid at this Mac's clock") {
		t.Errorf("no clock diagnostic: %q", logs.String())
	}
}

// safeBuf is a log sink lab-agent's goroutines may write at once.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A Tailscale join comes before labd can be reached, so with an enrollment
// token setup wants the terms accepted beforehand, and stops before changing
// anything without that.
func TestTailscaleJoinWaitsForAcceptedTerms(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("setup runs as root (this runs in a user namespace in the sandbox)")
	}
	var said []string
	err := Setup(context.Background(), SetupOptions{Server: "https://labd.example.com/maclab", Token: "enr_x", TailscaleAuthKey: "tskey-x",
		Log: func(f string, a ...any) { said = append(said, f) }})
	if err == nil || !strings.Contains(err.Error(), "--accept-terms") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("setup: %v", err)
	}
	if len(said) != 0 {
		t.Errorf("setup did something first: %q", said)
	}
}

// Setup forgets the activation key only once everything has succeeded: a
// setup that fails anywhere before that (writing units, starting lab-agent)
// leaves the key, so running the same one-liner again enrolls with it, which
// labd takes as the same activation until the Mac's first check-in. Checked
// in setup's source, since setup itself changes the Mac: the only call to
// activationDone is the last statement before Setup's final return.
func TestSetupKeepsTheActivationKeyUntilItSucceeds(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "setup.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body []ast.Stmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "Setup" {
			body = fn.Body.List
		}
	}
	if len(body) < 2 {
		t.Fatal("no Setup")
	}
	calls := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "activationDone" {
				calls++
			}
		}
		return true
	})
	isCall := func(s ast.Stmt) bool {
		e, ok := s.(*ast.ExprStmt)
		if !ok {
			return false
		}
		c, ok := e.X.(*ast.CallExpr)
		id, ok2 := c.Fun.(*ast.Ident)
		return ok && ok2 && id.Name == "activationDone"
	}
	ret, ok := body[len(body)-1].(*ast.ReturnStmt)
	if calls != 1 || !isCall(body[len(body)-2]) || !ok || len(ret.Results) != 1 || fmt.Sprint(ret.Results[0]) != "nil" {
		t.Errorf("activationDone is called %d time(s), and not only as the step before Setup's final return nil", calls)
	}
	// A run that failed before that point leaves the key; the next run of the
	// same one-liner finds it.
	dir := t.TempDir()
	k1, _ := activationKey(dir, "enr_x")
	if k2, _ := activationKey(dir, "enr_x"); k2 != k1 {
		t.Error("the key of a failed run was not kept")
	}
}

package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// startLabd starts a labd with cfg behind httptest and returns its URL and a
// stop function, so a test can stop it and start another on the same data.
func startLabd(t *testing.T, cfg Config) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := New(ctx, cfg, log.New(io.Discard, "", 0))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	hs := httptest.NewServer(s.Handler())
	stop := func() { cancel(); hs.Close() }
	t.Cleanup(stop)
	return hs.URL, stop
}

// maintainersAt lists the Maintainers of the labd at url as the holder of token.
func maintainersAt(t *testing.T, url, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/api/maintainers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

// listed is the names in a Maintainer list, comma-separated.
func listed(body string) string {
	var ms []api.Maintainer
	json.Unmarshal([]byte(body), &ms)
	return strings.Join(maintainerNames(ms), ",")
}

func TestUpgradeMakesTheAdminTokenTheFirstMaintainers(t *testing.T) {
	dir := t.TempDir()
	const old = "adm_0123456789abcdef0123456789abcdef01234567"
	tokPath := filepath.Join(dir, "admin.token")
	os.WriteFile(tokPath, []byte("  "+old+"\n"), 0o600)

	tok, created, err := FirstMaintainerToken(dir)
	if err != nil || created || tok != old {
		t.Fatalf("FirstMaintainerToken on an upgrade: %q created=%v %v", tok, created, err)
	}
	if b, _ := os.ReadFile(tokPath); strings.TrimSpace(string(b)) != old {
		t.Fatalf("the admin token file was rewritten: %q", b)
	}
	url, _ := startLabd(t, Config{DataDir: dir, FirstMaintainer: "naeem", FirstMaintainerToken: tok})
	code, body := maintainersAt(t, url, old)
	if code != 200 || listed(body) != "naeem" {
		t.Fatalf("the old admin token after the upgrade: %d %s", code, body)
	}
}

func TestFreshLabdCreatesTheFirstMaintainer(t *testing.T) {
	dir := t.TempDir()
	tok, created, err := FirstMaintainerToken(dir)
	if err != nil || !created || !reMaintainerToken.MatchString(tok) {
		t.Fatalf("FirstMaintainerToken on a fresh labd: %q created=%v %v", tok, created, err)
	}
	tokPath := filepath.Join(dir, "admin.token")
	fi, err := os.Stat(tokPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(tokPath); strings.TrimSpace(string(b)) != tok {
		t.Fatalf("token file holds %q, not %q", b, tok)
	}
	again, created, err := FirstMaintainerToken(dir)
	if err != nil || created || again != tok {
		t.Fatalf("FirstMaintainerToken the second time: %q created=%v %v", again, created, err)
	}

	url, _ := startLabd(t, Config{DataDir: dir, FirstMaintainer: "naeem", FirstMaintainerToken: tok})
	code, body := maintainersAt(t, url, tok)
	if code != 200 || listed(body) != "naeem" {
		t.Fatalf("the first Maintainer's token: %d %s", code, body)
	}
}

func TestFirstMaintainerSettingsAreIgnoredOnceThereIsOne(t *testing.T) {
	dir := t.TempDir()
	const tok = "mnt_1111111111111111111111111111111111111111"
	_, stop := startLabd(t, Config{DataDir: dir, FirstMaintainer: "naeem", FirstMaintainerToken: tok})
	stop()

	// a rewritten token file and a different --maintainer add nobody
	const other = "mnt_2222222222222222222222222222222222222222"
	url, stop := startLabd(t, Config{DataDir: dir, FirstMaintainer: "someone", FirstMaintainerToken: other})
	if code, body := maintainersAt(t, url, other); code != 401 {
		t.Fatalf("the rewritten token after a restart: %d %s", code, body)
	}
	code, body := maintainersAt(t, url, tok)
	if code != 200 || listed(body) != "naeem" {
		t.Fatalf("Maintainers after a restart with other settings: %d %s", code, body)
	}
	stop()

	// nor are they needed
	url, _ = startLabd(t, Config{DataDir: dir})
	if code, body := maintainersAt(t, url, tok); code != 200 {
		t.Fatalf("the first Maintainer's token, restarted without settings: %d %s", code, body)
	}
}

func TestLabdWithNoMaintainerNeedsAValidFirstOne(t *testing.T) {
	const tok = "mnt_1111111111111111111111111111111111111111"
	cases := []struct{ what, name, token string }{
		{"no name", "", tok},
		{"a name with a space", "naeem malik", tok},
		{"a name starting with a dash", "-naeem", tok},
		{"no token", "naeem", ""},
	}
	for _, c := range cases {
		ctx, cancel := context.WithCancel(context.Background())
		if _, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: c.name, FirstMaintainerToken: c.token}, log.New(io.Discard, "", 0)); err == nil {
			t.Errorf("%s: labd started with no Maintainer", c.what)
		}
		cancel()
	}
}

func TestEmptyAdminTokenFileIsAnErrorNamingIt(t *testing.T) {
	for _, content := range []string{"", " \n\t\n"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "admin.token"), []byte(content), 0o600)
		tok, _, err := FirstMaintainerToken(dir)
		if err == nil {
			ctx, cancel := context.WithCancel(context.Background())
			_, err = New(ctx, Config{DataDir: dir, FirstMaintainer: "naeem", FirstMaintainerToken: tok}, log.New(io.Discard, "", 0))
			cancel()
		}
		if err == nil || !strings.Contains(err.Error(), "admin.token") {
			t.Errorf("admin.token holding %q: %v", content, err)
		}
	}
}

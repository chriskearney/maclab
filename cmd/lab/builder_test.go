package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

const (
	testBuilderToken = "bldr_0123456789abcdef0123456789abcdef01234567"
	testGeneration   = "0123456789abcdef0123456789abcdef"
)

// fakeBuilderLabd answers lab builder add and remove, recording each request.
// replaced makes a removal by generation find a newer builder (409).
func fakeBuilderLabd(t *testing.T, addCode int, replaced ...bool) (*client.Client, *[]string) {
	var mu sync.Mutex
	var seen []string
	labd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, strings.TrimSuffix(r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery, "?"))
		mu.Unlock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/builders" && addCode == 200:
			var req api.BuilderRequest
			json.NewDecoder(r.Body).Decode(&req)
			json.NewEncoder(w).Encode(api.NewBuilder{Builder: api.Builder{Name: req.Name, Kinds: []string{"kernel"}}, Token: testBuilderToken, Generation: testGeneration})
		case r.Method == "POST" && r.URL.Path == "/api/builders":
			http.Error(w, "there is already a builder named m5mbp", addCode)
		case r.Method == "DELETE" && len(replaced) > 0 && replaced[0]:
			http.Error(w, "builder m5mbp is another generation now; nothing was removed", 409)
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/builders/"):
			json.NewEncoder(w).Encode(api.RemovedBuilder{Removed: strings.TrimPrefix(r.URL.Path, "/api/builders/"), FailedBuilds: []string{}})
		default:
			http.Error(w, "unexpected", 400)
		}
	}))
	t.Cleanup(labd.Close)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("MACLAB_URL", labd.URL)
	t.Setenv("MACLAB_TOKEN", "tok")
	c, err := client.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c, &seen
}

func TestBuilderAddWritesTheTokenOnlyToItsFile(t *testing.T) {
	c, seen := fakeBuilderLabd(t, 200)
	file := filepath.Join(t.TempDir(), "m5mbp.token")
	var out bytes.Buffer
	if err := addBuilder(context.Background(), c, "m5mbp", []string{"kernel"}, file, &out); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", st, err)
	}
	if raw, _ := os.ReadFile(file); string(raw) != testBuilderToken {
		t.Fatalf("file holds %q", raw)
	}
	if strings.Contains(out.String(), testBuilderToken) || !strings.Contains(out.String(), "--token-file") ||
		!strings.Contains(out.String(), "--generation "+testGeneration) {
		t.Fatalf("output: %s", out.String())
	}
	if strings.Join(*seen, "|") != "POST /api/builders" {
		t.Fatalf("requests %q", *seen)
	}
	// Never over an existing file, and then labd isn't asked at all.
	err = addBuilder(context.Background(), c, "other", nil, file, &out)
	if err == nil || len(*seen) != 1 {
		t.Fatalf("over an existing file: %v, requests %q", err, *seen)
	}
}

func TestBuilderAddWithoutAFilePrintsTheTokenOnce(t *testing.T) {
	c, _ := fakeBuilderLabd(t, 200)
	var out bytes.Buffer
	if err := addBuilder(context.Background(), c, "m5mbp", nil, "", &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), testBuilderToken) != 1 {
		t.Fatalf("output: %s", out.String())
	}
}

func TestBuilderAddRefusedLeavesNoFile(t *testing.T) {
	c, _ := fakeBuilderLabd(t, 409)
	file := filepath.Join(t.TempDir(), "m5mbp.token")
	if err := addBuilder(context.Background(), c, "m5mbp", nil, file, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("refused add: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("file left behind: %v", err)
	}
}

// When the token can't be written, the builder is removed again and no
// error shows the token.
func TestBuilderAddUndoneWhenTheFileFails(t *testing.T) {
	c, seen := fakeBuilderLabd(t, 200)
	old := writeToken
	writeToken = func(*os.File, string) error { return errors.New("no space left on device") }
	defer func() { writeToken = old }()
	file := filepath.Join(t.TempDir(), "m5mbp.token")
	var out bytes.Buffer
	err := addBuilder(context.Background(), c, "m5mbp", nil, file, &out)
	if err == nil || strings.Contains(err.Error(), testBuilderToken) || !strings.Contains(err.Error(), "was removed again") {
		t.Fatalf("error: %v", err)
	}
	if strings.Contains(out.String(), testBuilderToken) {
		t.Fatalf("output shows the token: %s", out.String())
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("file left behind: %v", err)
	}
	if strings.Join(*seen, "|") != "POST /api/builders|DELETE /api/builders/m5mbp?generation="+testGeneration {
		t.Fatalf("requests %q", *seen)
	}
}

// Undoing its own add never removes a builder added under the same name since.
func TestBuilderAddUndoLeavesAReplacementAlone(t *testing.T) {
	c, seen := fakeBuilderLabd(t, 200, true)
	old := writeToken
	writeToken = func(*os.File, string) error { return errors.New("no space left on device") }
	defer func() { writeToken = old }()
	err := addBuilder(context.Background(), c, "m5mbp", nil, filepath.Join(t.TempDir(), "t"), &bytes.Buffer{})
	if err == nil || strings.Contains(err.Error(), testBuilderToken) || !strings.Contains(err.Error(), "another generation") {
		t.Fatalf("error: %v", err)
	}
	if strings.Join(*seen, "|") != "POST /api/builders|DELETE /api/builders/m5mbp?generation="+testGeneration {
		t.Fatalf("requests %q", *seen)
	}
}

func TestBuilderRemoveByGeneration(t *testing.T) {
	c, seen := fakeBuilderLabd(t, 200)
	if err := dispatch(context.Background(), c, "builder", []string{"remove", "m5mbp", "--generation", testGeneration}); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(context.Background(), c, "builder", []string{"remove", "m5mbp"}); err != nil {
		t.Fatal(err)
	}
	if want := "DELETE /api/builders/m5mbp?generation=" + testGeneration + "|DELETE /api/builders/m5mbp"; strings.Join(*seen, "|") != want {
		t.Fatalf("requests %q", *seen)
	}
}

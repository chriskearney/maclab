package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/client"
)

// enrollTokenLab is a labd that only answers POST /api/enroll-tokens, and
// remembers what the Maintainer asked for.
func enrollTokenLab(t *testing.T) (*client.Client, *[]map[string]any) {
	t.Helper()
	var asked []map[string]any
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/enroll-tokens" {
			http.NotFound(w, r)
			return
		}
		var m map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &m)
		asked = append(asked, m)
		json.NewEncoder(w).Encode(map[string]any{"token": "enr_fixture_token", "expires": time.Now().Add(time.Hour)})
	}))
	t.Cleanup(hs.Close)
	t.Setenv("MACLAB_URL", hs.URL)
	t.Setenv("MACLAB_TOKEN", "tok")
	c, err := client.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c, &asked
}

// runLab runs `lab <cmd> <args>` and returns what it printed.
func runLab(t *testing.T, c *client.Client, cmd string, args ...string) (string, error) {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := dispatch(context.Background(), c, cmd, args)
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), err
}

func TestEnrollTokenForAVolunteerSendsTheirNameAndContact(t *testing.T) {
	c, asked := enrollTokenLab(t)
	out, err := runLab(t, c, "enroll", "ada-mbp", "--volunteer", "Ada Lovelace", "--contact", "ada@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 1 {
		t.Fatalf("labd was asked %d times", len(*asked))
	}
	got := (*asked)[0]
	if got["name"] != "ada-mbp" || got["volunteer_name"] != "Ada Lovelace" || got["contact"] != "ada@example.org" {
		t.Fatalf("request: %v", got)
	}
	if !strings.Contains(out, "enr_fixture_token") {
		t.Fatalf("the token is not printed:\n%s", out)
	}
}

func TestEnrollTokenWithoutVolunteerMakesALabOwnedMac(t *testing.T) {
	c, asked := enrollTokenLab(t)
	if _, err := runLab(t, c, "enroll", "rack-mac"); err != nil {
		t.Fatal(err)
	}
	got := (*asked)[0]
	if v, _ := got["volunteer_name"].(string); v != "" {
		t.Fatalf("a Volunteer was sent: %v", got)
	}
	if v, _ := got["contact"].(string); v != "" {
		t.Fatalf("a contact was sent: %v", got)
	}
}

func TestEnrollTokenForAVolunteerNeedsTheirContact(t *testing.T) {
	c, asked := enrollTokenLab(t)
	if _, err := runLab(t, c, "enroll", "ada-mbp", "--volunteer", "Ada Lovelace"); err == nil {
		t.Fatal("a Volunteer with no contact was accepted")
	}
	if len(*asked) != 0 {
		t.Fatal("labd was asked anyway")
	}
}

func TestEnrollTokenWithAContactAloneIsRefused(t *testing.T) {
	c, asked := enrollTokenLab(t)
	if _, err := runLab(t, c, "enroll", "rack-mac", "--contact", "ada@example.org"); err == nil {
		t.Fatal("a contact with no Volunteer was accepted")
	}
	if len(*asked) != 0 {
		t.Fatal("labd was asked anyway")
	}
}

func TestEnrollTokenForAVolunteerNeedsAMacName(t *testing.T) {
	c, _ := enrollTokenLab(t)
	if _, err := runLab(t, c, "enroll", "--volunteer", "Ada", "--contact", "a@b.c"); err == nil {
		t.Fatal("no Mac name was accepted")
	}
}

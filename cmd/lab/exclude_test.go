package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

// lab exclude sends the reason and who asks; --clear takes the mark off; and
// with no reason nothing is sent.
func TestExclude(t *testing.T) {
	var got []string
	labd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/jobs/j1/exclude" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unexpected request", 400)
			return
		}
		j := api.Job{ID: "j1", Spec: api.JobSpec{Device: "m1air"}, State: api.JobDone, Outcome: api.OutcomeCrashedOrHung}
		if r.Method == "POST" {
			var req api.ExcludeRequest
			json.NewDecoder(r.Body).Decode(&req)
			got = append(got, "POST "+req.Reason+" by "+req.By)
			j.GateExclusion = &api.GateExclusion{By: req.By, Reason: req.Reason, Time: time.Now()}
		} else {
			got = append(got, r.Method)
		}
		json.NewEncoder(w).Encode(j)
	}))
	defer labd.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("MACLAB_URL", labd.URL)
	t.Setenv("MACLAB_TOKEN", "tok")
	c, err := client.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := dispatch(ctx, c, "exclude", []string{"j1"}); err == nil || !strings.Contains(err.Error(), "--reason") {
		t.Fatalf("no reason: %v", err)
	}
	if err := dispatch(ctx, c, "exclude", []string{"j1", "--clear", "--reason", "x"}); err == nil {
		t.Fatal("--clear with a reason")
	}
	if err := dispatch(ctx, c, "exclude", []string{"j1", "--reason", "the AP went down"}); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(ctx, c, "exclude", []string{"j1", "--clear"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST the AP went down by " + holder(), "DELETE"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("sent %q, want %q", got, want)
	}
}

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/client"
)

// A second lab forget of the same Mac finds no such device, which means it
// is done: it exits 0, so scripts can run it again. --force goes to labd,
// and labd's refusals still fail.
func TestForgetTwice(t *testing.T) {
	devices := map[string]bool{"m1air": true, "leased": true}
	var queries []string
	labd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := strings.CutPrefix(r.URL.Path, "/api/devices/")
		if r.Method != "DELETE" || !ok || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unexpected request", 400)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		switch {
		case !devices[name]:
			http.Error(w, `no device "`+name+`"`, http.StatusNotFound)
		case name == "leased" && r.URL.Query().Get("force") != "1":
			http.Error(w, "leased is leased by alice until 2026-10-16 18:00:00: release the lease first", http.StatusConflict)
		default:
			delete(devices, name)
			w.Write([]byte(`{"forgot":"` + name + `"}`))
		}
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
	for i := range 2 {
		if err := dispatch(ctx, c, "forget", []string{"m1air"}); err != nil {
			t.Fatalf("forget %d: %v", i+1, err)
		}
	}
	if err := dispatch(ctx, c, "forget", []string{"leased"}); err == nil || !strings.Contains(err.Error(), "leased by alice") {
		t.Fatalf("forgetting a leased Mac: %v", err)
	}
	if err := dispatch(ctx, c, "forget", []string{"leased", "--force"}); err != nil {
		t.Fatalf("forget --force: %v", err)
	}
	h := "holder=" + url.QueryEscape(holder())
	if want := []string{h, h, h, "force=1&" + h}; strings.Join(queries, "|") != strings.Join(want, "|") {
		t.Fatalf("queries %q", queries)
	}
}

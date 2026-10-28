package client

import (
	"context"
	"encoding/json"
	"github.com/iconidentify/maclab/internal/api"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMesaNeverFallsBackToLegacyKernelPost(t *testing.T) {
	for _, which := range []string{"old", "bad-schema", "partial-rollout", "new"} {
		t.Run(which, func(t *testing.T) {
			legacy, mesa := 0, 0
			spec := api.JobSpec{Device: "mac", Mesa: &api.MesaSpec{Mode: api.MesaStaged, Packages: []api.MesaPackage{{Name: "mesa-aurora", SHA256: "pinned"}}}}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/mesa":
					if which == "old" {
						http.NotFound(w, r)
						return
					}
					schema := 1
					if which == "bad-schema" {
						schema = 0
					}
					json.NewEncoder(w).Encode(api.MesaCapabilities{Schema: schema, Staged: true})
				case "/api/jobs":
					legacy++
					json.NewEncoder(w).Encode(api.Job{ID: "wrong-kernel-job"})
				case "/api/mesa/jobs":
					mesa++
					if which == "partial-rollout" {
						http.NotFound(w, r)
						return
					}
					json.NewEncoder(w).Encode(api.Job{ID: "mesa-job", Spec: spec})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			c := &Client{URL: srv.URL, Token: "test", http: srv.Client()}
			j, e := c.Submit(context.Background(), spec)
			if legacy != 0 {
				t.Fatal("sent Mesa request to legacy kernel route")
			}
			if which == "new" {
				if e != nil || j.ID != "mesa-job" || mesa != 1 {
					t.Fatal(j, e)
				}
			} else if e == nil {
				t.Fatal("unsupported controller admitted Mesa")
			}
		})
	}
}

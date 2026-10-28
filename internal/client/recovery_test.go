package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/iconidentify/maclab/internal/api"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoveryCapabilityGatePrecedesEveryExplicitPost(t *testing.T) {
	for _, mode := range []string{api.RecoveryNetworkOnly, api.RecoverySerialAssisted} {
		for _, kind := range []string{"old-server", "old-schema", "no-isolation", "missing-mode", "valid", "mismatched-return"} {
			t.Run(mode+kind, func(t *testing.T) {
				posts := 0
				gets := 0
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "GET" && r.URL.Path == "/api/recovery" {
						gets++
						if kind == "old-server" {
							http.NotFound(w, r)
							return
						}
						caps := api.RecoveryCapabilities{Schema: 1, Modes: []string{mode}, PerJobOOBIsolation: true}
						if kind == "old-schema" {
							caps.Schema = 0
						}
						if kind == "no-isolation" {
							caps.PerJobOOBIsolation = false
						}
						if kind == "missing-mode" {
							caps.Modes = nil
						}
						json.NewEncoder(w).Encode(caps)
						return
					}
					if r.Method == "POST" && r.URL.Path == "/api/jobs" {
						posts++
						var spec api.JobSpec
						json.NewDecoder(r.Body).Decode(&spec)
						if spec.RecoveryMode != mode {
							t.Fatal("requested mode changed")
						}
						if kind == "mismatched-return" {
							spec.RecoveryMode = ""
						}
						json.NewEncoder(w).Encode(api.Job{ID: "exact-job", Spec: spec})
						return
					}
					t.Fatal(r.URL.Path)
				}))
				defer s.Close()
				c := &Client{URL: s.URL, Token: "CPU_ONLY", http: s.Client()}
				j, e := c.Submit(context.Background(), api.JobSpec{Device: "m1", RecoveryMode: mode})
				if kind == "valid" {
					if e != nil || j.Spec.RecoveryMode != mode || posts != 1 {
						t.Fatal(j, e, posts)
					}
				} else {
					if e == nil {
						t.Fatal("unsupported/mismatched mode admitted")
					}
					if kind == "mismatched-return" {
						if posts != 1 || !strings.Contains(e.Error(), "exact-job") {
							t.Fatal("ambiguous real job identity lost", e)
						}
					} else if posts != 0 {
						t.Fatal("old server queued unsafe job", posts)
					}
				}
				if gets != 1 {
					t.Fatal("capability request missing", gets)
				}
			})
		}
	}
}

func TestRecoveryTransactionCapabilityBeforeSelectionPost(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(fmt.Sprint(supported), func(t *testing.T) {
			posts := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					json.NewEncoder(w).Encode(api.RecoveryCapabilities{Schema: 1, Modes: []string{api.RecoveryNetworkOnly}, PerJobOOBIsolation: true, TransactionIsolation: supported})
					return
				}
				posts++
				var q api.RecoveryModeRequest
				json.NewDecoder(r.Body).Decode(&q)
				json.NewEncoder(w).Encode(api.RecoveryModeSelection{Schema: 1, Device: "m1", Mode: q.Mode, Holder: q.Holder, Transaction: q.Transaction, Quiescent: true})
			}))
			defer s.Close()
			c := &Client{URL: s.URL, http: s.Client()}
			_, e := c.SelectRecoveryMode(context.Background(), "m1", api.RecoveryModeRequest{Mode: api.RecoveryNetworkOnly, Holder: "own", Transaction: "fresh"})
			if supported {
				if e != nil || posts != 1 {
					t.Fatal(e, posts)
				}
			} else if e == nil || posts != 0 {
				t.Fatal("old server received selection", e, posts)
			}
		})
	}
}

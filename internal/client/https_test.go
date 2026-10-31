package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
	"github.com/iconidentify/maclab/internal/testpki"
)

func loadWith(t *testing.T, env map[string]string) (*Client, error) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	for _, k := range []string{"MACLAB_URL", "MACLAB_TOKEN", "MACLAB_CA_FILE", "MACLAB_ALLOW_PLAIN_HTTP"} {
		t.Setenv(k, env[k])
	}
	return Load()
}

// The lab CLI and MCP send their token to labd over https, or plain http on
// this machine; plain http elsewhere only when told so.
func TestLoadRefusesPlainHTTPToAnotherMachine(t *testing.T) {
	if _, err := loadWith(t, map[string]string{"MACLAB_URL": "http://10.1.1.55:7770", "MACLAB_TOKEN": "mnt_x"}); !errors.Is(err, labhttp.ErrPlainHTTP) {
		t.Errorf("plain http to the LAN: %v", err)
	}
	if _, err := loadWith(t, map[string]string{"MACLAB_URL": "http://10.1.1.55:7770", "MACLAB_TOKEN": "mnt_x", "MACLAB_ALLOW_PLAIN_HTTP": "1"}); err != nil {
		t.Errorf("plain http allowed on purpose: %v", err)
	}
	if _, err := loadWith(t, map[string]string{"MACLAB_URL": "http://127.0.0.1:7770", "MACLAB_TOKEN": "mnt_x"}); err != nil {
		t.Errorf("plain http on this machine: %v", err)
	}
	junk := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(junk, []byte("junk"), 0o600)
	if _, err := loadWith(t, map[string]string{"MACLAB_URL": "https://lab.example.com/maclab", "MACLAB_TOKEN": "mnt_x", "MACLAB_CA_FILE": junk}); err == nil {
		t.Error("a junk CA file was taken")
	}
}

// With a CA file, the CLI reaches an https labd under a prefix.
func TestClientReachesHTTPSLabdWithItsCA(t *testing.T) {
	ca := testpki.NewCA(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/maclab/api/devices" || r.Header.Get("Authorization") != "Bearer mnt_x" {
			http.Error(w, "no", 404)
			return
		}
		w.Write([]byte("[]"))
	}))
	srv.TLS = ca.Leaf("127.0.0.1").ServerTLS()
	srv.StartTLS()
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, ca.PEM, 0o600)
	c, err := loadWith(t, map[string]string{"MACLAB_URL": srv.URL + "/maclab/", "MACLAB_TOKEN": "mnt_x", "MACLAB_CA_FILE": caFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Devices(context.Background()); err != nil {
		t.Fatalf("devices: %v", err)
	}
	c2, _ := loadWith(t, map[string]string{"MACLAB_URL": srv.URL + "/maclab", "MACLAB_TOKEN": "mnt_x"})
	if _, err := c2.Devices(context.Background()); err == nil {
		t.Error("an untrusted certificate was accepted")
	}
}

// Wait asks in slices of at most 50 seconds, so a proxy that cuts a request
// silent for a minute never cuts one, and stops when the job is done.
func TestWaitAsksInSlicesAProxyWontCut(t *testing.T) {
	var calls atomic.Int32
	var longest atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("timeout"))
		if int64(n) > longest.Load() {
			longest.Store(int64(n))
		}
		j := api.Job{ID: "j1", State: api.JobTesting}
		if calls.Add(1) == 3 {
			j.State = api.JobDone
		}
		json.NewEncoder(w).Encode(j)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "t", http: srv.Client()}
	j, err := c.Wait(context.Background(), "j1", 30*time.Minute)
	if err != nil || j.State != api.JobDone {
		t.Fatalf("wait: %+v %v", j, err)
	}
	if calls.Load() != 3 || longest.Load() > 50 || longest.Load() < 1 {
		t.Errorf("%d calls, longest %d s", calls.Load(), longest.Load())
	}
}

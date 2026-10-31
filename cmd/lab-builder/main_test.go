package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func TestUploadKernelAndModuleInputs(t *testing.T) {
	for _, failInputs := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained", true: "upload refused"}[failInputs], func(t *testing.T) {
			payloads := map[string]string{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/api/builder/artifacts" || r.Header.Get("Authorization") != "Bearer fixture" {
					http.Error(w, "wrong upload request", 400)
					return
				}
				body, _ := io.ReadAll(r.Body)
				if failInputs && string(body) == "module inputs" {
					http.Error(w, "storage refused", 500)
					return
				}
				sum := sha256.Sum256(body)
				sha := hex.EncodeToString(sum[:])
				payloads[sha] = string(body)
				json.NewEncoder(w).Encode(map[string]string{"sha256": sha})
			}))
			defer srv.Close()
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "out"), 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{"kernel.tar.zst": "boot", "module-build.tar.zst": "module inputs"} {
				if err := os.WriteFile(filepath.Join(dir, "out", name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "kernel"), []byte("kernel.tar.zst\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			b := &builder{server: srv.URL, token: "fixture"}
			var result api.BuildResult
			b.uploadPackages(context.Background(), dir, &result, func(string) {})
			if failInputs {
				if result.Error == "" {
					t.Fatal("failed archive upload reported success")
				}
				return
			}
			if result.Error != "" || len(result.Files) != 2 || payloads[result.Artifact] != "boot" {
				t.Fatalf("result %+v", result)
			}
			for _, file := range result.Files {
				want := map[string]string{"kernel.tar.zst": "boot", "module-build.tar.zst": "module inputs"}[file.Name]
				if payloads[file.SHA256] != want || file.Size != int64(len(want)) {
					t.Fatalf("file %+v", file)
				}
			}
		})
	}
}

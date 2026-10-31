package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

func TestKernelModuleBuildOutputs(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		old, inputs, wrongKernel bool
		want                     api.BuildState
	}{
		{name: "future missing inputs", want: api.BuildFailed},
		{name: "future complete", inputs: true, want: api.BuildDone},
		{name: "future wrong boot binding", inputs: true, wrongKernel: true, want: api.BuildFailed},
		{name: "historic artifact unchanged", old: true, want: api.BuildDone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := New(ctx, Config{DataDir: t.TempDir(), FirstMaintainer: "ada", FirstMaintainerToken: "admin"}, log.New(io.Discard, "", 0))
			if err != nil {
				t.Fatal(err)
			}
			store := func(text string) string {
				sha, _, err := s.storeArtifact(strings.NewReader(text))
				if err != nil {
					t.Fatal(err)
				}
				return sha
			}
			boot, inputs := store("boot archive"), store("module build archive")
			src := api.Source{Repo: "https://example.invalid/kernel", SHA: strings.Repeat("a", 40)}
			b := &api.Build{ID: "future-build", Source: src, ConfigSHA: strings.Repeat("b", 64), State: api.BuildRunning, Created: time.Now()}
			b.Key = buildKey(src, b.ConfigSHA)
			if tc.old {
				b.Key = "historical-key"
			}
			s.saveBuild(b)
			result := api.BuildResult{Release: "future-release", Artifact: boot}
			if tc.inputs {
				result.Files = []api.BuildFile{{Name: "kernel.tar.zst", SHA256: boot}, {Name: "module-build.tar.zst", SHA256: inputs}}
				if tc.wrongKernel {
					result.Files[0].SHA256 = inputs
				}
			}
			raw, _ := json.Marshal(result)
			r := httptest.NewRequest("POST", "/done", bytes.NewReader(raw))
			r.SetPathValue("id", b.ID)
			s.hBuilderDone(httptest.NewRecorder(), r)
			got, err := s.getBuild(b.ID)
			if err != nil || got.State != tc.want {
				t.Fatalf("state=%v err=%v want=%s", got, err, tc.want)
			}
			if got.State == api.BuildDone && tc.inputs {
				request := httptest.NewRequest("GET", "/file", nil)
				request.SetPathValue("id", b.ID)
				request.SetPathValue("name", "module-build.tar.zst")
				response := httptest.NewRecorder()
				s.hBuildFile(response, request)
				if response.Code != 200 || response.Body.String() != "module build archive" {
					t.Fatalf("named artifact: %d %q", response.Code, response.Body.String())
				}
			}
		})
	}
}

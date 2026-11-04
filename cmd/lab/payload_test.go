package main

import (
	"context"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func TestPayloadFlagTakesANameAndAnUploadedSha(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	got, err := payloadFiles(context.Background(), nil, []string{"mod.ko=" + sha})
	if err != nil || len(got) != 1 || got[0] != (api.PayloadFile{Name: "mod.ko", SHA256: sha}) {
		t.Fatalf("payloadFiles = %+v, %v", got, err)
	}
	for _, bad := range []string{"mod.ko", "=" + sha, "mod.ko="} {
		if _, err := payloadFiles(context.Background(), nil, []string{bad}); err == nil || !strings.Contains(err.Error(), "NAME=FILE") {
			t.Errorf("--payload %q: err = %v, want a NAME=FILE usage error", bad, err)
		}
	}
}

func TestScriptTestsTakeThePayloadButGUIScriptsDoNot(t *testing.T) {
	files := []api.PayloadFile{{Name: "mod.ko", SHA256: strings.Repeat("ab", 32)}}
	if _, err := withPayload(nil, files); err == nil || !strings.Contains(err.Error(), "--script") {
		t.Fatalf("a payload with no --script test: err = %v", err)
	}
	tests := []api.TestSpec{{Name: "a", Script: "s"}, {Name: "b", Script: "s", GUI: true}}
	got, err := withPayload(tests, files)
	if err != nil || len(got[0].Payload) != 1 || len(got[1].Payload) != 0 {
		t.Fatalf("withPayload = %+v, %v: want the payload on the root script only", got, err)
	}
}

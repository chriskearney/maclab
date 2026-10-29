package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// payloadFetch serves artifacts by sha256 from a map and counts the calls.
func payloadFetch(files map[string]string, calls *[]string) Fetcher {
	return func(ctx context.Context, sha, dst string) error {
		*calls = append(*calls, sha)
		return os.WriteFile(dst, []byte(files[sha]), 0o644)
	}
}

func payloadSpec(files ...api.PayloadFile) api.TestSpec {
	return api.TestSpec{Name: "p", Script: strings.Repeat("a", 64), Payload: files}
}

func TestAScriptFindsItsPayloadFilesInMACLAB_IN(t *testing.T) {
	mod, fw := strings.Repeat("b", 64), strings.Repeat("c", 64)
	files := map[string]string{
		strings.Repeat("a", 64): "#!/bin/bash\nset -e\ntest -x \"$MACLAB_IN/mod.ko\"\ncat \"$MACLAB_IN/mod.ko\" \"$MACLAB_IN/fw.bin\" > \"$MACLAB_OUT/got\"\nls \"$MACLAB_IN\" > \"$MACLAB_OUT/names\"\n",
		mod:                     "module bytes;",
		fw:                      "firmware bytes",
	}
	var calls []string
	out := t.TempDir()
	l := &Linux{WorkDir: t.TempDir()}
	res := l.RunTest(context.Background(), "j1", payloadSpec(api.PayloadFile{Name: "mod.ko", SHA256: mod}, api.PayloadFile{Name: "fw.bin", SHA256: fw}), payloadFetch(files, &calls), nil, out)
	if !res.Passed {
		t.Fatalf("the script did not pass: %+v", res)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "got")); string(got) != "module bytes;firmware bytes" {
		t.Fatalf("the script read %q from $MACLAB_IN", got)
	}
	if names, _ := os.ReadFile(filepath.Join(out, "names")); string(names) != "fw.bin\nmod.ko\n" {
		t.Fatalf("$MACLAB_IN holds %q, want only the payload files", names)
	}
	if len(calls) != 3 || calls[0] != strings.Repeat("a", 64) {
		t.Fatalf("fetches %v: want the script first, then each payload file", calls)
	}
}

func TestAPayloadThatCannotBeFetchedFailsTheTestWithoutRunningIt(t *testing.T) {
	script := strings.Repeat("a", 64)
	files := map[string]string{script: "#!/bin/bash\ntouch \"$MACLAB_OUT/ran\"\n"}
	l := &Linux{WorkDir: t.TempDir()}
	out := t.TempDir()
	fetch := func(ctx context.Context, sha, dst string) error {
		if sha != script {
			return os.ErrNotExist
		}
		return os.WriteFile(dst, []byte(files[sha]), 0o644)
	}
	res := l.RunTest(context.Background(), "j1", payloadSpec(api.PayloadFile{Name: "mod.ko", SHA256: strings.Repeat("b", 64)}), fetch, nil, out)
	if res.Passed || res.Error == "" {
		t.Fatalf("a test with a missing payload file did not fail: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(out, "ran")); err == nil {
		t.Fatal("the script ran although a payload file was missing")
	}
}

func TestLabAgentRefusesAPayloadNameThatLeavesTheDirectoryWhateverLabdSends(t *testing.T) {
	script := strings.Repeat("a", 64)
	files := map[string]string{script: "#!/bin/bash\ntrue\n"}
	for _, name := range []string{"../escape", "a/b", ".hidden", ""} {
		var calls []string
		l := &Linux{WorkDir: t.TempDir()}
		res := l.RunTest(context.Background(), "j1", payloadSpec(api.PayloadFile{Name: name, SHA256: strings.Repeat("b", 64)}), payloadFetch(files, &calls), nil, t.TempDir())
		if res.Passed || res.Error == "" {
			t.Errorf("payload name %q was accepted: %+v", name, res)
		}
		if len(calls) != 0 {
			t.Errorf("payload name %q: lab-agent fetched %v before refusing it", name, calls)
		}
	}
}

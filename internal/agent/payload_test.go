package agent

import (
	"context"
	"encoding/json"
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
		strings.Repeat("a", 64): "#!/bin/bash\nset -e\ntest -x \"$MACLAB_IN/mod.ko\"\ncat \"$MACLAB_IN/mod.ko\" \"$MACLAB_IN/fw.bin\" > \"$MACLAB_OUT/got\"\nls \"$MACLAB_IN\" > \"$MACLAB_OUT/names\"\nstat -c %a \"$MACLAB_IN\" > \"$MACLAB_OUT/mode\"\n",
		mod:                     "module bytes;",
		fw:                      "firmware bytes",
	}
	var calls []string
	out := t.TempDir()
	l := &Linux{WorkDir: t.TempDir()}
	stale := filepath.Join(l.jobDir("j1"), "in-p")
	if err := os.MkdirAll(stale, 0o755); err != nil || os.WriteFile(filepath.Join(stale, "left-by-a-retry"), nil, 0o644) != nil {
		t.Fatal(err)
	}
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
	if mode, _ := os.ReadFile(filepath.Join(out, "mode")); string(mode) != "700\n" {
		t.Fatalf("$MACLAB_IN has mode %q, want only root to read it (700)", mode)
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

func TestLabAgentRefusesATestNameThatLeavesTheJobDirectoryWhenItHasPayloadFiles(t *testing.T) {
	var calls []string
	l := &Linux{WorkDir: t.TempDir()}
	spec := payloadSpec(api.PayloadFile{Name: "mod.ko", SHA256: strings.Repeat("b", 64)})
	spec.Name = "../../x"
	res := l.RunTest(context.Background(), "j1", spec, payloadFetch(map[string]string{}, &calls), nil, t.TempDir())
	if res.Passed || res.Error == "" || len(calls) != 0 {
		t.Fatalf("test name %q was accepted: %+v, fetches %v", spec.Name, res, calls)
	}
}

func TestTheBudgetStartsAfterTheLastDownloadOrTheFirstFailure(t *testing.T) {
	ok := func(context.Context, string, string) error { return nil }
	var started []int
	n := 0
	f := budgetFetch(ok, 3, func() { started = append(started, n) })
	for n = 1; n <= 3; n++ {
		f(context.Background(), "", "")
	}
	if len(started) != 1 || started[0] != 3 {
		t.Fatalf("the budget started after downloads %v, want only after the 3rd", started)
	}
	started, n = nil, 0
	f = budgetFetch(func(context.Context, string, string) error { return os.ErrNotExist }, 3, func() { started = append(started, n) })
	n = 1
	if err := f(context.Background(), "", ""); err == nil || len(started) != 1 {
		t.Fatalf("a failed download: err %v, budget started %v, want it started at once and the error passed on", err, started)
	}
}

func TestTheAuditLogNamesEachPayloadFileWithItsHash(t *testing.T) {
	spec := payloadSpec(api.PayloadFile{Name: "mod.ko", SHA256: strings.Repeat("b", 64)})
	args, _ := json.Marshal(spec)
	got := describe(api.Command{Kind: api.CmdRunTest, Args: args})
	if !strings.Contains(got, "mod.ko "+strings.Repeat("b", 12)) {
		t.Fatalf("the Audit log says %q; want the payload file and its short hash", got)
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

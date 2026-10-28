package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// Opt-in hardware regression for a compiled test binary on the Mac. It runs
// the ordinary GUI test implementation without staging a kernel or rebooting.
// No report is uploaded: the builtin invokes omarchy-m-test with --dry-run.
func TestGUILiveOMT(t *testing.T) {
	u, out := os.Getenv("MACLAB_LIVE_GUI_USER"), os.Getenv("MACLAB_LIVE_OUTPUT")
	if u == "" || out == "" {
		t.Skip("set MACLAB_LIVE_GUI_USER and MACLAB_LIVE_OUTPUT on the test Mac")
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(out) {
		t.Fatal("requires root and an absolute, new output directory")
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	l := &Linux{WorkDir: t.TempDir(), GUIUser: u}
	result := l.RunTest(context.Background(), "live-gui", api.TestSpec{
		Name: "omarchy-m-test", Builtin: "omarchy-m-test", GUI: true, TimeoutSec: 300,
	}, nil, nil, out)
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(out, "runner-result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Fatalf("runner failed: exit=%d error=%s", result.ExitCode, result.Error)
	}
	if _, err := os.Stat(filepath.Join(out, "omt-report.json")); err != nil {
		t.Fatal(err)
	}
}

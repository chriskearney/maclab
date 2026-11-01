package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// The dashboard in a real browser, under a prefix: headless Chromium driven
// by testdata/browser_smoke.mjs (Node, no packages) unlocks it with the
// Maintainer token, finds the lab's Mac, sees a change arrive without a
// reload, makes an invite, and checks no request left /maclab. It runs only
// when MACLAB_BROWSER (a Chromium) and MACLAB_NODE (a Node 22 or later) are
// set: not in CI.
func TestBrowserDashboardUnderPrefix(t *testing.T) {
	chrome, node := os.Getenv("MACLAB_BROWSER"), os.Getenv("MACLAB_NODE")
	if chrome == "" || node == "" {
		t.Skip("set MACLAB_BROWSER and MACLAB_NODE to run the browser smoke test")
	}
	agentBin := filepath.Join(t.TempDir(), "lab-agent-linux-arm64")
	os.WriteFile(agentBin, []byte("lab-agent for the browser test"), 0o755)
	l := newLabWith(t, labConfig{prefix: "/maclab", config: func(c *Config) { c.AgentBinary = agentBin }})
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	script, _ := filepath.Abs("testdata/browser_smoke.mjs")
	out, err := exec.CommandContext(ctx, node, script, chrome, l.url, harnessToken, l.name).CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("browser smoke: %v", err)
	}
}

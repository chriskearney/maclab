package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// A hangup ends signalContext's context rather than the process, so setup
// cleans up after a dropped SSH session. The signals go to a copy of this
// test binary: one left uncaught kills only that copy.
func TestSignalsEndTheContext(t *testing.T) {
	if sig := os.Getenv("LAB_AGENT_TEST_SIGNAL"); sig != "" {
		ctx, stop := signalContext()
		defer stop()
		n := map[string]syscall.Signal{"HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "TERM": syscall.SIGTERM}[sig]
		syscall.Kill(os.Getpid(), n)
		select {
		case <-ctx.Done():
			os.Exit(0)
		case <-time.After(10 * time.Second):
			os.Exit(3)
		}
	}
	for _, sig := range []string{"HUP", "INT", "TERM"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSignalsEndTheContext$")
		cmd.Env = append(os.Environ(), "LAB_AGENT_TEST_SIGNAL="+sig)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("SIG%s: %v\n%s", sig, err, out)
		}
	}
}

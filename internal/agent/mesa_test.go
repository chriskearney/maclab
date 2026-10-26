package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The runtime's adversarial tests use temporary files, simulated unit metadata
// and CPU-only subprocesses. They do not initialize a GPU or systemd service.
func TestMesaRuntimeHostControls(t *testing.T) {
	if _, e := exec.LookPath("python3"); e != nil {
		t.Skip("python3 unavailable")
	}
	cmd := exec.Command("python3", "-B", "-m", "unittest", "discover", "-s", filepath.Clean("."), "-p", "test_mesa_runtime.py")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("Mesa runtime host controls: %v\n%s", e, out)
	}
}

func TestMesaCleanupPreservesNestedOrUnreadableCgroup(t *testing.T) {
	root := t.TempDir()
	group := filepath.Join(root, "maclab-mesa-j-test-gl.service")
	child := filepath.Join(group, "child")
	if e := os.MkdirAll(child, 0700); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{group, child} {
		if e := os.WriteFile(filepath.Join(p, "cgroup.procs"), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := mesaGroupsEmpty(root, "j-test"); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(child, "cgroup.procs"), []byte("123\n"), 0600)
	if e := mesaGroupsEmpty(root, "j-test"); e == nil {
		t.Fatal("live nested member accepted")
	}
	os.Remove(filepath.Join(child, "cgroup.procs"))
	if e := mesaGroupsEmpty(root, "j-test"); e == nil {
		t.Fatal("missing nested membership accepted")
	}
}

func TestMesaCleanupReserveFitsInsideTestWatchdogBudget(t *testing.T) {
	for _, total := range []time.Duration{120 * time.Second, 2100 * time.Second} {
		run, cleanup, err := mesaProcessBudget(total)
		if err != nil || cleanup < 60*time.Second || cleanup <= 39*time.Second || run+cleanup != total {
			t.Fatalf("total=%s run=%s cleanup=%s err=%v", total, run, cleanup, err)
		}
	}
	if _, _, err := mesaProcessBudget(60 * time.Second); err == nil {
		t.Fatal("no cleanup reserve accepted")
	}
}

func TestMesaSessionEnvironmentIsExplicitAdapterContract(t *testing.T) {
	env := mesaSessionEnv([]string{"HOME=/normal/home", "USER=owner", "XDG_SESSION_ID=7", "LD_PRELOAD=bad", "XDG_RUNTIME_DIR=/run/user/1001", "WAYLAND_DISPLAY=wayland-1", "HYPRLAND_INSTANCE_SIGNATURE=actual"})
	if len(env) != 3 || env["XDG_RUNTIME_DIR"] != "/run/user/1001" || env["HYPRLAND_INSTANCE_SIGNATURE"] != "actual" {
		t.Fatal(env)
	}
	for _, k := range []string{"HOME", "USER", "XDG_SESSION_ID", "LD_PRELOAD"} {
		if _, exists := env[k]; exists {
			t.Fatal("leaked", k)
		}
	}
}

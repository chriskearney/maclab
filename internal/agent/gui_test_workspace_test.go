package agent

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func guiWorkspaceForTest(t *testing.T) *guiTestWorkspace {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "test.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := newGUITestWorkspace(script, u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	return w
}

func TestGUIWorkspaceCopiesOnlyItsRegularOutputs(t *testing.T) {
	w := guiWorkspaceForTest(t)
	if err := os.Mkdir(filepath.Join(w.outputPath(), "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.outputPath(), "nested", "report.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := w.collect(dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "nested", "report.json"))
	if err != nil || string(b) != "{}\n" {
		t.Fatalf("output %q: %v", b, err)
	}
	info, err := os.Stat(filepath.Join(dst, "nested", "report.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private output permissions: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "test.sh")); !os.IsNotExist(err) {
		t.Fatal("script was copied as an output")
	}
}

func TestGUIWorkspaceRejectsSymlinksAndFIFOs(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			w := guiWorkspaceForTest(t)
			secret := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(secret, []byte("private-agent-state"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(w.outputPath(), "report")
			var err error
			if kind == "symlink" {
				err = os.Symlink(secret, path)
			} else {
				err = unix.Mkfifo(path, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			dst := t.TempDir()
			done := make(chan error, 1)
			go func() { done <- w.collect(dst) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("unsafe output accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("collection blocked on special file")
			}
			if _, err := os.Stat(filepath.Join(dst, "report")); !os.IsNotExist(err) {
				t.Fatal("unsafe output was copied")
			}
		})
	}
}

func TestGUIWorkspacePinsOutputBeforeUserCanReplacePath(t *testing.T) {
	w := guiWorkspaceForTest(t)
	if err := os.WriteFile(filepath.Join(w.outputPath(), "result"), []byte("intended-output"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("root-private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(w.outputPath(), filepath.Join(w.dir, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, w.outputPath()); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := w.collect(dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "result"))
	if err != nil || string(b) != "intended-output" {
		t.Fatalf("lost pinned directory: %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "secret")); !os.IsNotExist(err) {
		t.Fatal("replacement directory exposed private files")
	}
}

func TestGUIWorkspaceCannotOverwriteRunnerLog(t *testing.T) {
	w := guiWorkspaceForTest(t)
	if err := os.WriteFile(filepath.Join(w.outputPath(), "log.txt"), []byte("forged"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, "log.txt"), []byte("real-runner-log"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.collect(dst); err == nil {
		t.Fatal("runner log overwritten")
	}
	b, err := os.ReadFile(filepath.Join(dst, "log.txt"))
	if err != nil || string(b) != "real-runner-log" {
		t.Fatalf("runner log changed: %q, %v", b, err)
	}
}

func TestGUIWorkspaceRejectsInvalidUID(t *testing.T) {
	if _, err := newGUITestWorkspace("not-read", &user.User{Uid: "-1", Gid: "0"}); err == nil {
		t.Fatal("negative UID accepted")
	}
}

// Run this regression as root as well: the original script must remain
// inaccessible to the GUI user, while only its staged copy becomes readable.
func TestGUIWorkspacePrivateAgentDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to exercise a distinct unprivileged GUI uid")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no nobody account")
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(private, "agent-secret")
	if err := os.WriteFile(secret, []byte("must-not-be-readable"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(private, "test.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nset -eu\ntest ! -r \"$PRIVATE_STATE\"\nprintf okay > \"$MACLAB_OUT/report.txt\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := exec.Command("runuser", "-u", u.Username, "--", "bash", script)
	old.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	if b, err := old.CombinedOutput(); err == nil || !strings.Contains(string(b), "Permission denied") {
		t.Fatalf("old-path failure did not reproduce: %s %v", b, err)
	}
	w, err := newGUITestWorkspace(script, u)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	c := exec.Command("runuser", "-u", u.Username, "--", "bash", w.scriptPath())
	c.Env = []string{"PATH=/usr/bin:/bin", "MACLAB_OUT=" + w.outputPath(), "PRIVATE_STATE=" + secret}
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("staged test: %s %v", b, err)
	}
	dst := t.TempDir()
	if err := w.collect(dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "report.txt"))
	if err != nil || string(b) != "okay" {
		t.Fatalf("GUI output: %q %v", b, err)
	}
	info, err := os.Stat(private)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("agent directory permissions changed")
	}
}

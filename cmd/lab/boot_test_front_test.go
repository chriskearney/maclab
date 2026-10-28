package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootTestDispatchProcess(t *testing.T) {
	if os.Getenv("MACLAB_BOOT_TEST_ENTRY_CONTROL") == "1" {
		args := []string{"--help"}
		if os.Getenv("MACLAB_BOOT_TEST_PROFILE_CONTROL") == "1" {
			args = []string{"profile-bundle", "--help"}
		}
		if err := bootTest(args); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(71)
		}
		os.Exit(72)
	}
	root := t.TempDir()
	binary := filepath.Join(root, "bin", "lab")
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(binary, raw, 0700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "share", "maclab", "boot-test")
	if err = os.MkdirAll(dest, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"intake.py", "catalog.py", "metadata.py", "runtime.py", "util.py", "frozen-controller-ea3.py", "profile_bundle.py"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "boot-test", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dest, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func() ([]byte, error) {
		c := exec.Command(binary, "-test.run=^TestBootTestDispatchProcess$")
		c.Env = append(os.Environ(), "MACLAB_BOOT_TEST_ENTRY_CONTROL=1")
		return c.CombinedOutput()
	}
	output, err := run()
	if err != nil {
		t.Fatalf("relocated real entry: %v %s", err, output)
	}
	if !strings.Contains(string(output), "--catalog-descriptor") || !strings.Contains(string(output), "--execute") {
		t.Fatalf("wrong help: %s", output)
	}
	c := exec.Command(binary, "-test.run=^TestBootTestDispatchProcess$")
	c.Env = append(os.Environ(), "MACLAB_BOOT_TEST_ENTRY_CONTROL=1", "MACLAB_BOOT_TEST_PROFILE_CONTROL=1")
	output, err = c.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "{pack,install}") {
		t.Fatalf("relocated profile installer entry: %v %s", err, output)
	}
	entry := filepath.Join(dest, "intake.py")
	if err = os.Chmod(entry, 0666); err != nil {
		t.Fatal(err)
	}
	output, err = run()
	if err == nil || !strings.Contains(string(output), "non-writable resource") {
		t.Fatalf("writable entry accepted: %v %s", err, output)
	}
	if err = os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(dest, "catalog.py"), entry); err != nil {
		t.Fatal(err)
	}
	output, err = run()
	if err == nil || !strings.Contains(string(output), "regular") {
		t.Fatalf("symlink entry accepted: %v %s", err, output)
	}
}

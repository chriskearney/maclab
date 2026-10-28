package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// bootTest loads only the installed, relocatable resource bundle. Reviewed
// catalogs, artifacts, authorizations and durable state remain explicit inputs.
func bootTest(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	entry := filepath.Join(filepath.Dir(exe), "..", "share", "maclab", "boot-test", "intake.py")
	st, err := os.Lstat(entry)
	if err != nil {
		return fmt.Errorf("boot-test resource bundle missing: %w", err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("boot-test entry must be a regular, non-writable resource")
	}
	return syscall.Exec("/usr/bin/python3", append([]string{"/usr/bin/python3", "-E", "-B", entry}, args...), os.Environ())
}

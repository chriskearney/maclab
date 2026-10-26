package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// Installing a Release is a named lab operation, not a Maintainer's root
// command: lab-agent installs exactly the Release's packages, fetched from
// labd by sha256, the way the Omarchy installer does (pacman, whose hooks
// write the Release's boot files and its installer entry). A Volunteer's Mac
// takes it at Qualification, inside its Availability window, and its Audit
// log records it with the Maintainer and the Release before it runs.

// installTimeout bounds pacman, inside labd's own wait for the install.
const installTimeout = api.InstallTimeout - time.Minute

// describeInstall is how the Audit log names an install.
func describeInstall(a api.InstallArgs) string {
	var pkgs []string
	for _, p := range a.Packages {
		pkgs = append(pkgs, p.File)
	}
	return fmt.Sprintf("install Release %s (kernel %s: %s)", a.Release, a.Kernel, strings.Join(pkgs, ", "))
}

// checkInstall refuses an install that names no Release, or a package that
// is not a plain package file name.
func checkInstall(a api.InstallArgs) error {
	if a.Release == "" || a.Kernel == "" || len(a.Packages) == 0 {
		return errors.New("an install names a Release, its kernel and its packages")
	}
	for _, p := range a.Packages {
		if p.File == "" || strings.ContainsAny(p.File, "/\x00") || strings.HasPrefix(p.File, ".") || !strings.Contains(p.File, ".pkg.tar") {
			return fmt.Errorf("package file %q is not a package's file name", p.File)
		}
		if len(p.SHA256) != 64 {
			return fmt.Errorf("package %s has no sha256", p.File)
		}
	}
	return nil
}

func (l *Linux) Install(ctx context.Context, job string, a api.InstallArgs, fetch Fetcher) error {
	defer syncDisks()
	if strings.ContainsAny(job, "/. ") || job == "" {
		return fmt.Errorf("bad job id %q", job)
	}
	dir := filepath.Join(l.jobDir(job), "install")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	var files []string
	for _, p := range a.Packages {
		dst := filepath.Join(dir, p.File)
		if err := fetch(ctx, p.SHA256, dst); err != nil {
			return fmt.Errorf("fetching %s: %w", p.File, err)
		}
		files = append(files, dst)
	}
	// Once pacman starts, it runs to its end (or its timeout): stopped
	// mid-transaction it would leave the system half-installed.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), installTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pacman", append([]string{"-U", "--noconfirm"}, files...)...)
	var out capped
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pacman -U %s: %v: %s", strings.Join(files, " "), err, lastLines(out.String(), 10))
	}
	return nil
}

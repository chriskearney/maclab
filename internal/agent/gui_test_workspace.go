package agent

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// A GUI test cannot traverse the agent's private state directory. Give it only
// its script and an isolated output directory; keep the agent logs private.
type guiTestWorkspace struct {
	dir    string
	output *os.Root
}

func newGUITestWorkspace(script string, u *user.User) (_ *guiTestWorkspace, err error) {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid < 0 {
		return nil, fmt.Errorf("invalid GUI uid %q", u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil || gid < 0 {
		return nil, fmt.Errorf("invalid GUI gid %q", u.Gid)
	}
	b, err := os.ReadFile(script)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("/tmp", "maclab-gui-*")
	if err != nil {
		return nil, err
	}
	w := &guiTestWorkspace{dir: dir}
	defer func() {
		if err != nil {
			w.close()
		}
	}()
	if err = os.WriteFile(w.scriptPath(), b, 0o644); err != nil {
		return nil, err
	}
	if err = os.Mkdir(w.outputPath(), 0o700); err != nil {
		return nil, err
	}
	// Pin this exact directory before the GUI user can rename it. Opening the
	// path after the test would let a replacement symlink expose root-only files.
	w.output, err = os.OpenRoot(w.outputPath())
	if err != nil {
		return nil, err
	}
	if err = os.Chown(w.outputPath(), uid, gid); err != nil {
		return nil, err
	}
	if err = os.Chown(dir, uid, gid); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *guiTestWorkspace) scriptPath() string { return filepath.Join(w.dir, "test.sh") }
func (w *guiTestWorkspace) outputPath() string { return filepath.Join(w.dir, "out") }

func (w *guiTestWorkspace) close() {
	if w.output != nil {
		w.output.Close()
	}
	os.RemoveAll(w.dir)
}

func (w *guiTestWorkspace) collect(destination string) error {
	dst, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer dst.Close()
	return fs.WalkDir(w.output.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if entry.IsDir() {
			return dst.MkdirAll(name, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported GUI output %q (%s)", name, entry.Type())
		}
		return copyGUIFile(w.output, dst, name)
	})
}

func copyGUIFile(src, dst *os.Root, name string) error {
	// Do not follow a file swapped for a symlink after WalkDir, or block on a
	// file replaced by a FIFO. os.Root also confines any replaced parent paths.
	in, err := src.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("GUI output %q is no longer a regular file", name)
	}
	// Never overwrite the runner's log, nor follow an existing destination.
	out, err := dst.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.CopyN(out, in, info.Size()); err != nil {
		return err
	}
	return out.Sync()
}

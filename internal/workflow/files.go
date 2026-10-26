package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Open O_PATH first: opening a device/FIFO before fstat is itself unsafe. Reopen
// only the held regular inode, then require full final-path identity throughout.
func openRegular(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	held := os.NewFile(uintptr(fd), path)
	defer held.Close()
	st, err := held.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("not a regular final inode: %s", path)
	}
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, nil, err
	}
	actual, err := f.Stat()
	if err != nil || !same(st, actual) {
		f.Close()
		return nil, nil, errors.New("held regular inode identity drift")
	}
	return f, st, nil
}
func same(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok && ok2 && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func finalSame(path string, initial os.FileInfo) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !same(initial, st) {
		return fmt.Errorf("final path identity drift: %s", path)
	}
	return nil
}
func readRegular(path string, max int64) ([]byte, error) {
	f, st, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size() > max {
		return nil, errors.New("regular file exceeds bound")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("file grew beyond bound")
	}
	if err = finalSame(path, st); err != nil {
		return nil, err
	}
	return b, nil
}
func copyPinned(ctx context.Context, p Pin, w io.Writer) error {
	if err := validPin(p); err != nil {
		return err
	}
	f, st, err := openRegular(p.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	if st.Size() != p.Bytes {
		return fmt.Errorf("file size mismatch: %s", p.Path)
	}
	h := sha256.New()
	buf := make([]byte, 128<<10)
	var n int64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		nr, er := f.Read(buf)
		if nr > 0 {
			n += int64(nr)
			if n > p.Bytes {
				return errors.New("file exceeded pinned size")
			}
			h.Write(buf[:nr])
			if w != nil {
				if _, err = w.Write(buf[:nr]); err != nil {
					return err
				}
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			return er
		}
	}
	if n != p.Bytes || hex.EncodeToString(h.Sum(nil)) != p.SHA256 {
		return fmt.Errorf("file checksum mismatch: %s", p.Path)
	}
	end, err := f.Stat()
	if err != nil || !same(st, end) {
		return errors.New("held file mutated during hash")
	}
	return finalSame(p.Path, st)
}
func verifyPin(p Pin) error { return copyPinned(context.Background(), p, nil) }
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".workflow-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if err = syncDir(dir); err != nil {
		return err
	}
	actual, err := readRegular(path, int64(len(b)))
	if err != nil {
		return err
	}
	if string(actual) != string(b) {
		return errors.New("durable write readback mismatch")
	}
	return nil
}

const cacheSyncBytes = 1 << 20

// Bound pending data in this cache file without relaxing final durability or
// readback checks. A sync error aborts this attempt; it is never retried here.
type cacheChunkWriter struct {
	file    *os.File
	sync    func(*os.File) error
	pending int
}

func (w *cacheChunkWriter) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		count := min(len(b), cacheSyncBytes-w.pending)
		n, err := w.file.Write(b[:count])
		total += n
		w.pending += n
		b = b[n:]
		if err != nil {
			return total, err
		}
		if n != count {
			return total, io.ErrShortWrite
		}
		if w.pending == cacheSyncBytes {
			if err = w.sync(w.file); err != nil {
				return total, err
			}
			w.pending = 0
		}
	}
	return total, nil
}
func (r *Runner) cache(ctx context.Context, p Pin) ([]byte, error) {
	return r.cacheWithSync(ctx, p, func(f *os.File) error { return f.Sync() })
}

// The private callback permits a real cache failure test without a global hook
// or a runtime configuration that could disable checked syncs.
func (r *Runner) cacheWithSync(ctx context.Context, p Pin, syncFile func(*os.File) error) ([]byte, error) {
	dir := filepath.Join(r.Dir, "cache")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	dst := filepath.Join(dir, p.SHA256)
	cached := p
	cached.Path = dst
	if _, err := os.Lstat(dst); err == nil {
		if err = copyPinned(ctx, cached, nil); err != nil {
			return nil, fmt.Errorf("cached artifact corrupt; refusing silent replacement: %w", err)
		}
		return json.Marshal(map[string]any{"path": dst, "sha256": p.SHA256, "bytes": p.Bytes, "reused": true, "controller_cas_present": false})
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".cache-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	err = copyPinned(ctx, p, &cacheChunkWriter{file: f, sync: syncFile})
	if err == nil {
		err = syncFile(f)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	tmp := cached
	tmp.Path = f.Name()
	if err = copyPinned(ctx, tmp, nil); err != nil {
		return nil, err
	}
	if err = os.Rename(f.Name(), dst); err != nil {
		return nil, err
	}
	if err = syncDir(dir); err != nil {
		return nil, err
	}
	if err = copyPinned(ctx, cached, nil); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"path": dst, "sha256": p.SHA256, "bytes": p.Bytes, "reused": false, "controller_cas_present": false})
}

package workflow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type boundedBuffer struct {
	b      bytes.Buffer
	excess bool
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := MaxJSON - w.b.Len()
	if len(p) > remain {
		w.b.Write(p[:remain])
		w.excess = true
		return n, errors.New("helper output exceeded bound")
	}
	return w.b.Write(p)
}

// With the leader deliberately UNREAPED, its PID/PGID cannot be reused while
// inspecting/draining its process group. Zombies do not execute work.
func groupLive(pgid int) (bool, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	for _, d := range dirs {
		if _, err = strconv.Atoi(d.Name()); err != nil {
			continue
		}
		b, er := os.ReadFile("/proc/" + d.Name() + "/stat")
		if os.IsNotExist(er) {
			continue
		}
		if er != nil {
			return false, er
		}
		end := bytes.LastIndexByte(b, ')')
		if end < 0 {
			return false, errors.New("malformed process stat")
		}
		fields := strings.Fields(string(b[end+1:]))
		if len(fields) < 3 {
			return false, errors.New("short process stat")
		}
		g, er := strconv.Atoi(fields[2])
		if er != nil {
			return false, er
		}
		if g == pgid && fields[0] != "Z" && fields[0] != "X" {
			return true, nil
		}
	}
	return false, nil
}
func drainGroup(pgid int) error {
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return err
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		live, err := groupLive(pgid)
		if err != nil {
			return err
		}
		if !live {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return err
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		live, err := groupLive(pgid)
		if err != nil {
			return err
		}
		if !live {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("owned helper group remains live after KILL")
}

// RunHelper uses one fixed protocol, not a shell/argv template. It never
// elevates privilege. Target-side transient-unit ownership still belongs to the
// reviewed helper; this coordinator only owns its immediate process group.
func RunHelper(ctx context.Context, h Helper, binding []byte, dir string) (out []byte, retErr error) {
	if err := verifyPin(h.Python); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	var stdout, stderr boundedBuffer
	defer func() { // Keep the original error AND any retention failure.
		retErr = errors.Join(retErr, atomicWrite(filepath.Join(dir, "stderr.txt"), stderr.b.Bytes()), atomicWrite(filepath.Join(dir, "stdout.json"), stdout.b.Bytes()))
	}()
	source := ""
	names := map[string]bool{}
	for i, p := range append([]Pin{h.Source}, h.Closure...) {
		if p.Bytes > MaxJSON {
			return nil, errors.New("helper source closure file exceeds 4MiB")
		}
		name := filepath.Base(p.Path)
		if names[name] {
			return nil, errors.New("helper source basename collision")
		}
		names[name] = true
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		err = copyPinned(ctx, p, f)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, err
		}
		staged := p
		staged.Path = f.Name()
		if err = copyPinned(ctx, staged, nil); err != nil {
			return nil, fmt.Errorf("staged helper readback: %w", err)
		}
		if i == 0 {
			source = f.Name()
		}
	}
	if names["binding.json"] || names["stdout.json"] || names["stderr.txt"] {
		return nil, errors.New("source closure collides with reserved receipt")
	}
	request := filepath.Join(dir, "binding.json")
	if err := atomicWrite(request, binding); err != nil {
		return nil, err
	}
	python, pythonIdentity, err := openRegular(h.Python.Path)
	if err != nil {
		return nil, err
	}
	defer python.Close()
	cmd := exec.Command("/proc/self/fd/3", "-I", "-B", "-c", "import runpy,sys; sys.executable=sys.argv.pop(1); p=sys.argv.pop(1); sys.argv[0]=p; runpy.run_path(p,run_name='__main__')", h.Python.Path, source, "--binding", request)
	cmd.ExtraFiles = []*os.File{python}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second
	if err = verifyPin(h.Python); err != nil {
		return nil, err
	}
	if err = finalSame(h.Python.Path, pythonIdentity); err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	// Do NOT call cmd.Wait until process-group cleanup is finished. A retained
	// zombie leader reserves the numeric identity through the cleanup race.
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		clean := drainGroup(cmd.Process.Pid)
		return nil, errors.Join(err, clean, cmd.Wait())
	}
	defer unix.Close(fd)
	aborted := false
	for {
		if ctx.Err() != nil {
			aborted = true
			break
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err = unix.Poll(poll, 50)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			break
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			break
		}
	}
	// The leader may have exited0 while a redirected child continues: drain it
	// before returning success, then reap. External detached contexts are not
	// inferred safe; their receipt belongs to each reviewed target helper.
	liveAtExit, liveErr := groupLive(cmd.Process.Pid)
	cleanup := drainGroup(cmd.Process.Pid)
	waitErr := cmd.Wait()
	if !aborted && liveAtExit {
		waitErr = errors.Join(waitErr, errors.New("INCOMPLETE: helper exited with live owned descendants; forced cleanup cannot complete its work"))
	}
	cleanup = errors.Join(cleanup, liveErr)
	if aborted {
		return nil, errors.Join(fmt.Errorf("helper aborted; reconcile side effects: %w", ctx.Err()), cleanup, waitErr)
	}
	if err != nil || waitErr != nil || cleanup != nil {
		return nil, errors.Join(err, waitErr, cleanup)
	}
	if stdout.excess || stderr.excess {
		return nil, errors.New("helper output exceeded bound")
	}
	if err = verifyPin(h.Python); err != nil {
		return nil, err
	}
	return stdout.b.Bytes(), nil
}

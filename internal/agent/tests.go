package agent

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

//go:embed tests/*.sh
var builtinTests embed.FS

// Builtins lists the tests embedded in the agent: the scripts, and
// suspend-devices, which is Go.
func Builtins() []string {
	ents, _ := builtinTests.ReadDir("tests")
	var names []string
	for _, e := range ents {
		names = append(names, e.Name()[:len(e.Name())-3])
	}
	return append(names, suspendDevicesTest)
}

// guiSessionWait is how long a GUI test waits for the desktop session. The
// wait counts against the test's timeout but isn't cut short by it, so a GUI
// test with a shorter timeout can take this long.
const guiSessionWait = 2 * time.Minute

// testTimeout is how long a test may run before it is killed.
func testTimeout(t api.TestSpec) time.Duration {
	if t.TimeoutSec > 0 {
		return time.Duration(t.TimeoutSec) * time.Second
	}
	return 5 * time.Minute
}

func (l *Linux) RunTest(ctx context.Context, job string, t api.TestSpec, fetch Fetcher, quiet Quieter, outDir string) api.TestResult {
	if t.Builtin == suspendDevicesTest {
		return suspendDevices(ctx, t, outDir, l.GUIUser, quiet)
	}
	res := api.TestResult{Name: t.Name}
	fail := func(err error) api.TestResult { res.Error = err.Error(); res.ExitCode = -1; return res }

	script := filepath.Join(l.jobDir(job), "test-"+t.Name+".sh")
	os.MkdirAll(filepath.Dir(script), 0o755)
	switch {
	case t.Builtin != "":
		b, err := builtinTests.ReadFile("tests/" + t.Builtin + ".sh")
		if err != nil {
			return fail(fmt.Errorf("no builtin test %q (have %v)", t.Builtin, Builtins()))
		}
		if err := os.WriteFile(script, b, 0o755); err != nil {
			return fail(err)
		}
	case t.Script != "":
		if err := fetch(ctx, t.Script, script); err != nil {
			return fail(err)
		}
		os.Chmod(script, 0o755)
	default:
		return fail(errors.New("test has neither builtin nor script"))
	}

	tctx, cancel := context.WithTimeout(ctx, testTimeout(t))
	defer cancel()

	env := append(os.Environ(), "MACLAB_OUT="+outDir, "MACLAB_JOB="+job, "MACLAB_TEST="+t.Name)
	var cmd *exec.Cmd
	if t.GUI {
		if l.GUIUser == "" {
			return fail(errors.New("gui test, but no gui_user configured (lab-agent setup --gui-user)"))
		}
		u, genv, err := guiEnv(l.GUIUser, guiSessionWait)
		if err != nil {
			return fail(err)
		}
		chownTree(outDir, u)
		os.Chmod(script, 0o755)
		args := append([]string{"-u", u.Username, "--", "env"}, append(genv, "MACLAB_OUT="+outDir, "MACLAB_JOB="+job, "bash", script)...)
		cmd = exec.CommandContext(tctx, "runuser", args...)
	} else {
		cmd = exec.CommandContext(tctx, "bash", script)
		cmd.Env = env
	}
	logPath := filepath.Join(outDir, "log.txt")
	logf, err := os.Create(logPath)
	if err != nil {
		return fail(err)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.WaitDelay = 5 * time.Second
	start := time.Now()
	err = cmd.Run()
	logf.Close()
	res.Seconds = time.Since(start).Seconds()
	res.Tail = tail(logPath, 40)
	if tctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		res.Passed = true
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		return fail(err)
	}
	return res
}

func chownTree(dir string, u *user.User) {
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Lchown(p, uid, gid)
		}
		return nil
	})
}

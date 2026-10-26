package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// WatchSleep reports suspend and resume as logind announces them, so labd can
// tell a sleeping Mac from a hung one. A delay lock holds each suspend back
// until fn(true) returns (at most logind's InhibitDelayMaxSec, 5s by default),
// which is when the agent has told labd. Suspends that bypass logind (writing
// /sys/power/state) aren't seen.
func (l *Linux) WatchSleep(ctx context.Context, fn func(sleeping bool)) {
	for ctx.Err() == nil {
		l.watchSleep(ctx, fn)
		sleepCtx(ctx, WallClock, 10*time.Second) // busctl or logind went away; start over
	}
}

func (l *Linux) watchSleep(ctx context.Context, fn func(sleeping bool)) {
	var lock *exec.Cmd
	take := func() {
		lock = exec.CommandContext(ctx, "systemd-inhibit", "--what=sleep", "--mode=delay", "--who=lab-agent",
			"--why=tells the lab the Mac is going to sleep", "sleep", "infinity")
		if lock.Start() != nil {
			lock = nil
		}
	}
	release := func() {
		if lock != nil {
			lock.Process.Kill()
			lock.Wait()
			lock = nil
		}
	}
	defer release()
	mon := exec.CommandContext(ctx, "busctl", "monitor", "--system", "--json=short",
		"--match=type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'")
	out, err := mon.StdoutPipe()
	if err != nil || mon.Start() != nil {
		return
	}
	defer mon.Wait()
	take()
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		sleeping, ok := parseSleepSignal(sc.Bytes())
		if !ok {
			continue
		}
		if sleeping {
			fn(true)
			release() // let the suspend go ahead
		} else {
			fn(false)
			take()
		}
	}
}

// parseSleepSignal reads one `busctl monitor --json=short` line: logind's
// PrepareForSleep carries true before a suspend and false after the resume.
func parseSleepSignal(line []byte) (sleeping, ok bool) {
	var m struct {
		Member  string `json:"member"`
		Payload struct {
			Type string `json:"type"`
			Data []bool `json:"data"`
		} `json:"payload"`
	}
	if json.Unmarshal(line, &m) != nil || m.Member != "PrepareForSleep" || m.Payload.Type != "b" || len(m.Payload.Data) != 1 {
		return false, false
	}
	return m.Payload.Data[0], true
}

// inhibitSuspendArgs is the command line that keeps the Mac from suspending
// while a job holds it, for the reason why. It blocks sleep only: idle stays
// free, so the Volunteer's idle lock and screensaver keep working.
func inhibitSuspendArgs(why string) []string {
	return []string{"systemd-inhibit", "--what=sleep", "--mode=block", "--who=lab-agent", "--why=" + why, "sleep", "infinity"}
}

func (l *Linux) InhibitSuspend(why string) (func(), error) {
	args := inhibitSuspendArgs(why)
	cmd := exec.Command(args[0], args[1:]...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("systemd-inhibit: %w", err)
	}
	return func() {
		cmd.Process.Kill()
		cmd.Wait()
	}, nil
}

// awakeHold is the suspend inhibitor lab-agent holds while a job holds the Mac.
type awakeHold struct {
	mu      sync.Mutex
	bootID  string // the boot it was taken on, which ends it
	release func()
}

// keepAwake keeps a Volunteer's Mac from suspending while a job holds it: on
// a Lab boot, or while one of a job's commands runs. Nothing wakes a Mac that
// sleeps before a job starts. A Lab-owned Mac stays awake by its own settings.
func (a *Agent) keepAwake() {
	bootID, _, cmdline := a.sys.Identity()
	job := ""
	if a.volunteer() {
		a.mu.Lock()
		for _, r := range a.running {
			if r.c.JobID != "" && r.bootID == bootID {
				job = r.c.JobID
				break
			}
		}
		a.mu.Unlock()
		if job == "" && IsLabBoot(cmdline) {
			job = jobTag(cmdline)
			if job == "" {
				job = "on a Lab boot"
			}
		}
	}
	h := &a.awake
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.release != nil && h.bootID != bootID {
		h.release = nil // gone with its boot
	}
	switch {
	case job != "" && h.release == nil:
		release, err := a.sys.InhibitSuspend("maclab job " + job + " holds the Mac")
		if err != nil {
			a.log.Printf("keep the Mac awake: %v", err)
			return
		}
		h.release, h.bootID = release, bootID
	case job == "" && h.release != nil:
		h.release()
		h.release = nil
	}
}

package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// warnBeforeReboot is the reboot warning: on a Volunteer's Mac, about to arm
// a job's first Lab boot, it shows the Volunteer a notice naming the job and
// the reboot's time, records in the Audit log whether the notice was shown,
// and waits the warning out before the boot is armed. Pause, from the notice
// or the `pause` command, closes the window, and lab-agent stops the command
// as it would at the window's end, before anything is armed. With no desktop
// session the notice is not shown, and the job goes ahead after the same wait.
func (a *Agent) warnBeforeReboot(ctx context.Context, c api.Command, args api.BootOnceArgs) error {
	if !a.volunteer() || args.RebootWarningSec <= 0 {
		return nil
	}
	wait := time.Duration(args.RebootWarningSec) * time.Second
	at := a.clock().Now().Add(wait)
	text := fmt.Sprintf("The lab will reboot this Mac for job %s at %s. Press Pause to stop the job and keep your Mac.", c.JobID, at.In(time.Local).Format("15:04"))
	onPause := func() {
		if err := pause(ctx, a.cfg, a.sys, nil, io.Discard); err != nil {
			a.log.Printf("reboot warning: Pause: %v", err)
		}
	}
	shown, why := showNoticeWithPause(ctx, a.sys, a.cfg.GUIUser, text, onPause)
	action := fmt.Sprintf("the reboot warning for job %s was shown to you, %s before the reboot", c.JobID, wait)
	if !shown {
		action = fmt.Sprintf("the reboot warning for job %s was not shown (%s); the job goes ahead after %s", c.JobID, why, wait)
	}
	if err := appendAudit(a.workDir(), api.AuditEntry{Time: a.clock().Now(), Job: c.JobID, Action: action}); err != nil {
		return fmt.Errorf("the Audit log can't be written, so lab-agent does not reboot for %s: %w", c.JobID, err)
	}
	select {
	case <-a.clock().After(wait):
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// noticeUpAfter is how long notify-send must stay up before the notice counts
// as shown: with --wait it blocks while the notice is on screen, and exits
// at once when there is no session bus or its libnotify lacks --action.
const noticeUpAfter = 2 * time.Second

// showNoticeWithPause shows the Volunteer a notice on their desktop with a
// Pause button that runs onPause. It reports whether the notice was shown,
// and if not why. The notice stays until ctx ends or the Volunteer answers it.
func showNoticeWithPause(ctx context.Context, sys System, guiUser, text string, onPause func()) (bool, string) {
	if n, ok := sys.(interface {
		NotifyWithPause(context.Context, string, func()) bool
	}); ok {
		if n.NotifyWithPause(ctx, text, onPause) {
			return true, ""
		}
		return false, "no desktop session"
	}
	u, env, err := guiEnv(guiUser, 0)
	if err != nil {
		return false, "no desktop session: " + err.Error()
	}
	argv := append([]string{"-u", u.Username, "--", "env"}, env...)
	argv = append(argv, "notify-send", "-u", "critical", "--wait", "--action=pause=Pause", "maclab", text)
	cmd := exec.CommandContext(ctx, "runuser", argv...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return false, "notify-send could not start"
	}
	read := make(chan struct{})
	go func() {
		defer close(read)
		// notify-send prints the action's key once the Volunteer presses it
		if l, _ := bufio.NewReader(out).ReadString('\n'); strings.TrimSpace(l) == "pause" {
			onPause()
		}
	}()
	exited := make(chan error, 1)
	go func() {
		<-read
		exited <- cmd.Wait()
	}()
	select {
	case err := <-exited:
		if err != nil {
			return false, "notify-send failed: " + strings.TrimSpace(err.Error()+" "+stderr.String())
		}
		return true, ""
	case <-time.After(noticeUpAfter):
		return true, ""
	}
}

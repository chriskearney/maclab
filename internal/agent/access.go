package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// accessFile holds what the Volunteer allows Maintainers on the Mac, under
// the work directory: the Access level and the publishing opt-in. The
// Volunteer's commands write it and take effect at once; lab-agent reads it
// before every lab command and carries it to labd in its check-ins.
const accessFile = "access.json"

// access is what accessFile holds.
type access struct {
	Level   string `json:"access_level"`
	Publish bool   `json:"publish"`
}

// loadAccess reads the Mac's Access level and publishing opt-in. A Mac whose
// Volunteer has chosen nothing is at Qualification with publishing off.
func loadAccess(workDir string) (access, error) {
	ac := access{Level: api.AccessQualification}
	b, err := os.ReadFile(filepath.Join(workDir, accessFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ac, nil
	case err != nil:
		return ac, err
	}
	if err := json.Unmarshal(b, &ac); err != nil {
		return access{Level: api.AccessQualification}, fmt.Errorf("%s: %w", accessFile, err)
	}
	if ac.Level != api.AccessFull {
		ac.Level = api.AccessQualification
	}
	return ac, nil
}

// changeAccess is the read-change-write access and publish do. A Lab-owned
// Mac has no Access level.
func changeAccess(cfg *Config, f func(ac *access)) error {
	if cfg.Enrollment.Kind == api.KindLabOwned {
		return errors.New("a Lab-owned Mac has no Access level: Maintainers may do anything on it")
	}
	ac, err := loadAccess(cfg.workDir())
	if err != nil {
		return err
	}
	f(&ac)
	if err := os.MkdirAll(cfg.workDir(), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(ac, "", "  ")
	return writeAtomic(filepath.Join(cfg.workDir(), accessFile), append(b, '\n'))
}

// levelName is how the Volunteer's commands name an Access level.
func levelName(level string) string {
	if level == api.AccessFull {
		return "Full (everything a Lab-owned Mac allows)"
	}
	return "Qualification (no lab exec, --script or --gui-script)"
}

// accessCmd is `access qualification|full`. Lowering the level stops at once
// whatever it no longer allows: lab-agent sees the change within a second.
func accessCmd(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	if len(args) != 1 || (args[0] != api.AccessQualification && args[0] != api.AccessFull) {
		return errors.New("usage: access qualification|full")
	}
	if err := changeAccess(cfg, func(ac *access) { ac.Level = args[0] }); err != nil {
		return err
	}
	fmt.Fprintf(out, "Access level: %s\n", levelName(args[0]))
	if args[0] == api.AccessQualification {
		fmt.Fprintln(out, "Anything this level doesn't allow stops now: a lease ends, and a job running a Maintainer's script ends incomplete.")
	}
	return nil
}

// publishCmd is `publish on|off`: whether omarchy-m-test reports of this Mac
// may go on omarchy-m-testing.org. `publish on` shows the deletion link of
// every report published so far, each time it runs.
func publishCmd(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
		return errors.New("usage: publish on|off")
	}
	on := args[0] == "on"
	if err := changeAccess(cfg, func(ac *access) { ac.Publish = on }); err != nil {
		return err
	}
	if !on {
		fmt.Fprintln(out, "Publishing is off: no omarchy-m-test report of this Mac goes on omarchy-m-testing.org from its next check-in. Reports already published stay up until you delete them.")
	} else {
		fmt.Fprintln(out, "Publishing is on: the lab may publish this Mac's omarchy-m-test reports on omarchy-m-testing.org from its next check-in.")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var pubs []api.Published
	if err := getJSON(ctx, http.DefaultClient, strings.TrimRight(cfg.Server, "/")+"/api/agent/published", cfg.Secret, &pubs); err != nil {
		fmt.Fprintf(out, "The reports published so far can't be listed now (labd did not answer: %v); run publish on again later to see them.\n", err)
		return nil
	}
	if len(pubs) == 0 {
		fmt.Fprintln(out, "No report of this Mac has been published yet.")
		return nil
	}
	fmt.Fprintln(out, "Published reports (open the deletion link to take one down):")
	for _, p := range pubs {
		fmt.Fprintf(out, "  job %s: %s\n    delete: %s\n", p.Job, p.ReportURL, p.DeletionURL)
	}
	return nil
}

// errAccessLevel is lab-agent refusing, or stopping, a command the Mac's
// Access level doesn't allow.
var errAccessLevel = errors.New("refused")

// needsFull is whether a command needs a Volunteer's Mac at Full: lab exec,
// a Maintainer's script (--script as root, --gui-script in the Volunteer's
// own session), and a Lab boot for a job that runs one.
func needsFull(c api.Command) bool {
	switch c.Kind {
	case api.CmdExec, api.CmdMesaStage:
		return true
	case api.CmdRunTest:
		var t api.TestSpec
		return json.Unmarshal(c.Args, &t) != nil || t.MaintainerScript() || t.Builtin == "mesa-provider"
	case api.CmdBootOnce:
		var b api.BootOnceArgs
		return json.Unmarshal(c.Args, &b) != nil || testsNeedFull(b.Tests)
	}
	return false
}

// testsNeedFull is whether any of a job's tests is a Maintainer's script.
func testsNeedFull(tests []api.TestSpec) bool {
	return slices.ContainsFunc(tests, func(t api.TestSpec) bool { return t.MaintainerScript() || t.Builtin == "mesa-provider" })
}

// watches is whether a command reads the Mac's screen or its live journal.
func watches(c api.Command) bool { return c.Kind == api.CmdScreen || c.Kind == api.CmdLogs }

// refuseByAccess is nil when a Volunteer's Mac allows c, whatever labd
// thought. Its Access level gates exec and scripts; its screen and live
// journal are read only while a job or lease holds it (inside its window,
// which refuseOutsideWindow checks): a job's own captures carry the job.
func (a *Agent) refuseByAccess(c api.Command) error {
	if !a.volunteer() {
		return nil
	}
	if needsFull(c) {
		ac, err := loadAccess(a.workDir())
		if err != nil {
			return fmt.Errorf("%w: %s: the Access level can't be read: %v", errAccessLevel, c.Kind, err)
		}
		if ac.Level != api.AccessFull {
			return fmt.Errorf("%w: %s's Access level is Qualification, so lab-agent runs no lab exec and no Maintainer's script (its Volunteer allows them with `sudo lab-agent access full`)", errAccessLevel, a.cfg.Name)
		}
	}
	a.mu.Lock()
	held := a.held
	a.mu.Unlock()
	if watches(c) && c.JobID == "" && !held {
		return fmt.Errorf("%w: no job or lease holds %s, so lab-agent does not show its screen or live journal", errAccessLevel, a.cfg.Name)
	}
	return nil
}

// accessLowered is whether a Lab boot holds a job that runs what only Full
// allows, on a Mac no longer at Full. The early unit reads it every second.
func accessLowered(workDir string, d labBootDeadlines) bool {
	if !d.NeedsFull {
		return false
	}
	ac, err := loadAccess(workDir)
	return err != nil || ac.Level != api.AccessFull
}

// watchAccess stops a running command the Access level no longer allows,
// the moment the Volunteer lowers it. A Lab boot for a job that runs such a
// command is the early unit's to end: it reboots to the Known-good kernel.
func (a *Agent) watchAccess() {
	if !a.volunteer() {
		return
	}
	a.mu.Lock()
	var full []runningCmd
	for _, r := range a.running {
		if needsFull(r.c) {
			full = append(full, r)
		}
	}
	a.mu.Unlock()
	if len(full) == 0 {
		return
	}
	if ac, err := loadAccess(a.workDir()); err == nil && ac.Level == api.AccessFull {
		return
	}
	for _, r := range full {
		r.stop(fmt.Errorf("%w: %s's Volunteer lowered the Access level to Qualification, so lab-agent stopped %s", errAccessLevel, a.cfg.Name, describe(r.c)))
	}
}

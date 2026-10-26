package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// auditFile is a Volunteer Mac's Audit log under the work directory: one JSON
// line per Maintainer action that reached the Mac, appended before lab-agent
// acts on it, never rewritten. It is the Volunteer's record, so it stays when
// the Mac leaves the lab. Reports carry what labd's copy lacks.
const auditFile = "audit.log"

// maxScriptText is how much of a Maintainer's script the Audit log keeps.
const maxScriptText = 16 << 10

// appendAudit adds e to the Audit log in workDir and syncs it to disk.
func appendAudit(workDir string, e api.AuditEntry) error {
	e.End = 0
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(workDir, auditFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// readAudit reads the Audit log in workDir from byte offset from, at most
// limit entries (0: all), each with where it ends.
func readAudit(workDir string, from int64, limit int) ([]api.AuditEntry, error) {
	f, err := os.Open(filepath.Join(workDir, auditFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return nil, err
	}
	var out []api.AuditEntry
	r := bufio.NewReader(f)
	end := from
	for limit == 0 || len(out) < limit {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break // EOF, or a line still being written
		}
		end += int64(len(line))
		var e api.AuditEntry
		if json.Unmarshal(bytes.TrimSpace(line), &e) != nil {
			continue
		}
		e.End = end
		out = append(out, e)
	}
	return out, nil
}

// audit records c in the Audit log before lab-agent acts on it, or with why
// it refused it. A command it can't record is not run.
func (a *Agent) audit(ctx context.Context, c api.Command, refused error) error {
	if !a.volunteer() {
		return nil
	}
	e := api.AuditEntry{Time: a.clock().Now(), Maintainer: c.Maintainer, Job: c.JobID, Action: a.describeWithScript(ctx, c)}
	if refused != nil {
		e.Refused = strings.TrimPrefix(refused.Error(), "refused: ")
	}
	if err := appendAudit(a.workDir(), e); err != nil {
		return fmt.Errorf("the Audit log can't be written, so lab-agent does not run %s: %w", c.Kind, err)
	}
	return nil
}

// describeWithScript is describe with a Maintainer's script's text, which
// lab-agent fetches to record what will run.
func (a *Agent) describeWithScript(ctx context.Context, c api.Command) string {
	var t api.TestSpec
	if c.Kind != api.CmdRunTest || json.Unmarshal(c.Args, &t) != nil || t.Script == "" {
		return describe(c)
	}
	dir, err := a.outDir(api.Command{ID: c.ID + "-audit"})
	if err != nil {
		return describe(c)
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "script")
	if err := a.fetch(ctx, t.Script, p); err != nil {
		return describe(c) + fmt.Sprintf(" (its text could not be fetched: %v)", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return describe(c)
	}
	text := string(b)
	if len(text) > maxScriptText {
		text = text[:maxScriptText] + "…(cut)"
	}
	return describe(c) + ": " + fmt.Sprintf("%q", text)
}

// describe is what a command does, as the Audit log says it.
func describe(c api.Command) string {
	switch c.Kind {
	case api.CmdExec:
		var a api.ExecArgs
		_ = json.Unmarshal(c.Args, &a)
		return fmt.Sprintf("lab exec as root: %q", a.Command)
	case api.CmdRunTest:
		var t api.TestSpec
		_ = json.Unmarshal(c.Args, &t)
		switch {
		case t.Script != "" && t.GUI:
			return fmt.Sprintf("test %s: a Maintainer's script in your desktop session (--gui-script %s)", t.Name, short(t.Script))
		case t.Script != "":
			return fmt.Sprintf("test %s: a Maintainer's script as root (--script %s)", t.Name, short(t.Script))
		case t.Builtin != "":
			return fmt.Sprintf("test %s (built-in %s)", t.Name, t.Builtin)
		case t.Identity != nil:
			return fmt.Sprintf("test %s (the lab's read-only identity check of Release kernel %s)", t.Name, t.Identity.Kernel)
		}
		return "test " + t.Name
	case api.CmdStage:
		var s api.StageArgs
		_ = json.Unmarshal(c.Args, &s)
		if s.Installed != nil {
			return "stage installed Release " + s.Installed.Release + " for a Lab boot"
		}
		if s.Artifact == "" {
			return "stage the known-good kernel for a Lab boot"
		}
		return "stage test kernel " + short(s.Artifact) + " for a Lab boot"
	case api.CmdBootOnce:
		var b api.BootOnceArgs
		_ = json.Unmarshal(c.Args, &b)
		var tests []string
		for _, t := range b.Tests {
			tests = append(tests, describe(api.Command{Kind: api.CmdRunTest, Args: mustJSON(t)}))
		}
		if len(tests) == 0 {
			return "reboot once into Lab boot entry " + b.Entry
		}
		return "reboot once into Lab boot entry " + b.Entry + " to run " + strings.Join(tests, "; ")
	case api.CmdReboot:
		return "reboot"
	case api.CmdCrash:
		return "a deliberate kernel panic (crash test)"
	case api.CmdScreen:
		if c.JobID != "" {
			return "screenshot for the job"
		}
		return "live screenshot"
	case api.CmdLogs:
		var l api.LogsArgs
		_ = json.Unmarshal(c.Args, &l)
		return fmt.Sprintf("read the live %s log (%d lines)", l.Source, l.Lines)
	case api.CmdCollect, api.CmdCollectLost:
		return "collect logs"
	case api.CmdCleanup:
		return "remove staged lab kernels"
	case api.CmdConfig:
		return "read the running kernel's config"
	case api.CmdInstall:
		var i api.InstallArgs
		_ = json.Unmarshal(c.Args, &i)
		return describeInstall(i)
	case api.CmdRecordKnownGood:
		var r api.RecordKnownGoodArgs
		_ = json.Unmarshal(c.Args, &r)
		return "record " + r.Kernel + " as the known-good kernel"
	}
	return c.Kind
}

// formatAudit is one Audit log entry as `log` and `status` print it, in the
// Mac's local time.
func formatAudit(e api.AuditEntry) string { return e.Line(time.Local) }

// logCmd is `log`: every Maintainer action on this Mac, oldest first, from
// lab-agent's own Audit log. It needs neither labd nor the network.
func logCmd(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: log")
	}
	es, err := readAudit(cfg.workDir(), 0, 0)
	if err != nil {
		return fmt.Errorf("the Audit log can't be read: %w", err)
	}
	if len(es) == 0 {
		fmt.Fprintln(out, "No Maintainer has done anything on this Mac yet.")
	}
	for _, e := range es {
		fmt.Fprintln(out, formatAudit(e))
	}
	return nil
}

// jobsCmd is `jobs`: the lab's jobs on this Mac, from its Audit log, oldest first.
func jobsCmd(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: jobs")
	}
	es, err := readAudit(cfg.workDir(), 0, 0)
	if err != nil {
		return fmt.Errorf("the Audit log can't be read: %w", err)
	}
	type job struct {
		id, who      string
		first, last  time.Time
		lastAction   string
		actions      int
		refusedCount int
	}
	var order []string
	jobs := map[string]*job{}
	for _, e := range es {
		if e.Job == "" {
			continue
		}
		j := jobs[e.Job]
		if j == nil {
			j = &job{id: e.Job, who: e.Maintainer, first: e.Time}
			if j.who == "" {
				j.who = "labd"
			}
			jobs[e.Job] = j
			order = append(order, e.Job)
		}
		j.last, j.lastAction = e.Time, e.Action
		j.actions++
		if e.Refused != "" {
			j.refusedCount++
		}
	}
	if len(order) == 0 {
		fmt.Fprintln(out, "The lab has run no job on this Mac yet.")
		return nil
	}
	for _, id := range order {
		j := jobs[id]
		fmt.Fprintf(out, "%s  %s, by %s: %d actions, the last at %s: %s", id, j.first.In(time.Local).Format("2006-01-02 15:04"), j.who,
			j.actions, j.last.In(time.Local).Format("15:04"), j.lastAction)
		if j.refusedCount > 0 {
			fmt.Fprintf(out, " (%d refused)", j.refusedCount)
		}
		fmt.Fprintln(out)
	}
	return nil
}

// latestAudit is the last n entries of the Audit log, as status shows them.
func latestAudit(workDir string, n int) ([]string, error) {
	es, err := readAudit(workDir, 0, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es[max(0, len(es)-n):] {
		out = append(out, strings.TrimSpace(formatAudit(e)))
	}
	return out, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

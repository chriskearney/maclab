package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/window"
)

// windowFile holds the Mac's Availability window settings under the work
// directory. The Volunteer's commands write it and take effect at once;
// lab-agent reads it before every lab command and carries it to labd in its
// check-ins, so it works with labd or the tailnet down.
const windowFile = "availability.json"

// loadWindow reads the Mac's window settings in its local time zone. A Mac
// whose Volunteer has set nothing has none (set false), and is closed.
func loadWindow(cfg *Config) (s window.Settings, set bool, err error) {
	return readWindow(cfg.workDir())
}

// readWindow is loadWindow from the work directory alone, as the early unit
// reads it.
func readWindow(workDir string) (s window.Settings, set bool, err error) {
	b, err := os.ReadFile(filepath.Join(workDir, windowFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		err = nil
	case err == nil:
		set = true
		if err = json.Unmarshal(b, &s); err != nil {
			err = fmt.Errorf("%s: %w", windowFile, err)
		}
	}
	s.Zone = localZone()
	return s, set, err
}

func saveWindow(cfg *Config, s window.Settings) error {
	s.Zone = ""
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.MkdirAll(cfg.workDir(), 0o755); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(cfg.workDir(), windowFile), append(b, '\n'))
}

// localZone is the IANA name of the Mac's local time zone, which its weekly
// windows are in: the system's (what /etc/localtime links to), so that the
// daemon and a Volunteer's command agree, else TZ if it names one.
func localZone() string {
	if p, err := os.Readlink("/etc/localtime"); err == nil {
		if _, name, ok := strings.Cut(p, "zoneinfo/"); ok {
			return name
		}
	}
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" {
		if _, err := time.LoadLocation(tz); err == nil {
			return tz
		}
	}
	return "" // the evaluator reads that as time.Local
}

// changeWindow is the read-change-write every window command does. A
// Lab-owned Mac has no Availability windows.
func changeWindow(cfg *Config, f func(s *window.Settings, now time.Time) error) error {
	if cfg.Enrollment.Kind == api.KindLabOwned {
		return errors.New("a Lab-owned Mac has no Availability windows")
	}
	s, _, err := loadWindow(cfg)
	if err != nil {
		return err
	}
	if err := f(&s, cfg.clock().Now()); err != nil {
		return err
	}
	return saveWindow(cfg, s)
}

// windowCmd is `window show`, `window add <days> <HH:MM-HH:MM>` and
// `window remove <days> <HH:MM-HH:MM>`.
func windowCmd(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	usage := errors.New("usage: window show | window add <days> <HH:MM-HH:MM> | window remove <days> <HH:MM-HH:MM>, e.g. window add mon-fri 19:00-07:00")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "show":
		if len(args) != 1 {
			return usage
		}
		s, _, err := loadWindow(cfg)
		if err != nil {
			return err
		}
		if len(s.Rules) == 0 {
			fmt.Fprintln(out, "No weekly windows: the lab uses this Mac only when you open it (open --until HH:MM).")
		}
		for _, r := range s.Rules {
			fmt.Fprintln(out, r)
		}
		fmt.Fprintln(out, "Window: "+describeWindow(s, cfg.clock().Now()))
		return nil
	case "add", "remove":
		if len(args) != 3 {
			return usage
		}
		r, err := window.ParseRule(args[1] + " " + args[2])
		if err != nil {
			return err
		}
		return changeWindow(cfg, func(s *window.Settings, now time.Time) error {
			i := slices.Index(s.Rules, r)
			switch {
			case args[0] == "add" && i >= 0:
				fmt.Fprintf(out, "%s is already a window\n", r)
			case args[0] == "add":
				s.Rules = append(s.Rules, r)
				fmt.Fprintf(out, "added %s (in this Mac's local time)\n", r)
			case i < 0:
				return fmt.Errorf("%s is not one of this Mac's windows (see window show)", r)
			default:
				s.Rules = slices.Delete(s.Rules, i, i+1)
				fmt.Fprintf(out, "removed %s\n", r)
			}
			fmt.Fprintln(out, "Window: "+describeWindow(*s, now))
			return nil
		})
	}
	return usage
}

// untilArg reads the one flag pause and open take: --until VALUE.
func untilArg(args []string) (string, bool, error) {
	switch {
	case len(args) == 0:
		return "", false, nil
	case len(args) == 1 && strings.HasPrefix(args[0], "--until="):
		return strings.TrimPrefix(args[0], "--until="), true, nil
	case len(args) == 2 && args[0] == "--until":
		return args[1], true, nil
	}
	return "", false, fmt.Errorf("unexpected arguments %q: the only option is --until", strings.Join(args, " "))
}

// pause is `pause`, which ends the current window, and `pause --until DATE`,
// which keeps the Mac closed until that date begins. Either cancels an
// Open now.
func pause(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	date, hasDate, err := untilArg(args)
	if err != nil {
		return err
	}
	return changeWindow(cfg, func(s *window.Settings, now time.Time) error {
		if hasDate {
			until, err := time.ParseInLocation("2006-01-02", date, s.Location())
			if err != nil {
				return fmt.Errorf("pause --until %q: give a date as YYYY-MM-DD", date)
			}
			if !until.After(now) {
				return fmt.Errorf("pause --until %s: that date has begun already", date)
			}
			s.PausedUntil = until
		} else {
			st := window.Evaluate(*s, now)
			if !st.Open {
				fmt.Fprintln(out, "The window is closed already; nothing to pause.")
				return nil
			}
			if st.End.After(s.PausedUntil) {
				s.PausedUntil = st.End
			}
		}
		s.OpenUntil, s.Attended = time.Time{}, false
		fmt.Fprintln(out, "Window: "+describeWindow(*s, now))
		return nil
	})
}

// open is `open --until HH:MM`: the Mac is open to the lab from now until the
// next HH:MM in its local time, whatever its schedule or a Pause says. A
// Pause stays: it holds again once the Open now ends.
func open(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	hhmm, has, err := untilArg(args)
	if err != nil {
		return err
	}
	if !has {
		return errors.New("open needs an end: open --until HH:MM")
	}
	m, err := window.ParseClock(hhmm)
	if err != nil {
		return fmt.Errorf("open --until: %w", err)
	}
	return changeWindow(cfg, func(s *window.Settings, now time.Time) error {
		local := now.In(s.Location())
		until := time.Date(local.Year(), local.Month(), local.Day(), 0, m, 0, 0, local.Location())
		if !until.After(now) {
			until = time.Date(local.Year(), local.Month(), local.Day()+1, 0, m, 0, 0, local.Location())
		}
		// Attended windows (open --until HH:MM --attended) set s.Attended here.
		s.OpenUntil, s.Attended = until, false
		fmt.Fprintln(out, "Window: "+describeWindow(*s, now))
		return nil
	})
}

// describeWindow is the window state as status and the window commands
// print it: open, closed or paused, and when that changes.
func describeWindow(s window.Settings, now time.Time) string {
	st := window.Evaluate(s, now)
	when := func(t time.Time) string { return t.In(s.Location()).Format("Mon 2 Jan 15:04") }
	var b strings.Builder
	switch {
	case st.Open && st.Attended:
		fmt.Fprintf(&b, "open (attended) until %s", when(st.End))
	case st.Open:
		fmt.Fprintf(&b, "open until %s", when(st.End))
	case s.PausedUntil.After(now):
		fmt.Fprintf(&b, "paused until %s", when(s.PausedUntil))
	default:
		b.WriteString("closed")
	}
	if !st.Next.IsZero() {
		fmt.Fprintf(&b, "; next window opens %s", when(st.Next))
	} else if !st.Open {
		b.WriteString("; no window ahead, so the lab can't use this Mac")
	}
	return b.String()
}

// windowGated is whether lab-agent refuses a command of this kind outside
// the Availability window: everything that would start or carry on lab work.
// What returns the Mac to its own system (collecting a lost boot's logs,
// cleanup, recording its Known-good kernel) runs whenever labd asks.
func windowGated(kind string) bool {
	switch kind {
	case api.CmdCollect, api.CmdCollectLost, api.CmdCleanup, api.CmdRecordKnownGood:
		return false
	}
	return true
}

// errRefusedOutsideWindow is lab-agent refusing a lab command outside the
// window; labd records the error on the job.
var errRefusedOutsideWindow = errors.New("refused")

// errStoppedAtWindowClose is lab-agent stopping a lab command that was
// running when the window closed.
var errStoppedAtWindowClose = errors.New("stopped")

// refuseOutsideWindow is nil when a Volunteer's Mac may run c now. A reboot
// out of a Lab boot goes back to the Mac's own system, so it always may.
func (a *Agent) refuseOutsideWindow(c api.Command) error {
	if !a.volunteer() || !windowGated(c.Kind) {
		return nil
	}
	if _, _, cmdline := a.sys.Identity(); c.Kind == api.CmdReboot && IsLabBoot(cmdline) {
		return nil
	}
	s, _, err := loadWindow(a.cfg)
	if err != nil {
		return fmt.Errorf("%w: %s: the Availability window can't be read: %v", errRefusedOutsideWindow, c.Kind, err)
	}
	now := a.clock().Now()
	if window.Evaluate(s, now).Open {
		return nil
	}
	return fmt.Errorf("%w: %s is outside its Availability window (%s), so lab-agent does not run %s", errRefusedOutsideWindow, a.cfg.Name, describeWindow(s, now), c.Kind)
}

// volunteer is whether this is a Volunteer's Mac, as setup recorded it or
// labd's check-ins say.
func (a *Agent) volunteer() bool {
	if a.cfg.Enrollment.IsVolunteer() {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.kind == api.KindVolunteer
}

// capAtWindowEnd caps a Lab boot's hard ceiling at the Availability window's
// end on a Volunteer's Mac.
func (a *Agent) capAtWindowEnd(ceiling time.Time) time.Time {
	if !a.volunteer() {
		return ceiling
	}
	s, _, err := loadWindow(a.cfg)
	if err != nil {
		return ceiling
	}
	if st := window.Evaluate(s, a.clock().Now()); st.Open && st.End.Before(ceiling) {
		return st.End
	}
	return ceiling
}

// watchWindow stops lab work on a Volunteer's Mac as soon as its Availability
// window closes, at its end or on a Pause, on lab-agent's own clock: it needs
// neither labd nor the tailnet. On the Mac's own boot it stops every lab
// command still running (staging, say), which ends with the window closed. A
// Lab boot is the early unit's to end: it reboots to the Known-good kernel.
// It also keeps the Mac awake while a job holds it, a Lab boot that can't
// reach labd included. An Installed run's Rollback at the window's end
// belongs here too.
func (a *Agent) watchWindow(ctx context.Context) {
	tick := a.clock().NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C():
		}
		a.keepAwake()
		a.watchAccess()
		if _, _, cmdline := a.sys.Identity(); !a.volunteer() || IsLabBoot(cmdline) {
			continue
		}
		a.mu.Lock()
		var gated []runningCmd
		for _, r := range a.running {
			if windowGated(r.c.Kind) {
				gated = append(gated, r)
			}
		}
		a.mu.Unlock()
		if len(gated) == 0 {
			continue
		}
		now := a.clock().Now()
		s, _, err := loadWindow(a.cfg)
		if err == nil && window.Evaluate(s, now).Open {
			continue
		}
		for _, r := range gated {
			r.stop(fmt.Errorf("%w: %s's Availability window closed (%s), so lab-agent stopped %s", errStoppedAtWindowClose, a.cfg.Name, describeWindow(s, now), r.c.Kind))
		}
	}
}

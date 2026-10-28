package agent

// A Volunteer leaves the lab with `sudo lab-agent leave`, or the Maintainers
// end their Mac's enrollment and lab-agent learns of it at its next check-in.
// Either way lab-agent stops any job (it ends incomplete), puts the Mac back
// on its own system, removes the lab's boot entries, units, autologin drop-in
// and device secret, and tells labd. The Audit log and Access level stay: they
// are the Volunteer's, and `log` still reads them afterwards.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// leaveLayout is where the lab put things on a Mac, as paths, so the plan of
// what leaving removes can be made (and tested) without touching a real Mac.
type leaveLayout struct {
	Config     string   // the agent config holding the device secret
	Units      []string // the lab's systemd unit files (lab-agent, deadlines, session, lock)
	UnitNames  []string // the same units by name, to stop and disable
	DropIns    []string // the Lab-boot autologin drop-in, sysctl and watchdog files the lab wrote
	LimineConf string   // limine.conf with the lab's marked block ("" if the Mac boots GRUB)
	Stage      string   // where staged UKIs / entries live
	GrubDir    string   // /boot/grub ("" if the Mac boots Limine)
	GrubEnv    string   // the lab's one-shot env file on the ESP
	WorkDir    string   // the lab's records under it go; the Audit log and Access level stay
}

// leavePlan is what leaving does to a Mac.
type leavePlan struct {
	Remove  []string          // files and directories deleted
	Disable []string          // systemd units stopped and disabled
	Rewrite map[string]string // path -> its new whole content (the file keeps everything that is not the lab's)
	ByHand  []string          // what is left for the Volunteer to remove
}

const (
	serialGettyDropIn = "/etc/systemd/system/serial-getty@ttySAC0.service.d/maclab.conf"
	sddmAutologinConf = "/etc/sddm.conf.d/zz-maclab-autologin.conf"
)

// defaultLeaveLayout is the layout setup writes on a real Mac.
func defaultLeaveLayout() leaveLayout {
	l := leaveLayout{
		Config:    ConfigPath,
		Units:     []string{unitPath, labBootDeadlineUnitPath, labBootSessionUnitPath, labBootLockUnitPath},
		UnitNames: []string{"lab-agent.service", labBootDeadlineUnitName, labBootSessionUnitName, labBootLockUnitName},
		DropIns:   []string{labBootAutologinPath, sysctlPath, watchdogCfg, serialGettyDropIn, sddmAutologinConf},
		Stage:     stageDir(),
		WorkDir:   "/var/lib/maclab",
	}
	switch b, _ := detectBootloader(); b := b.(type) {
	case *limineLayout:
		l.LimineConf, l.Stage = b.Conf, b.Stage
	case *grubLayout:
		l.GrubDir, l.GrubEnv = b.Dir, b.EnvFile
	}
	return l
}

var reGrubHook = regexp.MustCompile(`(?s)\n?` + regexp.QuoteMeta(hookMarker) + `.*?# maclab: end\n?`)

// leaveCleanup plans what leaving removes from the Mac described by l,
// reading the current limine.conf / custom.cfg from disk. It changes nothing.
func leaveCleanup(l leaveLayout) (leavePlan, error) {
	p := leavePlan{Rewrite: map[string]string{}}
	remove := func(paths ...string) {
		for _, f := range paths {
			if _, err := os.Lstat(f); f != "" && err == nil {
				p.Remove = append(p.Remove, f)
			}
		}
	}
	p.Disable = append(p.Disable, l.UnitNames...)
	remove(l.Units...)
	remove(l.DropIns...)
	remove(l.Config, l.Stage)
	if l.WorkDir != "" {
		remove(filepath.Join(l.WorkDir, "known-good.json"), filepath.Join(l.WorkDir, "known-good.json.prev"), filepath.Join(l.WorkDir, labBootDir))
	}

	if l.LimineConf != "" {
		conf, err := os.ReadFile(l.LimineConf)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return p, err
		}
		if reMaclabBlock.Match(conf) {
			p.Rewrite[l.LimineConf] = strings.TrimRight(reMaclabBlock.ReplaceAllString(string(conf), "\n"), "\n") + "\n"
		}
	}
	if l.GrubDir != "" {
		custom := filepath.Join(l.GrubDir, "custom.cfg")
		b, err := os.ReadFile(custom)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return p, err
		}
		if reGrubHook.Match(b) {
			rest := reGrubHook.ReplaceAllString(string(b), "\n")
			if strings.TrimSpace(rest) == "" {
				remove(custom) // the lab made it
			} else {
				p.Rewrite[custom] = strings.TrimRight(rest, "\n") + "\n"
			}
		}
		remove(custom+".pre-maclab", filepath.Join(l.GrubDir, maclabCfg), l.GrubEnv)
	}
	p.ByHand = leftByHand(l.WorkDir)
	return p, nil
}

// leftByHand is what leaving does not remove, for the Volunteer to.
func leftByHand(workDir string) []string {
	if workDir == "" {
		workDir = "/var/lib/maclab"
	}
	return []string{
		"The lab-agent package: remove it with your package manager (or delete /usr/local/bin/lab-agent). It no longer runs, but the program is still installed.",
		"The Tailscale node: run `sudo tailscale logout`, and ask a Maintainer to delete the node from the tailnet if it is still listed.",
		"Your Audit log, " + filepath.Join(workDir, auditFile) + ", stays on your Mac for you to read with `sudo lab-agent log`; delete it yourself if you want it gone.",
	}
}

// apply carries the plan out on this Mac. The units go first so nothing of
// the lab restarts. lab-agent's own is only disabled, never stopped: it may be
// the process running this, and it exits by itself once it has left.
// keepAgent leaves lab-agent's unit in place, for when labd has not yet been
// told: it tells labd at the next chance and then finishes leaving.
func (p leavePlan) apply(keepAgent bool) error {
	for _, u := range p.Disable {
		if u != "lab-agent.service" {
			exec.Command("systemctl", "disable", "--now", u).Run()
		} else if !keepAgent {
			exec.Command("systemctl", "disable", u).Run()
		}
	}
	var errs []error
	for path, content := range p.Rewrite {
		if err := rewriteBootFile(path, content); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		// the boot entries still list the staged kernels: keep them
		return errors.Join(errs...)
	}
	for _, f := range p.Remove {
		if keepAgent && f == unitPath {
			continue
		}
		if err := os.RemoveAll(f); err != nil {
			errs = append(errs, err)
		}
	}
	exec.Command("systemctl", "daemon-reload").Run()
	syncDisks()
	return errors.Join(errs...)
}

// rewriteBootFile replaces a boot file the lab edited. limine.conf is written
// under the same locks Omarchy's Limine tools take.
func rewriteBootFile(path, content string) error {
	if unlock, err := lockBootPartition(time.Minute); err == nil {
		defer unlock()
	} else if strings.HasSuffix(path, "limine.conf") {
		return err
	}
	return writeSynced(path, []byte(content))
}

// LeaveLab removes the lab from this Mac (see leaveCleanup). keepAgent keeps
// lab-agent itself until labd has been told.
func (l *Linux) LeaveLab(keepAgent bool) error {
	if b, err := detectBootloader(); err == nil {
		b.disarm() // no lab entry may be left armed to boot
	}
	p, err := leaveCleanup(defaultLeaveLayout())
	if err != nil {
		return err
	}
	return p.apply(keepAgent)
}

// LeaveLab removes the lab's boot entries from the simulated Mac.
func (s *Sim) LeaveLab(keepAgent bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staged, s.armed = map[string]simEntry{}, ""
	return nil
}

// LeavingStagedEntries is how many lab boot entries the Sim still has staged.
func (s *Sim) LeavingStagedEntries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.staged)
}

// ---- the record of a Mac that left ----

// leftFile is, under the work directory, the record that this Mac has left
// the lab. It holds what lab-agent needs to tell labd until labd has been
// told, then nothing secret. Setup removes it when the Mac enrolls again.
const leftFile = "left.json"

type left struct {
	Server   string    `json:"server"`
	DeviceID string    `json:"device_id"`
	Name     string    `json:"name"`
	Secret   string    `json:"secret,omitempty"` // until labd has been told
	EndedBy  string    `json:"ended_by,omitempty"`
	Time     time.Time `json:"time"`
	Told     bool      `json:"told"` // labd knows: the Maintainers ended it, or it has been told
}

func readLeft(workDir string) (*left, error) {
	b, err := os.ReadFile(filepath.Join(workDir, leftFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r left
	return &r, json.Unmarshal(b, &r)
}

func writeLeft(workDir string, r *left) error {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	tmp := filepath.Join(workDir, leftFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(workDir, leftFile))
}

// tellLabd tells labd this Mac has left. A refusal of the secret counts as
// told: labd no longer knows the Mac.
func (r *left) tellLabd(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := postJSON(ctx, http.DefaultClient, strings.TrimRight(r.Server, "/")+"/api/agent/left", r.Secret, struct{}{}, nil)
	var se *statusError
	return err == nil || (errors.As(err, &se) && se.Code == http.StatusUnauthorized)
}

// finishLeaving tells labd of a Mac that left, retrying every few seconds
// until it can, and then removes lab-agent itself. Nothing to do when this
// Mac has not left.
func finishLeaving(ctx context.Context, c Clock, workDir string, sys System, logf func(string, ...any)) error {
	for {
		r, err := readLeft(workDir)
		if err != nil || r == nil {
			return err
		}
		if !r.Told {
			if !r.tellLabd(ctx) {
				logf("this Mac has left the lab; labd has not been told yet, trying again")
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-c.After(5 * time.Second):
				}
				continue
			}
			r.Told, r.Secret = true, ""
			if err := writeLeft(workDir, r); err != nil {
				return err
			}
		}
		return sys.LeaveLab(false)
	}
}

// leaveMac does everything leaving does on the Mac itself: the record that it
// left, telling labd if it can, removing the lab, and the way back to the
// Mac's own system from a Lab boot. rec.Told says labd already knows.
func leaveMac(ctx context.Context, cfg *Config, sys System, rec *left) error {
	if err := writeLeft(cfg.workDir(), rec); err != nil {
		return fmt.Errorf("lab-agent could not record that this Mac left: %w", err)
	}
	if !rec.Told && rec.tellLabd(ctx) {
		rec.Told, rec.Secret = true, ""
		writeLeft(cfg.workDir(), rec)
	}
	err := sys.LeaveLab(!rec.Told)
	if _, _, cmdline := sys.Identity(); IsLabBoot(cmdline) {
		if rerr := sys.Reboot(); err == nil {
			err = rerr
		}
	}
	return err
}

// leaveCmd is `leave --yes`: the Volunteer leaving the lab at once.
func leaveCmd(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("leave needs your confirmation, and there is no terminal to ask on: run `sudo lab-agent leave --yes` to leave the lab")
	}
	if len(args) != 1 || args[0] != "--yes" {
		return errors.New("usage: leave [--yes]")
	}
	if macIsLabOwned(ctx, cfg) {
		return errors.New("a Lab-owned Mac has no Volunteer to leave: the Maintainers end its enrollment")
	}
	rec := &left{Server: cfg.Server, DeviceID: cfg.DeviceID, Name: cfg.Name, Secret: cfg.Secret, Time: cfg.clock().Now()}
	err := leaveMac(ctx, cfg, sys, rec)
	fmt.Fprintf(out, "%s has left the lab: any job stopped, the lab's boot entries, units and device secret are removed, and the Mac boots its own system.\n", cfg.Name)
	if !rec.Told {
		fmt.Fprintln(out, "labd could not be reached; lab-agent tells it as soon as it can, and finishes leaving then.")
	}
	fmt.Fprintln(out, "Left for you to remove by hand:")
	for _, s := range leftByHand(cfg.workDir()) {
		fmt.Fprintf(out, "  - %s\n", s)
	}
	return err
}

// macIsLabOwned is whether this Mac is Lab-owned, as labd says now or, when it
// can't be reached, as setup recorded.
func macIsLabOwned(ctx context.Context, cfg *Config) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var live api.AgentEnrollment
	if err := getJSON(ctx, http.DefaultClient, strings.TrimRight(cfg.Server, "/")+"/api/agent/enrollment", cfg.Secret, &live); err == nil {
		return live.Kind == api.KindLabOwned
	}
	return cfg.Enrollment.Kind == api.KindLabOwned
}

// ---- the Maintainers ending the enrollment ----

// endedBy is the Maintainer named by labd's answer to a Mac whose enrollment
// they ended.
func endedBy(err error) (string, bool) {
	var se *statusError
	if errors.As(err, &se) && se.Code == http.StatusUnauthorized && se.Header.Get(api.EndedHeader) != "" {
		return se.Header.Get(api.EndedHeader), true
	}
	return "", false
}

// enrollmentEnded is lab-agent learning that Maintainer by ended this Mac's
// enrollment: it records it in the Audit log first, tells the Volunteer on
// the desktop (labd has told their ntfy topic), and leaves as the Volunteer
// would. It runs once.
func (a *Agent) enrollmentEnded(by string) {
	a.endedOnce.Do(func() {
		a.log.Printf("%s ended this Mac's enrollment", by)
		a.halt(errLeft)
		e := api.AuditEntry{Time: a.clock().Now(), Maintainer: by, Action: "ended this Mac's enrollment in the lab; lab-agent removed the lab from this Mac"}
		if err := appendAudit(a.workDir(), e); err != nil {
			a.log.Printf("Audit log: %v", err)
		}
		desktopNotice(a.sys, a.cfg.GUIUser, fmt.Sprintf("%s ended this Mac's enrollment in the lab. lab-agent is removing the lab from it; `sudo lab-agent log` records it.", by))
		rec := &left{Server: a.cfg.Server, DeviceID: a.cfg.DeviceID, Name: a.cfg.Name, EndedBy: by, Time: a.clock().Now(), Told: true}
		if err := leaveMac(a.life, a.cfg, a.sys, rec); err != nil {
			a.log.Printf("leaving: %v", err)
		}
		a.stop()
	})
}

// errLeft is why lab-agent stops what a Mac that left was running.
var errLeft = errors.New("this Mac left the lab")

// halt stops every command lab-agent is running.
func (a *Agent) halt(cause error) {
	a.mu.Lock()
	var all []runningCmd
	for _, r := range a.running {
		all = append(all, r)
	}
	a.mu.Unlock()
	for _, r := range all {
		r.stop(cause)
	}
}

// watchLeft sees the Volunteer leave (`lab-agent leave` runs in its own
// process), stops the lab's work and sees the leaving through.
func (a *Agent) watchLeft(ctx context.Context) {
	tick := a.clock().NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C():
		}
		if r, err := readLeft(a.workDir()); err != nil || r == nil {
			continue
		}
		a.hasLeft.Store(true)
		a.halt(errLeft)
		if err := finishLeaving(ctx, a.clock(), a.workDir(), a.sys, a.log.Printf); err != nil && ctx.Err() == nil {
			a.log.Printf("leaving: %v", err)
		}
		a.stop()
		return
	}
}

// Farewell is what lab-agent does when it starts on a Mac that has left but
// has not yet told labd: tell it, then finish leaving.
func Farewell(ctx context.Context, workDir string, sys System, logf func(string, ...any)) error {
	return finishLeaving(ctx, WallClock, workDir, sys, logf)
}

// HasLeft is whether the Mac has left the lab.
func HasLeft(workDir string) bool {
	r, err := readLeft(workDir)
	return err == nil && r != nil
}

// desktopNotice shows the Volunteer a notice on their desktop.
func desktopNotice(sys System, guiUser, text string) {
	if n, ok := sys.(interface{ Notify(string) }); ok {
		n.Notify(text)
		return
	}
	u, env, err := guiEnv(guiUser, 0)
	if err != nil {
		return
	}
	exec.Command("runuser", append([]string{"-u", u.Username, "--", "env"}, append(env, "notify-send", "-u", "critical", "maclab", text)...)...).Run()
}

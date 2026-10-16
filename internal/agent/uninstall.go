package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

type UninstallOptions struct {
	Force  bool // even with a job in flight: its one-shot and staged kernel go too
	DryRun bool // print each action without taking it
	Log    func(format string, args ...any)
}

// Uninstall undoes everything setup did, so a volunteer's Mac leaves the lab
// as it came. Like setup it is idempotent: it acts only on what is still there.
func Uninstall(o UninstallOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must run as root")
	}
	if b, _ := os.ReadFile("/proc/self/cgroup"); bytes.Contains(b, []byte("/lab-agent.service")) {
		return fmt.Errorf("run uninstall from a shell on the Mac, not through the lab: stopping lab-agent.service would kill it")
	}
	_, kernel, cmdline := (&Linux{}).Identity()
	u := &uninstaller{dry: o.DryRun, force: o.Force, say: o.Log, running: kernel, cmdline: cmdline, cmd: runCmd, home: homeDir, bootTime: bootTime(), leave: Leave}
	u.boot, u.bootErr = detectBootloader()
	return u.uninstall()
}

// uninstaller undoes setup under root ("" on a Mac, a temp dir in tests).
type uninstaller struct {
	root    string
	dry     bool
	force   bool
	say     func(format string, args ...any)
	running string // the running kernel release
	cmdline string
	boot    bootloader // nil when bootErr says why
	bootErr error
	cmd     func(name string, args ...string) error
	home    func(user string) (string, error)
	// bootTime is when this boot started. Work files older than it are left
	// from a boot that crashed or hung mid-command, not a job in flight; zero
	// counts them all.
	bootTime time.Time
	acted    int
	removed  map[string]bool // so a dry run sees the directories it would empty
	// leave tells labd the Mac is leaving the lab (Leave); nil tells no one.
	leave func(cfg *Config, req api.LeaveRequest) (*api.LeaveResponse, error)
	// heard is what labd made of it: "told", "forgotten" (it no longer knows
	// the Mac), or "" when no one was asked or it couldn't be reached; then
	// todo is what to run on the controller instead.
	heard, todo string
}

// Leave tells labd, with the device secret in cfg, that the Mac is leaving the
// lab: labd cancels its jobs and stops recovering it.
func Leave(cfg *Config, req api.LeaveRequest) (*api.LeaveResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var resp api.LeaveResponse
	err := postJSON(ctx, http.DefaultClient, strings.TrimRight(cfg.Server, "/")+"/api/agent/leave", cfg.Secret, req, &resp)
	return &resp, err
}

func runCmd(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func homeDir(user string) (string, error) {
	u, err := osuser.Lookup(user)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

func (u *uninstaller) path(p ...string) string {
	return filepath.Join(append([]string{u.root}, p...)...)
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// do prints one action and takes it; a dry run only prints it.
func (u *uninstaller) do(f func() error, format string, args ...any) error {
	u.acted++
	if u.dry {
		u.say("would "+format, args...)
		return nil
	}
	u.say(format, args...)
	if err := f(); err != nil {
		return fmt.Errorf(format+": %w", append(args, err)...)
	}
	return nil
}

// remove deletes p, and everything under it, if it is there.
func (u *uninstaller) remove(p, why string) error {
	if !exists(p) {
		return nil
	}
	if u.removed == nil {
		u.removed = map[string]bool{}
	}
	u.removed[p] = true
	return u.do(func() error { return os.RemoveAll(p) }, "remove %s%s", p, why)
}

// removeEmptyDir deletes a directory setup created, once nothing is left in it.
func (u *uninstaller) removeEmptyDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if !u.removed[filepath.Join(dir, e.Name())] {
			return nil
		}
	}
	return u.do(func() error { return os.Remove(dir) }, "remove empty %s", dir)
}

func (u *uninstaller) systemctl(args ...string) error {
	return u.do(func() error { return u.cmd("systemctl", args...) }, "run systemctl %s", strings.Join(args, " "))
}

// busy lists the signs of a job in flight: an armed lab one-shot, a staged
// test kernel (a job removes its own when it ends), or a job's work files.
func (u *uninstaller) busy() []string {
	var b []string
	if u.boot != nil {
		if e := u.boot.armed(); strings.HasPrefix(e, entryPrefix) {
			b = append(b, "one-shot boot into "+e+" is armed")
		}
	}
	for _, dir := range u.stageDirs() {
		jobs, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, j := range jobs {
			b = append(b, "job "+filepath.Base(j)+" is staged in "+dir)
		}
	}
	for _, sub := range []string{"jobs", "out"} {
		ents, _ := os.ReadDir(u.path(workDir, sub))
		n := 0
		for _, e := range ents {
			if info, err := e.Info(); err == nil && info.ModTime().After(u.bootTime) {
				n++
			}
		}
		if n > 0 {
			b = append(b, fmt.Sprintf("%d job work dirs from this boot in %s", n, u.path(workDir, sub)))
		}
	}
	return b
}

// inFlight lists the jobs busy finds signs of, by ID.
func (u *uninstaller) inFlight() []string {
	var ids []string
	if u.boot != nil {
		if e, ok := strings.CutPrefix(u.boot.armed(), entryPrefix); ok {
			ids = append(ids, e)
		}
	}
	for _, dir := range u.stageDirs() {
		jobs, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, j := range jobs {
			ids = append(ids, filepath.Base(j))
		}
	}
	ents, _ := os.ReadDir(u.path(workDir, "jobs"))
	for _, e := range ents {
		if info, err := e.Info(); err == nil && info.ModTime().After(u.bootTime) {
			ids = append(ids, e.Name())
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// tellLabd tells labd, before anything is undone, that this Mac is leaving.
// Otherwise labd reads the agent stopping as a Mac that hung: with a job in
// flight it resets the Mac through its out-of-band controller, twice, and
// then asks a human to power cycle it. Uninstall goes on whether or not labd
// hears it, and says what to run on the controller if it doesn't.
func (u *uninstaller) tellLabd(cfg *Config) {
	if u.leave == nil || cfg == nil || cfg.Server == "" || cfg.Secret == "" {
		return
	}
	jobs := u.inFlight()
	why := "lab-agent uninstall"
	if u.force {
		why += " --force"
	}
	if len(jobs) > 0 {
		why += " with " + strings.Join(jobs, ", ") + " in flight"
	}
	if u.dry {
		u.say("would tell labd at %s that %s is leaving the lab", cfg.Server, cfg.Name)
		return
	}
	resp, err := u.leave(cfg, api.LeaveRequest{Reason: why, Jobs: jobs})
	switch {
	case err == nil:
		u.heard = "told"
		msg := ""
		if len(resp.Canceled) > 0 {
			msg = "; it canceled " + strings.Join(resp.Canceled, ", ")
		}
		u.say("told labd at %s that %s is leaving the lab%s", cfg.Server, cfg.Name, msg)
	case strings.HasPrefix(err.Error(), "401 "):
		u.heard = "forgotten" // no device has this secret
		u.say("labd at %s no longer knows this Mac (lab forget already ran)", cfg.Server)
	default:
		u.todo = labdSteps(cfg.Name, jobs)
		u.say("labd at %s was not told that %s is leaving the lab (%v): it may reset this Mac and ask for hands. On the controller, run %s",
			cfg.Server, cfg.Name, err, u.todo)
	}
}

// labdSteps is what to run on the controller when labd wasn't told.
func labdSteps(name string, jobs []string) string {
	cancel := fmt.Sprintf("`lab cancel <job>` for each job `lab jobs %s` lists as running or queued", name)
	if len(jobs) > 0 {
		cancel = "`lab cancel " + strings.Join(jobs, "`, `lab cancel ") + "`"
	}
	return cancel + ", then `lab forget " + name + "`"
}

// bootTime is when the running boot started, from /proc/uptime.
func bootTime() time.Time {
	var up float64
	if _, err := fmt.Sscan(readTrim("/proc/uptime"), &up); err != nil {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(up * float64(time.Second)))
}

// stageDirs are where setup may have put staged test kernels: only the
// lab's own fixed paths, never whatever a record names.
func (u *uninstaller) stageDirs() []string {
	switch b := u.boot.(type) {
	case *limineLayout:
		return []string{b.Stage}
	case *grubLayout:
		return []string{u.path(defaultStage), u.path(altStage)}
	}
	return nil
}

func (u *uninstaller) uninstall() error {
	if tag := jobTag(u.cmdline); tag != "" {
		return fmt.Errorf("running a lab kernel (job %s); reboot into your normal kernel before uninstall", tag)
	}
	if u.bootErr != nil && !u.force {
		return fmt.Errorf("bootloader: %w; fix that (is the ESP mounted?), or pass --force to leave the bootloader alone", u.bootErr)
	}
	if b := u.busy(); len(b) > 0 && !u.force {
		return fmt.Errorf("a job is in flight (%s); wait for it to end, or pass --force to remove it too", strings.Join(b, "; "))
	}
	if err := u.enrolled(); err != nil {
		return err
	}
	cfg, _ := LoadConfig(u.path(ConfigPath))
	// The known-good kernel (and the one before a promotion) may be a kernel
	// the lab installed: its modules carry the marker too.
	var knownGood []string
	for _, f := range []string{"known-good.json", "known-good.json.prev"} {
		var kg KnownGood
		if b, err := os.ReadFile(u.path(workDir, f)); err == nil && json.Unmarshal(b, &kg) == nil && kg.Kernel != "" {
			knownGood = append(knownGood, kg.Kernel)
		}
	}

	u.tellLabd(cfg)
	// A running agent could arm a one-shot or rewrite limine.conf
	// mid-uninstall: nothing else changes until it is stopped.
	if err := u.service(); err != nil {
		return fmt.Errorf("%w; uninstall stopped there and left the rest: run it again once lab-agent.service is stopped", err)
	}
	var errs []error
	// Each step stops at its first failure; the next still runs.
	for _, step := range []func() error{
		u.bootloader,
		func() error { return u.modules(knownGood) },
		func() error {
			return u.remove(u.path(sysctlPath), " (kernel.panic goes back to the distro's at the next boot)")
		},
		u.watchdog,
		u.journald,
		u.serialGetty,
		u.autologin,
		func() error { return u.remove(u.path(filepath.Dir(ConfigPath)), " (the device secret)") },
		func() error { return u.remove(u.path(binPath+".new"), "") },
		func() error { return u.remove(u.path(binPath), "") },
	} {
		if err := step(); err != nil {
			errs = append(errs, err)
		}
	}
	// With the bootloader not found (--force), a one-shot may still be armed
	// into the stage in workDir (GRUB's alternative one).
	if u.bootErr != nil {
		u.say("bootloader: %v; left as it is", u.bootErr)
		errs = append(errs, u.bootErr)
	}
	// The records the steps above read go last, and only once they all
	// worked, so running uninstall again can finish the job.
	if len(errs) > 0 {
		u.say("keep %s until the errors below are fixed: run uninstall again then", u.path(workDir))
	} else if err := u.remove(u.path(workDir), ""); err != nil {
		errs = append(errs, err)
	}
	if !u.dry {
		syncDisks() // the ESP is FAT: see syncDisks
	}
	switch {
	case len(errs) > 0:
		return errors.Join(errs...)
	case u.acted == 0:
		u.say("nothing to undo: no lab setup is left on this Mac")
	case u.dry:
		u.say("dry run: nothing was changed")
	case u.todo != "":
		u.say("uninstalled, but labd wasn't told: on the controller, run %s", u.todo)
	case u.heard == "told":
		u.say("uninstalled. labd lists this Mac as %s, left: `lab forget %s` takes it off the list", cfg.Name, cfg.Name)
	case u.heard == "forgotten":
		u.say("uninstalled")
	case cfg != nil && cfg.Name != "":
		u.say("uninstalled. labd still lists this Mac as %s", cfg.Name)
	default:
		u.say("uninstalled")
	}
	return nil
}

// enrolled refuses to take the maclab block out of limine.conf while Limine
// config enrollment is on. With a checksum enrolled in a Limine binary, the
// Mac would not boot again; the lab has no way to enroll the edited file.
// With ENABLE_ENROLL_LIMINE_CONFIG=yes and none enrolled yet, any Limine
// update or snapshot sync could enroll one, block and all, between this
// check and the edit. Either way enrollment goes off first.
func (u *uninstaller) enrolled() error {
	l, ok := u.boot.(*limineLayout)
	if !ok {
		return nil
	}
	if conf, err := os.ReadFile(l.Conf); err != nil || !reMaclabBlock.Match(conf) {
		return nil // uninstall leaves limine.conf as it is
	}
	if why := l.enrollment(u.path("/etc/default/limine")); why != "" {
		return fmt.Errorf("uninstall takes the maclab block out of %s, and %s; then run uninstall again", l.Conf, why)
	}
	return nil
}

// service stops the agent first, so labd can't start anything mid-uninstall.
func (u *uninstaller) service() error {
	unit := u.path(unitPath)
	if !exists(unit) {
		return nil
	}
	if err := u.systemctl("disable", "--now", "lab-agent.service"); err != nil {
		return err
	}
	if err := u.remove(unit, ""); err != nil {
		return err
	}
	return u.systemctl("daemon-reload")
}

func (u *uninstaller) bootloader() error {
	if u.boot == nil {
		return nil
	}
	// Only the lab's own one-shot: someone else's reboot into an entry stays.
	if e := u.boot.armed(); strings.HasPrefix(e, entryPrefix) {
		if err := u.do(u.boot.disarm, "clear the one-shot boot into %s", e); err != nil {
			return err
		}
	}
	switch b := u.boot.(type) {
	case *limineLayout:
		return u.limine(b)
	case *grubLayout:
		return u.grub(b)
	}
	return nil
}

// limine removes the marked block from limine.conf and the staged UKIs, under
// the same locks as writeEntries: a snapshot sync rewriting limine.conf at the
// same time could otherwise put the block back or lose its own change.
func (u *uninstaller) limine(l *limineLayout) error {
	conf, err := os.ReadFile(l.Conf)
	if err != nil {
		return err
	}
	block := reMaclabBlock.Match(conf)
	// Its entries name the staged UKIs: they stay until the block can go.
	if !block && bytes.Contains(conf, []byte(limineBegin)) {
		return fmt.Errorf("%s: the maclab block has no %q line; remove it by hand", l.Conf, limineEnd)
	}
	// writeSynced's temporary copies, left by a write the Mac died during
	tmps := []string{l.Conf + ".tmp"}
	if l.VarFile != "" {
		tmps = append(tmps, l.VarFile+".tmp")
	}
	if !block && !exists(l.Stage) && !slices.ContainsFunc(tmps, exists) {
		return nil
	}
	if !u.dry {
		unlock, err := lockBootPartition(time.Minute)
		if err != nil {
			return err
		}
		defer unlock()
	}
	if block {
		if err := u.do(l.removeEntriesLocked, "remove the maclab block from %s", l.Conf); err != nil {
			return err
		}
	}
	if err := u.remove(l.Stage, " (staged test kernels)"); err != nil {
		return err
	}
	for _, t := range tmps {
		if err := u.remove(t, " (left by an interrupted write)"); err != nil {
			return err
		}
	}
	// U-Boot's variable file from before setup is not restored: it would drop
	// every variable set since (boot order, the firmware's own). The lab only
	// ever added and removed LoaderEntryOneShot in it, and the one-shot is
	// cleared above and persisted the way disarm does.
	if l.VarFile != "" && exists(l.VarFile+".pre-maclab") {
		u.say("keep %s.pre-maclab (U-Boot's variables before setup): restoring it would drop any set since", l.VarFile)
	}
	return nil
}

// grub takes the one-shot hook out of custom.cfg, then the lab's own files.
func (u *uninstaller) grub(g *grubLayout) error {
	if err := u.unhook(g); err != nil {
		return err
	}
	for _, p := range []string{filepath.Join(g.Dir, maclabCfg), filepath.Join(g.Dir, maclabCfg+".tmp"), g.EnvFile, u.path(defaultStage)} {
		if err := u.remove(p, ""); err != nil {
			return err
		}
	}
	return nil // altStage is in workDir, which goes last
}

// unhook restores custom.cfg from setup's backup when, without the hook, it
// is still what setup found. If it was edited since, only the hook goes and
// the backup stays for comparison.
func (u *uninstaller) unhook(g *grubLayout) error {
	custom := filepath.Join(g.Dir, "custom.cfg")
	bak := custom + ".pre-maclab"
	cur, err := os.ReadFile(custom)
	if os.IsNotExist(err) || (err == nil && !bytes.Contains(cur, []byte(hookMarker))) {
		// custom.cfg was restored, but the Mac died before the backup went:
		// it holds nothing custom.cfg doesn't
		if old, berr := os.ReadFile(bak); err == nil && berr == nil && bytes.Equal(old, cur) {
			return u.remove(bak, " (custom.cfg was already restored from it)")
		}
		return nil
	} else if err != nil {
		return err
	}
	rest, ok := stripHook(cur)
	if !ok {
		return fmt.Errorf("%s: the maclab hook has no \"# maclab: end\" line; remove it by hand", custom)
	}
	old, berr := os.ReadFile(bak)
	switch {
	case berr == nil && strings.TrimRight(string(rest), "\n") == strings.TrimRight(string(old), "\n"):
		if err := u.do(func() error { return writeAtomic(custom, old) }, "restore %s from %s", custom, filepath.Base(bak)); err != nil {
			return err
		}
		return u.remove(bak, "")
	case berr == nil:
		return u.do(func() error { return writeAtomic(custom, rest) }, "remove the one-shot hook from %s (edited since setup: %s kept)", custom, filepath.Base(bak))
	case len(bytes.TrimSpace(rest)) == 0:
		return u.remove(custom, " (setup created it for the one-shot hook)")
	default:
		return u.do(func() error { return writeAtomic(custom, rest) }, "remove the one-shot hook from %s", custom)
	}
}

// modules removes the test kernels' modules the lab installed, each marked
// with markerFile. Nothing unmarked, never the running kernel, never the
// known-good ones, and nothing at all without the known-good record.
func (u *uninstaller) modules(knownGood []string) error {
	marks, _ := filepath.Glob(u.path("/usr/lib/modules", "*", markerFile))
	for _, m := range marks {
		dir, job := filepath.Dir(m), readTrim(m)
		krel := filepath.Base(dir)
		switch {
		case job == "":
		case krel == u.running:
			u.say("keep %s (job %s): it is the running kernel", dir, job)
		case len(knownGood) == 0:
			u.say("keep %s (job %s): with no known-good record, it may be the kernel this Mac boots", dir, job)
		case slices.Contains(knownGood, krel):
			u.say("keep %s (job %s): it is the known-good kernel", dir, job)
		default:
			if err := u.do(func() error { return os.RemoveAll(dir) }, "remove %s (test kernel of job %s)", dir, job); err != nil {
				return err
			}
		}
	}
	return nil
}

func (u *uninstaller) watchdog() error {
	wd := u.path(watchdogCfg)
	if !exists(wd) {
		return nil
	}
	if err := u.remove(wd, ""); err != nil {
		return err
	}
	if err := u.removeEmptyDir(filepath.Dir(wd)); err != nil {
		return err
	}
	return u.systemctl("daemon-reexec")
}

// journaldCfg is the lab's own journald drop-in, which turns persistent
// storage on so a crashed lab boot's logs survive the reboot.
const journaldCfg = "/etc/systemd/journald.conf.d/90-maclab.conf"

// journald removes the lab's journald drop-in, if there is one, and restarts
// journald so the distro's storage setting applies again. The journal kept
// on disk stays.
func (u *uninstaller) journald() error {
	jc := u.path(journaldCfg)
	if !exists(jc) {
		return nil
	}
	if err := u.remove(jc, " (the journal goes back to the distro's setting)"); err != nil {
		return err
	}
	if err := u.removeEmptyDir(filepath.Dir(jc)); err != nil {
		return err
	}
	return u.systemctl("restart", "systemd-journald")
}

// serialGetty removes the lab's getty drop-in and disables the getty, unless
// it was enabled before setup. The running getty is left alone: stopping it
// would end the session of anyone uninstalling over `lab shell`. It drops the
// autologin when it next starts and is gone after the next boot.
func (u *uninstaller) serialGetty() error {
	dropIn := u.path(gettyDropIn)
	if !exists(dropIn) {
		return nil
	}
	// Setups before the record existed always enabled it themselves.
	if !exists(u.path(workDir, gettyWasEnabled)) {
		if err := u.systemctl("disable", "serial-getty@ttySAC0.service"); err != nil {
			return err
		}
	}
	if err := u.remove(dropIn, ""); err != nil {
		return err
	}
	if err := u.removeEmptyDir(filepath.Dir(dropIn)); err != nil {
		return err
	}
	return u.systemctl("daemon-reload")
}

// autologin removes the lab's SDDM autologin and turns Omarchy's stay-awake
// off for the user it named, unless that user had it on before setup.
func (u *uninstaller) autologin() error {
	conf := u.path(sddmConf)
	b, err := os.ReadFile(conf)
	if err != nil {
		return nil
	}
	user := ""
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "User="); ok {
			user = strings.TrimSpace(v)
		}
	}
	if user != "" && !exists(u.path(workDir, stayAwakeWasOn)) {
		home, err := u.home(user)
		var gone osuser.UnknownUserError
		switch {
		case errors.As(err, &gone):
			u.say("autologin user %s no longer exists: no stay-awake to turn off", user)
		case err != nil:
			return fmt.Errorf("autologin user %s: %w", user, err)
		default:
			if f := filepath.Join(home, stayAwake); exists(f) {
				// as the user, like setup: root must not follow links in their home
				if err := u.do(func() error { return u.cmd("runuser", "-u", user, "--", "rm", "-f", f) },
					"turn Omarchy's stay-awake off for %s (remove %s)", user, f); err != nil {
					return err
				}
			}
		}
	}
	if err := u.remove(conf, ""); err != nil {
		return err
	}
	return u.removeEmptyDir(filepath.Dir(conf))
}

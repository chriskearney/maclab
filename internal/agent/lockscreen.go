package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// A Volunteer's Mac never loses its lock screen to the lab. Tests need a
// logged-in Wayland session for the GUI user, not an unlocked screen, so a
// Lab boot logs the GUI user in and locks the session at once. The autologin
// is decided per boot from the command line and lives under /run, so any boot
// of the Volunteer's own entry (a deadline fallback, a power cut) can't have it.

// AutologinDropIn is the SDDM drop-in a Lab boot gets.
type AutologinDropIn struct {
	Path    string // under /run, so it never outlives the boot
	Content string
}

const labBootAutologinPath = "/run/sddm.conf.d/zz-maclab-lab-boot-autologin.conf"

// labBootAutologin is the drop-in a boot needs, if any: only a Lab boot of a
// Volunteer's unencrypted Mac with a GUI user. A Lab-owned Mac keeps its
// permanent autologin, and an encrypted Mac keeps the one Omarchy's installer
// set (the disk password prompt is its auth boundary).
func labBootAutologin(cmdline, kind, guiUser string, encrypted bool) (AutologinDropIn, bool) {
	if !IsLabBoot(cmdline) || kind != api.KindVolunteer || guiUser == "" || encrypted {
		return AutologinDropIn{}, false
	}
	return AutologinDropIn{Path: labBootAutologinPath, Content: fmt.Sprintf(
		"# maclab: this is a Lab boot, so the GUI user is logged in (and locked at once). Gone with the boot.\n[Autologin]\nUser=%s\nSession=%s\nRelogin=false\n",
		guiUser, desktopSession())}, true
}

// lockCommand is Omarchy's own lock: Quickshell's omarchy-system-lock on
// current Omarchy, hyprlock on older ones.
func lockCommand(has func(name string) bool) ([]string, bool) {
	for _, name := range []string{"omarchy-system-lock", "hyprlock"} {
		if has(name) {
			return []string{name}, true
		}
	}
	return nil, false
}

const (
	labBootSessionUnitName = "maclab-lab-boot-session.service"
	labBootSessionUnitPath = "/etc/systemd/system/" + labBootSessionUnitName
	labBootLockUnitName    = "maclab-lab-boot-lock.service"
	labBootLockUnitPath    = "/etc/systemd/system/" + labBootLockUnitName
)

// labBootSessionUnit writes the autologin drop-in, before SDDM starts.
func labBootSessionUnit() string {
	return `[Unit]
Description=maclab: log the GUI user in on a Lab boot of a Volunteer's Mac
DefaultDependencies=no
After=local-fs.target
Before=sddm.service display-manager.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + binPath + ` lab-boot-session

[Install]
WantedBy=sysinit.target
`
}

// labBootLockUnit locks the session the drop-in logged in.
func labBootLockUnit() string {
	return `[Unit]
Description=maclab: lock the GUI user's session on a Lab boot of a Volunteer's Mac
After=display-manager.service

[Service]
ExecStart=` + binPath + ` lab-boot-lock

[Install]
WantedBy=graphical.target
`
}

func desktopSession() string {
	if b, err := os.ReadFile("/var/lib/sddm/state.conf"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Session="); ok && v != "" {
				return filepath.Base(strings.TrimSpace(v))
			}
		}
	}
	return "hyprland-uwsm.desktop"
}

// rootEncrypted is whether the root filesystem sits on a LUKS device. When it
// can't tell, it says yes: the lab then adds no autologin.
func rootEncrypted() bool {
	src, err := exec.Command("findmnt", "-no", "SOURCE", "/").Output()
	if err != nil {
		return true
	}
	dev, _, _ := strings.Cut(strings.TrimSpace(string(src)), "[")
	out, err := exec.Command("lsblk", "-srno", "TYPE", dev).Output()
	return err != nil || strings.Contains(string(out), "crypt")
}

// WriteLabBootAutologin is the unit before SDDM: on a Lab boot of a
// Volunteer's Mac it writes the autologin drop-in under /run.
func WriteLabBootAutologin(cfg *Config, say func(string, ...any)) error {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return err
	}
	cmdline := string(b)
	if !IsLabBoot(cmdline) {
		return nil
	}
	d, ok := labBootAutologin(cmdline, cfg.Enrollment.Kind, cfg.GUIUser, rootEncrypted())
	if !ok {
		say("Lab boot with no autologin drop-in (no GUI user, or an encrypted Mac keeping Omarchy's own)")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(d.Path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(d.Path, []byte(d.Content), 0o644); err != nil {
		return err
	}
	say("Lab boot: %s logs in as %s, locked at once", d.Path, cfg.GUIUser)
	return nil
}

// labBootLockedPath is the lock unit's note of how locking went: "locked", or
// "failed: <why>". The tests of a job wait for it.
const labBootLockedPath = "/run/maclab-lab-boot-lock"

// lockHoldTime is how long the lock process must stay up to count as locked.
const lockHoldTime = 5 * time.Second

// LockLabBootSession locks the GUI user's session once the drop-in has logged
// it in, and notes the result in labBootLockedPath. A session it can't lock is
// terminated: a Lab boot never leaves a Volunteer's session unlocked. A boot
// without the drop-in has nothing to lock.
func LockLabBootSession(cfg *Config, say func(string, ...any)) error {
	if _, err := os.Stat(labBootAutologinPath); err != nil {
		return nil
	}
	err := lockSession(cfg.GUIUser, say)
	if err == nil {
		return nil // locked (with hyprlock, and lifted again by the Volunteer)
	}
	say("%v: terminating the session", err)
	os.WriteFile(labBootLockedPath, []byte("failed: "+err.Error()), 0o644)
	exec.Command("loginctl", "terminate-user", cfg.GUIUser).Run()
	return err
}

// lockSession runs the lock as user and returns once it is up
// (omarchy-system-lock) or when the Volunteer unlocks (hyprlock), or with an
// error if the lock did not come up.
func lockSession(user string, say func(string, ...any)) error {
	argv, ok := lockCommand(func(n string) bool { _, err := exec.LookPath(n); return err == nil })
	if !ok {
		return fmt.Errorf("neither omarchy-system-lock nor hyprlock is installed")
	}
	u, genv, err := guiEnv(user, 2*time.Minute)
	if err != nil {
		return err
	}
	asUser := func(args ...string) *exec.Cmd {
		return exec.Command("runuser", append([]string{"-u", u.Username, "--", "env"}, append(genv, args...)...)...)
	}
	if argv[0] == "omarchy-system-lock" {
		// It asks Omarchy's shell to lock and returns at once, so the shell,
		// not the process, says whether the lock is up. omarchy-shell refuses
		// to run without the session's OMARCHY_PATH, which genv lacks.
		inSession := func(args ...string) *exec.Cmd {
			out, _ := asUser("systemctl", "--user", "show-environment").Output()
			return asUser(append([]string{"OMARCHY_PATH=" + omarchyPath(out)}, args...)...)
		}
		err := confirmShellLock(func() { inSession(argv...).Run() }, func() (shellLock, error) {
			out, err := inSession("omarchy-shell", "lock", "status").Output()
			if err != nil {
				return shellLock{}, err
			}
			return parseShellLock(out)
		}, shellLockWait, time.Second)
		if err != nil {
			return err
		}
		say("locked %s's session with %s", u.Username, argv[0])
		return os.WriteFile(labBootLockedPath, []byte("locked"), 0o644)
	}
	cmd := asUser(argv...)
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		return fmt.Errorf("%s exited at once: %v", argv[0], err)
	case <-time.After(lockHoldTime):
	}
	say("locked %s's session with %s", u.Username, argv[0])
	os.WriteFile(labBootLockedPath, []byte("locked"), 0o644)
	<-exited // the lock stays up until the Volunteer unlocks
	return nil
}

// shellLockWait bounds how long Omarchy's shell gets to come up and confirm
// the lock once the session exists.
const shellLockWait = 30 * time.Second

// shellLock is what `omarchy-shell lock status` reports.
type shellLock struct {
	Locked    bool   `json:"locked"`    // also true once a lock is only requested
	Requested bool   `json:"requested"` // the shell has started locking
	Secure    bool   `json:"secure"`    // the compositor confirmed every output is covered
	LastEvent string `json:"lastEvent"`
}

// omarchyPath is OMARCHY_PATH from the user manager's environment (`systemctl
// --user show-environment`, where uwsm puts the session's), else where
// Omarchy installs itself.
func omarchyPath(showEnv []byte) string {
	for _, l := range strings.Split(string(showEnv), "\n") {
		if v, ok := strings.CutPrefix(l, "OMARCHY_PATH="); ok && v != "" {
			return v
		}
	}
	return "/usr/share/omarchy"
}

func parseShellLock(b []byte) (shellLock, error) {
	var s shellLock
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("omarchy-shell lock status: %w", err)
	}
	return s, nil
}

// confirmShellLock asks for the lock until the shell has started locking, and
// returns once the compositor has secured it. A shell that is not up yet
// fails status; asking again while a lock is underway is left out, since the
// shell takes a second request while locked as a sleep request.
func confirmShellLock(request func(), status func() (shellLock, error), wait, every time.Duration) error {
	deadline := time.Now().Add(wait)
	var last string
	for {
		s, err := status()
		switch {
		case err == nil && s.Secure:
			return nil
		case err != nil:
			last = err.Error()
		default:
			last = "not secured, last event " + s.LastEvent
			if !s.Locked && !s.Requested {
				request()
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Omarchy's shell did not confirm the lock within %s (%s)", wait, last)
		}
		time.Sleep(every)
	}
}

// labBootLockWait bounds how long a job's tests wait for the lock.
const labBootLockWait = 3 * time.Minute

// awaitLabBootLock holds a job's tests back on a Lab boot that logged the GUI
// user in, until the session is locked. If the lock can't be confirmed in
// time, the session is terminated and the job fails.
func (l *Linux) awaitLabBootLock(ctx context.Context) error {
	if _, err := os.Stat(labBootAutologinPath); err != nil {
		return nil
	}
	deadline := time.Now().Add(labBootLockWait)
	for {
		b, _ := os.ReadFile(labBootLockedPath)
		switch got := string(b); {
		case got == "locked":
			return nil
		case strings.HasPrefix(got, "failed"):
			return fmt.Errorf("the Volunteer's session could not be locked (%s); no test ran on it", got)
		case time.Now().After(deadline):
			exec.Command("loginctl", "terminate-user", l.GUIUser).Run()
			return fmt.Errorf("the Volunteer's session was not locked within %s; it was terminated and no test ran on it", labBootLockWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

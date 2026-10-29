package agent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

const lockScreenBase = "root=UUID=abc rw quiet"

func labBootLine() string { return lockScreenBase + " " + strings.Join(labBootParams(0), " ") }

func TestLabBootOnAVolunteersMacGetsAnAutologinDropIn(t *testing.T) {
	d, ok := labBootAutologin(labBootLine(), api.KindVolunteer, "ada", false)
	if !ok {
		t.Fatal("no autologin drop-in on a Lab boot of a Volunteer's Mac")
	}
	if !strings.Contains(d.Content, "[Autologin]") {
		t.Errorf("drop-in has no [Autologin] section:\n%s", d.Content)
	}
}

func TestAutologinDropInLogsInTheVolunteersGuiUser(t *testing.T) {
	d, ok := labBootAutologin(labBootLine(), api.KindVolunteer, "ada", false)
	if !ok {
		t.Fatal("no drop-in")
	}
	var users []string
	for _, l := range strings.Split(d.Content, "\n") {
		if u, ok := strings.CutPrefix(strings.TrimSpace(l), "User="); ok {
			users = append(users, u)
		}
	}
	if len(users) != 1 || users[0] != "ada" {
		t.Errorf("User= lines %v, want exactly [ada]:\n%s", users, d.Content)
	}
}

func TestAutologinDropInLivesUnderRunNeverEtc(t *testing.T) {
	d, ok := labBootAutologin(labBootLine(), api.KindVolunteer, "ada", false)
	if !ok {
		t.Fatal("no drop-in")
	}
	if !strings.HasPrefix(d.Path, "/run/") || strings.HasPrefix(d.Path, "/etc/") || !strings.HasSuffix(d.Path, ".conf") {
		t.Errorf("drop-in path %q: want a .conf under /run, so it never outlives the boot", d.Path)
	}
}

func TestBootWithoutTheLabBootMarkerCannotAutologin(t *testing.T) {
	for name, cmdline := range map[string]string{
		"the Volunteer's own default entry": lockScreenBase,
		"empty command line":                "",
		"a Lab boot's other params only":    lockScreenBase + " panic=10 watchdog.open_timeout=150",
		"marker with another value":         lockScreenBase + " maclab.lab_boot=0",
		"marker as a prefix":                lockScreenBase + " maclab.lab_boot=10",
		"marker as a suffix":                lockScreenBase + " xmaclab.lab_boot=1",
		"marker inside a longer token":      lockScreenBase + " foo=maclab.lab_boot=1",
		"marker name without value":         lockScreenBase + " maclab.lab_boot",
	} {
		if d, ok := labBootAutologin(cmdline, api.KindVolunteer, "ada", false); ok {
			t.Errorf("%s: drop-in written: %+v", name, d)
		}
	}
}

func TestLabBootDropInIsDecidedFromTheCmdlineAlone(t *testing.T) {
	// the marker is where the decision comes from, wherever it sits on the line
	for _, cmdline := range []string{"maclab.lab_boot=1", "maclab.lab_boot=1 " + lockScreenBase, lockScreenBase + " maclab.lab_boot=1  quiet"} {
		if !IsLabBoot(cmdline) {
			t.Fatalf("IsLabBoot(%q) is false", cmdline)
		}
		if _, ok := labBootAutologin(cmdline, api.KindVolunteer, "ada", false); !ok {
			t.Errorf("no drop-in for Lab boot %q", cmdline)
		}
	}
}

func TestVolunteerMacWithoutAGuiUserGetsNoAutologinDropIn(t *testing.T) {
	if d, ok := labBootAutologin(labBootLine(), api.KindVolunteer, "", false); ok {
		t.Errorf("drop-in with no user to log in: %+v", d)
	}
}

func TestEncryptedMacKeepsOmarchysOwnAutologin(t *testing.T) {
	if d, ok := labBootAutologin(labBootLine(), api.KindVolunteer, "ada", true); ok {
		t.Errorf("drop-in on an encrypted Mac, where the installer's autologin stands: %+v", d)
	}
}

func TestLabOwnedMacNeedsNoDropInBecauseItKeepsPermanentAutologin(t *testing.T) {
	if d, ok := labBootAutologin(labBootLine(), api.KindLabOwned, "ada", false); ok {
		t.Errorf("drop-in on a Lab-owned Mac: %+v", d)
	}
}

func TestLockUsesOmarchysQuickshellLockWhenItIsThere(t *testing.T) {
	argv, ok := lockCommand(func(n string) bool { return n == "omarchy-system-lock" || n == "hyprlock" })
	if !ok || len(argv) == 0 || argv[0] != "omarchy-system-lock" {
		t.Errorf("lock command %v (ok=%v), want omarchy-system-lock", argv, ok)
	}
	argv, ok = lockCommand(func(n string) bool { return n == "omarchy-system-lock" })
	if !ok || len(argv) == 0 || argv[0] != "omarchy-system-lock" {
		t.Errorf("lock command %v (ok=%v), want omarchy-system-lock", argv, ok)
	}
}

func TestLockFallsBackToHyprlockOnOlderOmarchy(t *testing.T) {
	argv, ok := lockCommand(func(n string) bool { return n == "hyprlock" })
	if !ok || len(argv) == 0 || argv[0] != "hyprlock" {
		t.Errorf("lock command %v (ok=%v), want hyprlock", argv, ok)
	}
}

func TestNoLockCommandMeansNoLockCommand(t *testing.T) {
	if argv, ok := lockCommand(func(string) bool { return false }); ok {
		t.Errorf("lock command %v with neither lock installed", argv)
	}
}

// What a current Omarchy shell answers, unlocked and once the compositor has
// secured the lock.
const (
	shellUnlocked = `{"locked":false,"requested":false,"pending":false,"sessionLocked":false,"secure":false,"realScreens":1,"passwordPam":true,"lastEvent":"init","lastEventAt":""}`
	shellSecured  = `{"locked":true,"requested":true,"pending":false,"sessionLocked":true,"secure":true,"realScreens":1,"passwordPam":true,"lastEvent":"locked","lastEventAt":""}`
)

func TestShellLockStatusParses(t *testing.T) {
	for in, want := range map[string]bool{shellUnlocked: false, shellSecured: true} {
		s, err := parseShellLock([]byte(in))
		if err != nil || s.Secure != want {
			t.Errorf("parse %s: secure %v, %v; want %v", in, s.Secure, err, want)
		}
	}
	if _, err := parseShellLock([]byte("not json")); err == nil {
		t.Error("garbage status parsed")
	}
}

// omarchy-system-lock returns at once; the lock counts once the shell, which
// may not be up yet, says the compositor secured it.
func TestShellLockIsConfirmedOnceSecured(t *testing.T) {
	answers := []func() (shellLock, error){
		func() (shellLock, error) { return shellLock{}, errors.New("shell not running") },
		func() (shellLock, error) { return shellLock{}, nil },
		func() (shellLock, error) { return shellLock{Locked: true, Requested: true}, nil },
		func() (shellLock, error) { return shellLock{Locked: true, Requested: true, Secure: true}, nil },
	}
	requests, i := 0, 0
	err := confirmShellLock(func() { requests++ }, func() (shellLock, error) { i++; return answers[i-1]() }, time.Second, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if i != len(answers) {
		t.Errorf("confirmed after %d status calls, want %d", i, len(answers))
	}
	// asked once the shell answered unlocked, never while the lock was underway
	if requests != 1 {
		t.Errorf("%d lock requests, want 1", requests)
	}
}

func TestShellLockNeverSecuredFails(t *testing.T) {
	requested := false
	err := confirmShellLock(func() { requested = true }, func() (shellLock, error) {
		return shellLock{Locked: requested, Requested: requested, LastEvent: "pending"}, nil
	}, 20*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "pending") {
		t.Errorf("err %v, want a failure naming the shell's last event", err)
	}
}

// omarchy-shell exits 1 without OMARCHY_PATH, so every status call failed and
// the lock never came up (naeem-naeems-m3-max, job j1028-225951-4248).
func TestOmarchyPathComesFromTheSession(t *testing.T) {
	env := "HOME=/home/ada\nOMARCHY_PATH=/opt/omarchy\nPATH=/usr/bin\n"
	if got := omarchyPath([]byte(env)); got != "/opt/omarchy" {
		t.Errorf("OMARCHY_PATH %q, want the session's /opt/omarchy", got)
	}
	for _, env := range []string{"", "HOME=/home/ada\n", "OMARCHY_PATH=\n", "MY_OMARCHY_PATH=/x\n"} {
		if got := omarchyPath([]byte(env)); got != "/usr/share/omarchy" {
			t.Errorf("OMARCHY_PATH %q from %q, want Omarchy's own /usr/share/omarchy", got, env)
		}
	}
}

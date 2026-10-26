package agent

import (
	"context"
	"encoding/json"
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

// A Lab boot comes back to the Mac's own entry by itself, whatever breaks.
// Its command line reboots a panic (panic=10) and resets an early hang
// (watchdog.open_timeout: the kernel stops feeding the watchdog U-Boot left
// running unless systemd opens it in time). A deadline record, written before
// the boot and enforced by an early systemd unit with no network dependency,
// reboots a boot that never reaches labd or outlives its job. The one-shot is
// spent by then, so every one of these lands on the Known-good kernel.

// defaultWatchdogOpenTimeout is watchdog.open_timeout when labd sets neither
// one nor a boot timeout: labBootDeadline. It covers a slow initramfs; worst
// case the Mac resets about 30 s after it.
const defaultWatchdogOpenTimeout = labBootDeadline

// labBootOpenTimeout is a Lab boot's watchdog.open_timeout: labd's
// --watchdog-open-timeout if it set one, else half the job's boot timeout and
// at least labBootDeadline (bootDeadline).
func labBootOpenTimeout(a api.StageArgs) time.Duration {
	if t := a.WatchdogOpenTimeout(); t > 0 {
		return t
	}
	if a.BootTimeoutSec > 0 {
		return bootDeadline(time.Duration(a.BootTimeoutSec) * time.Second)
	}
	return defaultWatchdogOpenTimeout
}

// labBootMarker on a command line says the boot is a Lab boot.
const labBootMarker = "maclab.lab_boot=1"

// labBootParams are the parameters every Lab boot's command line gains.
func labBootParams(openTimeout time.Duration) []string {
	if openTimeout <= 0 {
		openTimeout = defaultWatchdogOpenTimeout
	}
	return []string{"panic=10", fmt.Sprintf("watchdog.open_timeout=%d", int(openTimeout/time.Second)), labBootMarker}
}

// IsLabBoot is whether a command line carries the Lab boot marker.
func IsLabBoot(cmdline string) bool { return slices.Contains(strings.Fields(cmdline), labBootMarker) }

// IsLabBootParam is whether a command-line token is one lab-agent adds to
// every Lab boot.
func IsLabBootParam(tok string) bool {
	if tok == "panic=10" || tok == labBootMarker {
		return true
	}
	v, ok := strings.CutPrefix(tok, "watchdog.open_timeout=")
	return ok && v != "" && strings.Trim(v, "0123456789") == ""
}

// isLabBootParamName is whether a base command line's token sets something
// labBootParams sets, so a test boot drops it from the base.
func isLabBootParamName(tok string) bool {
	return strings.HasPrefix(tok, "maclab.") || strings.HasPrefix(tok, "panic=") || strings.HasPrefix(tok, "watchdog.open_timeout=") ||
		strings.HasPrefix(tok, "systemd.watchdog_sec=") || strings.HasPrefix(tok, "watchdog.handle_boot_enabled=")
}

// withLabBootParams adds the Lab boot parameters a command line lacks
// (an installed run's comes from labd, panic=10 included).
func withLabBootParams(cmdline string, openTimeout time.Duration) string {
	fields := strings.Fields(cmdline)
	for _, p := range labBootParams(openTimeout) {
		name, _, _ := strings.Cut(p, "=")
		if !slices.ContainsFunc(fields, func(f string) bool { k, _, _ := strings.Cut(f, "="); return k == name }) {
			fields = append(fields, p)
		}
	}
	return strings.Join(fields, " ")
}

// labBootDeadlines is the deadline record lab-agent writes before a Lab boot.
type labBootDeadlines struct {
	Armed     time.Time `json:"armed"`      // when lab-agent armed the Lab boot
	NoContact time.Time `json:"no_contact"` // reboot unless lab-agent has reached labd by then
	Ceiling   time.Time `json:"ceiling"`    // reboot regardless
	// WindowGated is a Volunteer's Mac: the boot also ends as soon as its
	// Availability window closes, at its end or the Volunteer's Pause.
	WindowGated bool `json:"window_gated,omitempty"`
}

// newLabBootDeadlines is the record for a Lab boot starting now: about twice
// the job's boot timeout to reach labd, and the job's end as the ceiling.
func newLabBootDeadlines(now time.Time, bootTimeout time.Duration, jobEnd time.Time) labBootDeadlines {
	return labBootDeadlines{Armed: now, NoContact: now.Add(2 * bootTimeout), Ceiling: jobEnd}
}

// rebootDue is whether the early unit reboots the Mac now.
func rebootDue(d labBootDeadlines, now time.Time, contacted bool) bool {
	return d.due(now, contacted) != ""
}

// due is the deadline that reboots the Mac now, or "".
func (d labBootDeadlines) due(now time.Time, contacted bool) api.Deadline {
	switch {
	case !d.Ceiling.IsZero() && !now.Before(d.Ceiling):
		return api.DeadlineCeiling
	case !contacted && !d.NoContact.IsZero() && !now.Before(d.NoContact):
		return api.DeadlineNoContact
	}
	return ""
}

func writeLabBootDeadlines(path string, d labBootDeadlines) error {
	return writeJSONAtomic(path, d)
}

func readLabBootDeadlines(path string) (labBootDeadlines, error) {
	var d labBootDeadlines
	b, err := os.ReadFile(path)
	if err != nil {
		return d, err
	}
	return d, json.Unmarshal(b, &d)
}

func writeJSONAtomic(path string, v any) error {
	b, _ := json.Marshal(v)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomic(path, b)
}

// The early unit and lab-agent share a directory under lab-agent's work dir:
// lab-agent writes the deadline record when it arms a Lab boot and the boot ID
// that reached labd; the unit writes which Lab boot it watched and the
// deadline it rebooted it at.
const (
	labBootDir          = "lab-boot"
	labBootDeadlineFile = "deadlines.json"
	labBootContactFile  = "contact"
	labBootSeenFile     = "boot.json"
)

const (
	labBootDeadlineUnitName = "maclab-lab-boot-deadlines.service"
	labBootDeadlineUnitPath = "/etc/systemd/system/" + labBootDeadlineUnitName
)

// labBootDeadlineUnit is the early systemd unit that enforces the record. It
// needs only the local disk: a Lab boot without network must still reboot.
func labBootDeadlineUnit() string {
	return `[Unit]
Description=maclab: reboot a Lab boot that misses its deadline
DefaultDependencies=no
After=local-fs.target
Conflicts=shutdown.target
Before=shutdown.target

[Service]
ExecStart=` + binPath + ` lab-boot-deadlines
Restart=on-failure
RestartSec=5

[Install]
WantedBy=sysinit.target
`
}

// labBootSeen is the early unit's note of the Lab boot it watched.
type labBootSeen struct {
	BootID   string       `json:"boot_id"`
	Deadline api.Deadline `json:"deadline,omitempty"` // the deadline it rebooted the boot at
}

// enforceLabBootDeadlines is the early unit: on a Lab boot, it reboots the Mac
// once a deadline in the record under lab-agent's work directory passes, or on
// a Volunteer's Mac once the Availability window there closes. It needs
// neither labd nor lab-agent, so the Mac is back on time with both gone. On
// the Mac's own boot there is nothing to do.
func enforceLabBootDeadlines(ctx context.Context, c Clock, workDir string, sys System, logf func(string, ...any)) error {
	dir := filepath.Join(workDir, labBootDir)
	bootID, _, cmdline := sys.Identity()
	if !IsLabBoot(cmdline) {
		return nil
	}
	d, err := readLabBootDeadlines(filepath.Join(dir, labBootDeadlineFile))
	if err != nil {
		logf("Lab boot %s has no deadline record, so nothing reboots it but labd: %v", bootID, err)
		return nil // restarting the unit can't make one
	}
	seen := labBootSeen{BootID: bootID}
	note := func() {
		if err := writeJSONAtomic(filepath.Join(dir, labBootSeenFile), seen); err != nil {
			logf("Lab boot %s: %v", bootID, err)
		}
	}
	note()
	// Every second: a Pause should hand the Mac back at once.
	tick := c.NewTicker(time.Second)
	defer tick.Stop()
	for {
		now := c.Now()
		contacted := readTrim(filepath.Join(dir, labBootContactFile)) == bootID
		seen.Deadline = d.due(now, contacted)
		if d.WindowGated && !windowOpen(workDir, now) {
			seen.Deadline = api.DeadlineWindowClosed
		}
		if seen.Deadline != "" {
			note()
			syncDisks()
			logf("Lab boot %s passed its %s deadline: rebooting to the known-good kernel", bootID, seen.Deadline)
			return sys.Reboot()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C():
		}
	}
}

// windowOpen is whether the Availability window in workDir is open at now.
// Settings that can't be read count as closed, as lab-agent refuses lab
// commands then.
func windowOpen(workDir string, now time.Time) bool {
	s, _, err := readWindow(workDir)
	return err == nil && window.Evaluate(s, now).Open
}

// EnforceLabBootDeadlines runs the early unit on this Mac.
func EnforceLabBootDeadlines(ctx context.Context, workDir string) error {
	return enforceLabBootDeadlines(ctx, WallClock, workDir, &Linux{WorkDir: workDir},
		func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })
}

// kernelHasAppleWDT is whether a kernel .config builds apple_wdt.
func kernelHasAppleWDT(kconfig string) bool {
	for _, l := range strings.Split(kconfig, "\n") {
		if l = strings.TrimSpace(l); l == "CONFIG_APPLE_WATCHDOG=y" || l == "CONFIG_APPLE_WATCHDOG=m" {
			return true
		}
	}
	return false
}

// collectPstore copies pstore/ramoops records into outDir and returns their
// names relative to it. No records, or no pstore at all, is no error.
func collectPstore(pstoreDir, outDir string) ([]string, error) {
	var names []string
	err := filepath.Walk(pstoreDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == pstoreDir {
				return filepath.SkipAll
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(pstoreDir, p)
		if err := copyFile(p, filepath.Join(outDir, rel)); err != nil {
			return err
		}
		names = append(names, rel)
		return nil
	})
	return names, err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

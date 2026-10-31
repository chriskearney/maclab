// Package api holds the wire types shared by labd, lab-agent, oobd and the lab CLI.
package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/window"
)

// DeviceState is where a device sits in the lab's lifecycle.
type DeviceState string

const (
	StateNew        DeviceState = "new"         // enrolled, baseline not yet passed
	StateReady      DeviceState = "ready"       // idle, in the pool
	StateBusy       DeviceState = "busy"        // running a job
	StateRecovering DeviceState = "recovering"  // walking the recovery ladder
	StateNeedsHands DeviceState = "needs_hands" // waiting for a human power cycle
	StateOffline    DeviceState = "offline"     // idle and not heartbeating
	// StateLeft: lab-agent uninstall told labd the Mac is leaving the lab. Its
	// jobs were canceled and no automatic recovery touches it; it stays until
	// lab forget, unless uninstall says it stays after all (LeaveRequest.Undo)
	// or lab reset puts it back.
	StateLeft DeviceState = "left"
)

// Model decides which human instructions a device gets.
const (
	ModelLaptop  = "laptop"
	ModelDesktop = "desktop"
)

// OOBConfig points labd at the controller that can reset a device and read its serial console.
type OOBConfig struct {
	Driver string `json:"driver"` // "oobd"
	URL    string `json:"url"`
	Token  string `json:"token,omitempty"`
}

type Lease struct {
	Holder  string    `json:"holder"`
	Expires time.Time `json:"expires"`
}

// HumanAction is the one instruction a person needs when the lab cannot recover a device itself.
type HumanAction struct {
	Title   string    `json:"title"`
	Steps   []string  `json:"steps"`
	Why     string    `json:"why"`
	LastLog string    `json:"last_log,omitempty"`
	Since   time.Time `json:"since"`
}

type Device struct {
	EffectiveRecoveryMode string       `json:"effective_recovery_mode,omitempty"` // last explicit transaction policy; OOB config is preserved
	RecoveryTransaction   string       `json:"recovery_transaction,omitempty"`
	RecoveryHolder        string       `json:"recovery_holder,omitempty"`
	RecoveryModeJob       string       `json:"recovery_mode_job,omitempty"`
	ID                    string       `json:"id"`
	Name                  string       `json:"name"`
	Label                 string       `json:"label"` // physical description for humans
	Model                 string       `json:"model"`
	Volunteer             bool         `json:"volunteer,omitempty"` // a Volunteer's Mac (Kind volunteer): an agent the lab doesn't control, so lab gate leaves it out
	OOB                   *OOBConfig   `json:"oob,omitempty"`
	State                 DeviceState  `json:"state"`
	StateReason           string       `json:"state_reason,omitempty"`
	Action                *HumanAction `json:"action,omitempty"`
	LastSeen              time.Time    `json:"last_seen"`
	BootID                string       `json:"boot_id"`
	Kernel                string       `json:"kernel"`
	Cmdline               string       `json:"cmdline"`
	KnownGood             string       `json:"known_good,omitempty"` // kernel release the baseline ran on
	Facts                 Facts        `json:"facts"`
	Health                Health       `json:"health"`
	Lease                 *Lease       `json:"lease,omitempty"`
	ActiveJob             string       `json:"active_job,omitempty"`

	// VolunteeredBy is the tailnet login whose ./volunteer token enrolled the
	// Mac, lowercased; empty for a token an admin asked for. It counts toward
	// that login's limit of Macs (see POST /api/volunteer).
	VolunteeredBy string `json:"volunteered_by,omitempty"`
	Enrollment
	// SnapshotEligible is whether the Mac's @ can be snapshotted, as its
	// latest check-in said: a Mac that can't is not eligible for Installed runs.
	SnapshotEligible bool `json:"snapshot_eligible"`
	// Window is a Volunteer Mac's Availability window settings as its latest
	// check-in carried them. Only the Volunteer changes them, on the Mac.
	Window *window.Settings `json:"window,omitempty"`
	// AccessLevel is what Maintainers may do on a Volunteer's Mac, and
	// Publish whether its omarchy-m-test reports may be published, as its
	// latest check-in carried them. Only the Volunteer changes them, on the Mac.
	AccessLevel string `json:"access_level,omitempty"`
	Publish     bool   `json:"publish,omitempty"`
}

// Access levels of a Volunteer's Mac. Qualification, the default, allows
// only what a Qualification needs: no exec and no Maintainer's script.
const (
	AccessQualification = "qualification"
	AccessFull          = "full"
)

// AllowsAnything is whether Maintainers may do anything on the Mac a
// Lab-owned Mac allows: a Lab-owned Mac, or a Volunteer's at Full.
func (d *Device) AllowsAnything() bool { return !d.IsVolunteer() || d.AccessLevel == AccessFull }

// Kinds of Mac. A Mac keeps its kind for as long as it is enrolled.
const (
	KindLabOwned  = "lab-owned"
	KindVolunteer = "volunteer"
)

// Enrollment is what a Mac's enrollment token made it: its kind and, on a
// Volunteer's Mac, who the Volunteer is and the Mac's own ntfy topic.
type Enrollment struct {
	Kind string `json:"kind"`
	// VolunteerName is the Volunteer's name: from a Maintainer's token, or
	// the tailnet login that ran ./volunteer. Device.Volunteer is true
	// exactly when Kind is KindVolunteer.
	VolunteerName string `json:"volunteer_name,omitempty"`
	Contact       string `json:"contact,omitempty"`
	NtfyTopic     string `json:"ntfy_topic,omitempty"`
	// NtfyOwnURL is the topic the Volunteer chose with `notify --topic`, as
	// the Mac's check-ins carried it; it replaces the generated one.
	NtfyOwnURL string `json:"ntfy_own_url,omitempty"`
}

func (e Enrollment) IsVolunteer() bool { return e.Kind == KindVolunteer }

// Tier is how much of the recovery ladder a device supports: 0 panic reboot only,
// 1 plus an armed hardware watchdog, 2 plus out-of-band reset and serial.
func (d *Device) Tier() int {
	t := 0
	if d.Facts.WatchdogArmed {
		t = 1
	}
	if d.OOB != nil && d.EffectiveRecoveryMode != RecoveryNetworkOnly {
		t = 2
	}
	return t
}

// Facts are reported by the agent at startup and refreshed by preflight.
type Facts struct {
	Hostname      string   `json:"hostname"`
	Machine       string   `json:"machine"`              // uname -m
	DTModel       string   `json:"dt_model"`             // /proc/device-tree/model
	Compatible    []string `json:"compatible,omitempty"` // /proc/device-tree/compatible: board, then SoC
	Bootloader    string   `json:"bootloader"`
	Initramfs     string   `json:"initramfs"`
	Watchdog      bool     `json:"watchdog"`
	WatchdogArmed bool     `json:"watchdog_armed"`
	PanicTimeout  int      `json:"panic_timeout"`
	GUIUser       string   `json:"gui_user,omitempty"`
	AgentVersion  string   `json:"agent_version"`
	MesaStaged    bool     `json:"mesa_staged,omitempty"`
	MesaOfficial  bool     `json:"mesa_official,omitempty"`
	PreflightOK   bool     `json:"preflight_ok"`
	Problems      []string `json:"problems,omitempty"` // each one holds jobs back
	Warnings      []string `json:"warnings,omitempty"` // costs evidence, not the Mac: jobs still run
}

type Health struct {
	Uptime      float64 `json:"uptime"`
	SystemState string  `json:"system_state"` // systemctl is-system-running
	Tainted     int64   `json:"tainted"`
	JobTag      string  `json:"job_tag,omitempty"`    // maclab.job= from the running cmdline
	OnBattery   bool    `json:"on_battery,omitempty"` // unplugged from AC power
}

// KernelEvent is a classified kernel log line, from the agent's /dev/kmsg or from serial.
type KernelEvent struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Source string    `json:"source"` // "kmsg" or "serial"
	BootID string    `json:"boot_id,omitempty"`
	Line   string    `json:"line"`
}

// Checkin is the agent heartbeat. It also carries command results and new kernel events.
type Checkin struct {
	BootID  string          `json:"boot_id"`
	Kernel  string          `json:"kernel"`
	Cmdline string          `json:"cmdline"`
	Facts   *Facts          `json:"facts,omitempty"`
	Health  Health          `json:"health"`
	Events  []KernelEvent   `json:"events,omitempty"`
	Results []CommandResult `json:"results,omitempty"`
	Running []string        `json:"running,omitempty"` // command IDs still executing
	// SnapshotEligible is whether @ can be snapshotted right now.
	SnapshotEligible bool `json:"snapshot_eligible"`
	// Window is the Mac's Availability window settings, once its Volunteer
	// has set any: check-ins are how they reach labd.
	Window *window.Settings `json:"window,omitempty"`
	// NtfyOwnURL is the topic the Volunteer set with `notify --topic`, if any.
	NtfyOwnURL string `json:"ntfy_own_url,omitempty"`
	// AccessLevel and Publish are a Volunteer's Mac's Access level and
	// publishing opt-in; a Lab-owned Mac sends no AccessLevel.
	AccessLevel string `json:"access_level,omitempty"`
	Publish     bool   `json:"publish,omitempty"`
}

// Report carries command results and kernel events as soon as they exist.
type Report struct {
	Results []CommandResult `json:"results,omitempty"`
	Events  []KernelEvent   `json:"events,omitempty"`
	Quiet   *Quiet          `json:"quiet,omitempty"`
	// Audit is the part of the Mac's Audit log labd's copy lacks.
	Audit []AuditEntry `json:"audit,omitempty"`
}

// Quiet is the agent saying, while it can, that the Mac is about to go off
// the network on boot BootID for up to Seconds from now (suspend-devices,
// whose suspend takes Wi-Fi down). labd waits that out on that boot before
// it counts the Mac as lost. Seconds 0, sent once the Mac is back, ends that
// spell: a silence after it is no longer the spell's.
type Quiet struct {
	BootID  string `json:"boot_id"`
	Seconds int    `json:"seconds"`
}

// AuditEntry is one line of a Volunteer Mac's Audit log: a Maintainer action
// that reached the Mac, written there before lab-agent acted on it.
type AuditEntry struct {
	Time       time.Time `json:"time"`
	Maintainer string    `json:"maintainer,omitempty"` // "" when labd acted on its own
	Job        string    `json:"job,omitempty"`
	Action     string    `json:"action"` // what was done, with the command or script text
	// Refused is why lab-agent refused the action instead; "" when it acted.
	Refused string `json:"refused,omitempty"`
	// End is where the entry ends in the Mac's own log, in bytes: labd's copy
	// keeps each entry once however often the Mac sends it.
	End int64 `json:"end,omitempty"`
}

// Line is the entry as `lab-agent log` and `lab audit` print it, in the
// time zone of loc.
func (e AuditEntry) Line(loc *time.Location) string {
	who := e.Maintainer
	if who == "" {
		who = "labd"
	}
	job := ""
	if e.Job != "" {
		job = " job " + e.Job + ":"
	}
	what := e.Action
	if e.Refused != "" {
		what = "REFUSED " + what + " (" + e.Refused + ")"
	}
	return fmt.Sprintf("%s  %s%s %s", e.Time.In(loc).Format("2006-01-02 15:04:05"), who, job, what)
}

// Published is an omarchy-m-test report of a Volunteer's Mac on
// omarchy-m-testing.org, with the link that takes it down again.
type Published struct {
	Job         string `json:"job"`
	ReportURL   string `json:"report_url"`
	DeletionURL string `json:"deletion_url"`
}

type CheckinResponse struct {
	Commands   []Command `json:"commands,omitempty"`
	IntervalMS int       `json:"interval_ms"`
	// Kind is the Mac's kind as labd enrolled it, for a lab-agent set up
	// without it.
	Kind string `json:"kind,omitempty"`
	// Held is whether a job or lease holds the Mac now: a Volunteer's Mac
	// lets its screen and live journal be read only then.
	Held bool `json:"held,omitempty"`
	// AuditHave is how much of the Mac's Audit log labd's copy holds, in bytes.
	AuditHave int64 `json:"audit_have,omitempty"`
}

// Command kinds sent to the agent.
const (
	CmdMesaStage = "mesa_stage"
	CmdStage     = "stage"
	CmdBootOnce  = "boot_once"
	CmdReboot    = "reboot"
	CmdRunTest   = "run_test"
	CmdCollect   = "collect"
	// CmdCollectLost collects the Lab boot the Mac came back from (see LostBoot).
	CmdCollectLost = "collect_lost"
	CmdCleanup     = "cleanup"
	CmdCrash       = "crash"
	CmdScreen      = "screenshot"
	CmdLogs        = "logs"
	CmdConfig      = "config" // the running kernel's .config
	CmdExec        = "exec"
	// CmdRecordKnownGood makes the running kernel the agent's known-good, as
	// lab-agent setup does; it refuses unless the Mac runs exactly that kernel
	// outside a lab boot. Promotion sends it.
	CmdRecordKnownGood = "record_known_good"
	// CmdInstall installs a Release on the Mac as a named lab operation: the
	// install step of an Installed run, which a Volunteer's Mac allows at
	// Qualification and records in its Audit log with the Maintainer and the
	// Release.
	CmdInstall = "install"
)

// InstallTimeout is how long labd gives a Mac to install a Release: fetching
// its packages and running the installer's hooks.
const InstallTimeout = 10 * time.Minute

// InstallArgs is the Release CmdInstall installs: its packages, which
// lab-agent fetches from labd by sha256, and the kernel they carry.
type InstallArgs struct {
	Release  string           `json:"release"`
	Kernel   string           `json:"kernel"` // the kernel release the Release's package installs
	Packages []InstallPackage `json:"packages"`
}

// InstallPackage is one package file of a Release.
type InstallPackage struct {
	Name   string `json:"name"`
	File   string `json:"file"`   // the package's file name, as pacman wants it
	SHA256 string `json:"sha256"` // the package file, uploaded to labd
}

type Command struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	JobID string `json:"job_id,omitempty"`
	// Maintainer is who the command acts for: the Maintainer who asked, or
	// whose job it is; "" when labd acts on its own.
	Maintainer string          `json:"maintainer,omitempty"`
	Args       json.RawMessage `json:"args,omitempty"`
}

type CommandResult struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`
	// WindowClosed is lab-agent refusing or stopping the command because the
	// Mac's Availability window is closed: its end came, or its Volunteer paused.
	WindowClosed bool `json:"window_closed,omitempty"`
	// AccessLevel is lab-agent refusing or stopping the command because the
	// Mac's Access level doesn't allow it: its Volunteer lowered it.
	AccessLevel bool `json:"access_level,omitempty"`
}

type MesaCapabilities struct {
	Schema      int    `json:"schema"`
	Staged      bool   `json:"staged"`
	OfficialGPU bool   `json:"official_gpu"`
	AgentMin    string `json:"agent_min"`
}
type MesaStageArgs struct {
	Spec          MesaSpec `json:"spec"`
	BootID        string   `json:"boot_id"`
	Kernel        string   `json:"kernel"`
	CmdlineSHA256 string   `json:"cmdline_sha256"`
}
type MesaStageResult struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	Prefix         string `json:"prefix"`
}

type StageArgs struct {
	Artifact string `json:"artifact"` // sha256
	Cmdline  string `json:"cmdline"`  // extra args appended to the base cmdline
	Serial   bool   `json:"serial"`   // add the debug UART console
	// CmdlineBase picks the cmdline a test boot starts from: "" or "known-good"
	// (the known-good kernel's), "default" (the distro's stock cmdline, e.g.
	// Limine's KERNEL_CMDLINE[default]), or a literal cmdline with root=.
	CmdlineBase string `json:"cmdline_base,omitempty"`
	// CmdlineStrip removes base parameters whose name (before "=") or whole
	// text matches one of these globs, e.g. "asahi.*".
	CmdlineStrip []string `json:"cmdline_strip,omitempty"`
	// Verbose boots with loglevel=7 and without quiet/splash, for watching the
	// console. Otherwise a test boot keeps the base's own; a Mac with a serial
	// console is always verbose.
	Verbose bool `json:"verbose,omitempty"`
	// WatchdogOpenTimeoutSec is watchdog.open_timeout on the Lab boot's
	// command line: how long the kernel keeps the hardware watchdog fed until
	// systemd opens it. 0 is lab-agent's default.
	WatchdogOpenTimeoutSec int `json:"watchdog_open_timeout_sec,omitempty"`
	// Installed boots an installed release through its installer-made Limine
	// entry instead of staging a kernel (the installed-kernel job mode).
	Installed *InstalledStage `json:"installed,omitempty"`
	// BootTimeoutSec is how long labd waits for the test boot to check in.
	// The agent takes the boot's watchdog deadline from it; 0 (an older
	// labd) leaves the agent's default.
	BootTimeoutSec int `json:"boot_timeout_sec,omitempty"`
}

func (a StageArgs) WatchdogOpenTimeout() time.Duration {
	return time.Duration(a.WatchdogOpenTimeoutSec) * time.Second
}

// InstalledStage points a one-shot lab entry at the installer's own UKI, with
// the installer's cmdline plus only the lab's additions.
type InstalledStage struct {
	Path      string `json:"path"`       // the installer entry's path: line, verbatim (with its #hash)
	UKISHA256 string `json:"uki_sha256"` // the UKI file must have this sha256
	Cmdline   string `json:"cmdline"`    // the full cmdline to boot
	Release   string `json:"release"`    // the kernel release the UKI carries
}

type StageResult struct {
	KernelRelease string `json:"kernel_release"`
	Entry         string `json:"entry"`
	Cmdline       string `json:"cmdline"`
	// NoAppleWDT is a test kernel built without apple_wdt: the watchdog U-Boot
	// left running resets it about 60 s into every boot, healthy or not.
	NoAppleWDT bool `json:"no_apple_wdt,omitempty"`
}

// BootOnceArgs arms a Lab boot. lab-agent first writes its deadline record,
// on its own clock: no contact (2x BootTimeoutSec from now, unless lab-agent
// reaches labd) and the hard ceiling (the job's end, JobSec from now).
type BootOnceArgs struct {
	Entry          string `json:"entry"`
	BootTimeoutSec int    `json:"boot_timeout_sec"`
	JobSec         int    `json:"job_sec"`
	// Tests are what the job runs on the Lab boot: a Volunteer's Mac records
	// them in its Audit log, and holds them to its Access level for as long
	// as the Lab boot lasts.
	Tests []TestSpec `json:"tests,omitempty"`
	// RebootWarningSec, on a Volunteer's Mac, is how long before the reboot
	// lab-agent warns the Volunteer on their desktop, and how long it then
	// waits before arming the Lab boot; 0 is neither.
	RebootWarningSec int `json:"reboot_warning_sec,omitempty"`
}

type CollectArgs struct {
	Boot string `json:"boot"` // journalctl -b value: "0", "-1" or a boot ID
	// Dir is where the logs go in the job, instead of boot0 (or prevboot for
	// "-1"): an Installed run collects the Volunteer's own boot as preinstall.
	Dir string `json:"dir,omitempty"`
}

// LostBoot is what lab-agent collected of a Lab boot it came back from.
type LostBoot struct {
	BootID string `json:"boot_id,omitempty"` // "" when the journal never saw the boot
	// Deadline is the deadline the early unit rebooted the boot at, "" when it
	// came back some other way (a panic, the watchdog, a hard reset).
	Deadline Deadline `json:"deadline,omitempty"`
	Files    []string `json:"files,omitempty"` // its journal, kernel log and pstore records
}

// Deadline is one of a Lab boot's deadlines.
type Deadline string

const (
	DeadlineNoContact Deadline = "no_contact" // lab-agent never reached labd in time
	DeadlineCeiling   Deadline = "ceiling"    // the hard ceiling: the job's end
	// DeadlineWindowClosed is the Availability window closing: its end, or
	// the Volunteer's Pause.
	DeadlineWindowClosed Deadline = "window_closed"
	// DeadlineAccessLowered is the Volunteer lowering the Access level below
	// what the Lab boot's job runs.
	DeadlineAccessLowered Deadline = "access_lowered"
)

func (d Deadline) String() string {
	switch d {
	case DeadlineCeiling:
		return "hard ceiling"
	case DeadlineWindowClosed:
		return "Availability window closing"
	case DeadlineAccessLowered:
		return "Access level lowering"
	}
	return "no-contact"
}

type CleanupArgs struct {
	All bool `json:"all"` // remove every lab-staged kernel except the running one
}

// ScreenArgs asks for a capture of the GUI session. With a JobID the image is
// stored with the job as screen/<label>.jpg, otherwise as the device's live screen.
type ScreenArgs struct {
	Label   string `json:"label,omitempty"`
	WaitSec int    `json:"wait_sec,omitempty"` // how long to wait for a Wayland session
}

type ScreenResult struct {
	Name   string    `json:"name"`
	Time   time.Time `json:"time"`
	Width  int       `json:"width,omitempty"`
	Height int       `json:"height,omitempty"`
}

// LogsArgs reads the running system's logs.
type LogsArgs struct {
	Source string `json:"source"` // journal, kernel
	Lines  int    `json:"lines"`
	Unit   string `json:"unit,omitempty"`
}

type RecordKnownGoodArgs struct {
	Kernel string `json:"kernel"` // the release the Mac must be running
}

type CrashArgs struct {
	Mode string `json:"mode"` // "panic"
}

type TestSpec struct {
	Name       string `json:"name"`
	Builtin    string `json:"builtin,omitempty"` // name of a test embedded in the agent
	Script     string `json:"script,omitempty"`  // artifact sha256 of a shell script
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	GUI        bool   `json:"gui,omitempty"` // run as the GUI user inside their Wayland session
	// SkipOnScreen leaves out the checks that need the screen visible: a
	// Volunteer's Mac is locked while a test runs.
	SkipOnScreen bool `json:"skip_on_screen,omitempty"`
	// Identity makes the test the lab's own identity check of an Installed
	// run: lab-agent runs its own read-only collector, not a script.
	Identity *IdentityCheck `json:"identity,omitempty"`
}

// IdentityCheck is what an Installed run's identity check observes: the
// installed Release's kernel and packages, and its installer entry.
type IdentityCheck struct {
	Phase     string   `json:"phase"` // before, booted or after
	Device    string   `json:"device"`
	Kernel    string   `json:"kernel"`
	EntryPath string   `json:"entry_path,omitempty"` // the frozen installer entry's path; "" finds the installer's entry
	Packages  []string `json:"packages,omitempty"`
}

// MaintainerScript is whether the test runs a Maintainer's script (--script,
// or --gui-script in the GUI user's session): a Volunteer's Mac runs one only
// at Access level Full.
func (t TestSpec) MaintainerScript() bool { return t.Script != "" }

type TestResult struct {
	Mesa     *MesaResult `json:"mesa,omitempty"`
	Name     string      `json:"name"`
	Passed   bool        `json:"passed"`
	ExitCode int         `json:"exit_code"`
	Seconds  float64     `json:"seconds"`
	TimedOut bool        `json:"timed_out,omitempty"`
	// Skipped: the test couldn't run on this Mac (its kernel lacks what the
	// test needs), and Error says why. A skipped test is never Passed, so it
	// fails the job like any other test that didn't pass.
	Skipped bool     `json:"skipped,omitempty"`
	Tail    string   `json:"tail,omitempty"`
	Files   []string `json:"files,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type JobState string

const (
	JobQueued     JobState = "queued"
	JobBuilding   JobState = "building"
	JobStaging    JobState = "staging"
	JobBooting    JobState = "booting"
	JobTesting    JobState = "testing"
	JobCollecting JobState = "collecting"
	JobRestoring  JobState = "restoring"
	JobDone       JobState = "done"
)

// Outcomes, most specific first. Only "pass" is success.
const (
	OutcomeUnknown     = "unknown" // no observation proves what happened; never a pass
	OutcomePass        = "pass"
	OutcomeTestsFailed = "tests_failed"
	OutcomeUnhealthy   = "booted_unhealthy" // booted, but kernel errors or degraded system
	OutcomePanicked    = "panicked"         // a kernel panic or oops was captured
	OutcomeHung        = "hung"
	// rebooted during a test with no kernel error captured; the summary says
	// how long it was silent, which hints at a crash or a watchdog reset
	OutcomeCrashedOrHung = "crashed_or_hung"
	OutcomeBootFailed    = "boot_failed" // came back on the known-good kernel without a clear cause
	// OutcomeLostContact is a Lab boot that came back only through its
	// deadline: it booted, but never reached labd (the kernel or Release broke
	// networking), so lab-agent's early unit rebooted it.
	OutcomeLostContact = "lost_contact"
	OutcomeStageFailed = "stage_failed"
	OutcomeBuildFailed = "build_failed"
	OutcomeInfra       = "infra_error"
	OutcomeCanceled    = "canceled"
	// OutcomeIncomplete is a job its Availability window's end or the
	// Volunteer's Pause cut short: not a failure, and retried in a later window.
	OutcomeIncomplete = "incomplete"
)

type JobSpec struct {
	RecoveryTransaction string     `json:"recovery_transaction,omitempty"`
	RecoveryMode        string     `json:"recovery_mode,omitempty"` // explicit per-job controller policy; empty retains legacy/inherited behavior
	Device              string     `json:"device"`
	Kernel              string     `json:"kernel,omitempty"` // artifact sha256; empty = reboot on the current kernel
	Source              string     `json:"source,omitempty"` // build this first: a GitHub/git URL of a repo, branch, commit or PR
	Config              string     `json:"config,omitempty"` // source builds: artifact sha256 of a .config to build with, instead of the Mac's own
	Build               string     `json:"build,omitempty"`  // the build job that produced Kernel
	Cmdline             string     `json:"cmdline,omitempty"`
	CmdlineBase         string     `json:"cmdline_base,omitempty"`  // see StageArgs.CmdlineBase
	CmdlineStrip        []string   `json:"cmdline_strip,omitempty"` // see StageArgs.CmdlineStrip
	VerboseBoot         bool       `json:"verbose_boot,omitempty"`  // see StageArgs.Verbose
	Tests               []TestSpec `json:"tests,omitempty"`
	BootTimeoutSec      int        `json:"boot_timeout_sec,omitempty"`
	Crash               string     `json:"crash,omitempty"` // crash test mode, see CrashArgs
	Baseline            bool       `json:"baseline,omitempty"`
	Holder              string     `json:"holder,omitempty"`
	// Publish uploads the job's omarchy-m-test report to omarchy-m-testing.org.
	// Only a run on the Mac's known-good (packaged) kernel is ever published:
	// the site names a report's build from pacman, which doesn't know lab kernels.
	Publish bool `json:"publish,omitempty"`
	// OMTAllow names omarchy-m-test checks this kernel is expected to fail
	// (it lacks a feature on purpose): they're listed, not counted as regressions.
	// "hardware.drivers:<compatible>" allows just that device-tree node to go unbound.
	OMTAllow []string `json:"omt_allow,omitempty"`
	// InstalledManifest is the sha256 of a frozen expected manifest
	// (frozen/<release>/expected/manifest.json): the job boots the release as
	// the installer installed it, checks its identity against the frozen
	// expectation before, on and after the boot, compares omarchy-m-test and
	// kernel errors with the frozen pre-install baseline, and never promotes.
	InstalledManifest string `json:"installed_manifest,omitempty"`
	// Mesa makes the job a first-class Mesa test of pinned split packages.
	// See MesaSpec for what each mode does and does not claim.
	Mesa *MesaSpec `json:"mesa,omitempty"`
}

// Mesa test modes. Staged is a diagnostic of the packages: they are unpacked
// into a private per-job prefix on the Mac and only the job's own probe
// processes are pointed at it, while the desktop keeps the installed Mesa.
// A staged result therefore says nothing about the installed desktop.
// Installed (a real package transaction with a recovery contract, judged
// through the installed manifest/acceptance machinery) is not supported yet.
const (
	MesaStaged    = "staged"
	MesaInstalled = "installed"
)

// MesaSpec pins the split packages a Mesa job tests.
type MesaSpec struct {
	OfficialGPU         bool          `json:"official_gpu,omitempty"`
	SigningPublicSHA256 string        `json:"signing_public_sha256,omitempty"`
	SigningStateHome    string        `json:"signing_state_home,omitempty"`
	Mode                string        `json:"mode"`            // MesaStaged (MesaInstalled is refused for now)
	Packages            []MesaPackage `json:"packages"`        // the exact split packages, as uploaded artifacts
	Build               string        `json:"build,omitempty"` // the finished package build whose files they are (checked by sha256 at submission), if any
}

// MesaPackage is one pinned split package (for example mesa-aurora or
// vulkan-aurora): its pacman name and the sha256 of its .pkg.tar.zst artifact.
type MesaPackage struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// MesaResult is a Mesa job's verdicts. Semantics restates what the mode
// covers, so a staged result can never be read as an installed one.
type MesaOfficialResult struct {
	Status            string `json:"status"`
	NativeInvocations int    `json:"native_invocations"`
	SignatureVerified bool   `json:"signature_verified"`
	ReportSHA256      string `json:"report_sha256"`
	SealSHA256        string `json:"seal_sha256"`
	SourceCommit      string `json:"source_commit"`
	ArchiveSHA256     string `json:"archive_sha256"`
	ReportPath        string `json:"report_path"`
	SealPath          string `json:"seal_path"`
}
type MesaResult struct {
	Official        *MesaOfficialResult `json:"official,omitempty"`
	Job             string              `json:"job"`
	BootID          string              `json:"boot_id"`
	Kernel          string              `json:"kernel"`
	ManifestSHA256  string              `json:"manifest_sha256"`
	CleanupVerified bool                `json:"cleanup_verified"`
	Simulated       bool                `json:"simulated,omitempty"`
	Evidence        map[string]any      `json:"evidence,omitempty"`
	Mode            string              `json:"mode"`
	Semantics       string              `json:"semantics"`
	Packages        []MesaPackage       `json:"packages"`
	Provider        map[string]string   `json:"provider,omitempty"` // api (gl, vulkan) -> NATIVE_STAGED, SYSTEM_PROVIDER, SOFTWARE or MISSING
	Verdict         string              `json:"verdict"`            // PASS, FAIL or INCOMPLETE
}

type JobEvent struct {
	Time time.Time `json:"time"`
	Msg  string    `json:"msg"`
}

type JobResult struct {
	Booted        bool             `json:"booted"`
	BootKernel    string           `json:"boot_kernel,omitempty"`
	BootCmdline   string           `json:"boot_cmdline,omitempty"` // /proc/cmdline of the test boot
	BootSeconds   float64          `json:"boot_seconds,omitempty"`
	FellBack      bool             `json:"fell_back,omitempty"`
	Recovery      []string         `json:"recovery,omitempty"` // ladder steps that were needed
	Tests         []TestResult     `json:"tests,omitempty"`
	KernelEvents  []KernelEvent    `json:"kernel_events,omitempty"`
	NewErrorLines []string         `json:"new_error_lines,omitempty"` // dmesg errors not in the baseline
	Logs          []string         `json:"logs,omitempty"`
	OMT           *OMTResult       `json:"omt,omitempty"` // omarchy-m-test, when it ran
	Installed     *InstalledResult `json:"installed,omitempty"`
	Mesa          *MesaResult      `json:"mesa,omitempty"`
}

// InstalledResult is an installed-mode job's verdicts. The evidence files are
// in the job's installed/ directory and the frozen store.
type InstalledResult struct {
	Release        string            `json:"release"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	EntrySHA256    string            `json:"installer_entry_sha256"`
	Before         *TestResult       `json:"before,omitempty"`           // identity-before: not one of Tests
	Verdicts       map[string]string `json:"verdicts"`                   // phase -> MATCH/MISMATCH/INCOMPLETE
	OMT            string            `json:"omt,omitempty"`              // NO_REGRESSION or REGRESSION
	Dmesg          string            `json:"dmesg,omitempty"`            // NONE_NEW, REVIEW_REQUIRED or FATAL
	KernelLogFatal []string          `json:"kernel_log_fatal,omitempty"` // fatal events in the full kernel log (boot0/kernel.txt), at any priority
	Evidence       []string          `json:"evidence,omitempty"`
	Frozen         string            `json:"frozen_copy,omitempty"`
}

// OMTResult summarizes an omarchy-m-test report (github.com/maralcbr/omarchy-m-testing)
// and compares it with the same Mac's report on its known-good kernel.
type OMTResult struct {
	Report      string     `json:"report"` // job file holding the signed report
	Tool        string     `json:"tool"`
	Catalogue   int        `json:"catalogue"`
	Kernel      string     `json:"kernel"`
	KnownGood   bool       `json:"known_good"` // ran on the Mac's known-good kernel: becomes the baseline
	Pass        int        `json:"pass"`
	Fail        int        `json:"fail"`
	Skip        int        `json:"skip"`
	Fails       []OMTCheck `json:"fails,omitempty"`
	Regressions []OMTCheck `json:"regressions,omitempty"`  // passed on the known-good kernel, fail here
	Fixed       []OMTCheck `json:"fixed,omitempty"`        // failed on the known-good kernel, pass here
	LabBoot     []OMTCheck `json:"lab_boot,omitempty"`     // regressed only because a lab kernel isn't an installed package
	Allowed     []OMTCheck `json:"allowed,omitempty"`      // regressed, but the job said this kernel is expected to (omt_allow)
	ComparedTo  string     `json:"compared_to,omitempty"`  // the baseline job, or why there was no comparison
	BaselineJob string     `json:"baseline_job,omitempty"` // the known-good run it was compared with; "" for none, and then Regressions says nothing
	Published   string     `json:"published,omitempty"`    // the report's page on omarchy-m-testing.org
	PublishNote string     `json:"publish_note,omitempty"` // why it wasn't published, or the site's error
	Reference   string     `json:"reference,omitempty"`    // a known-good run: whether it became the reference, or why not
}

type OMTCheck struct {
	ID       string `json:"id"`
	Outcome  string `json:"outcome,omitempty"` // the catalogue's reading: fails, gap, n/a...
	Evidence string `json:"evidence,omitempty"`
}

type Job struct {
	EffectiveRecoveryMode string     `json:"effective_recovery_mode,omitempty"`
	ID                    string     `json:"id"`
	Spec                  JobSpec    `json:"spec"`
	State                 JobState   `json:"state"`
	Outcome               string     `json:"outcome,omitempty"`
	Summary               string     `json:"summary,omitempty"`
	Created               time.Time  `json:"created"`
	Updated               time.Time  `json:"updated"`
	Events                []JobEvent `json:"events"`
	Result                JobResult  `json:"result"`
	Canceled              bool       `json:"canceled,omitempty"`
	// Maintainer is who submitted it, from their token; empty when labd queued it.
	Maintainer string `json:"maintainer,omitempty"`
	// RetryOf is the job this one retries (lab retry).
	RetryOf string `json:"retry_of,omitempty"`
	// DeviceAtSubmit is what the job's Mac was when the job was submitted.
	// Jobs from before labd kept it have none.
	DeviceAtSubmit *DeviceSnapshot `json:"device_at_submit,omitempty"`
	// GateExclusion sets the job aside in every lab gate report until it is
	// cleared (lab exclude), say a failure the lab caused. Jobs without one,
	// those from before labd kept it among them, count as usual.
	GateExclusion *GateExclusion `json:"gate_exclusion,omitempty"`
}

// GateExclusion is an admin's lasting word that a finished job says nothing
// about its kernel: who said it, why and when.
type GateExclusion struct {
	By     string    `json:"by"`
	Reason string    `json:"reason"`
	Time   time.Time `json:"time"`
}

// ExcludeRequest sets a job aside in lab gate (POST /api/jobs/{id}/exclude).
type ExcludeRequest struct {
	Reason string `json:"reason"`       // required
	By     string `json:"by,omitempty"` // who asks; labd names the Maintainer by their token itself
}

// DeviceSnapshot is what lab gate needs to know about a job's Mac, as it was
// when the job was submitted: the gate judges an old job by the Mac it ran
// on, not by the device record as it is now.
type DeviceSnapshot struct {
	Family    string `json:"family,omitempty"`    // chip family (m1, m1-pro, ...); "" for one lab gate doesn't cover
	Volunteer bool   `json:"volunteer,omitempty"` // a volunteer's Mac (Device.Volunteer)
	OMT       bool   `json:"omt,omitempty"`       // labd ran omarchy-m-test in every job on it
}

type EnrollRequest struct {
	Token string `json:"token"`
	Facts Facts  `json:"facts"`
}

type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Secret   string `json:"secret"`
	AgentEnrollment
}

// AgentEnrollment is a Mac's Enrollment as labd tells the Mac itself, with
// its topic's URL on the lab's ntfy server when labd has one.
type AgentEnrollment struct {
	Enrollment
	NtfyURL string `json:"ntfy_url,omitempty"`
}

// Subscribe is what a Volunteer subscribes to: the topic's URL, or the bare
// topic when labd has no ntfy server.
func (e AgentEnrollment) Subscribe() string {
	if e.NtfyURL != "" {
		return e.NtfyURL
	}
	return e.NtfyTopic
}

type EnrollTokenRequest struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Model string `json:"model"`
	// Volunteer makes the Mac a volunteer's (see Device.Volunteer). labd sets
	// it on every POST /api/volunteer token, whatever the request says.
	Volunteer bool `json:"volunteer,omitempty"`
	// VolunteeredBy is the login that asked for a volunteer token, set by
	// labd only (see Device.VolunteeredBy).
	VolunteeredBy string `json:"-"`
	// VolunteerName and Contact make the token a Volunteer's: both or
	// neither. Either makes Volunteer true too.
	VolunteerName string `json:"volunteer_name,omitempty"`
	Contact       string `json:"contact,omitempty"`
}

type EnrollTokenResponse struct {
	Name    string    `json:"name"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

type DevicePatch struct {
	Label *string    `json:"label,omitempty"`
	Model *string    `json:"model,omitempty"`
	OOB   *OOBConfig `json:"oob,omitempty"`
	NoOOB bool       `json:"no_oob,omitempty"`
}

// LeaveRequest is lab-agent uninstall telling labd, before it undoes
// anything, that the Mac is leaving the lab.
type LeaveRequest struct {
	Reason string   `json:"reason"`         // what is taking it out, e.g. "lab-agent uninstall --force"
	Jobs   []string `json:"jobs,omitempty"` // the jobs the Mac still had in flight, as it sees them
	// Undo takes the leave back: uninstall failed, or was interrupted,
	// before it stopped the agent, which runs on. The Mac stays in the lab.
	Undo bool `json:"undo,omitempty"`
}

type LeaveResponse struct {
	Name     string   `json:"name"`
	Canceled []string `json:"canceled,omitempty"` // the Mac's running and queued jobs, canceled
	// Back: the Mac is in the lab again (Undo). An older labd takes an undo
	// for another leave, and says nothing.
	Back bool `json:"back,omitempty"`
}

type LeaseRequest struct {
	Holder string `json:"holder"`
	TTLSec int    `json:"ttl_sec"`
}

// Text renders the instruction for a notification or terminal.
func (a *HumanAction) Text() string {
	var b strings.Builder
	for i, s := range a.Steps {
		fmt.Fprintf(&b, "%d. %s\n", i+1, s)
	}
	fmt.Fprintf(&b, "Why: %s.", a.Why)
	if a.LastLog != "" {
		fmt.Fprintf(&b, "\nLast log line: %s", a.LastLog)
	}
	return b.String()
}

// ---- builds: kernels built from source by a builder host ----

type BuildState string

const (
	BuildQueued   BuildState = "queued"
	BuildRunning  BuildState = "running"
	BuildDone     BuildState = "done"
	BuildFailed   BuildState = "failed"
	BuildCanceled BuildState = "canceled"
)

// Source is a git commit to build, resolved from whatever the user handed over.
type Source struct {
	Input string `json:"input"`         // what was given: a GitHub URL, git URL#ref, ...
	Repo  string `json:"repo"`          // clone URL
	Ref   string `json:"ref,omitempty"` // branch, tag or refs/pull/N/head, if one was named
	SHA   string `json:"sha"`           // the exact commit built
}

// Build kinds. A kernel build makes a lab test artifact from a commit and a
// Mac's config; a package build runs a PKGBUILD recipe with makepkg and makes
// the release packages, byte for byte what testers install.
const (
	BuildKernel  = ""
	BuildPackage = "package"
)

// RecipeFile is the name under which a package build serves the recipe
// tarball it was built from, exactly as uploaded.
const RecipeFile = "recipe.tar"

// BuildFile is one named output of a kernel or package build.
type BuildFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Build struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind,omitempty"`   // "" (kernel) or "package"
	Key        string      `json:"key"`              // sha256 of everything that decides the output: same key, same result
	Source     Source      `json:"source"`           // package builds: the commit _commit was pointed at, if any
	Device     string      `json:"device,omitempty"` // whose running config it uses
	ConfigSHA  string      `json:"config_sha"`
	ConfigName string      `json:"config_name,omitempty"` // file name of an uploaded config
	Recipe     string      `json:"recipe,omitempty"`      // package builds: artifact sha256 of the recipe tarball
	RecipeDir  string      `json:"recipe_dir,omitempty"`  // where the recipe came from, for people
	Pkgrel     string      `json:"pkgrel,omitempty"`      // pkgrel set on the recipe, if any
	Files      []BuildFile `json:"files,omitempty"`       // named build outputs
	State      BuildState  `json:"state"`
	Stage      string      `json:"stage,omitempty"`    // fetch, checkout, configure, build, package, upload
	Progress   float64     `json:"progress,omitempty"` // 0..1 when known
	ETA        float64     `json:"eta_sec,omitempty"`  // estimated seconds left, from earlier builds
	Release    string      `json:"release,omitempty"`
	Artifact   string      `json:"artifact,omitempty"` // what `lab run --kernel` boots; for packages, the kernel package
	Size       int64       `json:"size,omitempty"`
	Error      string      `json:"error,omitempty"`
	Builder    string      `json:"builder,omitempty"`
	Reused     bool        `json:"reused,omitempty"` // an earlier identical build was reused
	Created    time.Time   `json:"created"`
	Started    time.Time   `json:"started,omitempty"`
	Updated    time.Time   `json:"updated"`
	Seconds    float64     `json:"seconds,omitempty"`
	LogLines   int         `json:"log_lines"`
}

type BuildRequest struct {
	Source string `json:"source"`           // URL of a repo, branch, commit or pull request
	Device string `json:"device,omitempty"` // build with this Mac's running config
	Config string `json:"config,omitempty"` // or: artifact sha256 of a .config
	Force  bool   `json:"force,omitempty"`  // rebuild even if an identical build exists
	// ConfigName is where an uploaded config came from (its file name), for people.
	ConfigName string `json:"config_name,omitempty"`

	// Package builds: Recipe is the artifact sha256 of a tarball of a PKGBUILD
	// directory. Source, if given, repoints the recipe's _commit; Pkgrel sets pkgrel.
	Recipe    string `json:"recipe,omitempty"`
	RecipeDir string `json:"recipe_dir,omitempty"`
	Pkgrel    string `json:"pkgrel,omitempty"`
}

// BuildAssignment is what a builder host receives.
type BuildAssignment struct {
	Build  Build  `json:"build"`
	LabVer string `json:"labver"` // release suffix, unique per build key
}

type BuildProgress struct {
	Stage    string   `json:"stage,omitempty"`
	Progress float64  `json:"progress,omitempty"`
	Lines    []string `json:"lines,omitempty"`
}

type BuildResult struct {
	Release  string      `json:"release,omitempty"`
	Artifact string      `json:"artifact,omitempty"`
	Files    []BuildFile `json:"files,omitempty"`
	Error    string      `json:"error,omitempty"`
	Seconds  float64     `json:"seconds"`
}

// ExecArgs runs a shell command on the Mac.
type ExecArgs struct {
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

type ExecResult struct {
	ExitCode int     `json:"exit_code"`
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
	Seconds  float64 `json:"seconds"`
	Via      string  `json:"via"` // agent or serial
}

// ---- release gate: a kernel's results across the supported chip families ----

// Gate results: of a run, a chip family, and the whole gate.
const (
	GatePass     = "pass"
	GateFail     = "fail"
	GateUntested = "untested"
	// GateStageFailed: the kernel never booted because staging it failed on
	// the Mac (e.g. a full boot partition). It says nothing about the kernel,
	// but the gate stays shut until a run gives a result.
	GateStageFailed = "stage_failed"
	// GateFlaky: a Mac both passed and failed on the kernel, e.g. a retry
	// passed after a failure. It doesn't pass: a script that looks for "fail"
	// must treat it as not passing too.
	GateFlaky = "flaky"
)

type GateKernel struct {
	SHA256  string `json:"sha256"`
	Build   string `json:"build,omitempty"`   // the build that produced it
	Release string `json:"release,omitempty"` // the kernel release it boots as
}

type GateTest struct {
	Name   string `json:"name"`
	Result string `json:"result"` // pass or fail
}

// GateRun is the job that decides one Mac's result on the kernel; a flaky
// Mac has two, its failure and then its pass. In a family's not_counted it is
// a run that decides nothing, and NotCounted says why.
type GateRun struct {
	Device     string     `json:"device"`
	Job        string     `json:"job"`
	Outcome    string     `json:"outcome"`
	Result     string     `json:"result"`           // pass, fail, flaky or stage_failed
	Reason     string     `json:"reason,omitempty"` // stage_failed: the job's summary; flaky: the Mac's other result
	Finished   time.Time  `json:"finished"`
	Tests      []GateTest `json:"tests,omitempty"`
	Volunteer  bool       `json:"volunteer,omitempty"`   // the Mac is a volunteer's (Device.Volunteer)
	NotCounted string     `json:"not_counted,omitempty"` // why the run doesn't count
	RetryOf    string     `json:"retry_of,omitempty"`    // the job this one retries (lab retry)
	Excluded   bool       `json:"excluded,omitempty"`    // the query (?exclude=, lab gate --exclude) or lab exclude set it aside
	// Exclusion is the lab exclude mark that set the run aside, if one did.
	Exclusion *GateExclusion `json:"exclusion,omitempty"`
}

// GateExcluded is one of a kernel's jobs that lab exclude set aside.
type GateExcluded struct {
	Job     string `json:"job"`
	Device  string `json:"device"`
	Outcome string `json:"outcome"`
	GateExclusion
}

type GateFamily struct {
	Family string    `json:"family"`         // m1, m1-pro, ...
	Name   string    `json:"name"`           // M1 Pro/Max/Ultra
	Result string    `json:"result"`         // pass, fail, flaky, stage_failed or untested
	Runs   []GateRun `json:"runs,omitempty"` // the deciding run first
	// NotCounted holds the runs that decide nothing: volunteers' Macs, Macs
	// labd no longer has, runs that weren't plain, passes with no
	// omarchy-m-test reference, tests that couldn't run, excluded jobs.
	NotCounted []GateRun `json:"not_counted,omitempty"`
}

// GateReport says whether a kernel passed on real hardware for every required
// chip family. It is also the evidence record `lab gate --evidence` writes.
type GateReport struct {
	Kernel       GateKernel   `json:"kernel"`
	Result       string       `json:"result"` // pass (the gate is open) or fail
	Summary      string       `json:"summary"`
	Required     []string     `json:"required"`
	Families     []GateFamily `json:"families"`
	Untested     []string     `json:"untested,omitempty"`
	Unclassified []string     `json:"unclassified,omitempty"` // Macs of no supported family, or too old an agent to say
	Labd         string       `json:"labd"`
	Generated    time.Time    `json:"generated"`
	// Volunteers lists the volunteers' Macs. Their runs count only when
	// VolunteersCounted (?volunteers=1, lab gate --volunteers).
	Volunteers        []string `json:"volunteers,omitempty"`
	VolunteersCounted bool     `json:"volunteers_counted,omitempty"`
	// Excluded lists the jobs the query set aside (?exclude=, lab gate
	// --exclude), say a failure the lab caused that reads as the kernel's.
	// Each one that would have counted is in its family's not_counted.
	Excluded []string `json:"excluded,omitempty"`
	// Exclusions lists the kernel's jobs set aside until cleared (lab
	// exclude), with who set each aside, why and when. Each one that would
	// have counted is in its family's not_counted too.
	Exclusions []GateExcluded `json:"exclusions,omitempty"`
	// NotCounted holds the runs no family can take: those of Macs labd no
	// longer has (lab forget) from jobs that didn't record their chip family.
	NotCounted []GateRun `json:"not_counted,omitempty"`
}

// ---- Maintainers: the named people with their own access to labd ----

type Maintainer struct {
	Name    string    `json:"name"`
	Added   time.Time `json:"added"`
	AddedBy string    `json:"added_by,omitempty"` // empty for the first Maintainer
}

type MaintainerRequest struct {
	Name string `json:"name"`
}

// NewMaintainer carries a new Maintainer's token, the only time labd shows it.
type NewMaintainer struct {
	Maintainer
	Token string `json:"token"`
}

// EndedHeader is the header on the 401 that tells a Mac its enrollment was
// ended by the Maintainers, not merely revoked: it holds the Maintainer's name.
const EndedHeader = "X-Maclab-Enrollment-Ended-By"

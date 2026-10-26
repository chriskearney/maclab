package agent

import (
	"context"
	"io"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// Fetcher downloads an artifact by sha256 into dst and verifies it.
type Fetcher func(ctx context.Context, sha, dst string) error

// Quieter tells labd, before the Mac goes off the network, how long it may be
// off on this boot, so that labd doesn't count it as lost meanwhile; 0, once
// it is back, ends that spell.
type Quieter func(ctx context.Context, d time.Duration) error

// System is everything the agent does to the machine. Linux is the real
// implementation; Sim stands in for a Mac in tests.
type System interface {
	Identity() (bootID, kernel, cmdline string)
	Facts() api.Facts
	Health() api.Health
	// WatchKernel feeds every kernel log line of this boot to fn until ctx ends.
	WatchKernel(ctx context.Context, fn func(line string))
	// WatchSleep calls fn(true) just before the machine suspends and
	// fn(false) once it has resumed.
	WatchSleep(ctx context.Context, fn func(sleeping bool))

	Stage(ctx context.Context, job string, a api.StageArgs, fetch Fetcher) (api.StageResult, error)
	BootOnce(entry string) error
	// RunTest runs a test; a test that takes the network down (suspend-devices)
	// tells labd first with quiet.
	RunTest(ctx context.Context, job string, t api.TestSpec, fetch Fetcher, quiet Quieter, outDir string) api.TestResult
	Collect(ctx context.Context, boot, outDir string) error
	// PreviousBoot is the ID of the boot before this one, if the journal saw
	// it start after since; "" if not.
	PreviousBoot(since time.Time) string
	// CollectPstore copies the pstore/ramoops records of crashes since since
	// into outDir and returns their names.
	CollectPstore(since time.Time, outDir string) ([]string, error)
	Cleanup(job string, all bool) error
	// Screenshot captures the GUI session as JPEG to path.
	Screenshot(ctx context.Context, path string, wait time.Duration) (w, h int, err error)
	Logs(ctx context.Context, a api.LogsArgs) (string, error)
	// KernelConfig is the running kernel's .config (/proc/config.gz).
	KernelConfig() (string, error)
	Exec(ctx context.Context, a api.ExecArgs) api.ExecResult
	// RecordKnownGood records the running kernel as known-good, as setup does,
	// if it is kernel and not a lab boot.
	RecordKnownGood(kernel string) error

	// Reboot and Crash run after the command's result has been reported.
	Reboot() error
	Crash(mode string) error

	// OpenWatchdog takes the hardware watchdog for the agent to feed on a
	// test boot. Nothing stops it again: once the agent exits, the machine
	// resets unless something else feeds it.
	OpenWatchdog() (io.Writer, error)
	// PingInit returns once the init system (PID 1) answers a question, or
	// an error if it doesn't before ctx ends. The agent feeds the watchdog
	// only while it answers.
	PingInit(ctx context.Context) error
	// InhibitSuspend keeps the machine from suspending, for the reason why,
	// until release; a boot ends it too. It never inhibits idle, so the idle
	// lock and screensaver carry on.
	InhibitSuspend(why string) (release func(), err error)

	// Alive is false while a simulated machine is hung. Always true on Linux.
	Alive() bool

	// SnapshotEligible is nil when @ can be snapshotted, else why not.
	SnapshotEligible() error
}

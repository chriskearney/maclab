package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// Sim is a pretend Mac. A kernel artifact for it is a text file such as
// "krel=7.1-test behavior=panic"; behaviors are ok, omt-regress (boots, but
// Wi-Fi fails in omarchy-m-test), panic (at boot),
// hang (at boot), silent (hang with no serial output), crash-in-test,
// reboot-in-test (reboots with no kernel message), hang-in-test (goes silent
// for HangFor, then a watchdog resets it, again with no kernel message) and
// no-network (boots to the login prompt, then never reaches labd). A field
// apple_wdt=n says the kernel was built without apple_wdt.
// A test named suspend-* puts it to sleep for SuspendFor, announcing it the way
// logind does; one named quiet-suspend-* sleeps without announcing it. The
// builtin suspend-devices tells labd to expect QuietFor of silence first, as
// the real one does, and then is quiet for SuspendFor, with no sleep
// announcement (on a real Mac that rarely reaches labd), and then tells labd
// it is back. A test named hang-* goes silent for HangFor, and then a
// watchdog resets the Mac, as hang-in-test does.
type Sim struct {
	RebootDelay time.Duration
	OnBoot      func() // called when the machine goes down, like a dropped connection
	Model       string
	Serial      func(line string) // wired to a fake OOB controller
	WorkDir     string
	SuspendFor  time.Duration
	QuietFor    time.Duration
	HangFor     time.Duration

	mu           sync.Mutex
	sleepFn      func(bool)
	bootID       string
	prevBootID   string
	kernel       string
	cmdline      string
	noAppleWDT   bool // the running kernel was built without apple_wdt
	alive        bool
	armed        string
	staged       map[string]simEntry
	behavior     string
	gen          int
	kmsg         chan string
	Boots        int
	InstalledObs func(phase, job, bootID, kernel, cmdline string) []byte
	// Tests may stand in fixture files: OMTReport replaces the synthetic
	// omarchy-m-test report, TestFiles adds files a test leaves in its output
	// directory, and DmesgErrors replaces the collected kernel error lines.
	OMTReport   func(kernel string) []byte
	TestFiles   func(test, kernel string) map[string][]byte
	DmesgErrors func(kernel string) string
	OnExec      func(command string) (stdout string, ok bool) // answers lab exec instead of echoing
	// DefaultKernel, once an installer has run, is what a plain reboot boots
	// instead of SimKnownGood; RecordedKnownGood is the agent's record.
	DefaultKernel     string
	RecordedKnownGood string
	// KnownGoodHook, when set, answers record_known_good instead; set it with
	// SetKnownGoodHook once the agent runs.
	KnownGoodHook func(kernel string) error
	// CollectHook, when set, replaces log collection: it may write other files or fail.
	CollectHook func(boot, outDir string) error
	// PackagedKernels are releases installed as packages (installed-mode jobs).
	PackagedKernels []string
	// installHook, when set, is called with the Release before the simulated
	// installer installs it; see SetInstallHook. installs are the Releases it
	// installed, in order.
	installHook func(release string) error
	installs    []string

	stageFail  func(attempt int) error
	stageTries int

	// A Volunteer's Mac. Every knob is off by default.
	// Encrypted holds every cold boot at the disk password prompt until TypePassword.
	Encrypted bool
	// KexecPass is whether the Mac can kexec a Lab boot with its volume key in memory.
	KexecPass bool
	// onBattery is a Mac unplugged from AC power; see SetOnBattery.
	onBattery bool
	// noSnapshot is a Mac whose @ can't be snapshotted; see SetSnapshotable.
	noSnapshot bool

	unlock   func() // the boot waiting at the disk password prompt
	snapshot *simDisk
	notices  []string
	// noDesktop is a Mac whose GUI user has no session that can show a notice;
	// pausers[i] is the Pause button of notices[i], nil for a notice without one.
	noDesktop bool
	pausers   []func()

	// earlyUnit runs from the start of each boot's userspace until the boot
	// ends, as lab-agent's early systemd unit does; the agent sets it.
	earlyUnit func(ctx context.Context)
	endBoot   context.CancelFunc
	down      chan struct{} // closed when the current boot ends

	testLength time.Duration    // see SetTestLength
	inhibitors map[int][]string // held inhibitors' --what names, by token; a boot clears them
	inhibitSeq int
}

// simDisk is what a snapper snapshot holds of the simulated @ (packages and
// the agent's record) and ESP (boot entries).
type simDisk struct {
	defaultKernel, recordedKnownGood, armed string
	packagedKernels                         []string
	staged                                  map[string]simEntry
}

type simEntry struct {
	krel, behavior, cmdline string
	half                    bool // a failed staging's leftovers
	noAppleWDT              bool
}

// InstalledObs, when set, answers installed-mode identity tests: it returns
// the collector's observation for a phase on the given running boot. Set it
// with SetInstalledObs once the agent runs.

const SimKnownGood = "7.1.12-good"

func NewSim(workDir string) *Sim {
	s := &Sim{RebootDelay: 100 * time.Millisecond, staged: map[string]simEntry{}, WorkDir: workDir}
	s.bootID = newID()
	s.kernel = SimKnownGood
	s.cmdline = "root=UUID=sim rw"
	s.alive = true
	s.kmsg = make(chan string, 100)
	s.down = make(chan struct{})
	return s
}

// newID is a boot ID shaped like /proc/sys/kernel/random/boot_id.
func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (s *Sim) say(line string) {
	if s.Serial != nil {
		s.Serial(line)
	}
}

func (s *Sim) Identity() (string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bootID, s.kernel, s.cmdline
}

func (s *Sim) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.alive
}

func (s *Sim) Facts() api.Facts {
	model := s.Model
	if model == "" {
		model = "Simulated Mac"
	}
	return api.Facts{Hostname: "sim", Machine: "aarch64", DTModel: model, Bootloader: "grub",
		Initramfs: "mkinitcpio", GUIUser: "sim", Watchdog: true, WatchdogArmed: true, PanicTimeout: 10, PreflightOK: true}
}

// SetSnapshotable says whether the simulated Mac's @ can be snapshotted
// (true by default).
func (s *Sim) SetSnapshotable(ok bool) {
	s.mu.Lock()
	s.noSnapshot = !ok
	s.mu.Unlock()
}

func (s *Sim) SnapshotEligible() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noSnapshot {
		return fmt.Errorf("the simulated @ cannot be snapshotted")
	}
	return nil
}

func (s *Sim) Health() api.Health {
	_, _, c := s.Identity()
	s.mu.Lock()
	defer s.mu.Unlock()
	return api.Health{Uptime: 1, SystemState: "running", JobTag: jobTag(c), OnBattery: s.onBattery}
}

// SetOnBattery unplugs the Mac from AC power, or plugs it back in.
func (s *Sim) SetOnBattery(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onBattery = on
}

func (s *Sim) WatchKernel(ctx context.Context, fn func(string)) {
	for {
		select {
		case <-ctx.Done():
			return
		case l := <-s.kmsg:
			fn(l)
		}
	}
}

// FailStage makes each staging from now on ask f first, with its number
// (from 1): an error fails that attempt and leaves the job half staged, as a
// dropped download or a full ESP would. A half-staged job stages again only
// after a cleanup. f runs outside the Sim's lock, so it may also take its
// time, or reboot or quiet the Sim, as staging on a real Mac can.
func (s *Sim) FailStage(f func(attempt int) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stageFail, s.stageTries = f, 0
}

// Quiet makes the machine unreachable for d on the same boot, as a network
// outage would: no check-ins, no reports, and whatever runs carries on.
func (s *Sim) Quiet(d time.Duration) { s.suspend(d, false) }

func (s *Sim) Stage(ctx context.Context, job string, a api.StageArgs, fetch Fetcher) (api.StageResult, error) {
	s.mu.Lock()
	if s.staged[job].half {
		s.mu.Unlock()
		return api.StageResult{}, fmt.Errorf("leftovers of an earlier attempt at %s are in the way", job)
	}
	fail := s.stageFail
	s.stageTries++
	n := s.stageTries
	s.mu.Unlock()
	if fail != nil {
		if err := fail(n); err != nil {
			s.mu.Lock()
			s.staged[job] = simEntry{half: true}
			s.mu.Unlock()
			return api.StageResult{}, err
		}
	}
	if in := a.Installed; in != nil {
		if in.Path == "" || in.UKISHA256 == "" || in.Cmdline == "" {
			return api.StageResult{}, fmt.Errorf("installed stage needs path, uki_sha256 and cmdline")
		}
		cmdline := withLabBootParams(in.Cmdline, labBootOpenTimeout(a))
		s.mu.Lock()
		s.staged[job] = simEntry{krel: in.Release, behavior: "ok", cmdline: cmdline}
		s.mu.Unlock()
		return api.StageResult{KernelRelease: in.Release, Entry: entryPrefix + job, Cmdline: cmdline}, nil
	}
	e := simEntry{krel: SimKnownGood, behavior: "ok"}
	if a.Artifact != "" {
		p := filepath.Join(s.WorkDir, job+".art")
		if err := fetch(ctx, a.Artifact, p); err != nil {
			return api.StageResult{}, err
		}
		b, _ := os.ReadFile(p)
		for _, f := range strings.Fields(string(b)) {
			if v, ok := strings.CutPrefix(f, "krel="); ok {
				e.krel = v
			}
			if v, ok := strings.CutPrefix(f, "behavior="); ok {
				e.behavior = v
			}
			e.noAppleWDT = e.noAppleWDT || f == "apple_wdt=n"
		}
		if e.krel == SimKnownGood {
			return api.StageResult{}, fmt.Errorf("artifact kernel release %s is the running kernel", e.krel)
		}
	}
	cmdline, err := stageCmdline(s.cmdline, func() (string, error) { return "root=UUID=sim rw quiet splash", nil }, a, job)
	if err != nil {
		return api.StageResult{}, err
	}
	e.cmdline = cmdline
	s.mu.Lock()
	s.staged[job] = e
	s.mu.Unlock()
	return api.StageResult{KernelRelease: e.krel, Entry: entryPrefix + job, Cmdline: e.cmdline, NoAppleWDT: e.noAppleWDT}, nil
}

func (s *Sim) BootOnce(entry string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.staged[strings.TrimPrefix(entry, entryPrefix)]; !ok {
		return fmt.Errorf("entry %s is not staged", entry)
	}
	s.armed = entry
	return nil
}

// Install is the Release's installer: its kernel becomes a package and the
// default a plain reboot boots, as on a Mac the Omarchy installer ran on.
func (s *Sim) Install(ctx context.Context, job string, a api.InstallArgs, fetch Fetcher) error {
	s.mu.Lock()
	hook := s.installHook
	s.mu.Unlock()
	if hook != nil {
		if err := hook(a.Release); err != nil {
			return fmt.Errorf("installing %s: %w", a.Release, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.PackagedKernels, a.Kernel) {
		s.PackagedKernels = append(s.PackagedKernels, a.Kernel)
	}
	s.DefaultKernel = a.Kernel
	s.installs = append(s.installs, a.Release)
	return nil
}

// SetInstallHook makes the simulated installer call f with the Release
// before it installs it, while the agent runs; an error from f fails the
// install and leaves the Mac as it was.
func (s *Sim) SetInstallHook(f func(release string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.installHook = f
}

// Installs lists the Releases the named install operation installed on the
// simulated Mac, in order.
func (s *Sim) Installs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.installs)
}

// SetInstalledObs sets InstalledObs while the agent runs.
func (s *Sim) SetInstalledObs(f func(phase, job, bootID, kernel, cmdline string) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InstalledObs = f
}

func (s *Sim) Reboot() error { s.boot("reboot: Restarting system"); return nil }

// OpenWatchdog fails: the Sim has no hardware watchdog.
func (s *Sim) OpenWatchdog() (io.Writer, error) { return nil, errors.New("no hardware watchdog") }

// PingInit always answers.
func (s *Sim) PingInit(ctx context.Context) error { return nil }

func (s *Sim) Crash(mode string) error {
	s.boot("Kernel panic - not syncing: sysrq triggered crash")
	return nil
}

// PowerCycle is what the OOB reset (or a human) does.
func (s *Sim) PowerCycle() { s.boot("") }

func (s *Sim) boot(last string) {
	s.mu.Lock()
	s.alive = false
	s.gen++
	gen := s.gen
	down := s.OnBoot
	if s.endBoot != nil {
		s.endBoot()
		s.endBoot = nil
	}
	close(s.down)
	s.down = make(chan struct{})
	s.inhibitors = nil
	s.mu.Unlock()
	if down != nil {
		down()
	}
	if last != "" {
		s.say(last)
	}
	go func() {
		time.Sleep(s.RebootDelay)
		s.mu.Lock()
		if gen != s.gen {
			s.mu.Unlock()
			return
		}
		e := simEntry{krel: SimKnownGood, behavior: "ok", cmdline: "root=UUID=sim rw"}
		if s.DefaultKernel != "" {
			e.krel = s.DefaultKernel
		}
		if s.armed != "" {
			e = s.staged[strings.TrimPrefix(s.armed, entryPrefix)]
			s.armed = "" // GRUB clears the one-shot before booting
		}
		s.prevBootID, s.bootID = s.bootID, newID()
		s.Boots++
		s.mu.Unlock()
		s.say("m1n1: booting")
		if e.behavior != "silent" {
			s.say("Booting Linux on physical CPU 0x0000000000 [0x611f0221]")
		}
		s.mu.Lock()
		if s.Encrypted && gen == s.gen {
			s.unlock = func() { s.up(gen, e) }
			s.mu.Unlock()
			s.say("Please enter passphrase for disk root:")
			return
		}
		s.mu.Unlock()
		s.up(gen, e)
	}()
}

// up carries a boot on from the kernel's first line, once any disk password is in.
func (s *Sim) up(gen int, e simEntry) {
	switch e.behavior {
	case "panic":
		s.say("Kernel panic - not syncing: VFS: Unable to mount root fs")
		s.say("Rebooting in 10 seconds..")
		time.Sleep(s.RebootDelay)
		s.boot("")
		return
	case "hang":
		s.say("rcu: INFO: rcu_sched self-detected stall on CPU")
		return
	case "silent":
		return
	}
	s.mu.Lock()
	if gen != s.gen {
		s.mu.Unlock()
		return
	}
	s.kernel, s.cmdline, s.behavior, s.noAppleWDT = e.krel, e.cmdline, e.behavior, e.noAppleWDT
	s.alive = e.behavior != "no-network" // up, but labd never hears from it
	if unit := s.earlyUnit; unit != nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.endBoot = cancel
		go unit(ctx)
	}
	s.mu.Unlock()
	s.say("Run /init as init process")
	s.say("sim login: ")
}

// TypePassword is the Volunteer typing the disk password at the prompt.
func (s *Sim) TypePassword() {
	s.mu.Lock()
	unlock := s.unlock
	s.unlock = nil
	s.mu.Unlock()
	if unlock != nil {
		unlock()
	}
}

// Snapshot takes a snapper snapshot of the simulated @ and ESP.
func (s *Sim) Snapshot() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = &simDisk{defaultKernel: s.DefaultKernel, recordedKnownGood: s.RecordedKnownGood, armed: s.armed,
		packagedKernels: slices.Clone(s.PackagedKernels), staged: maps.Clone(s.staged)}
}

// Rollback puts @ and the ESP back as Snapshot found them; the next boot shows it.
func (s *Sim) Rollback() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.snapshot
	if d == nil {
		return fmt.Errorf("no snapshot to roll back to")
	}
	s.DefaultKernel, s.RecordedKnownGood, s.armed = d.defaultKernel, d.recordedKnownGood, d.armed
	s.PackagedKernels, s.staged = d.packagedKernels, d.staged
	s.snapshot = nil
	return nil
}

// Notify shows a desktop notice to the Volunteer; Notices lists those shown.
func (s *Sim) Notify(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notices = append(s.notices, text)
	s.pausers = append(s.pausers, nil)
}

// NotifyWithPause shows a notice with a Pause button that runs onPause when
// pressed; false if the GUI user has no desktop session to show it in.
func (s *Sim) NotifyWithPause(ctx context.Context, text string, onPause func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noDesktop {
		return false
	}
	s.notices = append(s.notices, text)
	s.pausers = append(s.pausers, onPause)
	return true
}

// SetDesktopSession says whether the GUI user has a desktop session that can
// show a notice (true by default); without one, nothing is shown. Safe to
// call while the agent runs.
func (s *Sim) SetDesktopSession(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noDesktop = !on
}

// PressNoticePause presses the Pause button on the latest shown notice that
// has one, as the Volunteer would; it is an error if none has.
func (s *Sim) PressNoticePause() error {
	s.mu.Lock()
	var press func()
	for i := len(s.pausers) - 1; i >= 0 && press == nil; i-- {
		press = s.pausers[i]
	}
	s.mu.Unlock()
	if press == nil {
		return errors.New("no notice has a Pause button")
	}
	press()
	return nil
}

func (s *Sim) Notices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.notices)
}

func (s *Sim) WatchSleep(ctx context.Context, fn func(bool)) {
	s.mu.Lock()
	s.sleepFn = fn
	s.mu.Unlock()
}

// suspend sleeps the machine for d: no heartbeats, no reports, nothing lost.
func (s *Sim) suspend(d time.Duration, announce bool) {
	s.sleep(announce)
	time.Sleep(d)
	s.wake(announce)
}

// Sleep suspends the Mac the way closing its lid does, announced as logind
// does, until Wake.
func (s *Sim) Sleep() { s.sleep(true) }

// Wake resumes the Mac from Sleep.
func (s *Sim) Wake() { s.wake(true) }

func (s *Sim) sleep(announce bool) {
	s.mu.Lock()
	fn := s.sleepFn
	s.mu.Unlock()
	if announce && fn != nil {
		fn(true)
	}
	s.mu.Lock()
	s.alive = false
	s.mu.Unlock()
}

func (s *Sim) wake(announce bool) {
	s.mu.Lock()
	s.alive = true
	fn := s.sleepFn
	s.mu.Unlock()
	if announce && fn != nil {
		fn(false)
	}
}

// SetTestLength makes every test the Sim runs take d of wall time, unless its
// context ends or its boot ends first (the Mac reboots or powers off); 0, the
// default, is the usual near-instant test. Safe to call while the agent runs.
func (s *Sim) SetTestLength(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.testLength = d
}

// InhibitSuspend takes the inhibitor the real Mac's command line takes.
func (s *Sim) InhibitSuspend(why string) (func(), error) {
	var what []string
	for _, a := range inhibitSuspendArgs(why) {
		if v, ok := strings.CutPrefix(a, "--what="); ok {
			what = append(what, strings.Split(v, ":")...)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inhibitSeq++
	tok := s.inhibitSeq
	if s.inhibitors == nil {
		s.inhibitors = map[int][]string{}
	}
	s.inhibitors[tok] = what
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.inhibitors, tok)
	}, nil
}

// Inhibitors is what lab-agent holds inhibited on the Mac now, named as
// systemd-inhibit's --what names them ("sleep", "idle", ...). A boot ends
// every inhibitor taken on it.
func (s *Sim) Inhibitors() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for _, what := range s.inhibitors {
		for _, w := range what {
			if !slices.Contains(names, w) {
				names = append(names, w)
			}
		}
	}
	return names
}

func (s *Sim) RunTest(ctx context.Context, job string, t api.TestSpec, fetch Fetcher, quiet Quieter, outDir string) api.TestResult {
	s.mu.Lock()
	b, length, down := s.behavior, s.testLength, s.down
	s.mu.Unlock()
	if length > 0 {
		wait := time.NewTimer(length)
		defer wait.Stop()
		select {
		case <-wait.C:
		case <-ctx.Done():
			return api.TestResult{Name: t.Name, ExitCode: -1, Error: "stopped: " + context.Cause(ctx).Error()}
		case <-down:
			return api.TestResult{Name: t.Name, Error: "machine went away"}
		}
	}
	if t.Builtin == "omarchy-m-test" {
		return s.omtReport(t, outDir, b)
	}
	s.mu.Lock()
	obsFn := s.InstalledObs
	s.mu.Unlock()
	if t.Identity != nil && obsFn != nil {
		s.mu.Lock()
		boot, k, cmd := s.bootID, s.kernel, s.cmdline
		s.mu.Unlock()
		obs := obsFn(t.Identity.Phase, job, boot, k, cmd)
		os.WriteFile(filepath.Join(outDir, "observed.json"), obs, 0o644)
		return api.TestResult{Name: t.Name, Passed: true, Seconds: 0.01, Tail: "sim identity " + t.Name}
	}
	switch {
	case t.Builtin == suspendDevicesTest:
		quiet(ctx, s.QuietFor) // the real test carries on if labd didn't hear it, too
		s.suspend(s.SuspendFor, false)
		quiet(ctx, 0) // the network is back
	case strings.HasPrefix(t.Name, "suspend-") || strings.HasPrefix(t.Name, "quiet-suspend-"):
		s.suspend(s.SuspendFor, strings.HasPrefix(t.Name, "suspend-"))
	}
	if b == "crash-in-test" {
		s.kmsg <- "Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008"
		time.Sleep(50 * time.Millisecond)
		s.boot("Kernel panic - not syncing: Oops: Fatal exception")
		<-ctx.Done()
		return api.TestResult{Name: t.Name, Error: "machine went away"}
	}
	if hang := b == "hang-in-test" || strings.HasPrefix(t.Name, "hang-"); hang || b == "reboot-in-test" {
		if hang {
			s.mu.Lock()
			s.alive = false
			s.mu.Unlock()
			time.Sleep(s.HangFor)
		}
		s.boot("")
		<-ctx.Done()
		return api.TestResult{Name: t.Name, Error: "machine went away"}
	}
	os.WriteFile(filepath.Join(outDir, "log.txt"), []byte("sim test "+t.Name+" ok\n"), 0o644)
	if s.TestFiles != nil {
		s.mu.Lock()
		k := s.kernel
		s.mu.Unlock()
		for name, data := range s.TestFiles(t.Name, k) {
			p := filepath.Join(outDir, filepath.FromSlash(name))
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, data, 0o644)
		}
	}
	passed := !strings.Contains(t.Name, "fail")
	code := 0
	if !passed {
		code = 1
	}
	return api.TestResult{Name: t.Name, Passed: passed, ExitCode: code, Seconds: 0.01, Tail: "sim test " + t.Name}
}

func (s *Sim) Collect(ctx context.Context, boot, outDir string) error {
	if s.CollectHook != nil {
		return s.CollectHook(boot, outDir)
	}
	s.mu.Lock()
	k, cmdline := s.kernel, s.cmdline
	s.mu.Unlock()
	errs := "apple-dart 382f00000.dart: DART fault\n"
	if k != SimKnownGood {
		errs += "sim: new regression warning in driver foo\n"
	}
	if s.DmesgErrors != nil {
		errs = s.DmesgErrors(k)
	}
	os.WriteFile(filepath.Join(outDir, "dmesg-errors.txt"), []byte(errs), 0o644)
	os.WriteFile(filepath.Join(outDir, "journal.txt"), []byte("sim journal for boot "+boot+"\n"), 0o644)
	os.WriteFile(filepath.Join(outDir, "kernel.txt"), []byte("[    0.000000] Linux version "+k+"\n[    0.000000] Kernel command line: "+cmdline+"\n"), 0o644)
	return os.WriteFile(filepath.Join(outDir, "collect-status.txt"), []byte("journal.txt ok\nkernel.txt ok\ndmesg-errors.txt ok\n"), 0o644)
}

func (s *Sim) Screenshot(ctx context.Context, path string, wait time.Duration) (int, int, error) {
	s.mu.Lock()
	k := s.kernel
	s.mu.Unlock()
	const w, h = 640, 400
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// A desktop-ish frame: dark background, a bar, and a window whose tint encodes the kernel.
	tint := uint8(len(k) * 37)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{28, 34, 53, 255}
			switch {
			case y < 16:
				c = color.RGBA{20, 24, 38, 255}
			case x > 60 && x < 420 && y > 60 && y < 320:
				c = color.RGBA{40, 48 + tint/8, 72, 255}
			case x > 440 && x < 600 && y > 60 && y < 200:
				c = color.RGBA{154, 179, 255, 255}
			}
			img.Set(x, y, c)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	return w, h, jpeg.Encode(f, img, &jpeg.Options{Quality: 80})
}

func (s *Sim) Logs(ctx context.Context, a api.LogsArgs) (string, error) {
	_, k, _ := s.Identity()
	var b strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "Sep 30 00:%02d:%02d.000000 sim kernel: sim %s line %d from %s\n", i/60, i%60, a.Source, i, k)
	}
	return b.String(), nil
}

func (s *Sim) Cleanup(job string, all bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if all {
		s.staged = map[string]simEntry{}
		s.armed = ""
	} else {
		delete(s.staged, job)
	}
	return nil
}

func (s *Sim) KernelConfig() (string, error) {
	s.mu.Lock()
	k, wdt := s.kernel, "CONFIG_APPLE_WATCHDOG=y\n"
	if s.noAppleWDT {
		wdt = "# CONFIG_APPLE_WATCHDOG is not set\n"
	}
	s.mu.Unlock()
	return "# sim config for " + k + "\nCONFIG_ARM64=y\nCONFIG_LOCALVERSION=\"\"\n" + wdt, nil
}

// setEarlyUnit sets what runs at the start of each boot's userspace.
func (s *Sim) setEarlyUnit(f func(ctx context.Context)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.earlyUnit = f
}

// PreviousBoot is the boot before this one: the Sim's journal keeps every boot.
func (s *Sim) PreviousBoot(since time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prevBootID
}

func (s *Sim) CollectPstore(since time.Time, outDir string) ([]string, error) { return nil, nil }

func (s *Sim) Exec(ctx context.Context, a api.ExecArgs) api.ExecResult {
	if s.OnExec != nil {
		if out, ok := s.OnExec(a.Command); ok {
			return api.ExecResult{Stdout: out, Via: "agent"}
		}
	}
	return api.ExecResult{Stdout: "sim ran: " + a.Command + "\n", Via: "agent"}
}

// omtReport writes a small omarchy-m-test report like the real tool's.
func (s *Sim) omtReport(t api.TestSpec, outDir, behavior string) api.TestResult {
	s.mu.Lock()
	kernel, packaged := s.kernel, slices.Contains(s.PackagedKernels, s.kernel)
	s.mu.Unlock()
	wifi, pkg := "pass", "pass"
	if kernel != SimKnownGood && !packaged {
		pkg = "fail" // a lab kernel is never an installed package
	}
	unclaimed, drivers := "[]", "pass"
	if behavior == "omt-regress" {
		wifi = "fail"
	}
	if behavior == "omt-no-fingerprint" {
		unclaimed, drivers = `[{"compatible":"apple,mesa-fingerprint","count":1,"outcome":"unknown-hardware"}]`, "fail"
	}
	// display.cursor is the Sim's one check that needs the screen visible
	onScreen := `,
{"id":"display.cursor","kind":"human","status":"skip","evidence":["no answer"]}`
	if t.SkipOnScreen {
		onScreen = ""
	}
	report := fmt.Sprintf(`{"schema_version":1,"tool":{"name":"omarchy-m-test","version":"0.1.10"},"consent_version":6,"catalogue_version":11,
"inventory":{"unclaimed":%s},"machine":{"model":"Sim Mac","board":"j000","soc":"t0000","chip":"M0","arch":"aarch64","kernel":%q},"system":{"stack":"converged"},
"checks":[{"id":"boot.kernel-package","kind":"automatic","status":%q,"evidence":["kernel package"],"classification":{"outcome":"works"}},
{"id":"hardware.drivers","kind":"automatic","status":%q,"evidence":["nodes"],"classification":{"outcome":"works"}},
{"id":"wifi.connected","kind":"automatic","status":%q,"evidence":["wlan0 up"],"classification":{"outcome":"works"}},
{"id":"system.snapshots","kind":"automatic","status":"fail","evidence":["/.snapshots is not a btrfs subvolume"],"classification":{"outcome":"fails"}}%s],"signature":{"public_key":"ssh-ed25519 AAAA","signature":"sim"}}`, unclaimed, kernel, pkg, drivers, wifi, onScreen)
	if s.OMTReport != nil {
		report = string(s.OMTReport(kernel))
	}
	os.WriteFile(filepath.Join(outDir, "omt-report.json"), []byte(report), 0o644)
	return api.TestResult{Name: t.Name, Passed: true, Seconds: 0.01, Tail: "omarchy-m-test 0.1.10 on " + kernel}
}

func (s *Sim) RecordKnownGood(kernel string) error {
	s.mu.Lock()
	hook := s.KnownGoodHook
	s.mu.Unlock()
	if hook != nil {
		return hook(kernel)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kernel != kernel || strings.Contains(s.cmdline, "maclab.job=") {
		return fmt.Errorf("running %s (%q), not %s outside a lab boot", s.kernel, s.cmdline, kernel)
	}
	s.RecordedKnownGood = kernel
	return nil
}

// SetKnownGoodHook sets KnownGoodHook while the agent runs.
func (s *Sim) SetKnownGoodHook(f func(kernel string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.KnownGoodHook = f
}

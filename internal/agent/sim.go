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
// reboot-in-test (reboots with no kernel message) and hang-in-test (goes silent
// for HangFor, then a watchdog resets it, again with no kernel message).
// A test named suspend-* puts it to sleep for SuspendFor, announcing it the way
// logind does; one named quiet-suspend-* sleeps without announcing it. The
// builtin suspend-devices tells labd to expect QuietFor of silence first, as
// the real one does, and then is quiet for SuspendFor, with no sleep
// announcement (on a real Mac that rarely reaches labd).
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
	kernel       string
	cmdline      string
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

	stageFail  func(attempt int) error
	stageTries int
}

type simEntry struct {
	krel, behavior, cmdline string
	half                    bool // a failed staging's leftovers
}

// InstalledObs, when set, answers installed-mode identity tests: it returns
// the collector's observation for a phase on the given running boot.

const SimKnownGood = "7.1.12-good"

func NewSim(workDir string) *Sim {
	s := &Sim{RebootDelay: 100 * time.Millisecond, staged: map[string]simEntry{}, WorkDir: workDir}
	s.bootID = newID()
	s.kernel = SimKnownGood
	s.cmdline = "root=UUID=sim rw"
	s.alive = true
	s.kmsg = make(chan string, 100)
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

func (s *Sim) Health() api.Health {
	_, _, c := s.Identity()
	return api.Health{Uptime: 1, SystemState: "running", JobTag: jobTag(c)}
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
		s.mu.Lock()
		s.staged[job] = simEntry{krel: in.Release, behavior: "ok", cmdline: in.Cmdline}
		s.mu.Unlock()
		return api.StageResult{KernelRelease: in.Release, Entry: entryPrefix + job, Cmdline: in.Cmdline}, nil
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
	return api.StageResult{KernelRelease: e.krel, Entry: entryPrefix + job, Cmdline: e.cmdline}, nil
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
		s.bootID = newID()
		s.Boots++
		s.mu.Unlock()
		s.say("m1n1: booting")
		if e.behavior != "silent" {
			s.say("Booting Linux on physical CPU 0x0000000000 [0x611f0221]")
		}
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
		s.kernel, s.cmdline, s.behavior = e.krel, e.cmdline, e.behavior
		s.alive = true
		s.mu.Unlock()
		s.say("Run /init as init process")
		s.say("sim login: ")
	}()
}

func (s *Sim) WatchSleep(ctx context.Context, fn func(bool)) {
	s.mu.Lock()
	s.sleepFn = fn
	s.mu.Unlock()
}

// suspend sleeps the machine for d: no heartbeats, no reports, nothing lost.
func (s *Sim) suspend(d time.Duration, announce bool) {
	s.mu.Lock()
	fn := s.sleepFn
	s.mu.Unlock()
	if announce && fn != nil {
		fn(true)
	}
	s.mu.Lock()
	s.alive = false
	s.mu.Unlock()
	time.Sleep(d)
	s.mu.Lock()
	s.alive = true
	s.mu.Unlock()
	if announce && fn != nil {
		fn(false)
	}
}

func (s *Sim) RunTest(ctx context.Context, job string, t api.TestSpec, fetch Fetcher, quiet Quieter, outDir string) api.TestResult {
	s.mu.Lock()
	b := s.behavior
	s.mu.Unlock()
	if t.Builtin == "omarchy-m-test" {
		return s.omtReport(t, outDir, b)
	}
	if strings.HasPrefix(t.Name, "identity-") && s.InstalledObs != nil {
		s.mu.Lock()
		boot, k, cmd := s.bootID, s.kernel, s.cmdline
		s.mu.Unlock()
		obs := s.InstalledObs(strings.TrimPrefix(t.Name, "identity-"), job, boot, k, cmd)
		os.WriteFile(filepath.Join(outDir, "observed.json"), obs, 0o644)
		return api.TestResult{Name: t.Name, Passed: true, Seconds: 0.01, Tail: "sim identity " + t.Name}
	}
	switch {
	case t.Builtin == suspendDevicesTest:
		quiet(ctx, s.QuietFor) // the real test carries on if labd didn't hear it, too
		s.suspend(s.SuspendFor, false)
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
	if b == "reboot-in-test" || b == "hang-in-test" {
		if b == "hang-in-test" {
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
	_, k, _ := s.Identity()
	return "# sim config for " + k + "\nCONFIG_ARM64=y\nCONFIG_LOCALVERSION=\"\"\n", nil
}

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
	kernel := s.kernel
	s.mu.Unlock()
	wifi, pkg := "pass", "pass"
	if kernel != SimKnownGood && !slices.Contains(s.PackagedKernels, kernel) {
		pkg = "fail" // a lab kernel is never an installed package
	}
	unclaimed, drivers := "[]", "pass"
	if behavior == "omt-regress" {
		wifi = "fail"
	}
	if behavior == "omt-no-fingerprint" {
		unclaimed, drivers = `[{"compatible":"apple,mesa-fingerprint","count":1,"outcome":"unknown-hardware"}]`, "fail"
	}
	report := fmt.Sprintf(`{"schema_version":1,"tool":{"name":"omarchy-m-test","version":"0.1.10"},"consent_version":6,"catalogue_version":11,
"inventory":{"unclaimed":%s},"machine":{"model":"Sim Mac","board":"j000","soc":"t0000","chip":"M0","arch":"aarch64","kernel":%q},"system":{"stack":"converged"},
"checks":[{"id":"boot.kernel-package","kind":"automatic","status":%q,"evidence":["kernel package"],"classification":{"outcome":"works"}},
{"id":"hardware.drivers","kind":"automatic","status":%q,"evidence":["nodes"],"classification":{"outcome":"works"}},
{"id":"wifi.connected","kind":"automatic","status":%q,"evidence":["wlan0 up"],"classification":{"outcome":"works"}},
{"id":"system.snapshots","kind":"automatic","status":"fail","evidence":["/.snapshots is not a btrfs subvolume"],"classification":{"outcome":"fails"}},
{"id":"display.cursor","kind":"human","status":"skip","evidence":["no answer"]}],"signature":{"public_key":"ssh-ed25519 AAAA","signature":"sim"}}`, unclaimed, kernel, pkg, drivers, wifi)
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

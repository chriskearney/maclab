package agent

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/iconidentify/maclab/internal/api"
)

// KnownGood is the kernel the Mac falls back to. setup records it while
// running on that kernel; staged entries reuse its cmdline.
type KnownGood struct {
	Kernel     string `json:"kernel"`
	GrubLinux  string `json:"grub_linux"`
	GrubInitrd string `json:"grub_initrd"`
	Cmdline    string `json:"cmdline"`
	// The filesystem holding the kernel, when it isn't the one holding /boot
	// (e.g. /@/boot-test/... on the btrfs root while /boot is ext4).
	RootUUID string `json:"root_uuid,omitempty"`
	RootFS   string `json:"root_fs,omitempty"`
	// Where setup decided to stage test kernels (default /boot/maclab;
	// <esp>/maclab under Limine).
	StageDir string `json:"stage_dir,omitempty"`
	// The loader setup found: "limine", or "" for GRUB (older records).
	Loader string `json:"loader,omitempty"`
}

type Linux struct {
	WorkDir string
	GUIUser string
}

func (l *Linux) knownGoodPath() string { return filepath.Join(l.WorkDir, "known-good.json") }

func (l *Linux) knownGood() (*KnownGood, error) {
	b, err := os.ReadFile(l.knownGoodPath())
	if err != nil {
		return nil, fmt.Errorf("no known-good kernel recorded (run lab-agent setup): %w", err)
	}
	var k KnownGood
	return &k, json.Unmarshal(b, &k)
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

func (l *Linux) Identity() (string, string, string) {
	return readTrim("/proc/sys/kernel/random/boot_id"), readTrim("/proc/sys/kernel/osrelease"), readTrim("/proc/cmdline")
}

func (l *Linux) Alive() bool { return true }

func jobTag(cmdline string) string {
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "maclab.job="); ok {
			return v
		}
	}
	return ""
}

func (l *Linux) Health() api.Health {
	h := api.Health{}
	if f := strings.Fields(readTrim("/proc/uptime")); len(f) > 0 {
		h.Uptime, _ = strconv.ParseFloat(f[0], 64)
	}
	out, _ := exec.Command("systemctl", "is-system-running").Output()
	h.SystemState = strings.TrimSpace(string(out))
	h.Tainted, _ = strconv.ParseInt(readTrim("/proc/sys/kernel/tainted"), 10, 64)
	_, _, cmd := l.Identity()
	h.JobTag = jobTag(cmd)
	h.OnBattery = onBattery("/sys/class/power_supply")
	return h
}

// onBattery is whether the Mac has an AC adapter (a Mains power supply) and
// it is unplugged. A Mac with none, a desktop, is never on battery.
func onBattery(dir string) bool {
	supplies, _ := os.ReadDir(dir)
	mains, online := false, false
	for _, e := range supplies {
		p := filepath.Join(dir, e.Name())
		if readTrim(filepath.Join(p, "type")) != "Mains" {
			continue
		}
		mains = true
		online = online || readTrim(filepath.Join(p, "online")) == "1"
	}
	return mains && !online
}

func (l *Linux) Facts() api.Facts {
	f := api.Facts{GUIUser: l.GUIUser}
	f.Hostname, _ = os.Hostname()
	var u unix.Utsname // x/sys/unix: labd builds this package on the controller Mac too
	if unix.Uname(&u) == nil {
		f.Machine = unix.ByteSliceToString(u.Machine[:])
	}
	f.DTModel = readTrim("/proc/device-tree/model")
	if c := readTrim("/proc/device-tree/compatible"); c != "" {
		f.Compatible = strings.Split(c, "\x00")
	}
	if _, err := exec.LookPath("mkinitcpio"); err == nil {
		f.Initramfs = "mkinitcpio"
	} else if _, err := exec.LookPath("dracut"); err == nil {
		f.Initramfs = "dracut"
	}
	_, err := os.Stat("/dev/watchdog0")
	f.Watchdog = err == nil
	out, _ := exec.Command("systemctl", "show", "-p", "RuntimeWatchdogUSec", "--value").Output()
	v := strings.TrimSpace(string(out))
	f.WatchdogArmed = f.Watchdog && v != "" && v != "0" && v != "infinity"
	f.PanicTimeout, _ = strconv.Atoi(readTrim("/proc/sys/kernel/panic"))
	f.Problems, f.Warnings = l.Preflight()
	f.PreflightOK = len(f.Problems) == 0
	if b, err := detectBootloader(); err == nil {
		f.Bootloader = b.name()
	}
	return f
}

// Preflight lists everything that makes this Mac unsafe to hand to the lab,
// and, as warnings, what only loses evidence.
func (l *Linux) Preflight() (problems, warnings []string) {
	var p []string
	if os.Geteuid() != 0 {
		p = append(p, "lab-agent is not running as root")
	}
	bins := []string{"findmnt", "tar", "depmod", "journalctl"}
	minFree := uint64(300 << 20)
	var lim *limineLayout
	b, err := detectBootloader()
	if err != nil {
		p = append(p, "bootloader: "+err.Error())
	} else {
		p = append(p, b.problems()...)
		switch b := b.(type) {
		case *grubLayout:
			bins = append(bins, "grub-editenv")
		case *limineLayout:
			bins = append(bins, "chattr", "objcopy")
			lim = b
		}
	}
	hard, warnings := unattended(b)
	p = append(p, hard...)
	for _, bin := range bins {
		if _, err := exec.LookPath(bin); err != nil {
			p = append(p, "missing "+bin)
		}
	}
	if _, err := exec.LookPath("mkinitcpio"); err != nil {
		if _, err := exec.LookPath("dracut"); err != nil {
			p = append(p, "no initramfs generator (mkinitcpio or dracut)")
		}
	}
	if n, _ := strconv.Atoi(readTrim("/proc/sys/kernel/panic")); n <= 0 {
		p = append(p, "kernel.panic is 0: a panic would hang instead of rebooting (run lab-agent setup)")
	}
	if kg, err := l.knownGood(); err != nil {
		p = append(p, err.Error())
	} else if _, err := os.Stat("/usr/lib/modules/" + kg.Kernel); err != nil {
		p = append(p, "known-good kernel "+kg.Kernel+" is no longer installed")
	}
	var st syscall.Statfs_t
	stage := stageDir()
	probe := stage
	if _, err := os.Stat(probe); err != nil {
		probe = filepath.Dir(probe)
	}
	// Test kernels already staged there are deleted before the next job stages
	// (a job starts by cleaning up its Mac), so they count as free: otherwise
	// one staged job would block queueing the next.
	if syscall.Statfs(probe, &st) == nil {
		free := st.Bavail*uint64(st.Bsize) + dirSize(stage)
		if lim != nil {
			// Under Limine, staging needs what writeUKIWith checks, not just the reserve.
			if msg := limineStageProblem(lim.ESP.Target, stage, free, uint64(st.Bsize)); msg != "" {
				p = append(p, msg)
			}
		} else if free < minFree {
			p = append(p, fmt.Sprintf("less than %d MB free where test kernels are staged (%s)", minFree>>20, stage))
		}
	}
	return p, warnings
}

// WatchKernel reads /dev/kmsg from the start of this boot and follows it.
func (l *Linux) WatchKernel(ctx context.Context, fn func(string)) {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		return
	}
	go func() { <-ctx.Done(); f.Close() }()
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if err == syscall.EPIPE { // records overwritten before we read them
				continue
			}
			return
		}
		rec := string(buf[:n])
		if i := strings.IndexByte(rec, ';'); i >= 0 {
			msg := rec[i+1:]
			if j := strings.IndexByte(msg, '\n'); j >= 0 {
				msg = msg[:j]
			}
			fn(msg)
		}
	}
}

func (l *Linux) Reboot() error {
	exec.Command("sync").Run()
	return exec.Command("systemctl", "reboot").Run()
}

func (l *Linux) Crash(mode string) error {
	if mode != "panic" {
		return fmt.Errorf("unknown crash mode %q", mode)
	}
	syncDisks() // a crash test checks recovery, not FAT's tolerance of the lab's unflushed writes
	os.WriteFile("/proc/sys/kernel/sysrq", []byte("1"), 0)
	return os.WriteFile("/proc/sysrq-trigger", []byte("c"), 0)
}

func (l *Linux) BootOnce(entry string) error {
	defer syncDisks()
	b, err := detectBootloader()
	if err != nil {
		return err
	}
	return b.arm(entry)
}

// Collect saves the boot's logs. collect-status.txt says, for each file,
// "<file> ok" or why it isn't valid evidence (the command failed, or the file
// couldn't be written), so an empty log is never mistaken for a clean one.
func (l *Linux) Collect(ctx context.Context, boot, outDir string) error {
	var status strings.Builder
	save := func(name string, out []byte, cmdErr error, cmd string) {
		if cmdErr != nil {
			out = append(out, []byte("\n["+cmd+": "+cmdErr.Error()+"]\n")...)
		}
		werr := os.WriteFile(filepath.Join(outDir, name), out, 0o644)
		switch {
		case werr != nil:
			fmt.Fprintf(&status, "%s write failed: %v\n", name, werr)
		case cmdErr != nil:
			fmt.Fprintf(&status, "%s %s failed: %v\n", name, cmd, cmdErr)
		default:
			fmt.Fprintf(&status, "%s ok\n", name)
		}
	}
	run := func(name string, args ...string) {
		out, err := exec.CommandContext(ctx, "journalctl", args...).CombinedOutput()
		save(name, out, err, "journalctl")
	}
	run("journal.txt", "-b", boot, "-o", "short-monotonic", "--no-pager")
	run("kernel.txt", "-k", "-b", boot, "-o", "short-monotonic", "--no-pager")
	run("dmesg-errors.txt", "-k", "-b", boot, "-p", "warning", "-o", "cat", "--no-pager")
	run("boots.txt", "--list-boots", "--no-pager")
	if boot == "0" {
		// systemd-analyze only knows the running boot: how long firmware, loader,
		// kernel, initrd and userspace took, and which units held boot up.
		for name, args := range map[string][]string{
			"systemd-analyze.txt":        {"time"},
			"systemd-blame.txt":          {"blame", "--no-pager"},
			"systemd-critical-chain.txt": {"critical-chain", "--no-pager"},
		} {
			out, err := exec.CommandContext(ctx, "systemd-analyze", args...).CombinedOutput()
			save(name, out, err, "systemd-analyze")
		}
	}
	return os.WriteFile(filepath.Join(outDir, "collect-status.txt"), []byte(status.String()), 0o644)
}

func (l *Linux) PreviousBoot(since time.Time) string {
	out, err := exec.Command("journalctl", "--list-boots", "-o", "json", "--no-pager").Output()
	if err != nil {
		return ""
	}
	var boots []struct {
		Index      int    `json:"index"`
		BootID     string `json:"boot_id"`
		FirstEntry int64  `json:"first_entry"` // µs since the epoch
	}
	if json.Unmarshal(out, &boots) != nil {
		return ""
	}
	for _, b := range boots {
		if b.Index == -1 && !time.UnixMicro(b.FirstEntry).Before(since) {
			return dashedID(b.BootID)
		}
	}
	return ""
}

// dashedID writes a 128-bit ID the way /proc/sys/kernel/random/boot_id does.
func dashedID(id string) string {
	if len(id) != 32 {
		return id
	}
	return id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
}

// pstoreArchive is where systemd-pstore moves records out of /sys/fs/pstore
// at boot, one directory per crash.
const pstoreArchive = "/var/lib/systemd/pstore"

func (l *Linux) CollectPstore(since time.Time, outDir string) ([]string, error) {
	names, err := collectPstore("/sys/fs/pstore", filepath.Join(outDir, "sys"))
	for i, n := range names {
		// Collected, a record is gone from pstore, so a later recovery
		// doesn't attach it again (and ramoops has room for the next).
		if err == nil {
			os.Remove(filepath.Join("/sys/fs/pstore", n))
		}
		names[i] = filepath.Join("sys", n)
	}
	dirs, _ := os.ReadDir(pstoreArchive)
	for _, d := range dirs {
		if info, ierr := d.Info(); ierr != nil || !d.IsDir() || info.ModTime().Before(since) {
			continue
		}
		n, aerr := collectPstore(filepath.Join(pstoreArchive, d.Name()), filepath.Join(outDir, d.Name()))
		for _, f := range n {
			names = append(names, filepath.Join(d.Name(), f))
		}
		if err == nil {
			err = aerr
		}
	}
	return names, err
}

// dirSize is the total size of the regular files under dir.
func dirSize(dir string) uint64 {
	var n uint64
	filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			n += uint64(info.Size())
		}
		return nil
	})
	return n
}

// syncDisks flushes every filesystem before a stage, cleanup or one-shot
// reports back. The ESP is FAT, with no journal: a hard reset or a panic
// within the writeback window (about 30 s) after the lab deletes a staged UKI
// or rewrites limine.conf leaves corrupt directory entries and a zero-length
// limine.conf, which stops the next boot at the bootloader. labd acts on a
// command's result (rebooting, resetting, or moving on), so the result must
// only go out once the change is on disk. sync(2) also covers GRUB's /boot and
// U-Boot's variable file, whatever the layout.
func syncDisks() { unix.Sync() }

// guiEnv finds the GUI user's Wayland session so tests can drive Hyprland.
func guiEnv(name string, wait time.Duration) (*user.User, []string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, nil, err
	}
	run := "/run/user/" + u.Uid
	deadline := time.Now().Add(wait)
	for {
		socks, _ := filepath.Glob(filepath.Join(run, "wayland-*"))
		var sock string
		for _, s := range socks {
			if !strings.HasSuffix(s, ".lock") {
				sock = filepath.Base(s)
			}
		}
		if sock != "" {
			env := []string{"XDG_RUNTIME_DIR=" + run, "WAYLAND_DISPLAY=" + sock, "HOME=" + u.HomeDir, "USER=" + u.Username,
				"DBUS_SESSION_BUS_ADDRESS=unix:path=" + run + "/bus"}
			// The user's desktop session, so a test counts as run at the Mac's own seat.
			if o, err := exec.Command("loginctl", "show-user", u.Username, "--property=Display", "--value").Output(); err == nil {
				if id := strings.TrimSpace(string(o)); id != "" {
					env = append(env, "XDG_SESSION_ID="+id)
				}
			}
			if sigs, _ := filepath.Glob(filepath.Join(run, "hypr", "*")); len(sigs) > 0 {
				env = append(env, "HYPRLAND_INSTANCE_SIGNATURE="+filepath.Base(sigs[len(sigs)-1]))
			}
			return u, env, nil
		}
		if time.Now().After(deadline) {
			return nil, nil, fmt.Errorf("no Wayland session for %s after %s (is autologin enabled?)", name, wait)
		}
		time.Sleep(2 * time.Second)
	}
}

// Screenshot captures what the panel shows. It reads the display
// controller's scanout with ffmpeg kmsgrab, which works for anything past the
// DRM driver: boot splash, text console, emergency shell, login screen or
// desktop. Without that it falls back to grim in a Wayland session.
func (l *Linux) Screenshot(ctx context.Context, path string, wait time.Duration) (int, int, error) {
	if l.GUIUser != "" {
		awaitDRMMaster(ctx, min(wait, 30*time.Second))
	}
	kerr := kmsgrab(ctx, path)
	if kerr == nil {
		b, _ := os.ReadFile(path)
		w, h := jpegSize(b)
		return w, h, nil
	}
	w, h, gerr := l.grim(ctx, path, wait)
	if gerr != nil {
		return 0, 0, fmt.Errorf("kmsgrab: %v; grim: %v", kerr, gerr)
	}
	return w, h, nil
}

// displayCards lists DRM cards, the display controller's first.
func displayCards() []string {
	var first, rest []string
	links, _ := filepath.Glob("/dev/dri/by-path/*-card")
	for _, l := range links {
		t, err := filepath.EvalSymlinks(l)
		if err != nil {
			continue
		}
		if strings.Contains(l, "display") {
			first = append(first, t)
		} else {
			rest = append(rest, t)
		}
	}
	if len(first)+len(rest) == 0 {
		rest, _ = filepath.Glob("/dev/dri/card*")
	}
	return append(first, rest...)
}

// debugDRI is where the kernel lists each DRM minor's open files.
var debugDRI = "/sys/kernel/debug/dri"

// awaitDRMMaster keeps kmsgrab from taking the display card away from the
// desktop as it starts. A process that opens a DRM card nobody is master of
// becomes its master; if that happens while logind hands the card to the
// compositor, TakeDevice fails with EBUSY and the desktop never comes up. So
// for the first two minutes after boot it waits, at most limit, until
// something else (compositor, greeter or boot splash) is the card's master.
func awaitDRMMaster(ctx context.Context, limit time.Duration) {
	cards := displayCards()
	if len(cards) == 0 {
		return
	}
	deadline := time.Now().Add(limit)
	for uptime() < 2*time.Minute && time.Now().Before(deadline) {
		if has, known := drmHasMaster(cards[0]); has || !known {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// drmHasMaster reads a card's client list in debugfs. known is false when
// debugfs can't tell.
func drmHasMaster(card string) (has, known bool) {
	minor := strings.TrimPrefix(filepath.Base(card), "card")
	b, err := os.ReadFile(filepath.Join(debugDRI, minor, "clients"))
	if err != nil {
		return false, false
	}
	// "command tgid dev master a uid magic name id", one line per open file
	lines := strings.Split(string(b), "\n")
	for _, l := range lines[1:] {
		if f := strings.Fields(l); len(f) >= 4 && f[3] == "y" {
			return true, true
		}
	}
	return false, true
}

func uptime() time.Duration {
	f := strings.Fields(readTrim("/proc/uptime"))
	if len(f) == 0 {
		return 0
	}
	s, _ := strconv.ParseFloat(f[0], 64)
	return time.Duration(s * float64(time.Second))
}

func kmsgrab(ctx context.Context, path string) error {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return err
	}
	var last error = fmt.Errorf("no DRM card")
	for _, card := range displayCards() {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err := exec.CommandContext(cctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
			"-device", card, "-f", "kmsgrab", "-i", "-", "-frames:v", "1",
			"-vf", "hwdownload,format=bgr0", "-q:v", "4", path).CombinedOutput()
		cancel()
		if err == nil {
			if st, serr := os.Stat(path); serr == nil && st.Size() > 0 {
				return nil
			}
		}
		last = fmt.Errorf("%s: %v %s", card, err, strings.TrimSpace(lastLines(string(out), 2)))
	}
	return last
}

// grim captures a Wayland session: the GUI user's, or the login greeter's.
func (l *Linux) grim(ctx context.Context, path string, wait time.Duration) (int, int, error) {
	var u *user.User
	var env []string
	var err error
	if l.GUIUser != "" {
		u, env, err = guiEnv(l.GUIUser, wait)
	}
	if u == nil {
		for _, dm := range []string{"sddm", "gdm", "greeter"} {
			if gu, genv, gerr := guiEnv(dm, 0); gerr == nil {
				u, env, err = gu, genv, nil
				break
			}
		}
	}
	if u == nil {
		if err == nil {
			err = fmt.Errorf("no Wayland session to capture")
		}
		return 0, 0, err
	}
	tmp := filepath.Join("/tmp", fmt.Sprintf("maclab-screen-%d.jpg", time.Now().UnixNano()))
	defer os.Remove(tmp)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := append([]string{"-u", u.Username, "--", "env"}, append(env, "grim", "-t", "jpeg", "-q", "80", tmp)...)
	if out, err := exec.CommandContext(cctx, "runuser", args...).CombinedOutput(); err != nil {
		return 0, 0, fmt.Errorf("grim: %v: %s", err, strings.TrimSpace(string(out)))
	}
	b, err := os.ReadFile(tmp)
	if err != nil {
		return 0, 0, err
	}
	w, h := jpegSize(b)
	return w, h, os.WriteFile(path, b, 0o644)
}

// jpegSize reads the frame size from a JPEG's SOF marker.
func jpegSize(b []byte) (int, int) {
	for i := 2; i+9 < len(b); {
		if b[i] != 0xFF {
			return 0, 0
		}
		m := b[i+1]
		n := int(b[i+2])<<8 | int(b[i+3])
		if m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC {
			return int(b[i+7])<<8 | int(b[i+8]), int(b[i+5])<<8 | int(b[i+6])
		}
		i += 2 + n
	}
	return 0, 0
}

func (l *Linux) Logs(ctx context.Context, a api.LogsArgs) (string, error) {
	n := a.Lines
	if n <= 0 || n > 20000 {
		n = 500
	}
	args := []string{"-b", "0", "-n", strconv.Itoa(n), "-o", "short-precise", "--no-pager"}
	switch a.Source {
	case "kernel":
		args = append(args, "-k")
	case "journal", "":
		if a.Unit != "" {
			args = append(args, "-u", a.Unit)
		}
	default:
		return "", fmt.Errorf("unknown log source %q", a.Source)
	}
	out, err := exec.CommandContext(ctx, "journalctl", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("journalctl: %v", err)
	}
	return string(out), nil
}

func tail(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

func (l *Linux) KernelConfig() (string, error) {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return "", fmt.Errorf("no /proc/config.gz (kernel built without IKCONFIG_PROC?): %w", err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(z)
	return string(b), err
}

// Exec runs a command as root with bash, output capped at 1 MB per stream.
func (l *Linux) Exec(ctx context.Context, a api.ExecArgs) api.ExecResult {
	t := a.TimeoutSec
	if t <= 0 {
		t = 120
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(t)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "bash", "-c", a.Command)
	var out, errb capped
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 3 * time.Second
	t0 := time.Now()
	err := cmd.Run()
	res := api.ExecResult{Stdout: out.String(), Stderr: errb.String(), Seconds: time.Since(t0).Seconds(), Via: "agent"}
	if cctx.Err() == context.DeadlineExceeded {
		res.ExitCode = 124
		res.Stderr += fmt.Sprintf("\n[timed out after %ds]", t)
	} else if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
	} else if err != nil {
		res.ExitCode = 127
		res.Stderr += err.Error()
	}
	return res
}

type capped struct{ b []byte }

func (c *capped) Write(p []byte) (int, error) {
	if room := 1<<20 - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

func (c *capped) String() string { return string(c.b) }

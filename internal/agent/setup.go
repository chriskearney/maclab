package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	ConfigPath  = "/etc/maclab/agent.json"
	binPath     = "/usr/local/bin/lab-agent"
	unitPath    = "/etc/systemd/system/lab-agent.service"
	sysctlPath  = "/etc/sysctl.d/90-maclab.conf"
	watchdogCfg = "/etc/systemd/system.conf.d/90-maclab-watchdog.conf"
	journalCfg  = "/etc/systemd/journald.conf.d/90-maclab.conf"
	workDir     = "/var/lib/maclab"
	gettyDropIn = "/etc/systemd/system/serial-getty@ttySAC0.service.d/maclab.conf"
	sddmConf    = "/etc/sddm.conf.d/zz-maclab-autologin.conf"
	stayAwake   = ".local/state/omarchy/indicators/stay-awake" // in the GUI user's home
	// What setup found already on, in workDir, so uninstall leaves it on.
	gettyWasEnabled = "serial-getty.pre-maclab"
	stayAwakeWasOn  = "stay-awake.pre-maclab"
	// Whom setup turned stay-awake on for, in workDir, so uninstall turns it
	// off with or without autologin.
	stayAwakeUser = "stay-awake.maclab"
)

const unit = `[Unit]
Description=maclab test agent
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/lab-agent run
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`

type SetupOptions struct {
	Server    string
	Token     string
	GUIUser   string
	Autologin bool // log GUIUser into the desktop on boot; implies StayAwake
	StayAwake bool // turn GUIUser's idle lock and screensaver off
	// VolatileJournal leaves journald alone; preflight then warns that a
	// failed lab boot's journal is lost.
	VolatileJournal bool
	// TailscaleAuthKey, a one-off key a maintainer made by hand, joins the
	// lab's tailnet before anything else. It is never printed or stored, and
	// reaches tailscale in a file, not argv; lab-agent reads it with AuthKey.
	TailscaleAuthKey  string
	TailscaleHostname string // default maclab-<device name>, else this machine's hostname
	Log               func(format string, args ...any)
}

// Setup makes this Mac a lab device. Every step is idempotent, and every
// file it changes outside the lab's own paths is backed up first.
func Setup(ctx context.Context, o SetupOptions) error {
	say := o.Log
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup must run as root")
	}
	l := &Linux{WorkDir: workDir, GUIUser: o.GUIUser}
	if err := os.MkdirAll(l.WorkDir, 0o755); err != nil {
		return err
	}

	cfg, _ := LoadConfig(ConfigPath)
	if o.TailscaleAuthKey != "" {
		server := o.Server
		if server == "" && cfg != nil {
			server = cfg.Server
		}
		host := o.TailscaleHostname
		if host == "" {
			host = tailnetHostname(cfg)
		}
		if err := newTailnet(say).join(ctx, o.TailscaleAuthKey, host, server); err != nil {
			return err
		}
	} else if o.TailscaleHostname != "" {
		return fmt.Errorf("--tailscale-hostname needs --tailscale-authkey-file or --tailscale-authkey -")
	}

	// Enroll first: the token says what kind of Mac this is, and a Volunteer's
	// Mac refuses some of the changes below before any of them is made. Until
	// its first check-in the Mac can enroll again with the same token.
	if o.Token != "" {
		if o.Server == "" {
			return fmt.Errorf("--token needs --server")
		}
		facts := l.Facts()
		facts.AgentVersion = Version
		resp, err := Enroll(ctx, o.Server, o.Token, facts)
		if err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
		cfg = &Config{Server: o.Server, DeviceID: resp.DeviceID, Name: resp.Name, Secret: resp.Secret, Enrollment: resp.AgentEnrollment}
		say("enrolled as %s: %s", resp.Name, kindName(resp.Enrollment))
	}
	if cfg == nil {
		return fmt.Errorf("not enrolled: pass --server and --token")
	}
	if cfg.Enrollment.IsVolunteer() {
		if err := refuseOnVolunteer(o.Autologin, o.StayAwake); err != nil {
			return err
		}
	}
	if err := l.SnapshotEligible(); err != nil {
		say("NOT ELIGIBLE for Installed runs: @ cannot be snapshotted, so it could not be rolled back (%v)", err)
	} else {
		say("@ can be snapshotted: eligible for Installed runs")
	}

	b, err := detectBootloader()
	if err != nil {
		return err
	}
	if hard, _ := unattended(b); len(hard) > 0 {
		return fmt.Errorf("this Mac cannot reboot unattended; fix this and run setup again:\n  - %s", strings.Join(hard, "\n  - "))
	}
	if err := os.MkdirAll(l.WorkDir, 0o755); err != nil {
		return err
	}
	switch g := b.(type) {
	case *grubLayout:
		say("bootloader: GRUB in %s, one-shot flag in %s (ESP %s)", g.Dir, g.EnvFile, g.ESP.UUID)
		if err := g.installHook(); err != nil {
			return fmt.Errorf("install one-shot hook: %w", err)
		}
		say("installed one-shot hook in %s/custom.cfg (backup: custom.cfg.pre-maclab)", g.Dir)
	case *limineLayout:
		say("bootloader: Limine (%s), menu %s, one-shot via LoaderEntryOneShot", g.Loader, g.Conf)
		if g.VarFile != "" {
			say("U-Boot keeps EFI variables in RAM; the lab persists them to %s (backup: %s.pre-maclab)", g.VarFile, filepath.Base(g.VarFile))
		}
		if err := g.install(); err != nil {
			return fmt.Errorf("prepare Limine staging: %w", err)
		}
		say("test kernels are staged as UKIs in %s and listed at the end of %s", g.Stage, filepath.Base(g.Conf))
	}

	_, kernel, cmdline := l.Identity()
	if tag := jobTag(cmdline); tag != "" {
		return fmt.Errorf("running a lab kernel (job %s); reboot into your normal kernel before setup", tag)
	}
	if err := recordKnownGood(l, b, kernel, cmdline); err != nil {
		return err
	}
	say("known-good kernel: %s", kernel)
	if _, ok := b.(*grubLayout); ok && stageDir() != defaultStage {
		say("test kernels are staged in %s (/boot is short on space)", stageDir())
	}

	if err := os.WriteFile(sysctlPath, []byte("# maclab: reboot 10s after a panic instead of hanging\nkernel.panic = 10\n"), 0o644); err != nil {
		return err
	}
	exec.Command("sysctl", "-q", "-p", sysctlPath).Run()
	say("kernel.panic = 10")

	if _, err := os.Stat("/dev/watchdog0"); err == nil {
		os.MkdirAll(filepath.Dir(watchdogCfg), 0o755)
		conf := "# maclab: the hardware watchdog resets the Mac if systemd stops responding\n[Manager]\nRuntimeWatchdogSec=30s\nRebootWatchdogSec=2min\n"
		if err := os.WriteFile(watchdogCfg, []byte(conf), 0o644); err != nil {
			return err
		}
		exec.Command("systemctl", "daemon-reexec").Run()
		say("hardware watchdog armed via systemd (30s)")
	} else {
		say("no /dev/watchdog0: hangs after boot need out-of-band reset or a human")
	}

	if move, err := persistJournal("/", o.VolatileJournal); err != nil {
		say("journal: %v", err)
	} else if move {
		if err := moveJournal(); err != nil {
			return fmt.Errorf("journal: %w (running setup again retries it)", err)
		}
		say("journal: kept on disk across reboots (labd reads a failed lab boot's journal)")
	}

	if err := serialGetty(o.GUIUser); err != nil {
		say("serial console shell: %v", err)
	} else {
		say("serial console shell on ttySAC0 (lab shell reaches it through the controller Mac)")
	}
	if o.StayAwake || o.Autologin {
		if o.GUIUser == "" {
			return fmt.Errorf("--stay-awake and --autologin need --gui-user")
		}
		if err := keepAwake(o.GUIUser); err != nil {
			return fmt.Errorf("stay-awake: %w", err)
		}
		say("idle lock and screensaver off for %s (Omarchy stay-awake)", o.GUIUser)
	}
	if o.Autologin {
		if err := autologin(o.GUIUser); err != nil {
			return fmt.Errorf("autologin: %w", err)
		}
		say("desktop autologin for %s", o.GUIUser)
	}

	if o.GUIUser != "" {
		cfg.GUIUser = o.GUIUser
	}
	if err := cfg.Save(ConfigPath); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(l.WorkDir, leftFile)); err != nil && !os.IsNotExist(err) { // enrolling again after leaving
		return err
	}

	if err := installBinary(); err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(labBootDeadlineUnitPath, []byte(labBootDeadlineUnit()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(labBootSessionUnitPath, []byte(labBootSessionUnit()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(labBootLockUnitPath, []byte(labBootLockUnit()), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, append([]string{"enable"}, labUnitNames...), {"restart", "lab-agent.service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	say("lab-agent.service enabled and running")
	say("%s and %s enabled: a Lab boot of a Volunteer's Mac logs the GUI user in, locked at once", labBootSessionUnitName, labBootLockUnitName)
	say("%s enabled: a Lab boot that misses its deadline reboots to the known-good kernel", labBootDeadlineUnitName)

	if e := cfg.Enrollment; e.IsVolunteer() {
		var code strings.Builder
		if err := printTopicQR(&code, e.Subscribe()); err != nil {
			return err
		}
		say("%s", code.String())
	}

	p, w := l.Preflight()
	if len(p) > 0 {
		say("preflight problems:\n  - %s", strings.Join(p, "\n  - "))
	} else {
		say("preflight OK. Next: `lab baseline %s` proves the one-shot boot before any test kernel runs.", cfg.Name)
	}
	if len(w) > 0 {
		say("preflight warnings:\n  - %s", strings.Join(w, "\n  - "))
	}
	return nil
}

// persistJournal turns journald's persistent storage on with a drop-in,
// unless leave is set or the journal is already kept on disk without one: the
// drop-in existing means setup made it. It says whether journald still has to
// take the drop-in up and move this boot's journal to disk: setup wrote it
// just now, or restarting journald failed in an earlier run.
func persistJournal(root string, leave bool) (bool, error) {
	if leave {
		return false, nil
	}
	p := filepath.Join(root, journalCfg)
	wrote := false
	if volatileJournal(root) != "" {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return false, err
		}
		conf := "# maclab: keep the journal on disk, so labd can read a failed lab boot's journal from the next boot\n[Journal]\nStorage=persistent\n"
		if err := os.WriteFile(p, []byte(conf), 0o644); err != nil {
			return false, err
		}
		if why := volatileJournal(root); why != "" {
			return false, fmt.Errorf("wrote %s, but the journal is still not kept on disk (%s)", journalCfg, why)
		}
		wrote = true
	}
	if _, err := os.Stat(p); err != nil {
		return false, nil // kept on disk without the lab's drop-in
	}
	return wrote || journalInRun(root), nil
}

// moveJournal has journald take up setup's drop-in and move this boot's
// journal from /run to /var/log/journal. The directory comes first, with
// systemd-tmpfiles' attributes: on btrfs its NOCOW flag then reaches every
// journal file created in it, the first one included.
func moveJournal() error {
	if err := os.MkdirAll("/var/log/journal", 0o755); err != nil {
		return err
	}
	exec.Command("systemd-tmpfiles", "--create", "--prefix", "/var/log/journal").Run()
	for _, c := range [][]string{{"systemctl", "restart", "systemd-journald"}, {"journalctl", "--flush"}} {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, out)
		}
	}
	return nil
}

// RecordKnownGood re-records the known-good kernel after a promotion: the Mac
// must be running exactly kernel, outside a lab boot. The previous record is
// kept as known-good.json.prev.
func (l *Linux) RecordKnownGood(kernel string) error {
	_, running, cmdline := l.Identity()
	if err := recordable(kernel, running, cmdline); err != nil {
		return err
	}
	b, err := detectBootloader()
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(l.knownGoodPath()); err == nil {
		if err := os.WriteFile(l.knownGoodPath()+".prev", old, 0o644); err != nil {
			return err
		}
	}
	return recordKnownGood(l, b, kernel, cmdline)
}

// recordable says whether the running kernel may become known-good as kernel.
func recordable(kernel, running, cmdline string) error {
	switch {
	case kernel == "" || running != kernel:
		return fmt.Errorf("running %s, not %q: boot it before recording it as known-good", running, kernel)
	case jobTag(cmdline) != "":
		return fmt.Errorf("running a lab boot (job %s), not the installed entry", jobTag(cmdline))
	}
	return nil
}

func recordKnownGood(l *Linux, bl bootloader, kernel, cmdline string) error {
	kg, err := computeKnownGood(bl, kernel, cmdline)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(kg, "", "  ")
	// replaced whole: preflight never reads half a record
	tmp := l.knownGoodPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, l.knownGoodPath())
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// DescribeKnownGood shows what setup would record, without changing anything.
func DescribeKnownGood() (string, error) {
	bl, err := detectBootloader()
	if err != nil {
		return "", err
	}
	_, kernel, cmdline := (&Linux{}).Identity()
	kg, err := computeKnownGood(bl, kernel, cmdline)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(kg, "", "  ")
	return string(b), nil
}

func computeKnownGood(b bootloader, kernel, cmdline string) (*KnownGood, error) {
	if lim, ok := b.(*limineLayout); ok {
		return limineKnownGood(lim, kernel, cmdline)
	}
	g := b.(*grubLayout)
	var bootImage string
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "BOOT_IMAGE="); ok {
			bootImage = v
		}
	}
	if bootImage == "" {
		return nil, fmt.Errorf("no BOOT_IMAGE= on the cmdline; cannot tell which kernel file is running")
	}
	img, m, err := locateGrubFile(bootImage)
	if err != nil {
		return nil, fmt.Errorf("running kernel image (GRUB %s): %w", bootImage, err)
	}
	// Prefer the initrd the running kernel's own GRUB entry loads.
	grubInitrd := entryInitrd(filepath.Join(g.Dir, "grub.cfg"), bootImage)
	if grubInitrd == "" {
		guess := filepath.Join(filepath.Dir(img), "initramfs-"+strings.TrimPrefix(filepath.Base(img), "vmlinuz-")+".img")
		if _, err := os.Stat(guess); err != nil {
			return nil, fmt.Errorf("cannot find the initramfs for %s: no GRUB entry boots it and %s does not exist", img, guess)
		}
		grubInitrd = g.grubPath(guess)
	}
	for _, p := range strings.Fields(grubInitrd) {
		if _, _, err := locateGrubFile(p); err != nil {
			return nil, fmt.Errorf("initrd %s: %w", p, err)
		}
	}
	kg := KnownGood{Kernel: kernel, GrubLinux: bootImage, GrubInitrd: grubInitrd, Cmdline: cmdline}
	if m.UUID != g.Boot.UUID {
		kg.RootUUID, kg.RootFS = m.UUID, m.FSType
	}
	kg.StageDir = chooseStage()
	return &kg, nil
}

// limineKnownGood records the running kernel. Its UKI is the menu's default,
// which a Limine Mac boots whenever no one-shot is set; the lab only needs
// its release (to build a baseline UKI) and its cmdline.
func limineKnownGood(lim *limineLayout, kernel, cmdline string) (*KnownGood, error) {
	if _, err := os.Stat(filepath.Join("/usr/lib/modules", kernel, "vmlinuz")); err != nil {
		return nil, fmt.Errorf("running kernel %s has no /usr/lib/modules/%s/vmlinuz to build a baseline UKI from", kernel, kernel)
	}
	if strings.Contains(cmdline, "maclab.job=") {
		return nil, fmt.Errorf("the running kernel is a lab kernel")
	}
	return &KnownGood{Kernel: kernel, Cmdline: cmdline, Loader: lim.name(), StageDir: lim.Stage}, nil
}

// chooseStage keeps test kernels on /boot when it has room, else on the root
// filesystem. A lab kernel plus initramfs is about 70 MB.
func chooseStage() string {
	if _, err := os.Stat(defaultStage); err == nil {
		return defaultStage // already in use
	}
	free := func(p string) uint64 {
		var st syscall.Statfs_t
		if syscall.Statfs(p, &st) != nil {
			return 0
		}
		return st.Bavail * uint64(st.Bsize)
	}
	if free("/boot") >= 1<<30 {
		return defaultStage
	}
	if free("/var/lib") >= 4<<30 {
		return altStage
	}
	return defaultStage
}

// locateGrubFile finds the local file behind a GRUB path such as
// /@/boot-test/k/vmlinuz, trying the filesystems that hold /boot and /.
func locateGrubFile(gp string) (string, mount, error) {
	seen := map[string]bool{}
	for _, dir := range []string{"/boot", "/"} {
		m, err := findMount(dir)
		if err != nil || seen[m.Source] {
			continue
		}
		seen[m.Source] = true
		sub := ""
		if s := reSubvol.FindStringSubmatch(m.Source); s != nil && s[1] != "/" {
			sub = s[1]
		}
		if !strings.HasPrefix(gp, sub+"/") {
			continue
		}
		local := filepath.Join(m.Target, strings.TrimPrefix(gp, sub))
		if _, err := os.Stat(local); err == nil {
			return local, m, nil
		}
	}
	return "", mount{}, fmt.Errorf("not found on the /boot or / filesystem")
}

// entryInitrd returns the initrd paths of the grub.cfg entry that boots image.
func entryInitrd(cfg, image string) string {
	b, err := os.ReadFile(cfg)
	if err != nil {
		return ""
	}
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "}":
			in = false
		case (f[0] == "linux" || f[0] == "linux16") && len(f) > 1:
			in = f[1] == image
		case f[0] == "initrd" && in && len(f) > 1:
			return strings.Join(f[1:], " ")
		}
	}
	return ""
}

func installBinary() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self == binPath {
		return nil
	}
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := binPath + ".new"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	dst.Close()
	return os.Rename(tmp, binPath)
}

// serialGetty puts a shell on the debug UART, so a Mac can be reached over
// its out-of-band controller even with its network down. It logs in as the
// GUI user when there is one: anyone with the controller or the cable is
// already physically at the machine.
func serialGetty(user string) error {
	if _, err := os.Stat("/dev/ttySAC0"); err != nil {
		return fmt.Errorf("no /dev/ttySAC0 debug UART")
	}
	login := ""
	if user != "" {
		login = "--autologin " + user + " "
	}
	// Uninstall disables the getty again, unless it was enabled before the lab's first setup.
	if _, err := os.Stat(gettyDropIn); os.IsNotExist(err) {
		if out, _ := exec.Command("systemctl", "is-enabled", "serial-getty@ttySAC0.service").Output(); strings.TrimSpace(string(out)) == "enabled" {
			os.WriteFile(filepath.Join(workDir, gettyWasEnabled), []byte("enabled\n"), 0o644)
		}
	}
	os.MkdirAll(filepath.Dir(gettyDropIn), 0o755)
	conf := "# maclab: a shell on the debug UART, reached through the controller Mac over USB-C.\n" +
		"# Works with no network. Anyone holding the oobd token or the cable gets this shell.\n" +
		"[Service]\nExecStart=\nExecStart=-/sbin/agetty -o \"-p -f -- \\\\u\" " + login + "115200 - ${TERM}\n"
	if err := os.WriteFile(gettyDropIn, []byte(conf), 0o644); err != nil {
		return err
	}
	exec.Command("systemctl", "daemon-reload").Run()
	if out, err := exec.Command("systemctl", "enable", "--now", "serial-getty@ttySAC0.service").CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return exec.Command("systemctl", "restart", "serial-getty@ttySAC0.service").Run()
}

// refuseOnVolunteer is the check setup runs, on a Volunteer Mac, of the flags
// it was given: the lab never removes a Volunteer's lock screen for good.
func refuseOnVolunteer(autologin, stayAwake bool) error {
	switch {
	case autologin:
		return fmt.Errorf("--autologin is refused on a Volunteer's Mac: it would remove the lock screen for good")
	case stayAwake:
		return fmt.Errorf("--stay-awake is refused on a Volunteer's Mac: it would turn the idle lock off for good")
	}
	return nil
}

// autologin logs the GUI user into their last desktop session on boot, so
// GUI tests always find a session.
func autologin(user string) error {
	if _, err := osuser.Lookup(user); err != nil {
		return err
	}
	session := "hyprland-uwsm.desktop"
	if b, err := os.ReadFile("/var/lib/sddm/state.conf"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Session="); ok && v != "" {
				session = filepath.Base(strings.TrimSpace(v))
			}
		}
	}
	conf := fmt.Sprintf("# maclab: log straight into the desktop so GUI tests have a session after every lab reboot.\n[Autologin]\nUser=%s\nSession=%s\nRelogin=false\n", user, session)
	os.MkdirAll(filepath.Dir(sddmConf), 0o755)
	return os.WriteFile(sddmConf, []byte(conf), 0o644)
}

// keepAwake turns Omarchy's idle lock and screensaver off for user, so GUI
// tests find the session unlocked. Uninstall turns it off again, unless the
// user had it on before the lab first turned it on.
func keepAwake(user string) error {
	u, err := osuser.Lookup(user)
	if err != nil {
		return err
	}
	// A Mac the lab set up before stayAwakeUser existed has sddmConf instead.
	if !exists(filepath.Join(workDir, stayAwakeUser)) && !exists(sddmConf) {
		if exists(filepath.Join(u.HomeDir, stayAwake)) {
			os.WriteFile(filepath.Join(workDir, stayAwakeWasOn), []byte(user+"\n"), 0o644)
		}
	}
	if err := os.WriteFile(filepath.Join(workDir, stayAwakeUser), []byte(user+"\n"), 0o644); err != nil {
		return err
	}
	// Omarchy's stay-awake state file: the same thing `omarchy toggle idle stay-awake` sets.
	dir := filepath.Join(u.HomeDir, filepath.Dir(stayAwake))
	return exec.Command("runuser", "-u", user, "--", "sh", "-c", "mkdir -p '"+dir+"' && touch '"+dir+"/stay-awake'").Run()
}

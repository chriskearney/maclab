package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// GRUB cannot write grubenv on btrfs, LVM or LUKS, so a stock grub-reboot
// one-shot never clears there and the Mac keeps booting the test kernel.
// The lab keeps its one-shot flag in its own env file on the ESP (FAT),
// which GRUB can always write, and selects it from custom.cfg.

const (
	envName      = "maclab.env"
	envVar       = "maclab_next"
	maclabCfg    = "maclab.cfg"
	hookMarker   = "# maclab: one-shot hook"
	entryPrefix  = "maclab-"
	defaultStage = "/boot/maclab"
	altStage     = "/var/lib/maclab/boot" // on the root fs, for Macs whose /boot is small or full
	markerFile   = ".maclab-job"
)

type mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	FSType string `json:"fstype"`
	UUID   string `json:"uuid"`
}

func findMount(path string) (mount, error) {
	out, err := exec.Command("findmnt", "-J", "-T", path, "-o", "SOURCE,TARGET,FSTYPE,UUID").Output()
	if err != nil {
		return mount{}, fmt.Errorf("findmnt %s: %w", path, err)
	}
	var r struct{ Filesystems []mount }
	if err := json.Unmarshal(out, &r); err != nil || len(r.Filesystems) == 0 {
		return mount{}, fmt.Errorf("findmnt %s: unexpected output", path)
	}
	return r.Filesystems[0], nil
}

var reSubvol = regexp.MustCompile(`\[(/[^\]]*)\]$`)

type grubLayout struct {
	Dir       string // /boot/grub
	ESP       mount
	EnvFile   string // <esp>/maclab.env
	Boot      mount  // filesystem holding /boot
	prefix    string // GRUB path of local /boot, e.g. /@/boot
	LoadVideo bool
}

func detectGrub() (*grubLayout, error) {
	g := &grubLayout{}
	for _, d := range []string{"/boot/grub", "/efi/grub", "/boot/efi/grub"} {
		if _, err := os.Stat(filepath.Join(d, "grub.cfg")); err == nil {
			g.Dir = d
			break
		}
	}
	if g.Dir == "" {
		return nil, fmt.Errorf("no grub.cfg in /boot/grub, /efi/grub or /boot/efi/grub")
	}
	for _, d := range []string{"/boot/efi", "/efi", "/boot"} {
		m, err := findMount(d)
		if err == nil && m.Target == d && m.FSType == "vfat" {
			g.ESP = m
			g.EnvFile = filepath.Join(d, envName)
			break
		}
	}
	if g.EnvFile == "" {
		return nil, fmt.Errorf("no FAT ESP mounted at /boot/efi, /efi or /boot")
	}
	m, err := findMount("/boot")
	if err != nil {
		return nil, err
	}
	g.Boot = m
	sub := ""
	if s := reSubvol.FindStringSubmatch(m.Source); s != nil && s[1] != "/" {
		sub = s[1]
	}
	rel, _ := filepath.Rel(m.Target, "/boot")
	if rel == "." {
		rel = ""
	} else {
		rel = "/" + rel
	}
	g.prefix = sub + rel
	if cfg, err := os.ReadFile(filepath.Join(g.Dir, "grub.cfg")); err == nil {
		g.LoadVideo = strings.Contains(string(cfg), "function load_video")
	}
	return g, nil
}

// stageDir is where staged test kernels live, as chosen by setup.
func stageDir() string {
	b, err := os.ReadFile("/var/lib/maclab/known-good.json")
	if err == nil {
		var kg KnownGood
		if json.Unmarshal(b, &kg) == nil && kg.StageDir != "" {
			return kg.StageDir
		}
	}
	return defaultStage
}

// grubLocate maps any local file to the GRUB path, filesystem UUID and type
// GRUB needs to load it.
func grubLocate(local string) (path, uuid, fstype string, err error) {
	m, err := findMount(filepath.Dir(local))
	if err != nil {
		return "", "", "", err
	}
	sub := ""
	if s := reSubvol.FindStringSubmatch(m.Source); s != nil && s[1] != "/" {
		sub = s[1]
	}
	rel := strings.TrimPrefix(local, m.Target)
	if m.Target == "/" {
		rel = local
	}
	return sub + rel, m.UUID, m.FSType, nil
}

// grubPath maps a local file under /boot to the path GRUB sees.
func (g *grubLayout) grubPath(local string) string {
	return g.prefix + strings.TrimPrefix(local, "/boot")
}

// localPath maps a GRUB path (as in BOOT_IMAGE=) back to the local file.
func (g *grubLayout) localPath(gp string) string {
	return "/boot" + strings.TrimPrefix(gp, g.prefix)
}

func (g *grubLayout) fsModule() string { return fsModule(g.Boot.FSType) }

func fsModule(fstype string) string {
	switch fstype {
	case "btrfs":
		return "btrfs"
	case "vfat":
		return "fat"
	case "xfs":
		return "xfs"
	}
	return "ext2"
}

// hookProblems reports what stops the one-shot hook from working, without changing anything.
func (g *grubLayout) hookProblems() []string {
	var p []string
	cfg, err := os.ReadFile(filepath.Join(g.Dir, "grub.cfg"))
	if err != nil {
		return []string{"cannot read grub.cfg: " + err.Error()}
	}
	if !strings.Contains(string(cfg), "custom.cfg") {
		p = append(p, "grub.cfg does not source custom.cfg (41_custom missing); run grub-mkconfig once")
	}
	custom, _ := os.ReadFile(filepath.Join(g.Dir, "custom.cfg"))
	if !strings.Contains(string(custom), hookMarker) {
		p = append(p, "custom.cfg lacks the maclab one-shot hook (run lab-agent setup)")
	}
	if _, err := os.Stat(g.EnvFile); err != nil {
		p = append(p, "missing one-shot env file "+g.EnvFile+" (run lab-agent setup)")
	}
	return p
}

func (g *grubLayout) hookText() string {
	return fmt.Sprintf(`%s: GRUB cannot write grubenv on btrfs, so the lab's
# one-shot flag lives in %s on the ESP. Managed by lab-agent.
insmod part_gpt
insmod fat
if search --no-floppy --fs-uuid --set=maclab_esp %s; then
    if [ -f ($maclab_esp)/%s ]; then
        load_env -f ($maclab_esp)/%s %s
        if [ -n "$%s" ]; then
            set default="$%s"
            set %s=
            save_env -f ($maclab_esp)/%s %s
        fi
    fi
fi
if [ -f ${config_directory}/%s ]; then
    source ${config_directory}/%s
elif [ -f $prefix/%s ]; then
    source $prefix/%s
fi
# maclab: end
`, hookMarker, envName, g.ESP.UUID, envName, envName, envVar, envVar, envVar, envVar, envName, envVar,
		maclabCfg, maclabCfg, maclabCfg, maclabCfg)
}

var reHook = regexp.MustCompile(`(?s)\n?` + regexp.QuoteMeta(hookMarker) + `.*?\n# maclab: end\n?`)

// stripHook returns custom.cfg without the hook installHook appended, or false
// if the hook has lost its end marker.
func stripHook(custom []byte) ([]byte, bool) {
	if !reHook.Match(custom) {
		return custom, !bytes.Contains(custom, []byte(hookMarker))
	}
	return reHook.ReplaceAll(custom, nil), true
}

// installHook appends the one-shot hook to custom.cfg (backing it up first) and
// creates the ESP env file. It is idempotent.
func (g *grubLayout) installHook() error {
	custom := filepath.Join(g.Dir, "custom.cfg")
	old, err := os.ReadFile(custom)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if !strings.Contains(string(old), hookMarker) {
		if len(old) > 0 {
			if err := os.WriteFile(custom+".pre-maclab", old, 0o644); err != nil {
				return err
			}
		}
		text := string(old)
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if err := writeAtomic(custom, []byte(text+"\n"+g.hookText())); err != nil {
			return err
		}
	}
	if _, err := os.Stat(g.EnvFile); os.IsNotExist(err) {
		if out, err := exec.Command("grub-editenv", g.EnvFile, "create").CombinedOutput(); err != nil {
			return fmt.Errorf("grub-editenv create: %v: %s", err, out)
		}
	}
	return g.writeEntries()
}

func (g *grubLayout) arm(entry string) error {
	if !strings.HasPrefix(entry, entryPrefix) {
		return fmt.Errorf("refusing to arm non-lab entry %q", entry)
	}
	if _, err := os.Stat(filepath.Join(stageDir(), strings.TrimPrefix(entry, entryPrefix), "entry.cfg")); err != nil {
		return fmt.Errorf("entry %s is not staged", entry)
	}
	if out, err := exec.Command("grub-editenv", g.EnvFile, "set", envVar+"="+entry).CombinedOutput(); err != nil {
		return fmt.Errorf("grub-editenv set: %v: %s", err, out)
	}
	if got := g.armed(); got != entry {
		return fmt.Errorf("one-shot readback: got %q, want %q", got, entry)
	}
	exec.Command("sync").Run()
	return nil
}

func (g *grubLayout) armed() string {
	// grub-editenv list creates a missing env file, which uninstall removes.
	if _, err := os.Stat(g.EnvFile); os.IsNotExist(err) {
		return ""
	}
	out, _ := exec.Command("grub-editenv", g.EnvFile, "list").Output()
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(l, envVar+"="); ok {
			return v
		}
	}
	return ""
}

func (g *grubLayout) disarm() error {
	if g.armed() == "" {
		return nil
	}
	if out, err := exec.Command("grub-editenv", g.EnvFile, "unset", envVar).CombinedOutput(); err != nil {
		return fmt.Errorf("grub-editenv unset: %v: %s", err, out)
	}
	return nil
}

// entryText is one menuentry for a staged job.
func (g *grubLayout) entryText(job, title, linux, initrd, cmdline, uuid, fstype string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "menuentry '%s' --class gnu-linux --id %s%s {\n", strings.ReplaceAll(title, "'", ""), entryPrefix, job)
	if g.LoadVideo {
		b.WriteString("\tload_video\n\tset gfxpayload=keep\n")
	}
	fmt.Fprintf(&b, "\tinsmod gzio\n\tinsmod part_gpt\n\tinsmod %s\n", fsModule(fstype))
	if fstype == "btrfs" {
		b.WriteString("\tinsmod zstd\n") // btrfs compresses with zstd; lzo/zlib are built in
	}
	fmt.Fprintf(&b, "\tsearch --no-floppy --fs-uuid --set=root %s\n", uuid)
	fmt.Fprintf(&b, "\techo 'maclab %s: loading kernel'\n", job)
	fmt.Fprintf(&b, "\tlinux %s %s\n", linux, cmdline)
	fmt.Fprintf(&b, "\tinitrd %s\n}\n", initrd)
	return b.String()
}

// writeEntries regenerates maclab.cfg from every staged job's entry.cfg.
func (g *grubLayout) writeEntries() error {
	files, _ := filepath.Glob(filepath.Join(stageDir(), "*", "entry.cfg"))
	sort.Strings(files)
	var b strings.Builder
	b.WriteString("# Generated by lab-agent. Do not edit: staged test kernels, selected one-shot via " + envName + ".\n")
	for _, f := range files {
		t, err := os.ReadFile(f)
		if err == nil {
			b.WriteString("\n")
			b.Write(t)
		}
	}
	return writeAtomic(filepath.Join(g.Dir, maclabCfg), []byte(b.String()))
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

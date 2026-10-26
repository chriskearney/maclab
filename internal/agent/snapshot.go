package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// snapperRootConfig is the snapper config Omarchy makes for /.
const snapperRootConfig = "/etc/snapper/configs/root"

// SnapshotEligible says whether snapper can snapshot @, the subvolume the
// Mac's own system runs from: an Installed run's Rollback depends on it.
func (l *Linux) SnapshotEligible() error {
	root, err := findMount("/")
	if err != nil {
		return err
	}
	conf, _ := os.ReadFile(snapperRootConfig) // none: not eligible
	_, lookErr := exec.LookPath("snapper")
	return snapshotEligible(root, string(conf), lookErr == nil)
}

// snapshotEligible is the rule: / is the btrfs subvolume @, and snapper is
// installed with a config (snapperConf, "" for none) that covers /.
func snapshotEligible(root mount, snapperConf string, haveSnapper bool) error {
	if root.FSType != "btrfs" {
		return fmt.Errorf("/ is %s, not btrfs", root.FSType)
	}
	sub := ""
	if s := reSubvol.FindStringSubmatch(root.Source); s != nil {
		sub = s[1]
	}
	if sub != "/@" {
		return fmt.Errorf("/ is the btrfs subvolume %q, not @", sub)
	}
	if !haveSnapper {
		return fmt.Errorf("snapper is not installed")
	}
	if snapperConf == "" {
		return fmt.Errorf("snapper has no root config (%s)", snapperRootConfig)
	}
	for _, line := range strings.Split(snapperConf, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "SUBVOLUME="); ok {
			if strings.Trim(v, `"'`) == "/" {
				return nil
			}
			return fmt.Errorf("snapper's root config is for %s, not /", v)
		}
	}
	return fmt.Errorf("snapper's root config (%s) names no SUBVOLUME", snapperRootConfig)
}

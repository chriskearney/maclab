package agent

import (
	_ "embed"
	"fmt"
	"slices"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// The identity checks of an Installed run are the lab's own: lab-agent runs
// its embedded, read-only collector for them, so a Volunteer's Mac takes them
// at Qualification. A Maintainer's script is never one, whatever its name.

//go:embed collect.py
var identityCollector string

// IdentityCollector is the read-only collector the identity checks run.
func IdentityCollector() string { return identityCollector }

// checkIdentity refuses an identity check of no phase lab-agent knows.
func checkIdentity(c api.IdentityCheck) error {
	if !slices.Contains([]string{"before", "booted", "after"}, c.Phase) {
		return fmt.Errorf("identity check of unknown phase %q", c.Phase)
	}
	return nil
}

// IdentityScript is the shell test that runs the collector for one phase
// and writes its observation to $MACLAB_OUT/observed.json. payload hashes
// the kernel's installed files too.
func IdentityScript(c api.IdentityCheck, payload bool) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	args := []string{"--phase", q(c.Phase), "--device", q(c.Device), "--krel", q(c.Kernel), "--job", `"${MACLAB_JOB:-}"`}
	if c.EntryPath != "" {
		args = append(args, "--entry-path", q(c.EntryPath))
	}
	if len(c.Packages) > 0 {
		args = append(args, "--pkgs", q(strings.Join(c.Packages, ",")))
	}
	if payload {
		args = append(args, "--payload")
	}
	return "#!/bin/bash\n# maclab installed-mode identity, phase " + c.Phase + " (read only)\nset -u\n" +
		`out=${MACLAB_OUT:-.}` + "\n" +
		`py=$(mktemp); trap 'rm -f "$py"' EXIT` + "\n" +
		"cat > \"$py\" <<'MACLAB_COLLECTOR_EOF'\n" + identityCollector + "MACLAB_COLLECTOR_EOF\n" +
		`python3 "$py" ` + strings.Join(args, " ") + ` > "$out/observed.json" || exit 1` + "\n" +
		`python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["running"]["uname_r"], d["running"]["boot_id"], (d.get("installer_entry") or {}).get("uki_sha256"))' "$out/observed.json"` + "\n"
}

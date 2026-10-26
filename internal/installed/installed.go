// Package installed checks a Mac's installed release against a frozen,
// immutable expectation: the "installed-kernel" job mode of an acceptance run.
//
// A collector script (collect.py, run on the Mac) reports what is installed and
// running. Compare merges that observation with the frozen manifest and the
// frozen installer boot entry into an identity file with explicit checks, and
// keeps the raw observation alongside, so the checks can be verified
// independently. OMT and kernel-error comparisons are against the frozen
// pre-install baseline, never against anything that a later run could replace.
package installed

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/detect"
)

//go:embed collect.py
var collector string

// Collector is the observation script for the Mac.
func Collector() string { return collector }

// Phases of an installed-mode job. Before runs on whatever boot is current,
// booted is the first test on the installed kernel, after the last one.
const (
	PhaseBefore = "before"
	PhaseBooted = "booted"
	PhaseAfter  = "after"
)

// TestName is the lab test that observes a phase.
func TestName(phase string) string { return "identity-" + phase }

// Script is the shell test that runs the collector for one phase and writes
// its observation to $MACLAB_OUT/observed.json. entryPath is the frozen
// installer entry's path ("" when freezing it).
func Script(phase, device, krel, entryPath string, pkgs []string, payload bool) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	args := []string{"--phase", q(phase), "--device", q(device), "--krel", q(krel), "--job", `"${MACLAB_JOB:-}"`}
	if entryPath != "" {
		args = append(args, "--entry-path", q(entryPath))
	}
	if len(pkgs) > 0 {
		args = append(args, "--pkgs", q(strings.Join(pkgs, ",")))
	}
	if payload {
		args = append(args, "--payload")
	}
	return "#!/bin/bash\n# maclab installed-mode identity, phase " + phase + " (read only)\nset -u\n" +
		`out=${MACLAB_OUT:-.}` + "\n" +
		`py=$(mktemp); trap 'rm -f "$py"' EXIT` + "\n" +
		"cat > \"$py\" <<'MACLAB_COLLECTOR_EOF'\n" + collector + "MACLAB_COLLECTOR_EOF\n" +
		`python3 "$py" ` + strings.Join(args, " ") + ` > "$out/observed.json" || exit 1` + "\n" +
		`python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["running"]["uname_r"], d["running"]["boot_id"], (d.get("installer_entry") or {}).get("uki_sha256"))' "$out/observed.json"` + "\n"
}

// --- the frozen expectation ---

type Artifact struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	Version     string `json:"version"`
	MtreeSHA256 string `json:"mtree_sha256"` // sha256 of the package's DECOMPRESSED .MTREE
}

type DTB struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type MacExpect struct {
	Board         string `json:"board"`
	BoardDTB      string `json:"board_dtb"`
	UbootGzSHA256 string `json:"uboot_gz_sha256"`
	Trailer       string `json:"trailer"`
	BootBinSHA256 string `json:"boot_bin_sha256"` // "" makes the verdict INCOMPLETE
}

type Manifest struct {
	Schema     string     `json:"schema"`
	Release    string     `json:"release"`
	Created    string     `json:"created,omitempty"`
	ApprovedBy []string   `json:"approved_by,omitempty"`
	Artifacts  []Artifact `json:"artifacts"`
	Kernel     struct {
		Release               string   `json:"release"`
		VmlinuzSHA256         string   `json:"vmlinuz_sha256"`
		PayloadManifest       string   `json:"payload_manifest"`
		PayloadManifestSHA256 string   `json:"payload_manifest_sha256"`
		PayloadCount          int      `json:"payload_count"`
		RegeneratedOnMac      []string `json:"regenerated_on_mac"`
	} `json:"kernel"`
	M1n1 struct {
		BinSHA256 string `json:"bin_sha256"`
		Version   string `json:"version"`
	} `json:"m1n1"`
	DTBs       []DTB                `json:"dtbs"`
	DTBsSHA256 string               `json:"dtbs_sha256"`
	Macs       map[string]MacExpect `json:"macs"`
}

const ManifestSchema = "maclab.installed-manifest/2"

// DTBsDigest is sha256 over "<name> <sha256-hex>\n" per DTB, in order.
func DTBsDigest(dtbs []DTB) string {
	h := sha256.New()
	for _, d := range dtbs {
		fmt.Fprintf(h, "%s %s\n", d.Name, strings.ToLower(d.SHA256))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ParsePayload reads sha256sum-format lines ("<sha>  <relpath>") into relpath -> sha.
func ParsePayload(b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sha, path, ok := strings.Cut(line, " ")
		path = strings.TrimLeft(strings.TrimSpace(path), "*")
		if !ok || len(sha) != 64 || path == "" {
			return nil, fmt.Errorf("bad payload line %q", line)
		}
		out[path] = strings.ToLower(sha)
	}
	return out, sc.Err()
}

// Validate checks a manifest is complete and self-consistent against its payload list.
func (m *Manifest) Validate(payload []byte) error {
	switch {
	case m.Schema != ManifestSchema:
		return fmt.Errorf("schema %q, want %q", m.Schema, ManifestSchema)
	case m.Release == "" || m.Kernel.Release == "":
		return fmt.Errorf("release and kernel.release are required")
	case len(m.Artifacts) == 0:
		return fmt.Errorf("no artifacts")
	case m.Kernel.VmlinuzSHA256 == "" || m.M1n1.BinSHA256 == "" || m.M1n1.Version == "":
		return fmt.Errorf("kernel.vmlinuz_sha256, m1n1.bin_sha256 and m1n1.version are required")
	case len(m.DTBs) == 0 || DTBsDigest(m.DTBs) != m.DTBsSHA256:
		return fmt.Errorf("dtbs_sha256 %q does not match the dtbs list (%s)", m.DTBsSHA256, DTBsDigest(m.DTBs))
	case len(m.Macs) == 0:
		return fmt.Errorf("no macs")
	}
	for _, a := range m.Artifacts {
		if a.Name == "" || len(a.SHA256) != 64 || a.Version == "" || len(a.MtreeSHA256) != 64 {
			return fmt.Errorf("artifact %q needs name, sha256, version and mtree_sha256", a.Name)
		}
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != m.Kernel.PayloadManifestSHA256 {
		return fmt.Errorf("payload manifest sha256 %s does not match kernel.payload_manifest_sha256", hex.EncodeToString(sum[:]))
	}
	files, err := ParsePayload(payload)
	if err != nil {
		return err
	}
	if len(files) != m.Kernel.PayloadCount {
		return fmt.Errorf("payload has %d files, manifest says %d", len(files), m.Kernel.PayloadCount)
	}
	if files["vmlinuz"] != m.Kernel.VmlinuzSHA256 {
		return fmt.Errorf("payload vmlinuz %q differs from kernel.vmlinuz_sha256", files["vmlinuz"])
	}
	for mac, e := range m.Macs {
		if e.Board == "" || e.BoardDTB == "" || e.UbootGzSHA256 == "" {
			return fmt.Errorf("mac %s needs board, board_dtb and uboot_gz_sha256", mac)
		}
		if dtbSHA(m.DTBs, e.BoardDTB) == "" {
			return fmt.Errorf("mac %s: board_dtb %s is not in dtbs", mac, e.BoardDTB)
		}
	}
	return nil
}

func dtbSHA(dtbs []DTB, name string) string {
	for _, d := range dtbs {
		if d.Name == name {
			return d.SHA256
		}
	}
	return ""
}

// --- what the collector observes ---

type Section struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Text   string `json:"text,omitempty"`
}

type Entry struct {
	Found            bool               `json:"found"`
	Name             string             `json:"name,omitempty"`
	Protocol         string             `json:"protocol,omitempty"`
	Path             string             `json:"path,omitempty"`
	Cmdline          string             `json:"cmdline,omitempty"`
	CmdlineTokens    []string           `json:"cmdline_tokens,omitempty"`
	EntryLines       []string           `json:"entry_lines,omitempty"`
	EntrySHA256      string             `json:"entry_sha256,omitempty"` // sha256 of entry_lines joined with "\n", plus "\n"
	UKIFile          string             `json:"uki_file,omitempty"`
	UKISHA256        string             `json:"uki_sha256,omitempty"`
	UKIBlake2b       string             `json:"uki_blake2b,omitempty"` // measured BLAKE2b-512 of the UKI: what the path's #pin must name
	UKISections      map[string]Section `json:"uki_sections,omitempty"`
	LimineConfSHA256 string             `json:"limine_conf_sha256,omitempty"`
}

type Observed struct {
	Schema  string `json:"schema"`
	Phase   string `json:"phase"`
	Device  string `json:"device"`
	Job     string `json:"job"`
	Time    string `json:"time"`
	Running struct {
		BootID      string `json:"boot_id"`
		UnameR      string `json:"uname_r"`
		ProcCmdline string `json:"proc_cmdline"`
	} `json:"running"`
	Packages map[string]struct {
		Version     string `json:"version"`
		MtreeSHA256 string `json:"mtree_sha256"`
	} `json:"packages"`
	Payload *struct {
		Krel  string            `json:"krel"`
		Root  string            `json:"root"`
		Count int               `json:"count"`
		Files map[string]string `json:"files"`
	} `json:"payload,omitempty"`
	InstallerEntry Entry `json:"installer_entry"`
	BootBin        struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Parts  *struct {
			M1n1SHA256     string   `json:"m1n1_sha256"`
			M1n1Bytes      int      `json:"m1n1_bytes"`
			M1n1Versions   []string `json:"m1n1_versions"`
			DTBCount       int      `json:"dtb_count"`
			DTBSHAs        []string `json:"dtb_shas"`
			BoardDTBSHA256 string   `json:"board_dtb_sha256"`
			BoardDTBCount  int      `json:"board_dtb_count"`
			UbootGzSHA256  string   `json:"uboot_gz_sha256"`
			Trailer        string   `json:"trailer"`
		} `json:"parts"`
	} `json:"boot_bin"`
	DT struct {
		Board             string   `json:"board"`
		Compatible        []string `json:"compatible"`
		LiveModel         string   `json:"live_model"`
		LiveStage2Version string   `json:"live_stage2_version"`
		LiveFDTSHA256     string   `json:"live_fdt_sha256"`
	} `json:"dt"`
	Compositor any `json:"compositor"`
}

// InstallerEntry is the frozen record of the boot entry the installer made.
type InstallerEntry struct {
	Schema         string `json:"schema"` // maclab.installer-entry/1
	Device         string `json:"device"`
	Release        string `json:"release"`
	CapturedBootID string `json:"captured_boot_id"`
	CapturedTime   string `json:"captured_time"`
	Entry
}

// FreezeEntry makes the frozen installer entry from an observation of the
// installed (not yet test-booted) Mac.
func FreezeEntry(o *Observed, m *Manifest) (*InstallerEntry, error) {
	e := o.InstallerEntry
	switch {
	case !e.Found:
		return nil, fmt.Errorf("%s: no installer boot entry for %s", o.Device, m.Kernel.Release)
	case e.Protocol != "efi" || e.UKISHA256 == "":
		return nil, fmt.Errorf("%s: installer entry %q is not an efi UKI entry", o.Device, e.Name)
	case e.UKISections[".linux"].SHA256 != m.Kernel.VmlinuzSHA256:
		return nil, fmt.Errorf("%s: installer UKI .linux %s is not the manifest's vmlinuz %s", o.Device, e.UKISections[".linux"].SHA256, m.Kernel.VmlinuzSHA256)
	case e.UKISections[".initrd"].SHA256 == "" || len(e.CmdlineTokens) == 0:
		return nil, fmt.Errorf("%s: installer entry has no initrd or cmdline", o.Device)
	case EntryDigest(e.EntryLines) != e.EntrySHA256:
		return nil, fmt.Errorf("%s: entry_sha256 does not match entry_lines", o.Device)
	case e.UKISections[".uname"].Text != m.Kernel.Release:
		return nil, fmt.Errorf("%s: installer UKI .uname %q is not the manifest's kernel %s", o.Device, e.UKISections[".uname"].Text, m.Kernel.Release)
	case !slices.Equal(strings.Fields(e.UKISections[".cmdline"].Text), e.CmdlineTokens):
		return nil, fmt.Errorf("%s: the entry's cmdline differs from the UKI's built-in .cmdline", o.Device)
	case !reEntryPath.MatchString(e.Path):
		return nil, fmt.Errorf("%s: installer entry path %q is not a hash-pinned boot():/….efi#<blake2b>", o.Device, e.Path)
	case !reBlake2b.MatchString(e.UKIBlake2b) || PathPin(e.Path) != e.UKIBlake2b:
		return nil, fmt.Errorf("%s: the path pins BLAKE2b %s, but the UKI measures %q", o.Device, PathPin(e.Path), e.UKIBlake2b)
	}
	return &InstallerEntry{Schema: "maclab.installer-entry/1", Device: o.Device, Release: m.Release,
		CapturedBootID: o.Running.BootID, CapturedTime: o.Time, Entry: e}, nil
}

var (
	reEntryPath = regexp.MustCompile(`^boot\(\):/[^\s#]+\.efi#[0-9a-f]{128}$`)
	reBlake2b   = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// PathPin is the BLAKE2b a Limine path pins its file to (after "#"), or "".
func PathPin(path string) string {
	_, pin, ok := strings.Cut(path, "#")
	if !ok {
		return ""
	}
	return pin
}

// EntryDigest is sha256 over the entry's limine.conf lines joined with "\n", plus a final "\n".
func EntryDigest(lines []string) string {
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

// --- merged identity ---

type Check struct {
	ID            string `json:"id"`
	PhaseBinding  string `json:"phase_binding,omitempty"` // "booted|after only": informational before
	Expected      any    `json:"expected,omitempty"`
	Observed      any    `json:"observed,omitempty"`
	Detail        any    `json:"detail,omitempty"`
	Match         bool   `json:"match"`
	Informational bool   `json:"informational,omitempty"`
}

type Identity struct {
	Schema               string          `json:"schema"`
	Phase                string          `json:"phase"`
	Job                  string          `json:"job"`
	Device               string          `json:"device"`
	BootID               string          `json:"boot_id"`
	ManifestSHA256       string          `json:"manifest_sha256"`
	InstallerEntrySHA256 string          `json:"installer_entry_sha256"`
	Observed             json.RawMessage `json:"observed"`
	Checks               []Check         `json:"checks"`
	Verdict              string          `json:"verdict"` // MATCH, MISMATCH or INCOMPLETE
	Mismatches           []string        `json:"mismatches"`
}

// Additions are the only cmdline tokens labd adds to the installer's. lab-agent
// adds its Lab boot parameters on top (agent.IsLabBootParam).
func Additions(job string, serial bool) []string {
	a := []string{"maclab.job=" + job, "panic=10"}
	if serial {
		a = append(a, "console=ttySAC0,115200", "console=tty0", "loglevel=7")
	}
	return a
}

// Cmdline is the installed-mode boot cmdline: the installer's tokens in order,
// then exactly the lab additions.
func Cmdline(installer []string, job string, serial bool) string {
	return strings.Join(append(append([]string{}, installer...), Additions(job, serial)...), " ")
}

// Compare builds the identity file for one phase. booted is the booted phase's
// identity, required for the after phase (same boot).
func Compare(phase string, raw []byte, m *Manifest, manifestSHA string, payload map[string]string,
	e *InstallerEntry, entrySHA string, serial bool, booted *Identity) (*Identity, error) {
	var o Observed
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("observation is not JSON: %w", err)
	}
	mac, ok := m.Macs[o.Device]
	id := &Identity{Schema: "maclab.installed-identity/2", Phase: phase, Job: o.Job, Device: o.Device,
		BootID: o.Running.BootID, ManifestSHA256: manifestSHA, InstallerEntrySHA256: entrySHA, Observed: raw, Mismatches: []string{}}
	add := func(c Check) {
		if c.PhaseBinding != "" && phase == PhaseBefore {
			c.Informational = true
		}
		id.Checks = append(id.Checks, c)
		if !c.Match && !c.Informational {
			id.Mismatches = append(id.Mismatches, fmt.Sprintf("%s: expected %v, observed %v", c.ID, short(c.Expected), short(c.Observed)))
		}
	}
	if !ok {
		add(Check{ID: "device", Expected: keys(m.Macs), Observed: o.Device})
	}
	if o.Phase != phase {
		add(Check{ID: "phase", Expected: phase, Observed: o.Phase})
	}

	// packages: version and installed mtree (decompressed digest) per artifact
	exp, obs := map[string]string{}, map[string]string{}
	pkgOK := true
	for _, a := range m.Artifacts {
		exp[a.Name] = a.Version + " mtree:" + a.MtreeSHA256
		p := o.Packages[a.Name]
		obs[a.Name] = p.Version + " mtree:" + p.MtreeSHA256
		if p.Version != a.Version || p.MtreeSHA256 != a.MtreeSHA256 {
			pkgOK = false
		}
	}
	add(Check{ID: "packages", Expected: exp, Observed: obs, Match: pkgOK})

	// payload: every packaged file under usr/lib/modules/<krel>
	if o.Payload == nil {
		add(Check{ID: "payload", Expected: len(payload), Observed: "not collected"})
	} else {
		regen := map[string]bool{}
		for _, r := range m.Kernel.RegeneratedOnMac {
			regen[r] = true
		}
		var mismatched, missing, unpackaged []string
		regenerated := map[string]string{}
		checked := 0
		for rel, sha := range payload {
			got, ok := o.Payload.Files[rel]
			switch {
			case regen[rel]:
				regenerated[rel] = got
			case !ok:
				missing = append(missing, rel)
			case got != sha:
				mismatched = append(mismatched, rel)
			default:
				checked++
			}
		}
		for rel := range o.Payload.Files {
			if _, ok := payload[rel]; !ok {
				unpackaged = append(unpackaged, rel)
			}
		}
		sort.Strings(mismatched)
		sort.Strings(missing)
		sort.Strings(unpackaged)
		add(Check{ID: "payload", Expected: map[string]any{"count": len(payload), "payload_manifest_sha256": m.Kernel.PayloadManifestSHA256},
			Observed: map[string]any{"count": o.Payload.Count, "root": o.Payload.Root},
			Detail: map[string]any{"checked": checked, "mismatched": nz(mismatched), "missing": nz(missing),
				"unpackaged": nz(unpackaged), "regenerated": regenerated},
			Match: o.Payload.Krel == m.Kernel.Release && len(mismatched) == 0 && len(missing) == 0})
	}

	// the installer's UKI and entry, against the frozen entry
	ie := o.InstallerEntry
	if e == nil {
		add(Check{ID: "installer_entry", Expected: "frozen installer entry", Observed: "none frozen"})
	} else {
		secOK := map[string]bool{}
		for _, s := range []string{".linux", ".initrd", ".cmdline", ".uname"} {
			secOK[s] = ie.UKISections[s].SHA256 != "" && ie.UKISections[s].SHA256 == e.UKISections[s].SHA256
		}
		// the path's #pin must be the UKI's measured BLAKE2b, now and when frozen
		pinOK := reBlake2b.MatchString(ie.UKIBlake2b) && ie.UKIBlake2b == e.UKIBlake2b && PathPin(ie.Path) == ie.UKIBlake2b
		match := ie.Found && ie.Path == e.Path && ie.Protocol == e.Protocol && ie.UKISHA256 == e.UKISHA256 && pinOK &&
			ie.EntrySHA256 == e.EntrySHA256 && EntryDigest(ie.EntryLines) == ie.EntrySHA256 &&
			secOK[".linux"] && secOK[".initrd"] && secOK[".cmdline"] && secOK[".uname"] &&
			ie.UKISections[".linux"].SHA256 == m.Kernel.VmlinuzSHA256
		add(Check{ID: "installer_entry",
			Expected: map[string]any{"path": e.Path, "protocol": e.Protocol, "uki_sha256": e.UKISHA256, "uki_blake2b": e.UKIBlake2b, "entry_sha256": e.EntrySHA256, ".linux": m.Kernel.VmlinuzSHA256},
			Observed: map[string]any{"found": ie.Found, "path": ie.Path, "protocol": ie.Protocol, "uki_sha256": ie.UKISHA256, "uki_blake2b": ie.UKIBlake2b, "entry_sha256": ie.EntrySHA256},
			Detail:   map[string]any{"sections_match": secOK, "path_pin_is_measured_blake2b": pinOK}, Match: match})
		add(Check{ID: "initramfs_stable", Expected: e.UKISections[".initrd"].SHA256, Observed: ie.UKISections[".initrd"].SHA256,
			Match: ie.UKISections[".initrd"].SHA256 != "" && ie.UKISections[".initrd"].SHA256 == e.UKISections[".initrd"].SHA256})
	}

	// boot.bin, whole and by part
	p := o.BootBin.Parts
	if p == nil {
		add(Check{ID: "boot_bin", Expected: mac.BootBinSHA256, Observed: "unparseable boot.bin " + o.BootBin.SHA256})
	} else {
		expSHAs := make([]string, len(m.DTBs))
		for i, d := range m.DTBs {
			expSHAs[i] = d.SHA256
		}
		set := func(l []string) []string { c := append([]string{}, l...); sort.Strings(c); return c }
		parts := map[string]bool{
			"m1n1":      p.M1n1SHA256 == m.M1n1.BinSHA256,
			"dtb_set":   strings.Join(set(p.DTBSHAs), ",") == strings.Join(set(expSHAs), ","),
			"dtb_order": strings.Join(p.DTBSHAs, ",") == strings.Join(expSHAs, ","),
			"board_dtb": p.BoardDTBCount == 1 && p.BoardDTBSHA256 != "" && p.BoardDTBSHA256 == dtbSHA(m.DTBs, mac.BoardDTB),
			"uboot":     p.UbootGzSHA256 == mac.UbootGzSHA256,
			"trailer":   p.Trailer == mac.Trailer,
		}
		all := true
		for _, v := range parts {
			all = all && v
		}
		full := mac.BootBinSHA256 != "" && o.BootBin.SHA256 == mac.BootBinSHA256
		add(Check{ID: "boot_bin", Expected: map[string]any{"sha256": mac.BootBinSHA256, "dtbs_sha256": m.DTBsSHA256},
			Observed: map[string]any{"sha256": o.BootBin.SHA256, "dtb_count": p.DTBCount},
			Detail:   map[string]any{"parts_match": parts}, Match: all && (full || mac.BootBinSHA256 == "")})
	}

	// what is running: binding only on the installed kernel's boot
	add(Check{ID: "running_kernel", PhaseBinding: "booted|after only", Expected: m.Kernel.Release, Observed: o.Running.UnameR,
		Match: o.Running.UnameR == m.Kernel.Release})
	add(Check{ID: "stage2", PhaseBinding: "booted|after only", Expected: m.M1n1.Version, Observed: o.DT.LiveStage2Version,
		Match: o.DT.LiveStage2Version == m.M1n1.Version})
	add(Check{ID: "dt_board", Expected: mac.Board, Observed: o.DT.Board, Match: o.DT.Board == mac.Board}) // hardware: binding in every phase
	if e != nil {
		want := strings.Fields(Cmdline(e.CmdlineTokens, o.Job, serial))
		observed := strings.Fields(o.Running.ProcCmdline)
		got := slices.DeleteFunc(slices.Clone(observed), func(f string) bool { return agent.IsLabBootParam(f) && !slices.Contains(want, f) })
		add(Check{ID: "cmdline", PhaseBinding: "booted|after only",
			Expected: want, Observed: observed,
			Detail: map[string]any{"installer": e.CmdlineTokens, "permitted_additions": Additions(o.Job, serial),
				"unexpected": nz(minus(got, want)), "missing": nz(minus(want, got))},
			Match: strings.Join(got, " ") == strings.Join(want, " ")})
	}
	if phase == PhaseAfter {
		b := ""
		if booted != nil {
			b = booted.BootID
		}
		add(Check{ID: "same_boot_as_booted", Expected: b, Observed: o.Running.BootID, Match: b != "" && b == o.Running.BootID})
	}

	switch {
	case len(id.Mismatches) > 0:
		id.Verdict = "MISMATCH"
	case mac.BootBinSHA256 == "":
		id.Verdict = "INCOMPLETE"
		id.Mismatches = append(id.Mismatches, "manifest has no expected boot_bin_sha256 for "+o.Device)
	default:
		id.Verdict = "MATCH"
	}
	return id, nil
}

func minus(a, b []string) []string {
	n := map[string]int{}
	for _, x := range b {
		n[x]++
	}
	var out []string
	for _, x := range a {
		if n[x] > 0 {
			n[x]--
		} else {
			out = append(out, x)
		}
	}
	return out
}

func nz(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func keys[V any](m map[string]V) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func short(v any) string {
	s := fmt.Sprint(v)
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// --- OMT and kernel errors against the frozen baseline ---

type OMTSide struct {
	Job          string `json:"job,omitempty"`
	Report       string `json:"report"`
	ReportSHA256 string `json:"report_sha256"`
	Tool         string `json:"tool"`
	Kernel       string `json:"kernel"`
}

type Transition struct {
	ID      string `json:"id"`
	Frozen  string `json:"frozen"`
	Current string `json:"current"`
}

type OMTCompare struct {
	Schema      string       `json:"schema"`
	Job         string       `json:"job"`
	Device      string       `json:"device"`
	Frozen      OMTSide      `json:"frozen"`
	Current     OMTSide      `json:"current"`
	Transitions []Transition `json:"transitions"`
	Regressions []Transition `json:"regressions"`
	Fixed       []Transition `json:"fixed"`
	NewChecks   []string     `json:"new_checks"`
	Verdict     string       `json:"verdict"` // NO_REGRESSION or REGRESSION
}

// ReportStatus reads an omarchy-m-test report's checks (id -> status) and tool/kernel.
func ReportStatus(report []byte) (status map[string]string, tool, kernel string, err error) {
	var r struct {
		Tool struct {
			Version string `json:"version"`
		} `json:"tool"`
		Machine struct {
			Kernel string `json:"kernel"`
		} `json:"machine"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(report, &r); err != nil {
		return nil, "", "", err
	}
	status = map[string]string{}
	for _, c := range r.Checks {
		status[c.ID] = c.Status
	}
	return status, r.Tool.Version, r.Machine.Kernel, nil
}

// CompareOMT lists every transition from the frozen report's statuses to the
// current report's. A frozen pass that is now fail, skip or missing is a
// regression; no allow list applies here.
func CompareOMT(job, device string, frozen OMTSide, frozenStatus map[string]string, current OMTSide, currentStatus map[string]string) *OMTCompare {
	c := &OMTCompare{Schema: "maclab.omt-compare/2", Job: job, Device: device, Frozen: frozen, Current: current,
		Transitions: []Transition{}, Regressions: []Transition{}, Fixed: []Transition{}, NewChecks: []string{}}
	ids := map[string]bool{}
	for id := range frozenStatus {
		ids[id] = true
	}
	for id := range currentStatus {
		ids[id] = true
	}
	for _, id := range keys(ids) {
		f, inF := frozenStatus[id]
		cur, inC := currentStatus[id]
		if !inC {
			cur = "missing"
		}
		if !inF {
			c.NewChecks = append(c.NewChecks, id)
			f = "absent"
		}
		t := Transition{ID: id, Frozen: f, Current: cur}
		c.Transitions = append(c.Transitions, t)
		switch {
		case f == "pass" && cur != "pass":
			c.Regressions = append(c.Regressions, t)
		case inF && f != "pass" && cur == "pass":
			c.Fixed = append(c.Fixed, t)
		}
	}
	c.Verdict = "NO_REGRESSION"
	if len(c.Regressions) > 0 {
		c.Verdict = "REGRESSION"
	}
	return c
}

type FileRef struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type FatalHit struct {
	Kind string `json:"kind"`
	Line string `json:"line"`
}

type DmesgCompare struct {
	Schema      string     `json:"schema"`
	Job         string     `json:"job"`
	Device      string     `json:"device"`
	Frozen      FileRef    `json:"frozen"`
	Current     FileRef    `json:"current"`
	NewLines    []string   `json:"new_lines"`
	GoneLines   []string   `json:"gone_lines"`
	FatalHits   []FatalHit `json:"fatal_hits"`
	Disposition string     `json:"disposition"` // NONE_NEW, REVIEW_REQUIRED or FATAL
}

// CompareDmesg diffs the current kernel error lines against the frozen ones
// (detect.NewLines both ways). Fatal lines block wherever they appear, even
// if the frozen baseline had them too.
// FatalHits are the lines of a kernel log that name a fatal event (panic, oops,
// BUG, hung task...), whatever priority they were logged at.
func FatalHits(text string) []FatalHit {
	hits := []FatalHit{}
	for _, line := range strings.Split(text, "\n") {
		if k := detect.Classify(line); k != "" && detect.Fatal(k) {
			hits = append(hits, FatalHit{Kind: k, Line: strings.TrimSpace(line)})
		}
	}
	return hits
}

func CompareDmesg(job, device string, frozen FileRef, frozenText string, current FileRef, currentText string) *DmesgCompare {
	d := &DmesgCompare{Schema: "maclab.dmesg-compare/2", Job: job, Device: device, Frozen: frozen, Current: current,
		NewLines: nz(detect.NewLines(frozenText, currentText)), GoneLines: nz(detect.NewLines(currentText, frozenText)), FatalHits: []FatalHit{}}
	d.FatalHits = append(d.FatalHits, FatalHits(currentText)...)
	switch {
	case len(d.FatalHits) > 0:
		d.Disposition = "FATAL"
	case len(d.NewLines) > 0:
		d.Disposition = "REVIEW_REQUIRED"
	default:
		d.Disposition = "NONE_NEW"
	}
	return d
}

// SHA256 of a byte slice, hex.
func SHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

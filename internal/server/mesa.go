package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/mesa"
)

// First-class Mesa jobs test pinned split packages (see api.MesaSpec).
//
// Staged jobs keep their packages pinned while unfinished and require explicit
// staged-execution capability as well as mesaMinAgent. Installed/official modes
// remain refused until their separate recovery/runtime contracts are reviewed.

// mesaMinAgent is the first lab-agent with the staged Mesa command and probe.
const mesaMinAgent = "0.8.0"

// mesaMaxPackages bounds a request: the Mesa split packages are a handful.
const mesaMaxPackages = 8

// rePkgName is a pacman package name of the Mesa family: mesa, mesa-*,
// vulkan-*, or opencl-* (the split packages a Mesa recipe produces).
var rePkgName = regexp.MustCompile(`^(?:mesa|mesa-[a-z0-9+_.-]{1,60}|vulkan-[a-z0-9+_.-]{1,60}|opencl-[a-z0-9+_.-]{1,60})$`)

// reBuildID is a lab build id, as EnsureBuild makes them (b0102-150405-ab12).
var reBuildID = regexp.MustCompile(`^b[0-9]{4}-[0-9]{6}-[0-9a-f]{4}$`)

// validateMesa refuses a Mesa request the lab cannot honour exactly. It runs
// for every job that carries a MesaSpec, before the job is queued.
func (s *Server) validateMesa(spec api.JobSpec, d api.Device) (int, error) {
	m := spec.Mesa
	if err := refuseBelowFull(&d, actMesa); err != nil {
		return 403, err
	}
	switch {
	case m.OfficialGPU:
		return 409, errors.New("official GPU mode is disabled pending runtime qualification; staged provider mode is available")
	case m.SigningPublicSHA256 != "" || m.SigningStateHome != "":
		return 400, errors.New("signing public pin requires optional official GPU mode")
	case m.Mode == api.MesaInstalled:
		return 400, errors.New("installed Mesa mode is not supported yet: it needs a package transaction with a recovery contract, judged through the installed manifest")
	case m.Mode != api.MesaStaged:
		return 400, fmt.Errorf("unknown Mesa mode %q (supported: %s)", m.Mode, api.MesaStaged)
	case spec.InstalledManifest != "":
		return 400, errors.New("a staged Mesa job is not an installed-release job: drop --installed")
	case spec.Baseline || spec.Crash != "":
		return 400, errors.New("baseline and crash-test jobs take no Mesa packages")
	case spec.Publish:
		return 400, errors.New("a staged Mesa run is not the installed desktop and is never published")
	case len(spec.OMTAllow) > 0:
		return 400, errors.New("a Mesa job waives no check: drop --omt-allow")
	case len(m.Packages) == 0 || len(m.Packages) > mesaMaxPackages:
		return 400, fmt.Errorf("a Mesa job pins 1 to %d split packages, not %d", mesaMaxPackages, len(m.Packages))
	case m.Build != "" && !reBuildID.MatchString(m.Build):
		return 400, fmt.Errorf("mesa build %q is not a build id", m.Build)
	}
	for _, t := range spec.Tests {
		if t.Name == "mesa-provider" || t.Builtin == "mesa-provider" {
			return 400, errors.New("mesa-provider is managed by the Mesa job; do not override it")
		}
	}
	names := map[string]bool{}
	hashes := map[string]bool{}
	for _, p := range m.Packages {
		switch {
		case !rePkgName.MatchString(p.Name):
			return 400, fmt.Errorf("package %q is not a Mesa split package name (mesa, mesa-*, vulkan-*, opencl-*)", p.Name)
		case names[p.Name]:
			return 400, fmt.Errorf("package %s is pinned twice", p.Name)
		case hashes[p.SHA256]:
			return 400, errors.New("one archive cannot stand for two split packages")
		case !reSHA.MatchString(p.SHA256):
			return 400, fmt.Errorf("package %s must be an artifact sha256 (upload it first)", p.Name)
		}
		names[p.Name] = true
		hashes[p.SHA256] = true
		if st, err := os.Lstat(s.artifactPath(p.SHA256)); err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > mesa.MaxCompressed {
			return 400, fmt.Errorf("package %s artifact %s not uploaded", p.Name, p.SHA256)
		}
	}
	if m.Build != "" {
		if err := s.mesaBuildProvenance(m); err != nil {
			return 400, err
		}
	}
	for _, sha := range []string{mesa.GLProbeSHA, mesa.VKProbeSHA} {
		st, e := os.Lstat(s.artifactPath(sha))
		if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > mesa.MaxFile {
			return 409, fmt.Errorf("approved render-check helper %s not uploaded; use lab upload for the qualified helper artifact", sha)
		}
	}
	switch {
	case !d.Facts.MesaStaged:
		return 409, fmt.Errorf("%s does not advertise staged Mesa capability", d.Name)
	case d.Facts.GUIUser == "":
		return 409, fmt.Errorf("%s has no GUI user: the Mesa provider probe runs in the desktop session", d.Name)
	case !versionAtLeast(d.Facts.AgentVersion, mesaMinAgent):
		return 409, fmt.Errorf("%s runs lab-agent %s; staged Mesa jobs need %s or later", d.Name, orStr(d.Facts.AgentVersion, "(unknown)"), mesaMinAgent)
	}
	return 0, nil
}

// mesaBuildProvenance makes a named build real provenance rather than a
// label: it must be a finished package build, and each pinned package must be
// one of its files, by sha256, under a file name of that package
// (<name>-<version>-<arch>.pkg.tar.zst).
func (s *Server) mesaBuildProvenance(m *api.MesaSpec) error {
	b, err := s.getBuild(m.Build)
	if err != nil || b == nil {
		return fmt.Errorf("mesa build %s is not a lab build", m.Build)
	}
	if b.Kind != api.BuildPackage || b.State != api.BuildDone {
		return fmt.Errorf("mesa build %s is not a finished package build (kind %q, state %s)", m.Build, b.Kind, b.State)
	}
	for _, p := range m.Packages {
		found := false
		for _, f := range b.Files {
			if name, ok := pkgFileName(f.Name); ok && name == p.Name && f.SHA256 == p.SHA256 {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("package %s (%s) is not a file of build %s", p.Name, p.SHA256, m.Build)
		}
	}
	return nil
}

// pkgFileName is the package name of a pacman package file,
// <name>-<pkgver>-<pkgrel>-<arch>.pkg.tar.zst. pkgver, pkgrel and arch never
// contain '-', so the name is everything before the last three fields; a
// name that merely prefixes another (mesa, mesa-aurora) never matches.
func pkgFileName(file string) (string, bool) {
	base, ok := strings.CutSuffix(file, ".pkg.tar.zst")
	if !ok {
		return "", false
	}
	parts := strings.Split(base, "-")
	if len(parts) < 4 {
		return "", false
	}
	for _, f := range parts[len(parts)-3:] {
		if f == "" {
			return "", false
		}
	}
	name := strings.Join(parts[:len(parts)-3], "-")
	return name, name != ""
}

// mesaRefs are the artifacts a job's Mesa request needs, for the GC.
func mesaRefs(spec api.JobSpec) []string {
	if spec.Mesa == nil {
		return nil
	}
	refs := []string{mesa.GLProbeSHA, mesa.VKProbeSHA}
	if spec.Mesa.OfficialGPU {
		refs = append(refs, mesa.OfficialArchiveSHA)
	}
	for _, p := range spec.Mesa.Packages {
		refs = append(refs, p.SHA256)
	}
	return refs
}

// acceptMesa binds typed provider evidence to this staged job, never just an
// exit code or a caller-supplied native flag. Overall recovery still gates PASS.
func (r *jobRun) acceptMesa(t *api.TestResult) string {
	m := t.Mesa
	if m == nil {
		return "Mesa provider omitted typed evidence"
	}
	m.Semantics = mesa.Semantics
	if m.Mode != api.MesaStaged || m.Job != r.j.ID || m.BootID != r.bootID || m.Kernel != r.v.snapshot().Kernel || m.ManifestSHA256 != r.mesaManifest || !m.CleanupVerified || m.Verdict != "PASS" || len(m.Provider) != 2 || m.Provider["gl"] != "NATIVE_STAGED" || m.Provider["vulkan"] != "NATIVE_STAGED" {
		return "Mesa staged provider/boot/manifest/cleanup evidence incomplete"
	}
	if r.j.Spec.Mesa.OfficialGPU {
		o := m.Official
		if o == nil || o.Status != "PASS" || o.NativeInvocations != 65 || !o.SignatureVerified || o.SourceCommit != mesa.OfficialCommit || o.ArchiveSHA256 != mesa.OfficialArchiveSHA || !reSHA.MatchString(o.ReportSHA256) || !reSHA.MatchString(o.SealSHA256) || o.ReportPath != "official/report.json" || o.SealPath != "official/seal.json" {
			return "official signed suite/export evidence incomplete"
		}

		// uploadDir can omit a failed upload; check both acknowledgement and
		// independently reopened controller bytes before accepting the suite.
		files := map[string]int{}
		for _, name := range t.Files {
			files[name]++
		}
		names := append(mesa.OfficialExportNames(), "seal.json")

		for _, name := range names {
			path := "test-mesa-provider/official/" + name
			if files[path] != 1 {
				return "official collected artifact missing or duplicated"
			}
		}
		if files["test-mesa-provider/staged-manifest.json"] != 1 {
			return "official collected manifest acknowledgement missing or duplicated"
		}
		out := filepath.Join(r.s.jobDir(r.j.ID), "test-mesa-provider")
		if err := mesa.ValidateOfficialExport(out, r.j.ID, r.bootID, m.Kernel, r.mesaManifest, o); err != nil {
			return "official collected export invalid: " + err.Error()
		}
		if hash, err := mesa.Hash(filepath.Join(out, "staged-manifest.json"), 8<<20); err != nil || hash != r.mesaManifest {
			return "official collected manifest missing or drifted"
		}
	} else if m.Official != nil {
		return "unexpected official evidence in provider-only request"
	}
	want := map[string]string{}
	for _, p := range r.j.Spec.Mesa.Packages {
		want[p.Name] = p.SHA256
	}
	if len(m.Packages) != len(want) {
		return "Mesa package evidence count mismatch"
	}
	for _, p := range m.Packages {
		if want[p.Name] != p.SHA256 {
			return "Mesa package evidence pin mismatch"
		}
		delete(want, p.Name)
	}
	if len(want) != 0 {
		return "Mesa package evidence missing"
	}
	return ""
}

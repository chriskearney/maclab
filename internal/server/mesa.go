package server

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// First-class Mesa jobs test pinned split packages (see api.MesaSpec).
//
// This first increment defines and validates the request, keeps its package
// artifacts out of the GC while the job is unfinished, and refuses every job
// until an agent that implements the staged mode reports mesaMinAgent: no
// labd dispatches a Mesa job to an agent that cannot honour it.

// mesaMinAgent is the first lab-agent with the staged Mesa command and probe.
const mesaMinAgent = "0.8.0"

// mesaMaxPackages bounds a request: the Mesa split packages are a handful.
const mesaMaxPackages = 8

// rePkgName is a pacman package name of the Mesa family: mesa, mesa-*,
// vulkan-*, or opencl-* (the split packages a Mesa recipe produces).
var rePkgName = regexp.MustCompile(`^(?:mesa|mesa-[a-z0-9+_.-]{1,60}|vulkan-[a-z0-9+_.-]{1,60}|opencl-[a-z0-9+_.-]{1,60})$`)

// reBuildID is a lab build id, as EnsureBuild makes them (b0102-150405-ab12).
var reBuildID = regexp.MustCompile(`^b[0-9]{4}-[0-9]{6}-[0-9a-f]{4}$`)

// mesaStagedSemantics is recorded with every result, so a staged run is never
// mistaken for the installed desktop's Mesa.
const mesaStagedSemantics = "staged diagnostic: the pinned packages ran from a private per-job prefix for the job's probe processes only; the desktop kept the installed Mesa, so this says nothing about the installed desktop"

// validateMesa refuses a Mesa request the lab cannot honour exactly. It runs
// for every job that carries a MesaSpec, before the job is queued.
func (s *Server) validateMesa(spec api.JobSpec, d api.Device) (int, error) {
	m := spec.Mesa
	switch {
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
	names := map[string]bool{}
	for _, p := range m.Packages {
		switch {
		case !rePkgName.MatchString(p.Name):
			return 400, fmt.Errorf("package %q is not a Mesa split package name (mesa, mesa-*, vulkan-*, opencl-*)", p.Name)
		case names[p.Name]:
			return 400, fmt.Errorf("package %s is pinned twice", p.Name)
		case !reSHA.MatchString(p.SHA256):
			return 400, fmt.Errorf("package %s must be an artifact sha256 (upload it first)", p.Name)
		}
		names[p.Name] = true
		if _, err := os.Stat(s.artifactPath(p.SHA256)); err != nil {
			return 400, fmt.Errorf("package %s artifact %s not uploaded", p.Name, p.SHA256)
		}
	}
	if m.Build != "" {
		if err := s.mesaBuildProvenance(m); err != nil {
			return 400, err
		}
	}
	switch {
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
	refs := make([]string, 0, len(spec.Mesa.Packages))
	for _, p := range spec.Mesa.Packages {
		refs = append(refs, p.SHA256)
	}
	return refs
}

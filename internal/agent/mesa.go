package agent

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/mesa"
)

//go:embed mesa_runtime.py
var mesaRuntime []byte

//go:embed mesa_official.py
var mesaOfficial []byte

func (l *Linux) mesaParent() string { return filepath.Join(l.WorkDir, "mesa") }
func (l *Linux) StageMesa(ctx context.Context, job string, a api.MesaStageArgs, fetch Fetcher) (api.MesaStageResult, error) {
	var result api.MesaStageResult
	boot, kernel, cmdline := l.Identity()
	if boot != a.BootID || kernel != a.Kernel || mesa.Sum([]byte(cmdline+"\n")) != a.CmdlineSHA256 || jobTag(cmdline) != job {
		return result, errors.New("Mesa stage not the exact requested job boot")
	}
	if os.Geteuid() != 0 {
		return result, errors.New("Mesa stage requires root")
	}
	if a.Spec.Mode != api.MesaStaged {
		return result, errors.New("installed Mesa refused")
	}
	if a.Spec.OfficialGPU {
		return result, errors.New("official GPU adapter pending independent review")
	}
	if l.GUIUser == "" {
		return result, errors.New("Mesa needs existing GUI user")
	}
	if err := os.MkdirAll(l.mesaParent(), 0755); err != nil {
		return result, err
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(l.mesaParent(), &fs); err != nil {
		return result, err
	}
	if uint64(fs.Type) == 0x4d44 {
		return result, errors.New("staged Mesa prefix must not be on the FAT ESP")
	}
	m, err := mesa.Stage(ctx, l.mesaParent(), job, a.Spec, mesa.Fetch(fetch))
	if err != nil {
		return result, err
	}
	u, env, err := guiEnv(l.GUIUser, guiSessionWait)
	if err != nil {
		return result, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return result, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return result, err
	}
	if err = os.Chown(m.Prefix, 0, gid); err != nil {
		return result, err
	}
	if err = os.Chmod(m.Prefix, 0750); err != nil {
		return result, err
	}
	if uid <= 0 || gid <= 0 {
		return result, errors.New("Mesa probes require a nonroot GUI account")
	}
	envMap := map[string]string{}
	for _, entry := range env {
		key, v, ok := strings.Cut(entry, "=")
		if ok {
			envMap[key] = v
		}
	}
	h, err := mesa.Hash(filepath.Join(m.Prefix, "manifest.json"), 8<<20)
	if err != nil {
		return result, err
	}
	p := mesa.RuntimePlan{Schema: mesa.Schema, Job: job, BootID: boot, Kernel: kernel, CmdlineSHA256: a.CmdlineSHA256, ManifestPath: filepath.Join(m.Prefix, "manifest.json"), ManifestSHA256: h, GUIUser: l.GUIUser, GUIUID: uid, GUIGID: gid, GUIHome: u.HomeDir, GUIEnv: envMap, OfficialGPU: a.Spec.OfficialGPU, SigningPublicSHA256: a.Spec.SigningPublicSHA256}
	if err = mesaWrite(filepath.Join(m.Prefix, "runtime-plan.json"), mesa.JSON(p), 0600); err != nil {
		return result, err
	}
	if err = mesaWrite(filepath.Join(m.Prefix, "mesa_runtime.py"), mesaRuntime, 0600); err != nil {
		return result, err
	}
	if err = mesaWrite(filepath.Join(m.Prefix, "mesa_official.py"), mesaOfficial, 0600); err != nil {
		return result, err
	}
	return api.MesaStageResult{ManifestSHA256: h, Prefix: m.Prefix}, nil
}
func mesaWrite(path string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return e
}
func (l *Linux) runMesaProvider(ctx context.Context, job string, t api.TestSpec, out string) api.TestResult {
	r := api.TestResult{Name: t.Name, ExitCode: -1}
	fail := func(err error) api.TestResult { r.Error = err.Error(); return r }
	if strings.ContainsAny(job, "/\\. \n\r") {
		return fail(errors.New("invalid job"))
	}
	prefix := filepath.Join(l.mesaParent(), job)
	script := filepath.Join(prefix, "mesa_runtime.py")
	h, err := mesa.Hash(script, 1<<20)
	if err != nil || h != mesa.Sum(mesaRuntime) {
		return fail(errors.New("embedded Mesa runtime source drift"))
	}
	h, err = mesa.Hash(filepath.Join(prefix, "mesa_official.py"), 4<<20)
	if err != nil || h != mesa.Sum(mesaOfficial) {
		return fail(errors.New("official adapter source drift"))
	}
	if err = os.MkdirAll(out, 0700); err != nil {
		return fail(err)
	}
	if err = os.Chmod(out, 0700); err != nil {
		return fail(err)
	}
	// Preserve exact staged inputs/source pins in the ordinary uploaded job
	// artifacts before the private prefix is removed on normal return.
	for _, name := range []string{"manifest.json", "runtime-plan.json"} {
		b, e := mesa.Read(filepath.Join(prefix, name), 8<<20)
		if e != nil {
			return fail(e)
		}
		if e = mesaWrite(filepath.Join(out, "staged-"+name), b, 0600); e != nil {
			return fail(e)
		}
	}
	if err = mesaWrite(filepath.Join(out, "source-pins.json"), mesa.JSON(map[string]string{"runtime_sha256": mesa.Sum(mesaRuntime), "official_adapter_sha256": mesa.Sum(mesaOfficial), "gl_probe_sha256": mesa.GLProbeSHA, "vulkan_probe_sha256": mesa.VKProbeSHA}), 0600); err != nil {
		return fail(err)
	}
	tctx, cancel := context.WithTimeout(ctx, testTimeout(t))
	defer cancel()
	cmd := exec.CommandContext(tctx, "python3", "-B", script, filepath.Join(prefix, "runtime-plan.json"), out)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "PYTHONDONTWRITEBYTECODE=1"}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}
	cmd.WaitDelay = 20 * time.Second
	log, err := os.OpenFile(filepath.Join(out, "log.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail(err)
	}
	cmd.Stdout = log
	cmd.Stderr = log
	start := time.Now()
	runErr := cmd.Run()
	log.Close()
	r.Seconds = time.Since(start).Seconds()
	r.Tail = tail(filepath.Join(out, "log.txt"), 40)
	b, err := mesa.Read(filepath.Join(out, "mesa-result.json"), 4<<20)
	if err != nil {
		return fail(fmt.Errorf("Mesa result missing: %w", err))
	}
	var raw struct {
		Mode, Job, BootID, Kernel, ManifestSHA256, Verdict string
		Provider                                           map[string]struct {
			Verdict string `json:"verdict"`
		}
		CleanupVerified bool `json:"cleanup_verified"`
	}
	var doc map[string]any
	if err = json.Unmarshal(b, &doc); err != nil {
		return fail(err)
	}
	r.Mesa = &api.MesaResult{Mode: api.MesaStaged, Semantics: mesa.Semantics, Provider: map[string]string{}, Evidence: doc}
	raw.Mode, _ = doc["mode"].(string)
	raw.Job, _ = doc["job"].(string)
	raw.BootID, _ = doc["boot_id"].(string)
	raw.Kernel, _ = doc["kernel"].(string)
	raw.ManifestSHA256, _ = doc["manifest_sha256"].(string)
	raw.Verdict, _ = doc["verdict"].(string)
	raw.CleanupVerified, _ = doc["cleanup_verified"].(bool)
	r.Mesa.Job = raw.Job
	r.Mesa.BootID = raw.BootID
	r.Mesa.Kernel = raw.Kernel
	r.Mesa.ManifestSHA256 = raw.ManifestSHA256
	r.Mesa.CleanupVerified = raw.CleanupVerified
	r.Mesa.Verdict = raw.Verdict
	var m mesa.Manifest
	mb, e := mesa.Read(filepath.Join(prefix, "manifest.json"), 8<<20)
	if e != nil || json.Unmarshal(mb, &m) != nil {
		return fail(errors.New("staged manifest unreadable"))
	}
	for _, p := range m.Packages {
		r.Mesa.Packages = append(r.Mesa.Packages, p.MesaPackage)
	}
	if providers, ok := doc["provider"].(map[string]any); ok {
		for apiName, v := range providers {
			if v, ok := v.(map[string]any); ok {
				r.Mesa.Provider[apiName], _ = v["verdict"].(string)
			}
		}
	}
	if runErr != nil || tctx.Err() != nil {
		return fail(fmt.Errorf("Mesa supervisor failed/canceled: %v", runErr))
	}
	boot, kernel, _ := l.Identity()
	if raw.Mode != api.MesaStaged || raw.Job != job || raw.BootID != boot || raw.Kernel != kernel || raw.Verdict != "PASS" || !raw.CleanupVerified || r.Mesa.Provider["gl"] != "NATIVE_STAGED" || r.Mesa.Provider["vulkan"] != "NATIVE_STAGED" {
		return fail(errors.New("Mesa provider/identity/cleanup incomplete"))
	}
	r.Passed = true
	r.ExitCode = 0
	return r
}

// Cleanup only agent-owned per-job prefixes, never a broad disk sweep. A live
// owned cgroup keeps the prefix for later recovery rather than unlinking it.
func (l *Linux) cleanupMesa(job string, all bool) error {
	root := l.mesaParent()
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_, _, cmd := l.Identity()
	current := jobTag(cmd)
	for _, entry := range entries {
		j := entry.Name()
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || j == current || (!all && j != job) {
			continue
		}
		prefix := filepath.Join(root, j)
		b, e := mesa.Read(filepath.Join(prefix, "owner.json"), 4096)
		if e != nil {
			continue
		}
		var o struct {
			Schema int    `json:"schema"`
			Job    string `json:"job"`
			Kind   string `json:"kind"`
		}
		if json.Unmarshal(b, &o) != nil || o.Schema != mesa.Schema || o.Job != j || o.Kind != "mesa-staged" {
			continue
		}
		if err := mesaGroupsEmpty("/sys/fs/cgroup/system.slice", j); err != nil {
			return err
		}
		if err = os.RemoveAll(prefix); err != nil {
			return err
		}
	}
	return nil
}

// Include nested child cgroups: an empty unit leader does not establish that
// descendants have exited. Any unreadable membership keeps the prefix.
func mesaGroupsEmpty(root, job string) error {
	groups, err := filepath.Glob(filepath.Join(root, "maclab-mesa-"+job+"-*.service"))
	if err != nil {
		return err
	}
	for _, group := range groups {
		err = filepath.WalkDir(group, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("unexpected Mesa cgroup symlink; preserving prefix")
			}
			if d.IsDir() {
				b, e := os.ReadFile(filepath.Join(path, "cgroup.procs"))
				if e != nil {
					return e
				}
				if len(strings.Fields(string(b))) != 0 {
					return errors.New("Mesa prefix still has live cgroup; preserving it")
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

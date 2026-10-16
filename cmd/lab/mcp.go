package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

const mcpInstructions = `Mac test lab: boot kernels on real Apple Silicon Macs running Omarchy and run tests on them.
Flow: lab_devices -> (optionally lab_lease) -> lab_run with source=<GitHub URL> (or a kernel artifact path) -> lab_wait until done -> read lab_job / lab_log / lab_screenshot.
Each job stages the kernel beside the known-good one, boots it exactly once, runs the tests, collects logs, and puts the Mac back on its known-good kernel.
If a Mac crashes or hangs, the lab recovers it (panic reboot, watchdog, out-of-band reset) or tells a human exactly what to press; a device in state needs_hands is waiting for a person, so do not retry, tell the user.
Kernels are best given as source: a GitHub branch/commit/PR URL. The lab builds it on its builder with the target Mac's own config and reuses identical builds. Use lab_exec instead of ssh to run commands on a Mac.`

func serveMCP(ctx context.Context) error {
	c, err := client.Load()
	if err != nil {
		return err
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "maclab", Version: "0.1.0"}, &mcp.ServerOptions{Instructions: mcpInstructions})
	who := "mcp:" + holder()

	text := func(v any) *mcp.CallToolResult {
		var t string
		if s, ok := v.(string); ok {
			t = s
		} else {
			b, _ := json.MarshalIndent(v, "", "  ")
			t = string(b)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: t}}}
	}

	type none struct{}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_devices", Description: "List test Macs: state (ready, busy, recovering, needs_hands, offline, new, left), recovery tier, running kernel, lease, and any action a human must take."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, any, error) {
			d, err := c.Devices(ctx)
			return text(d), nil, err
		})

	type devArg struct {
		Device string `json:"device" jsonschema:"device name, e.g. m1air"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_device", Description: "Details for one Mac, including preflight problems and recent kernel events."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a devArg) (*mcp.CallToolResult, any, error) {
			d, err := c.Device(ctx, a.Device)
			return text(d), nil, err
		})

	type runArg struct {
		Device            string   `json:"device"`
		Source            string   `json:"source,omitempty" jsonschema:"build and boot this: a GitHub URL of a repo, branch (/tree/...), commit or pull request, or git URL#ref. Built with the Mac's own config; reused if built before"`
		KernelPath        string   `json:"kernel_path,omitempty" jsonschema:"local path of a kernel artifact to upload; omit to reboot on the current kernel"`
		KernelSHA256      string   `json:"kernel_sha256,omitempty" jsonschema:"sha256 of an artifact already uploaded"`
		BuildID           string   `json:"build_id,omitempty" jsonschema:"boot the kernel of a finished build, e.g. the linux package of a lab_package build"`
		Cmdline           string   `json:"cmdline,omitempty" jsonschema:"extra kernel command line arguments, appended to the base"`
		CmdlineBase       string   `json:"cmdline_base,omitempty" jsonschema:"cmdline the test boot starts from: known-good (default), default (the distro's stock KERNEL_CMDLINE[default]), or a literal cmdline with root="`
		CmdlineStrip      []string `json:"cmdline_strip,omitempty" jsonschema:"globs of base parameters to drop, e.g. asahi.* apple_t6030_display.*"`
		VerboseBoot       bool     `json:"verbose_boot,omitempty" jsonschema:"boot with loglevel=7 and without quiet/splash; by default a test boot keeps the Mac's own (always verbose with a serial console)"`
		InstalledManifest string   `json:"installed_manifest,omitempty" jsonschema:"sha256 of a frozen expected manifest: boot the INSTALLED release through its installer entry, check identity, compare with the frozen pre-install baseline, never promote (needs a lease)"`
		Tests             []string `json:"tests,omitempty" jsonschema:"builtin tests: boot-health (always run), gui-smoke, gui-terminal, suspend-devices"`
		GUITests          []string `json:"gui_tests,omitempty" jsonschema:"builtin tests to run inside the GUI user's Hyprland session: gui-smoke, gui-terminal"`
		Scripts           []string `json:"scripts,omitempty" jsonschema:"local paths of shell scripts to run as tests (as root); write outputs to $MACLAB_OUT"`
		GUIScripts        []string `json:"gui_scripts,omitempty" jsonschema:"local paths of shell scripts to run in the Wayland session"`
		BootTimeoutSec    int      `json:"boot_timeout_sec,omitempty"`
		ScriptTimeoutSec  int      `json:"script_timeout_sec,omitempty" jsonschema:"time each script test may run (default 300, at most 14400), e.g. 5400 for a hands-on session that waits for a person"`
		OMTAllow          []string `json:"omt_allow,omitempty" jsonschema:"omarchy-m-test checks this kernel is expected to fail; hardware.drivers:<compatible> allows one unbound node"`
		Publish           bool     `json:"publish,omitempty" jsonschema:"publish the omarchy-m-test report to omarchy-m-testing.org; only runs on the Mac's known-good kernel qualify"`
		WaitSec           int      `json:"wait_sec,omitempty" jsonschema:"wait up to this long for the result (max 900); 0 returns once queued"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_run", Description: "Boot a kernel on a Mac once and run tests. Give source (a GitHub URL) to build it first, or a kernel artifact. Returns the job; use lab_wait for the result."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a runArg) (*mcp.CallToolResult, any, error) {
			spec := api.JobSpec{Device: a.Device, Kernel: a.KernelSHA256, Source: a.Source, Cmdline: a.Cmdline, BootTimeoutSec: a.BootTimeoutSec, Holder: who, Publish: a.Publish, OMTAllow: a.OMTAllow,
				CmdlineBase: a.CmdlineBase, CmdlineStrip: a.CmdlineStrip, VerboseBoot: a.VerboseBoot, InstalledManifest: a.InstalledManifest}
			if a.KernelPath != "" {
				sha, err := c.Upload(ctx, a.KernelPath)
				if err != nil {
					return nil, nil, err
				}
				spec.Kernel = sha
			}
			if a.BuildID != "" {
				b, err := c.GetBuild(ctx, a.BuildID)
				if err != nil {
					return nil, nil, err
				}
				if b.State != api.BuildDone || b.Artifact == "" {
					return nil, nil, fmt.Errorf("build %s is %s and has no kernel to boot", b.ID, b.State)
				}
				spec.Kernel = b.Artifact
			}
			for _, t := range a.Tests {
				spec.Tests = append(spec.Tests, api.TestSpec{Name: t, Builtin: t})
			}
			for _, t := range a.GUITests {
				spec.Tests = append(spec.Tests, api.TestSpec{Name: t, Builtin: t, GUI: true})
			}
			for i, list := range [][]string{a.Scripts, a.GUIScripts} {
				for _, p := range list {
					sha, err := c.Upload(ctx, p)
					if err != nil {
						return nil, nil, err
					}
					spec.Tests = append(spec.Tests, api.TestSpec{Name: strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)), Script: sha, GUI: i == 1, TimeoutSec: min(a.ScriptTimeoutSec, 14400)})
				}
			}
			return submitAndWait(ctx, c, spec, a.WaitSec, text)
		})

	mcp.AddTool(s, &mcp.Tool{Name: "lab_publish", Description: "Upload a finished job's omarchy-m-test report to omarchy-m-testing.org. Only runs on the Mac's known-good (packaged) kernel qualify; lab kernels are refused because the site would file them under the wrong kernel."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct {
			JobID string `json:"job_id"`
		}) (*mcp.CallToolResult, any, error) {
			url, err := c.Publish(ctx, a.JobID)
			return text(url), nil, err
		})

	type waitDev struct {
		Device  string `json:"device"`
		WaitSec int    `json:"wait_sec,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_baseline", Description: "Baseline a newly enrolled Mac: proves the one-shot boot selects and clears, records baseline dmesg. Required once before other jobs."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a waitDev) (*mcp.CallToolResult, any, error) {
			return submitAndWait(ctx, c, api.JobSpec{Device: a.Device, Baseline: true, Holder: who}, a.WaitSec, text)
		})
	mcp.AddTool(s, &mcp.Tool{Name: "lab_crashtest", Description: "Deliberately panic a Mac and verify it recovers by itself."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a waitDev) (*mcp.CallToolResult, any, error) {
			return submitAndWait(ctx, c, api.JobSpec{Device: a.Device, Crash: "panic", Holder: who}, a.WaitSec, text)
		})

	type jobArg struct {
		JobID string `json:"job_id"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_job", Description: "A job's state, outcome, summary, boot and test results, recovery steps, new kernel errors vs baseline, and log file names."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a jobArg) (*mcp.CallToolResult, any, error) {
			j, err := c.Job(ctx, a.JobID)
			return text(j), nil, err
		})
	type waitArg struct {
		JobID      string `json:"job_id"`
		TimeoutSec int    `json:"timeout_sec,omitempty" jsonschema:"max 900, default 600"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_wait", Description: "Wait for a job to finish (or the timeout) and return it. Call again if state is not done."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a waitArg) (*mcp.CallToolResult, any, error) {
			t := a.TimeoutSec
			if t <= 0 || t > 900 {
				t = 600
			}
			j, err := c.Wait(ctx, a.JobID, time.Duration(t)*time.Second)
			return text(j), nil, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "lab_cancel", Description: "Cancel a job. A running job stops and the Mac is restored to its known-good kernel."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a jobArg) (*mcp.CallToolResult, any, error) {
			out, err := c.Cancel(ctx, a.JobID)
			return text(out), nil, err
		})
	type retryArg struct {
		JobID   string `json:"job_id"`
		WaitSec int    `json:"wait_sec,omitempty" jsonschema:"wait up to this long for the result (max 900); 0 returns once queued"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_retry", Description: "Run a finished job again as a new job: same Mac, kernel (for a source job, the same commit), tests and cmdline. A stage_failed job's summary says why, and whether labd already tried it again (up to 3 attempts); retry it once that cause is fixed. Returns the new job; use lab_wait for the result."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a retryArg) (*mcp.CallToolResult, any, error) {
			j, err := c.Retry(ctx, a.JobID, who)
			if err != nil {
				return nil, nil, err
			}
			return waitJob(ctx, c, j, a.WaitSec, text)
		})
	type jobsArg struct {
		Device string `json:"device,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_jobs", Description: "Recent jobs, newest first."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a jobsArg) (*mcp.CallToolResult, any, error) {
			jobs, err := c.Jobs(ctx, a.Device, 20)
			if err != nil {
				return nil, nil, err
			}
			var b strings.Builder
			for _, j := range jobs {
				fmt.Fprintf(&b, "%s %s %s %s: %s\n", j.ID, j.Spec.Device, j.State, j.Outcome, j.Summary)
			}
			return text(b.String()), nil, nil
		})

	type gateArg struct {
		Kernel     string   `json:"kernel" jsonschema:"the candidate kernel: a build id, or its artifact sha256 or a prefix of it"`
		Families   []string `json:"families,omitempty" jsonschema:"chip families that must pass (default all: m1, m1-pro, m2, m2-pro, m3, m3-pro)"`
		Volunteers bool     `json:"volunteers,omitempty" jsonschema:"count volunteers' Macs (enrolled with ./volunteer, agents the lab doesn't control) too; by default their runs are listed under not_counted"`
		Exclude    []string `json:"exclude,omitempty" jsonschema:"job ids of this kernel to set aside for this report only, e.g. a failure the lab caused (an access point outage reads as crashed_or_hung); the report lists them in excluded, and in not_counted marked excluded. Nothing is kept: lab_exclude sets a job aside for every report"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_gate", Description: "Release gate: whether a kernel passed on real hardware for every required chip family, from each Mac's plain runs on it: the known-good cmdline, at least the tests every job on that Mac runs, no omt_allow, and, where the Mac runs omarchy-m-test, a comparison with its known-good run (a pass with no OMT reference is not counted). Each job is judged by its Mac as it was when the job was submitted (chip family, volunteer, omarchy-m-test); a Mac labd no longer has (lab forget) is listed as device gone, not counted. A run with a changed cmdline counts neither way; one that tested less counts only if it failed. Canceled, infra_error and crash-test runs, and tests_failed runs whose failed tests never started (bash couldn't open the test script: exit 126 Permission denied or 127 No such file or directory for test-<name>.sh), say nothing; a test that ran and exited 126 or 127 itself is a failure. A job canceled after its kernel had already failed keeps that failure as its outcome. A Mac fails if it failed, passes if it passed, and is flaky (not a pass) if it did both, so a retry's pass doesn't hide a failure (retry_of links a retry to the job it retries); a Mac that couldn't stage the kernel counts only when it has neither. A family's result is one of pass, fail, flaky, stage_failed or untested: fail if any Mac failed, flaky if any is flaky, pass if one passed, stage_failed if its only results are Macs that couldn't stage the kernel (each such run gives the job's reason; run it again once that's fixed), and untested if none has a result. Anything checking results for \"fail\" must treat \"flaky\" as not passing too. Runs that don't count are in each family's not_counted with the reason (and the report's not_counted when no family is known); volunteers' Macs are there too unless volunteers is set, and excluded jobs, marked excluded. Jobs set aside with lab_exclude are excluded in every report: exclusions lists them with who set each aside, why and when, and their not_counted runs carry the same as exclusion. result is pass only when every required family passed."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a gateArg) (*mcp.CallToolResult, any, error) {
			r, err := c.Gate(ctx, a.Kernel, a.Families, a.Volunteers, a.Exclude)
			return text(r), nil, err
		})

	type excludeArg struct {
		JobID  string `json:"job_id"`
		Reason string `json:"reason,omitempty" jsonschema:"why the job says nothing about its kernel, e.g. the access point went down mid-test; required unless clear"`
		Clear  bool   `json:"clear,omitempty" jsonschema:"count the job in lab_gate again"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_exclude", Description: "Set a finished job aside in every lab_gate report until cleared, say a failure the lab caused (an access point outage reads as crashed_or_hung, which would keep its family flaky for good). Needs a lab admin and a reason; the gate lists the job in exclusions with who set it aside, why and when. Only for a failure that isn't the kernel's: never to make a gate pass. clear counts the job again. Returns the job."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a excludeArg) (*mcp.CallToolResult, any, error) {
			if a.Clear {
				j, err := c.ClearExclusion(ctx, a.JobID)
				return text(j), nil, err
			}
			if strings.TrimSpace(a.Reason) == "" {
				return nil, nil, errors.New("give a reason: why the job says nothing about its kernel")
			}
			j, err := c.Exclude(ctx, a.JobID, a.Reason, who)
			return text(j), nil, err
		})

	type logArg struct {
		JobID     string `json:"job_id"`
		File      string `json:"file" jsonschema:"a name from the job's logs or test files, e.g. serial.log, boot0/kernel.txt, prevboot/journal.txt, test-boot-health/log.txt"`
		TailLines int    `json:"tail_lines,omitempty" jsonschema:"only the last N lines (default 400)"`
		Grep      string `json:"grep,omitempty" jsonschema:"only lines containing this substring"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_log", Description: "Read a text log from a job."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a logArg) (*mcp.CallToolResult, any, error) {
			b, err := c.File(ctx, a.JobID, a.File)
			if err != nil {
				return nil, nil, err
			}
			lines := strings.Split(string(b), "\n")
			if a.Grep != "" {
				var keep []string
				for _, l := range lines {
					if strings.Contains(l, a.Grep) {
						keep = append(keep, l)
					}
				}
				lines = keep
			}
			n := a.TailLines
			if n <= 0 {
				n = 400
			}
			if len(lines) > n {
				lines = append([]string{fmt.Sprintf("[... %d earlier lines]", len(lines)-n)}, lines[len(lines)-n:]...)
			}
			return text(strings.Join(lines, "\n")), nil, nil
		})
	type shotArg struct {
		JobID string `json:"job_id"`
		File  string `json:"file" jsonschema:"e.g. test-gui-smoke/screenshot.png"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_screenshot", Description: "View a PNG a GUI test saved."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a shotArg) (*mcp.CallToolResult, any, error) {
			b, err := c.File(ctx, a.JobID, a.File)
			if err != nil {
				return nil, nil, err
			}
			mime := "image/png"
			if e := path.Ext(a.File); e == ".jpg" || e == ".jpeg" {
				mime = "image/jpeg"
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.ImageContent{Data: b, MIMEType: mime}}}, nil, nil
		})

	type leaseArg struct {
		Device     string `json:"device"`
		TTLMinutes int    `json:"ttl_minutes,omitempty" jsonschema:"default 60"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_lease", Description: "Reserve a Mac so only your jobs run on it."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a leaseArg) (*mcp.CallToolResult, any, error) {
			ttl := a.TTLMinutes
			if ttl <= 0 {
				ttl = 60
			}
			l, err := c.Lease(ctx, a.Device, who, time.Duration(ttl)*time.Minute)
			return text(l), nil, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "lab_release", Description: "Release your lease on a Mac."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a devArg) (*mcp.CallToolResult, any, error) {
			return text("released"), nil, c.Release(ctx, a.Device, who)
		})
	mcp.AddTool(s, &mcp.Tool{Name: "lab_reset", Description: "Run the recovery ladder on an idle Mac that is wedged or offline (soft reboot, hard reset, then ask a human). A Mac that left the lab (lab-agent uninstall) goes back in it first."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a devArg) (*mcp.CallToolResult, any, error) {
			out, err := c.Reset(ctx, a.Device, who)
			return text(out), nil, err
		})
	type serialArg struct {
		Device string `json:"device"`
		Lines  int    `json:"lines,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_serial", Description: "Recent serial console lines from a Mac with an out-of-band controller."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a serialArg) (*mcp.CallToolResult, any, error) {
			n := a.Lines
			if n <= 0 {
				n = 200
			}
			out, err := c.Serial(ctx, a.Device, n)
			return text(out), nil, err
		})

	type buildArg struct {
		Source     string `json:"source" jsonschema:"GitHub URL of a repo, branch, commit or pull request (or git URL#ref)"`
		Device     string `json:"device,omitempty" jsonschema:"build with this Mac's running kernel config"`
		ConfigPath string `json:"config_path,omitempty" jsonschema:"or: local path of a .config to build with; the result boots on every Mac"`
		Force      bool   `json:"force,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_build", Description: "Build a kernel from source without booting it. Identical builds (same commit and config) are reused. Returns the build; poll lab_build_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a buildArg) (*mcp.CallToolResult, any, error) {
			req := api.BuildRequest{Source: a.Source, Device: a.Device, Force: a.Force}
			if a.ConfigPath != "" {
				sha, err := c.Upload(ctx, a.ConfigPath)
				if err != nil {
					return nil, nil, err
				}
				req.Config, req.ConfigName, req.Device = sha, filepath.Base(a.ConfigPath), ""
			}
			b, err := c.Build(ctx, req)
			return text(b), nil, err
		})
	type packageArg struct {
		RecipeDir string `json:"recipe_dir" jsonschema:"local directory holding the PKGBUILD and its local sources (config, patches, rust-toolchain.toml...)"`
		Commit    string `json:"commit,omitempty" jsonschema:"point the recipe's _commit at this GitHub commit, branch or PR URL; source checksums are refreshed"`
		Pkgrel    string `json:"pkgrel,omitempty" jsonschema:"set pkgrel, e.g. 11.14"`
		Force     bool   `json:"force,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_package", Description: "Build release packages (e.g. linux-aurora and linux-aurora-headers) from a PKGBUILD recipe with makepkg on Arch Linux ARM, the way the release machine does. Takes 15-30 minutes. Poll lab_build_status; its files list names and sha256s every package. Boot the kernel package once with lab_run build_id; download with `lab build-get <build> -o dir`."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a packageArg) (*mcp.CallToolResult, any, error) {
			sha, _, err := uploadRecipe(ctx, c, a.RecipeDir)
			if err != nil {
				return nil, nil, err
			}
			abs, _ := filepath.Abs(a.RecipeDir)
			b, err := c.Build(ctx, api.BuildRequest{Recipe: sha, RecipeDir: abs, Source: a.Commit, Pkgrel: a.Pkgrel, Force: a.Force})
			return text(b), nil, err
		})
	type buildID struct {
		BuildID   string `json:"build_id"`
		TailLines int    `json:"tail_lines,omitempty" jsonschema:"include the last N log lines (default 30)"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_build_status", Description: "A build's state, stage, progress, ETA and the tail of its log."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a buildID) (*mcp.CallToolResult, any, error) {
			b, err := c.GetBuild(ctx, a.BuildID)
			if err != nil {
				return nil, nil, err
			}
			var log strings.Builder
			c.BuildLog(ctx, a.BuildID, false, &log)
			lines := strings.Split(strings.TrimRight(log.String(), "\n"), "\n")
			n := a.TailLines
			if n <= 0 {
				n = 30
			}
			if len(lines) > n {
				lines = lines[len(lines)-n:]
			}
			j, _ := json.MarshalIndent(b, "", "  ")
			return text(string(j) + "\n\nlog tail:\n" + strings.Join(lines, "\n")), nil, nil
		})
	type execArg struct {
		Device     string `json:"device"`
		Command    string `json:"command" jsonschema:"shell command, run as root with bash -c"`
		TimeoutSec int    `json:"timeout_sec,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lab_exec", Description: "Run a shell command on a Mac as root and get stdout, stderr and the exit code. Use this instead of ssh. It goes through the lab agent, or the serial console when the Mac's network is down."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a execArg) (*mcp.CallToolResult, any, error) {
			r, err := c.Exec(ctx, a.Device, api.ExecArgs{Command: a.Command, TimeoutSec: a.TimeoutSec})
			return text(r), nil, err
		})

	return s.Run(ctx, &mcp.StdioTransport{})
}

func submitAndWait(ctx context.Context, c *client.Client, spec api.JobSpec, waitSec int, text func(any) *mcp.CallToolResult) (*mcp.CallToolResult, any, error) {
	j, err := c.Submit(ctx, spec)
	if err != nil {
		return nil, nil, err
	}
	return waitJob(ctx, c, j, waitSec, text)
}

// waitJob waits up to waitSec (at most 900) for a job to finish, and returns it.
func waitJob(ctx context.Context, c *client.Client, j *api.Job, waitSec int, text func(any) *mcp.CallToolResult) (*mcp.CallToolResult, any, error) {
	var err error
	if waitSec > 0 {
		if waitSec > 900 {
			waitSec = 900
		}
		if j, err = c.Wait(ctx, j.ID, time.Duration(waitSec)*time.Second); err != nil {
			return nil, nil, err
		}
	}
	return text(j), nil, nil
}

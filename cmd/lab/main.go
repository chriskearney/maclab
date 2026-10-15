// Command lab is the CLI for the Mac test lab: enroll Macs, run kernels and
// tests on them, and see what state they are in. `lab mcp` serves the same
// operations to AI agents over MCP.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

const usage = `lab: run kernels and tests on Omarchy Macs

  lab login <labd-url> <admin-token>
  lab status [device]                 devices, what they're doing, and anything a human must do
  lab enroll <name> [--label "MacBook Air M1, left desk"] [--model laptop|desktop]
  lab device <name> [--label ..] [--model ..] [--oob-url http://m3:7780 --oob-token ..] [--no-oob]
  lab baseline <device>               prove the one-shot boot works; required once per Mac
  lab build <github-url> --device <mac> | --config <file>   build a kernel from a repo, branch, commit or PR URL (reused if built before)
  lab package <recipe-dir> [--commit <github-url>] [--pkgrel 11.14] [-o dir]
                                      build release packages from a PKGBUILD recipe with makepkg, as the release machine does
  lab builds | lab build-log <build> [-f] | lab build-get <build> [-o dir]
  lab exec <device> <command...>      run a command on a Mac as root (agent, or serial if its network is down)
  lab run <device> [--kernel <file|sha256|build-id|github-url>] [--cmdline ".."] [--cmdline-base known-good|default|"<cmdline>"] [--cmdline-strip "glob .."] [--verbose-boot] [--test boot-health] [--gui-test gui-smoke]
                   [--script t.sh] [--gui-script t.sh] [--boot-timeout 240] [--script-timeout 90m] [--publish] [--omt-allow ids] [--no-wait]
  lab crashtest <device>              deliberately panic the Mac and check it recovers by itself
  lab pack --build <O= dir> [-o kernel.tar.zst]    package a kernel build for lab run
  lab jobs [device] | lab job <id> | lab wait <id> | lab cancel <id> | lab logs <id> [file]
  lab publish <job>                   upload a known-good run's omarchy-m-test report to omarchy-m-testing.org
  lab lease <device> [--ttl 1h] | lab release <device>
  lab forget <device>                 take a Mac out of the lab (after lab-agent uninstall); its jobs stay
  lab installed freeze-manifest --release R <manifest.json> <payload.sha256> [--approved-by a,b]
  lab installed freeze-entry <device> --release R    freeze the installer's boot entry, after the install
  lab installed promote <device> --release R --job <id> --accepted-by <who>
                                      references + known-good, labd's and the agent's (Mac on that kernel, agent 0.7.3+)
  lab installed status --release R                   the frozen files of a release
  lab reset <device>                  run the recovery ladder on an idle Mac by hand
  lab shell <device>                  shell over the serial link: works with the Mac's network down (Ctrl-] exits)
  lab serial <device> [-n 100] | lab oob <device>
  lab upload <file>
  lab mcp                             MCP server on stdio, for AI agents
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx := context.Background()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "login":
		err = login(args)
	case "pack":
		err = pack(args)
	case "mcp":
		err = serveMCP(ctx)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		var c *client.Client
		if c, err = client.Load(); err == nil {
			err = dispatch(ctx, c, cmd, args)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
		os.Exit(1)
	}
}

func holder() string {
	if h := os.Getenv("MACLAB_HOLDER"); h != "" {
		return h
	}
	u, _ := user.Current()
	h, _ := os.Hostname()
	name := "someone"
	if u != nil {
		name = u.Username
	}
	return name + "@" + h
}

// parse lets flags come after positional arguments, as in `lab run m1air --kernel k.tar`.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for len(args) > 0 {
		fs.Parse(args)
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	return pos
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func need(pos []string, n int, what string) error {
	if len(pos) < n {
		return fmt.Errorf("usage: %s", what)
	}
	return nil
}

func dispatch(ctx context.Context, c *client.Client, cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "status", "devices":
		pos := parse(fs, args)
		if len(pos) > 0 {
			return showDevice(ctx, c, pos[0])
		}
		return showDevices(ctx, c)

	case "enroll":
		label := fs.String("label", "", "where the Mac physically is, for power-cycle instructions")
		model := fs.String("model", api.ModelLaptop, "laptop or desktop")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab enroll <name>"); err != nil {
			return err
		}
		t, err := c.EnrollToken(ctx, api.EnrollTokenRequest{Name: pos[0], Label: *label, Model: *model})
		if err != nil {
			return err
		}
		fmt.Printf("Enrollment token for %s (one use, expires %s):\n\n  %s\n\n", pos[0], t.Expires.Format(time.DateTime), t.Token)
		fmt.Printf("On the Mac, copy lab-agent over and run:\n\n  sudo ./lab-agent setup --server %s --token %s [--gui-user <you>]\n\n", c.URL, t.Token)
		fmt.Printf("Then: lab baseline %s\n", pos[0])
		return nil

	case "device":
		label := fs.String("label", "", "")
		model := fs.String("model", "", "")
		oobURL := fs.String("oob-url", "", "oobd URL for the controller host attached to this Mac")
		oobToken := fs.String("oob-token", "", "")
		noOOB := fs.Bool("no-oob", false, "detach the out-of-band controller")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab device <name> [flags]"); err != nil {
			return err
		}
		var p api.DevicePatch
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "label":
				p.Label = label
			case "model":
				p.Model = model
			}
		})
		if *oobURL != "" {
			p.OOB = &api.OOBConfig{Driver: "oobd", URL: *oobURL, Token: *oobToken}
		}
		p.NoOOB = *noOOB
		if _, err := c.PatchDevice(ctx, pos[0], p); err != nil {
			return err
		}
		return showDevice(ctx, c, pos[0])

	case "baseline":
		noWait := fs.Bool("no-wait", false, "")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab baseline <device>"); err != nil {
			return err
		}
		return submit(ctx, c, api.JobSpec{Device: pos[0], Baseline: true, Holder: holder()}, *noWait)

	case "crashtest":
		noWait := fs.Bool("no-wait", false, "")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab crashtest <device>"); err != nil {
			return err
		}
		return submit(ctx, c, api.JobSpec{Device: pos[0], Crash: "panic", Holder: holder()}, *noWait)

	case "run":
		kernel := fs.String("kernel", "", "kernel artifact: a file to upload, or a sha256 already uploaded")
		cmdline := fs.String("cmdline", "", "extra kernel arguments, appended to the base")
		runConfig := fs.String("config", "", "with a source URL --kernel: build with this .config (file or uploaded sha256) instead of the Mac's own")
		cmdlineBase := fs.String("cmdline-base", "", `cmdline the test boot starts from: known-good (default), "default" (the distro's stock KERNEL_CMDLINE[default]), or a literal cmdline with root=`)
		cmdlineStrip := fs.String("cmdline-strip", "", `globs of base parameters to drop, space- or comma-separated, e.g. 'asahi.* apple_t6030_display.* dcpext_*'`)
		verboseBoot := fs.Bool("verbose-boot", false, "boot with loglevel=7 and without quiet/splash, to watch the console (default: keep the Mac's own; always verbose with a serial console)")
		bootTimeout := fs.Int("boot-timeout", 0, "seconds to wait for the Mac to come back (default 240)")
		noWait := fs.Bool("no-wait", false, "queue and return")
		scriptTimeout := fs.Duration("script-timeout", 0, "time each --script/--gui-script test may run, e.g. 90m for a hands-on session (default 5m, at most 4h)")
		omtAllow := fs.String("omt-allow", "", "omarchy-m-test checks this kernel is expected to fail, comma-separated (hardware.drivers:<compatible> for one unbound node)")
		publish := fs.Bool("publish", false, "publish the omarchy-m-test report to omarchy-m-testing.org (known-good kernel runs only)")
		installedMan := fs.String("installed", "", "boot the INSTALLED release through its installer entry and check it against a frozen expected manifest (file or sha256); see `lab installed`")
		var tests, guiTests, scripts, guiScripts multi
		fs.Var(&tests, "test", "builtin test to run (repeatable)")
		fs.Var(&guiTests, "gui-test", "builtin GUI test to run in the Wayland session (repeatable)")
		fs.Var(&scripts, "script", "shell script test to upload and run (repeatable)")
		fs.Var(&guiScripts, "gui-script", "shell script test to run in the Wayland session (repeatable)")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab run <device> [flags]"); err != nil {
			return err
		}
		spec := api.JobSpec{Device: pos[0], Cmdline: *cmdline, BootTimeoutSec: *bootTimeout, Holder: holder(), Publish: *publish}
		spec.OMTAllow = splitAllow(*omtAllow)
		spec.CmdlineBase = *cmdlineBase
		spec.CmdlineStrip = strings.FieldsFunc(*cmdlineStrip, func(r rune) bool { return r == ',' || r == ' ' })
		spec.VerboseBoot = *verboseBoot
		if *installedMan != "" {
			sha, err := manifestSHA(*installedMan)
			if err != nil {
				return err
			}
			spec.InstalledManifest = sha
		}
		if *scriptTimeout > 4*time.Hour {
			return fmt.Errorf("--script-timeout %s: at most 4h", *scriptTimeout)
		}
		switch {
		case isSource(*kernel):
			spec.Source = *kernel
			if *runConfig != "" {
				sha, err := artifact(ctx, c, *runConfig)
				if err != nil {
					return err
				}
				spec.Config = sha
			}
		case reBuildID.MatchString(*kernel):
			b, err := c.GetBuild(ctx, *kernel)
			if err != nil {
				return err
			}
			if b.State != api.BuildDone || b.Artifact == "" {
				return fmt.Errorf("build %s is %s and has no kernel to boot", b.ID, b.State)
			}
			spec.Kernel = b.Artifact
		case *kernel != "":
			sha, err := artifact(ctx, c, *kernel)
			if err != nil {
				return err
			}
			spec.Kernel = sha
		}
		for _, t := range tests {
			spec.Tests = append(spec.Tests, api.TestSpec{Name: t, Builtin: t})
		}
		for _, t := range guiTests {
			spec.Tests = append(spec.Tests, api.TestSpec{Name: t, Builtin: t, GUI: true})
		}
		for i, list := range [][]string{scripts, guiScripts} {
			for _, p := range list {
				sha, err := c.Upload(ctx, p)
				if err != nil {
					return err
				}
				name := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
				spec.Tests = append(spec.Tests, api.TestSpec{Name: name, Script: sha, GUI: i == 1, TimeoutSec: int(scriptTimeout.Seconds())})
			}
		}
		return submit(ctx, c, spec, *noWait)

	case "build":
		dev := fs.String("device", "", "build with this Mac's running config")
		config := fs.String("config", "", "build with this .config (a file to upload, or an uploaded sha256) instead of a Mac's; one build boots on every Mac")
		force := fs.Bool("force", false, "rebuild even if this exact kernel was built before")
		noWait := fs.Bool("no-wait", false, "")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab build <github-url> --device <mac> | --config <file>"); err != nil {
			return err
		}
		req := api.BuildRequest{Source: pos[0], Device: *dev, Force: *force}
		if *config != "" {
			if *dev != "" {
				return fmt.Errorf("give --device or --config, not both")
			}
			sha, err := artifact(ctx, c, *config)
			if err != nil {
				return err
			}
			req.Config, req.ConfigName = sha, filepath.Base(*config)
		}
		b, err := c.Build(ctx, req)
		if err != nil {
			return err
		}
		fmt.Printf("build %s: %s @ %s (%s)\n", b.ID, b.Source.Repo, b.Source.SHA[:12], b.State)
		return followBuild(ctx, c, b, *noWait, "")

	case "package":
		commit := fs.String("commit", "", "point the recipe's _commit at this GitHub commit, branch or PR URL (checksums are refreshed)")
		pkgrel := fs.String("pkgrel", "", "set pkgrel, e.g. 11.14")
		force := fs.Bool("force", false, "rebuild even if this exact recipe was built before")
		noWait := fs.Bool("no-wait", false, "")
		out := fs.String("o", "", "download the packages and the PKGBUILD as built into this directory")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab package <recipe-dir> [--commit <url>] [--pkgrel N] [-o dir]"); err != nil {
			return err
		}
		sha, names, err := uploadRecipe(ctx, c, pos[0])
		if err != nil {
			return err
		}
		abs, _ := filepath.Abs(pos[0])
		b, err := c.Build(ctx, api.BuildRequest{Recipe: sha, RecipeDir: abs, Source: *commit, Pkgrel: *pkgrel, Force: *force})
		if err != nil {
			return err
		}
		fmt.Printf("build %s: packages from %s (%s) (%s)\n", b.ID, pos[0], strings.Join(names, ", "), b.State)
		if b.Source.SHA != "" {
			fmt.Printf("  _commit -> %s @ %s\n", b.Source.Repo, b.Source.SHA)
		}
		return followBuild(ctx, c, b, *noWait, *out)

	case "build-get":
		out := fs.String("o", ".", "directory")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab build-get <build> [-o dir]"); err != nil {
			return err
		}
		b, err := c.GetBuild(ctx, pos[0])
		if err != nil {
			return err
		}
		return getBuildFiles(ctx, c, b, *out)

	case "installed":
		return installedCmd(ctx, c, args)

	case "builds":
		l, err := c.Builds(ctx, 20)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "BUILD\tSTATE\tSOURCE\tCOMMIT\tRELEASE\tTIME")
		for _, b := range l {
			src, commit := shortSrc(b.Source), ""
			if b.Source.SHA != "" {
				commit = b.Source.SHA[:12]
			}
			if b.Kind == api.BuildPackage {
				src = "pkg " + filepath.Base(b.RecipeDir)
				if b.Pkgrel != "" {
					src += " -" + b.Pkgrel
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", b.ID, buildState(b), trunc(src, 44), commit, b.Release, fmtSecs(b.Seconds))
		}
		return w.Flush()

	case "build-log":
		follow := fs.Bool("f", false, "follow")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab build-log <build> [-f]"); err != nil {
			return err
		}
		return c.BuildLog(ctx, pos[0], *follow, os.Stdout)

	case "exec":
		timeout := fs.Int("timeout", 120, "seconds")
		pos := parse(fs, args)
		if err := need(pos, 2, "lab exec <device> <command...>"); err != nil {
			return err
		}
		res, err := c.Exec(ctx, pos[0], api.ExecArgs{Command: strings.Join(pos[1:], " "), TimeoutSec: *timeout})
		if err != nil {
			return err
		}
		os.Stdout.WriteString(res.Stdout)
		os.Stderr.WriteString(res.Stderr)
		os.Exit(res.ExitCode)
		return nil

	case "jobs":
		pos := parse(fs, args)
		dev := ""
		if len(pos) > 0 {
			dev = pos[0]
		}
		jobs, err := c.Jobs(ctx, dev, 20)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "JOB\tDEVICE\tSTATE\tOUTCOME\tCREATED\tSUMMARY")
		for _, j := range jobs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", j.ID, j.Spec.Device, j.State, j.Outcome, j.Created.Format("01-02 15:04"), trunc(j.Summary, 70))
		}
		return w.Flush()

	case "job":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab job <id>"); err != nil {
			return err
		}
		j, err := c.Job(ctx, pos[0])
		if err != nil {
			return err
		}
		printJob(j, true)
		return nil

	case "wait":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab wait <id>"); err != nil {
			return err
		}
		return follow(ctx, c, pos[0])

	case "publish":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab publish <job>"); err != nil {
			return err
		}
		url, err := c.Publish(ctx, pos[0])
		if err != nil {
			return err
		}
		fmt.Println(url)
		return nil

	case "cancel":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab cancel <id>"); err != nil {
			return err
		}
		out, err := c.Cancel(ctx, pos[0])
		fmt.Print(out)
		return err

	case "logs":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab logs <id> [file]"); err != nil {
			return err
		}
		if len(pos) == 1 {
			j, err := c.Job(ctx, pos[0])
			if err != nil {
				return err
			}
			for _, l := range j.Result.Logs {
				fmt.Println(l)
			}
			for _, t := range j.Result.Tests {
				for _, f := range t.Files {
					fmt.Println(f)
				}
			}
			return nil
		}
		b, err := c.File(ctx, pos[0], pos[1])
		if err != nil {
			return err
		}
		os.Stdout.Write(b)
		return nil

	case "lease":
		ttl := fs.Duration("ttl", time.Hour, "")
		who := fs.String("holder", holder(), "")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab lease <device>"); err != nil {
			return err
		}
		l, err := c.Lease(ctx, pos[0], *who, *ttl)
		if err != nil {
			return err
		}
		fmt.Printf("%s leased by %s until %s\n", pos[0], l.Holder, l.Expires.Format(time.TimeOnly))
		return nil

	case "forget":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab forget <device>"); err != nil {
			return err
		}
		if err := c.ForgetDevice(ctx, pos[0]); err != nil {
			return err
		}
		fmt.Printf("forgot %s; its jobs stay. `lab enroll %s` adds it again.\n", pos[0], pos[0])
		return nil

	case "release":
		who := fs.String("holder", holder(), "")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab release <device>"); err != nil {
			return err
		}
		return c.Release(ctx, pos[0], *who)

	case "reset":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab reset <device>"); err != nil {
			return err
		}
		out, err := c.Reset(ctx, pos[0], holder())
		fmt.Print(out)
		return err

	case "shell", "console":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab shell <device>"); err != nil {
			return err
		}
		return shell(ctx, c, pos[0])

	case "serial":
		n := fs.Int("n", 100, "lines")
		pos := parse(fs, args)
		if err := need(pos, 1, "lab serial <device>"); err != nil {
			return err
		}
		out, err := c.Serial(ctx, pos[0], *n)
		fmt.Print(out)
		return err

	case "oob":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab oob <device>"); err != nil {
			return err
		}
		st, err := c.OOBStatus(ctx, pos[0])
		if err != nil {
			return err
		}
		for k, v := range st {
			fmt.Printf("%s: %v\n", k, v)
		}
		return nil

	case "upload":
		pos := parse(fs, args)
		if err := need(pos, 1, "lab upload <file>"); err != nil {
			return err
		}
		sha, err := c.Upload(ctx, pos[0])
		if err == nil {
			fmt.Println(sha)
		}
		return err
	}
	return fmt.Errorf("unknown command %q (lab help)", cmd)
}

var reSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

func artifact(ctx context.Context, c *client.Client, v string) (string, error) {
	if reSHA.MatchString(v) {
		return v, nil
	}
	fmt.Fprintf(os.Stderr, "uploading %s... ", v)
	sha, err := c.Upload(ctx, v)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "%s\n", sha[:12])
	return sha, nil
}

func submit(ctx context.Context, c *client.Client, spec api.JobSpec, noWait bool) error {
	j, err := c.Submit(ctx, spec)
	if err != nil {
		return err
	}
	fmt.Printf("job %s queued on %s\n", j.ID, spec.Device)
	if noWait {
		return nil
	}
	return follow(ctx, c, j.ID)
}

// follow prints a job's events as they happen, then its result.
func follow(ctx context.Context, c *client.Client, id string) error {
	seen := 0
	for {
		j, err := c.Job(ctx, id)
		if err != nil {
			return err
		}
		for _, e := range j.Events[seen:] {
			fmt.Printf("  %s  %s\n", e.Time.Format(time.TimeOnly), e.Msg)
		}
		seen = len(j.Events)
		if j.State == api.JobDone {
			fmt.Println()
			printJob(j, false)
			if j.Outcome != api.OutcomePass {
				os.Exit(3)
			}
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

func printJob(j *api.Job, events bool) {
	fmt.Printf("job %s on %s: %s\n", j.ID, j.Spec.Device, strings.ToUpper(orDash(j.Outcome, string(j.State))))
	if j.Summary != "" {
		fmt.Printf("  %s\n", j.Summary)
	}
	r := j.Result
	if r.Booted {
		fmt.Printf("  booted %s in %.0fs\n", r.BootKernel, r.BootSeconds)
		if r.BootCmdline != "" {
			fmt.Printf("  cmdline: %s\n", r.BootCmdline)
		}
	}
	for _, t := range r.Tests {
		fmt.Printf("  test %-16s %s\n", t.Name, verdict(t))
	}
	for _, s := range r.Recovery {
		fmt.Printf("  recovery: %s\n", s)
	}
	if len(r.NewErrorLines) > 0 {
		fmt.Printf("  new kernel warnings/errors vs baseline:\n")
		for i, l := range r.NewErrorLines {
			if i == 15 {
				fmt.Printf("    ... %d more\n", len(r.NewErrorLines)-15)
				break
			}
			fmt.Printf("    %s\n", l)
		}
	}
	if o := r.OMT; o != nil {
		fmt.Printf("  omarchy-m-test %s on %s: %d pass, %d fail, %d skipped\n", o.Tool, o.Kernel, o.Pass, o.Fail, o.Skip)
		fmt.Printf("    compared with %s\n", o.ComparedTo)
		for _, c := range o.Regressions {
			fmt.Printf("    REGRESSED %s: %s\n", c.ID, trunc(c.Evidence, 100))
		}
		for _, c := range o.Fixed {
			fmt.Printf("    fixed     %s\n", c.ID)
		}
		for _, c := range o.Allowed {
			fmt.Printf("    allowed   %s (--omt-allow)\n", c.ID)
		}
		for _, c := range o.LabBoot {
			fmt.Printf("    lab boot  %s (fails for any kernel that isn't an installed package)\n", c.ID)
		}
		switch {
		case o.Published != "":
			fmt.Printf("    published: %s\n", o.Published)
		case o.PublishNote != "":
			fmt.Printf("    not published: %s\n", o.PublishNote)
		}
	}
	for _, e := range r.KernelEvents {
		if e.Kind != "warning" {
			fmt.Printf("  kernel %s (%s): %s\n", e.Kind, e.Source, trunc(e.Line, 120))
		}
	}
	if len(r.Logs) > 0 {
		fmt.Printf("  logs: lab logs %s <file>  (%s)\n", j.ID, strings.Join(r.Logs, ", "))
	}
	if events {
		fmt.Println("  events:")
		for _, e := range j.Events {
			fmt.Printf("    %s  %s\n", e.Time.Format(time.TimeOnly), e.Msg)
		}
	}
}

func verdict(t api.TestResult) string {
	switch {
	case t.Passed:
		return fmt.Sprintf("pass  (%.0fs)", t.Seconds)
	case t.TimedOut:
		return "TIMED OUT"
	case t.Error != "":
		return "ERROR " + t.Error
	}
	return fmt.Sprintf("FAIL  (exit %d)", t.ExitCode)
}

func showDevices(ctx context.Context, c *client.Client) error {
	devs, err := c.Devices(ctx)
	if err != nil {
		return err
	}
	if len(devs) == 0 {
		fmt.Println("no devices yet: lab enroll <name>")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "DEVICE\tSTATE\tTIER\tKERNEL\tLAST SEEN\tJOB\tLEASE")
	for _, d := range devs {
		lease := ""
		if d.Lease != nil {
			lease = d.Lease.Holder
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n", d.Name, d.State, d.Tier, d.Kernel, ago(d.LastSeen), d.ActiveJob, lease)
	}
	w.Flush()
	for _, d := range devs {
		if d.Action != nil {
			fmt.Printf("\n>>> %s\n%s\n", strings.ToUpper(d.Action.Title), indent(d.Action.Text()))
		}
	}
	return nil
}

func showDevice(ctx context.Context, c *client.Client, name string) error {
	d, err := c.Device(ctx, name)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s", d.Name, strings.ToUpper(string(d.State)))
	if d.StateReason != "" {
		fmt.Printf(" (%s)", d.StateReason)
	}
	fmt.Println()
	if d.Action != nil {
		fmt.Printf("\n>>> %s\n%s\n\n", strings.ToUpper(d.Action.Title), indent(d.Action.Text()))
	}
	fmt.Printf("  model:       %s, %s\n", d.Facts.DTModel, orDash(d.Label, "no label"))
	fmt.Printf("  kernel:      %s (known-good: %s)\n", d.Kernel, orDash(d.KnownGood, "no baseline yet"))
	fmt.Printf("  last seen:   %s, uptime %.0fs, systemd %s\n", ago(d.LastSeen), d.Health.Uptime, d.Health.SystemState)
	tiers := []string{"panic reboot + one-shot fallback", "+ hardware watchdog", "+ out-of-band reset and serial"}
	fmt.Printf("  recovery:    tier %d (%s)\n", d.Tier, tiers[d.Tier])
	if d.OOB != nil {
		fmt.Printf("  oob:         %s\n", d.OOB.URL)
	}
	if d.Lease != nil {
		fmt.Printf("  lease:       %s until %s\n", d.Lease.Holder, d.Lease.Expires.Format(time.TimeOnly))
	}
	if d.ActiveJob != "" {
		fmt.Printf("  job:         %s (%d queued)\n", d.ActiveJob, d.Queued)
	}
	if len(d.Facts.Problems) > 0 {
		fmt.Printf("  preflight problems:\n")
		for _, p := range d.Facts.Problems {
			fmt.Printf("    - %s\n", p)
		}
	}
	if len(d.Events) > 0 {
		fmt.Printf("  kernel events (24h):\n")
		for _, e := range d.Events[max(0, len(d.Events)-8):] {
			fmt.Printf("    %s %-11s %s\n", e.Time.Format(time.TimeOnly), e.Kind, trunc(e.Line, 100))
		}
	}
	return nil
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Round(time.Second).String() + " ago"
}

func indent(s string) string { return "    " + strings.ReplaceAll(s, "\n", "\n    ") }

func orDash(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func login(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: lab login <labd-url> <admin-token>")
	}
	c := &client.Client{URL: strings.TrimRight(args[0], "/"), Token: args[1]}
	if err := c.Save(); err != nil {
		return err
	}
	lc, err := client.Load()
	if err != nil {
		return err
	}
	if _, err := lc.Devices(context.Background()); err != nil {
		return fmt.Errorf("saved, but labd rejected it: %w", err)
	}
	fmt.Println("logged in to", c.URL)
	return nil
}

// pack builds a kernel artifact in the Arch package layout from an O= build tree.
func pack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	build := fs.String("build", "", "kernel build (O=) directory")
	out := fs.String("o", "", "output file (default kernel-<release>.tar.zst)")
	parse(fs, args)
	if *build == "" {
		return fmt.Errorf("usage: lab pack --build <O= dir> [-o file]")
	}
	b, err := os.ReadFile(filepath.Join(*build, "include/config/kernel.release"))
	if err != nil {
		return fmt.Errorf("not a built kernel tree: %w", err)
	}
	krel := strings.TrimSpace(string(b))
	image := filepath.Join(*build, "arch/arm64/boot/Image")
	if _, err := os.Stat(image); err != nil {
		return fmt.Errorf("no %s: build the kernel first", image)
	}
	stage, err := os.MkdirTemp("", "lab-pack-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	fmt.Fprintf(os.Stderr, "installing modules for %s...\n", krel)
	mk := exec.Command("make", "-C", *build, "-s", "INSTALL_MOD_PATH="+stage, "INSTALL_MOD_STRIP=1", "modules_install")
	mk.Stdout, mk.Stderr = os.Stderr, os.Stderr
	if err := mk.Run(); err != nil {
		return fmt.Errorf("modules_install: %w", err)
	}
	mods := filepath.Join(stage, "usr/lib/modules", krel)
	if _, err := os.Stat(mods); err != nil {
		os.MkdirAll(filepath.Join(stage, "usr/lib/modules"), 0o755)
		if err := os.Rename(filepath.Join(stage, "lib/modules", krel), mods); err != nil {
			return err
		}
	}
	os.Remove(filepath.Join(mods, "build"))
	os.Remove(filepath.Join(mods, "source"))
	if err := exec.Command("cp", image, filepath.Join(mods, "vmlinuz")).Run(); err != nil {
		return err
	}
	if *out == "" {
		*out = "kernel-" + krel + ".tar.zst"
	}
	abs, _ := filepath.Abs(*out)
	tarArgs := []string{"-C", stage, "-cf", abs, "usr"}
	if strings.HasSuffix(abs, ".zst") {
		tarArgs = append([]string{"--zstd"}, tarArgs...)
	} else if strings.HasSuffix(abs, ".gz") {
		tarArgs = append([]string{"-z"}, tarArgs...)
	}
	if o, err := exec.Command("tar", tarArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("tar: %v: %s", err, o)
	}
	fmt.Printf("%s (kernel release %s)\nnext: lab run <device> --kernel %s\n", *out, krel, *out)
	return nil
}

func isSource(k string) bool {
	return strings.HasPrefix(k, "https://") || strings.HasPrefix(k, "http://") || strings.HasPrefix(k, "github.com/") || strings.HasPrefix(k, "git@")
}

func shortSrc(s api.Source) string {
	r := strings.TrimPrefix(s.Repo, "https://github.com/")
	if s.Ref != "" && s.Ref != s.SHA {
		r += "@" + s.Ref
	}
	return r
}

func buildState(b *api.Build) string {
	if b.State == api.BuildRunning {
		st := b.Stage
		if b.Progress > 0 && b.Stage == "build" {
			st = fmt.Sprintf("build %d%%", int(b.Progress*100))
		}
		return "running: " + st
	}
	return string(b.State)
}

func fmtSecs(s float64) string {
	if s <= 0 {
		return ""
	}
	return (time.Duration(s) * time.Second).String()
}

func printBuild(b *api.Build) {
	fmt.Printf("build %s %s", b.ID, strings.ToUpper(string(b.State)))
	if b.Release != "" {
		fmt.Printf(": %s, %d MB, %s", b.Release, b.Size>>20, fmtSecs(b.Seconds))
	}
	if b.Error != "" {
		fmt.Printf(": %s", b.Error)
	}
	fmt.Println()
	for _, f := range b.Files {
		fmt.Printf("  %s  %s  (%d MB)\n", f.SHA256, f.Name, f.Size>>20)
	}
	if b.State == api.BuildDone && b.Artifact != "" {
		fmt.Printf("  boot it once: lab run <mac> --kernel %s\n", b.ID)
	}
	if len(b.Files) > 0 {
		fmt.Printf("  download: lab build-get %s -o <dir>\n", b.ID)
	}
}

// splitAllow splits --omt-allow on commas. Check ids always have a dot and a
// device-tree compatible's own comma doesn't start one, so a piece without a
// dot belongs to the one before it: hardware.drivers:apple,mesa-fingerprint.
func splitAllow(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
		case !strings.Contains(p, ".") && len(out) > 0 && strings.Contains(out[len(out)-1], ":"):
			out[len(out)-1] += "," + p
		default:
			out = append(out, p)
		}
	}
	return out
}

var reBuildID = regexp.MustCompile(`^b[0-9]{4}-[0-9]{6}-[0-9a-f]{4}$`)

// followBuild streams a build's log until it ends, prints the result, and
// downloads its files into out if asked. It exits 3 if the build failed.
func followBuild(ctx context.Context, c *client.Client, b *api.Build, noWait bool, out string) error {
	if noWait {
		printBuild(b)
		return nil
	}
	if b.State != api.BuildDone {
		if err := c.BuildLog(ctx, b.ID, true, os.Stdout); err != nil {
			return err
		}
		var err error
		if b, err = c.GetBuild(ctx, b.ID); err != nil {
			return err
		}
	}
	printBuild(b)
	if b.State != api.BuildDone {
		os.Exit(3)
	}
	if out != "" {
		return getBuildFiles(ctx, c, b, out)
	}
	return nil
}

// getBuildFiles downloads a package build's files and checks each sha256.
func getBuildFiles(ctx context.Context, c *client.Client, b *api.Build, dir string) error {
	if len(b.Files) == 0 {
		return fmt.Errorf("build %s has no files to download (only package builds do; %s is %s)", b.ID, b.ID, orDash(b.Kind, "a kernel build"))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range b.Files {
		dst := filepath.Join(dir, f.Name)
		sha, err := c.BuildFile(ctx, b.ID, f.Name, dst)
		if err != nil {
			return err
		}
		if sha != f.SHA256 {
			os.Remove(dst)
			return fmt.Errorf("%s: downloaded sha256 %s, but the build recorded %s", f.Name, sha, f.SHA256)
		}
		fmt.Printf("%s  %s\n", sha, dst)
	}
	if b.Recipe != "" {
		if err := getRecipe(ctx, c, b, dir); err != nil {
			fmt.Fprintf(os.Stderr, "lab: the packages are complete, but not the recipe: %v\n", err)
		}
	}
	return nil
}

// getRecipe unpacks the recipe a package build was made from, exactly as
// uploaded (PKGBUILD, patches, data files), into dir/recipe/.
func getRecipe(ctx context.Context, c *client.Client, b *api.Build, dir string) error {
	tarball := filepath.Join(dir, api.RecipeFile)
	sha, err := c.BuildFile(ctx, b.ID, api.RecipeFile, tarball)
	if err != nil {
		return err
	}
	defer os.Remove(tarball)
	if sha != b.Recipe {
		return fmt.Errorf("downloaded sha256 %s, but the build recorded %s", sha, b.Recipe)
	}
	rdir := filepath.Join(dir, "recipe")
	if err := os.MkdirAll(rdir, 0o755); err != nil {
		return err
	}
	if o, err := exec.Command("tar", "-C", rdir, "--no-same-owner", "-xf", tarball).CombinedOutput(); err != nil {
		return fmt.Errorf("unpacking: %v: %s", err, o)
	}
	fmt.Printf("%s  %s/ (the recipe as uploaded)\n", sha, rdir)
	return nil
}

// uploadRecipe tars a PKGBUILD directory, with only the files makepkg needs
// from it (PKGBUILD, local sources, install and changelog files), and uploads it.
func uploadRecipe(ctx context.Context, c *client.Client, dir string) (string, []string, error) {
	names, err := recipeFiles(dir)
	if err != nil {
		return "", nil, err
	}
	tmp, err := os.CreateTemp("", "lab-recipe-*.tar")
	if err != nil {
		return "", nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	tarArgs := append([]string{"-C", dir, "--owner=0", "--group=0", "-cf", tmp.Name(), "--"}, names...)
	if o, err := exec.Command("tar", tarArgs...).CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("tar: %v: %s", err, o)
	}
	sha, err := c.Upload(ctx, tmp.Name())
	return sha, names, err
}

// recipeFiles lists the recipe's own files by sourcing the PKGBUILD, as makepkg does.
func recipeFiles(dir string) ([]string, error) {
	if _, err := os.Stat(filepath.Join(dir, "PKGBUILD")); err != nil {
		return nil, fmt.Errorf("%s has no PKGBUILD", dir)
	}
	sh := `cd "$1" && source ./PKGBUILD >/dev/null 2>&1; printf '%s\n' "${source[@]}" "${source_aarch64[@]}" "$install" "$changelog"`
	o, err := exec.Command("bash", "-c", sh, "bash", dir).Output()
	if err != nil {
		return nil, fmt.Errorf("reading %s/PKGBUILD: %w", dir, err)
	}
	names := []string{"PKGBUILD"}
	seen := map[string]bool{"PKGBUILD": true}
	for _, l := range strings.Split(string(o), "\n") {
		name, loc := "", strings.TrimSpace(l)
		if i := strings.Index(loc, "::"); i >= 0 {
			name, loc = loc[:i], loc[i+2:]
		}
		if loc == "" || strings.Contains(loc, "://") {
			continue // downloaded by makepkg
		}
		if name == "" {
			name = filepath.Base(loc)
		}
		if seen[name] {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, loc)); err != nil {
			return nil, fmt.Errorf("the PKGBUILD lists %s, which is not in %s", loc, dir)
		}
		seen[name] = true
		names = append(names, loc)
	}
	return names, nil
}

// manifestSHA accepts a manifest file or its sha256.
func manifestSHA(arg string) (string, error) {
	if b, err := os.ReadFile(arg); err == nil {
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]), nil
	}
	if len(arg) == 64 && strings.Trim(arg, "0123456789abcdef") == "" {
		return arg, nil
	}
	return "", fmt.Errorf("--installed takes the frozen manifest file or its full sha256, not %q", arg)
}

// installedCmd handles `lab installed ...`: freezing a release's expectation
// and promoting an accepted installed run.
func installedCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) < 1 {
		return errors.New("lab installed freeze-manifest|freeze-entry|promote|status ...")
	}
	sub := args[0]
	fs := flag.NewFlagSet("installed "+sub, flag.ContinueOnError)
	release := fs.String("release", "", "release name, e.g. 12.0")
	approved := fs.String("approved-by", "", "who approved the manifest, comma-separated")
	job := fs.String("job", "", "the installed job to promote")
	accepted := fs.String("accepted-by", "", "who accepted it (required)")
	pos := parse(fs, args[1:])
	if *release == "" {
		return errors.New("--release is required")
	}
	var out map[string]any
	var err error
	switch sub {
	case "freeze-manifest":
		if err := need(pos, 2, "lab installed freeze-manifest --release R <manifest.json> <payload.sha256>"); err != nil {
			return err
		}
		m, err1 := c.Upload(ctx, pos[0])
		p, err2 := c.Upload(ctx, pos[1])
		if err1 != nil || err2 != nil {
			return errors.Join(err1, err2)
		}
		var by []string
		if *approved != "" {
			by = strings.Split(*approved, ",")
		}
		err = c.Installed(ctx, "POST", *release, "manifest", map[string]any{"manifest": m, "payload": p, "approved_by": by}, &out)
	case "freeze-entry":
		if err := need(pos, 1, "lab installed freeze-entry <device> --release R"); err != nil {
			return err
		}
		err = c.Installed(ctx, "POST", *release, "entry/"+pos[0], nil, &out)
	case "promote":
		if err := need(pos, 1, "lab installed promote <device> --release R --job <id> --accepted-by <who>"); err != nil {
			return err
		}
		err = c.Installed(ctx, "POST", *release, "promote", map[string]any{"device": pos[0], "job": *job, "accepted_by": *accepted}, &out)
	case "status":
		err = c.Installed(ctx, "GET", *release, "", nil, &out)
	default:
		return fmt.Errorf("unknown: lab installed %s", sub)
	}
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

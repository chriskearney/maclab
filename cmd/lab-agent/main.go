// Command lab-agent runs on each test Mac.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/iconidentify/maclab/internal/agent"
)

const usage = `lab-agent: the Mac side of the test lab

  sudo lab-agent setup --server http://labd:7770 --token enr_... [--gui-user you --autologin] [--volatile-journal]
        [--tailscale-authkey-file <file> | --tailscale-authkey - (key on stdin)] [--tailscale-hostname name]
  sudo lab-agent uninstall [--dry-run] [--force]   undo everything setup did
  sudo lab-agent preflight        what makes this Mac unsafe to test on
  sudo lab-agent known-good       the kernel setup would record as known-good (read-only)
  lab-agent run                   the daemon (started by lab-agent.service)
  lab-agent sim --server .. --token ..   a simulated Mac, to try the lab without hardware
  lab-agent version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	var err error
	switch os.Args[1] {
	case "setup":
		server := fs.String("server", "", "labd URL")
		token := fs.String("token", "", "one-time enrollment token from `lab enroll`")
		gui := fs.String("gui-user", "", "user whose Hyprland session GUI tests drive")
		auto := fs.Bool("autologin", false, "log the GUI user into the desktop on boot and turn idle lock off")
		volatile := fs.Bool("volatile-journal", false, "leave journald alone: a failed lab boot's journal is lost")
		tsKeyFile := fs.String("tailscale-authkey-file", "", "join the lab's tailnet first with the one-off auth key in this file (tagged tag:maclab, Tailscale SSH on); never stored")
		tsKey := fs.String("tailscale-authkey", "", "the one-off auth key, or - to read it from stdin; a key given here shows in the process list and sudo's journal")
		tsHost := fs.String("tailscale-hostname", "", "name on the tailnet (default maclab-<device name>, else this machine's hostname)")
		fs.Parse(os.Args[2:])
		var stdin io.Reader = os.Stdin
		if *tsKey == "-" && term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprint(os.Stderr, "Tailscale auth key: ")
			b, e := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if e != nil {
				log.Fatal(e)
			}
			stdin = bytes.NewReader(b)
		}
		key, warning, e := agent.AuthKey(*tsKey, *tsKeyFile, stdin)
		if e != nil {
			err = e
			break
		}
		if warning != "" {
			fmt.Fprintln(os.Stderr, "lab-agent: warning:", warning)
		}
		err = agent.Setup(ctx, agent.SetupOptions{Server: *server, Token: *token, GUIUser: *gui, Autologin: *auto, VolatileJournal: *volatile,
			TailscaleAuthKey: key, TailscaleHostname: *tsHost,
			Log: func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }})
	case "uninstall":
		dry := fs.Bool("dry-run", false, "print each action without taking it")
		force := fs.Bool("force", false, "uninstall even with a job in flight, or with the bootloader not found")
		fs.Parse(os.Args[2:])
		err = agent.Uninstall(agent.UninstallOptions{DryRun: *dry, Force: *force,
			Log: func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }})
	case "preflight":
		l := &agent.Linux{WorkDir: "/var/lib/maclab"}
		p, w := l.Preflight()
		if len(p) == 0 {
			fmt.Println("preflight OK")
		} else {
			fmt.Println("preflight problems:\n  - " + strings.Join(p, "\n  - "))
		}
		if len(w) > 0 {
			fmt.Println("preflight warnings:\n  - " + strings.Join(w, "\n  - "))
		}
		if len(p) > 0 {
			os.Exit(1)
		}
	case "known-good":
		var out string
		if out, err = agent.DescribeKnownGood(); err == nil {
			fmt.Println(out)
		}
	case "run":
		cfgPath := fs.String("config", agent.ConfigPath, "")
		fs.Parse(os.Args[2:])
		var cfg *agent.Config
		if cfg, err = agent.LoadConfig(*cfgPath); err == nil {
			sys := &agent.Linux{WorkDir: "/var/lib/maclab", GUIUser: cfg.GUIUser}
			err = agent.New(cfg, sys, nil).Run(ctx)
		}
	case "sim":
		server := fs.String("server", "", "labd URL")
		token := fs.String("token", "", "enrollment token")
		delay := fs.Duration("reboot-delay", 100*time.Millisecond, "how long a simulated reboot takes")
		model := fs.String("model", "Simulated Mac", "device-tree model string to report")
		fs.Parse(os.Args[2:])
		sim := agent.NewSim(os.TempDir())
		sim.RebootDelay = *delay
		sim.Model = *model
		resp, e := agent.Enroll(ctx, *server, *token, sim.Facts())
		if e != nil {
			log.Fatal(e)
		}
		log.Printf("simulated Mac enrolled as %s", resp.Name)
		err = agent.New(&agent.Config{Server: *server, DeviceID: resp.DeviceID, Name: resp.Name, Secret: resp.Secret, WorkDir: os.TempDir()}, sim, nil).Run(ctx)
	case "version":
		fmt.Println(agent.Version)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "lab-agent:", err)
		os.Exit(1)
	}
}

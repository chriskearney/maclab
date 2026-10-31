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
	"github.com/iconidentify/maclab/internal/labhttp"
)

const usage = `lab-agent: the Mac side of the test lab

  sudo lab-agent setup --server http://labd:7770 --token enr_... [--gui-user you --autologin|--stay-awake] [--volatile-journal]
        [--tailscale-authkey-file <file> | --tailscale-authkey - (key on stdin)] [--tailscale-hostname name]
                                  (a Volunteer's Mac refuses --autologin and --stay-awake)
  sudo lab-agent status           what this Mac is enrolled as, its ntfy topic, its Availability window,
                                  Access level, Installed-run eligibility and latest Audit log entries
  sudo lab-agent window show|add|remove [<days> <HH:MM-HH:MM>]
                                  when the lab may use a Volunteer's Mac, e.g. window add mon-fri 19:00-07:00
  sudo lab-agent pause [--until YYYY-MM-DD]
                                  end the current window now, or stay closed until that date
  sudo lab-agent open --until HH:MM
                                  open the Mac to the lab now, until HH:MM
  sudo lab-agent notify --topic URL
                                  send this Mac's notices to your own ntfy topic
  sudo lab-agent access qualification|full
                                  what Maintainers may do: Qualification (the default) allows no lab exec,
                                  --script or --gui-script; lowering it stops what it no longer allows
  sudo lab-agent publish on|off   whether this Mac's omarchy-m-test reports may be published (off until
                                  you turn it on); on lists the deletion links of those published
  sudo lab-agent log              every Maintainer action on this Mac, from its own Audit log (works offline)
  sudo lab-agent jobs             the lab's jobs on this Mac
  sudo lab-agent leave            leave the lab now (asks first; --yes skips the question): stops any job, returns
                                  to your own kernel, removes the lab's boot entries, units and device secret,
                                  tells labd, and lists what is left to remove by hand
  sudo lab-agent uninstall [--dry-run] [--force]   tell labd the Mac is leaving, then undo everything setup did
  sudo lab-agent preflight        what makes this Mac unsafe to test on
  sudo lab-agent known-good       the kernel setup would record as known-good (read-only)
  lab-agent run                   the daemon (started by lab-agent.service)
  lab-agent lab-boot-session      on a Lab boot of a Volunteer's Mac, log the GUI user in (before SDDM)
  lab-agent lab-boot-lock         lock that session at once
  lab-agent lab-boot-deadlines    reboot a Lab boot that misses its deadline (started early in boot by
                                  maclab-lab-boot-deadlines.service)
  lab-agent sim --server .. --token ..   a simulated Mac, to try the lab without hardware
  lab-agent version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx, stop := signalContext()
	defer stop()
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	var err error
	switch os.Args[1] {
	case "setup":
		server := fs.String("server", "", "labd URL, e.g. https://labd.example.com/maclab; without --token, moves an enrolled Mac to labd's new URL, keeping its enrollment")
		token := fs.String("token", "", "one-time enrollment token from `lab enroll` (shows in the process list and sudo's journal: prefer --token-stdin)")
		tokenStdin := fs.Bool("token-stdin", false, "read the one-time enrollment token from the first line of stdin")
		acceptTerms := fs.String("accept-terms", "", "accept labd's participation terms without a terminal: the sha256 of the terms you read (GET <labd>/api/join/terms)")
		caFile := fs.String("ca-file", "", "PEM file of CA certificates for labd's https certificate, when the system doesn't trust it (kept in agent.json)")
		plain := fs.Bool("allow-plain-http", false, "allow an http:// labd on another machine: the device secret then crosses the network unencrypted (recorded in agent.json)")
		gui := fs.String("gui-user", "", "user whose Hyprland session GUI tests drive")
		auto := fs.Bool("autologin", false, "log the GUI user into the desktop on boot and turn idle lock off")
		stay := fs.Bool("stay-awake", false, "turn the GUI user's idle lock and screensaver off")
		volatile := fs.Bool("volatile-journal", false, "leave journald alone: a failed lab boot's journal is lost")
		tsKeyFile := fs.String("tailscale-authkey-file", "", "join the lab's tailnet first with the one-off auth key in this file (tagged tag:maclab, Tailscale SSH on); never stored")
		tsKey := fs.String("tailscale-authkey", "", "- to read the one-off auth key from stdin; the key itself is refused here, since the process list and sudo's journal show it")
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
		if *tokenStdin {
			if *token != "" || *tsKey == "-" {
				err = fmt.Errorf("--token-stdin goes with neither --token nor --tailscale-authkey -")
				break
			}
			if *token, err = agent.ReadToken(os.Stdin); err != nil {
				break
			}
		}
		key, e := agent.AuthKey(*tsKey, *tsKeyFile, stdin)
		if e != nil {
			err = e
			break
		}
		err = agent.Setup(ctx, agent.SetupOptions{Server: *server, Token: *token, GUIUser: *gui, Autologin: *auto, StayAwake: *stay, VolatileJournal: *volatile,
			TailscaleAuthKey: key, TailscaleHostname: *tsHost, CAFile: *caFile, AllowPlainHTTP: *plain, AcceptTerms: *acceptTerms,
			Log: func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }})
	case "uninstall":
		dry := fs.Bool("dry-run", false, "print each action without taking it")
		force := fs.Bool("force", false, "uninstall even with a job in flight, or with the bootloader not found")
		fs.Parse(os.Args[2:])
		err = agent.Uninstall(ctx, agent.UninstallOptions{DryRun: *dry, Force: *force,
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
		if agent.HasLeft("/var/lib/maclab") {
			// This Mac left the lab; all that remains is to tell labd.
			err = agent.Farewell(ctx, "/var/lib/maclab", &agent.Linux{WorkDir: "/var/lib/maclab"}, log.Printf)
		} else if cfg, err = agent.LoadConfig(*cfgPath); err == nil {
			sys := &agent.Linux{WorkDir: "/var/lib/maclab", GUIUser: cfg.GUIUser}
			err = agent.New(cfg, sys, nil).Run(ctx)
		}
	case "lab-boot-deadlines":
		err = agent.EnforceLabBootDeadlines(ctx, "/var/lib/maclab")
	case "lab-boot-session", "lab-boot-lock":
		var cfg *agent.Config
		if cfg, err = agent.LoadConfig(agent.ConfigPath); err == nil {
			say := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
			if os.Args[1] == "lab-boot-session" {
				err = agent.WriteLabBootAutologin(cfg, say)
			} else {
				err = agent.LockLabBootSession(cfg, say)
			}
		}
	case "sim":
		server := fs.String("server", "", "labd URL")
		token := fs.String("token", "", "enrollment token")
		delay := fs.Duration("reboot-delay", 100*time.Millisecond, "how long a simulated reboot takes")
		model := fs.String("model", "Simulated Mac", "device-tree model string to report")
		caFile := fs.String("ca-file", "", "PEM file of CA certificates for labd's https certificate")
		plain := fs.Bool("allow-plain-http", false, "allow an http:// labd on another machine")
		fs.Parse(os.Args[2:])
		var caPEM []byte
		if *caFile != "" {
			if caPEM, err = labhttp.ReadCAFile(*caFile); err != nil {
				log.Fatal(err)
			}
		}
		sim := agent.NewSim(os.TempDir())
		sim.RebootDelay = *delay
		sim.Model = *model
		pol := labhttp.Policy{CAPEM: caPEM, AllowPlainHTTP: *plain}
		terms, e := agent.FetchTerms(ctx, *server, *token, pol)
		if e != nil {
			log.Fatal(e)
		}
		// A simulated Mac has no owner to read the terms: it accepts them.
		resp, e := agent.EnrollWith(ctx, *server, *token, sim.Facts(), pol, agent.Activation{Key: agent.NewActivationKey(), TermsSHA256: terms.SHA256})
		if e != nil {
			log.Fatal(e)
		}
		log.Printf("simulated Mac enrolled as %s", resp.Name)
		err = agent.New(&agent.Config{Server: *server, DeviceID: resp.DeviceID, Name: resp.Name, Secret: resp.Secret, WorkDir: os.TempDir(),
			ServerCA: string(caPEM), AllowPlainHTTP: plain}, sim, nil).Run(ctx)
	case "version":
		fmt.Println(agent.Version)
	default:
		if agent.IsVolunteerCommand(os.Args[1]) {
			var cfg *agent.Config
			cfg, err = agent.LoadConfig(agent.ConfigPath)
			if err != nil && os.Args[1] == "log" && agent.HasLeft("/var/lib/maclab") {
				cfg, err = &agent.Config{}, nil // a Mac that left still reads its own Audit log
			}
			if err == nil {
				args := os.Args[1:]
				if args[0] == "leave" && len(args) == 1 && confirmLeaving() {
					args = append(args, "--yes")
				}
				sys := &agent.Linux{WorkDir: "/var/lib/maclab", GUIUser: cfg.GUIUser}
				err = agent.Volunteer(ctx, cfg, sys, args, os.Stdout)
			}
			break
		}
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "lab-agent:", err)
		os.Exit(1)
	}
}

// signalContext ends when lab-agent is told to stop: Ctrl-C, systemd, or
// the terminal going away (SIGHUP, as when the SSH session that runs setup
// drops). Each ends ctx instead of killing the process, so what setup has
// to undo, such as the Tailscale key file, gets undone.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
}

// confirmLeaving asks the Volunteer, on their terminal, whether to leave the
// lab. Without a terminal it says no, and leave asks for --yes.
func confirmLeaving() bool {
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fmt.Print("Leave the lab now? Any job stops, your Mac returns to its own kernel, and the lab is removed from it. [y/N] ")
	var answer string
	fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

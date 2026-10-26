package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/iconidentify/maclab/internal/api"
)

// A volunteerCommand is one of the commands a Volunteer types on their own
// Mac. It runs with the agent's enrolled config, the Mac, and the terminal.
type volunteerCommand func(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error

// volunteerCommands are `sudo lab-agent status`, `window`, `pause` and the
// rest, by name. The Volunteer tickets add them here.
var volunteerCommands = map[string]volunteerCommand{
	"status":  showStatus,
	"window":  windowCmd,
	"pause":   pause,
	"open":    open,
	"notify":  notifyCmd,
	"access":  accessCmd,
	"publish": publishCmd,
	"log":     logCmd,
	"jobs":    jobsCmd,
}

// IsVolunteerCommand is whether lab-agent's command line routes name here.
func IsVolunteerCommand(name string) bool {
	_, ok := volunteerCommands[name]
	return ok
}

// Volunteer runs `sudo lab-agent <args>` for a Volunteer.
func Volunteer(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("no Volunteer command given")
	}
	cmd, ok := volunteerCommands[args[0]]
	if !ok {
		return fmt.Errorf("%q is not a Volunteer command", args[0])
	}
	return cmd(ctx, cfg, sys, args[1:], out)
}

// showStatus shows what the Mac is enrolled as, its ntfy topic, its Availability
// window and whether it is eligible for Installed runs. The window and
// eligibility are read from the Mac now; the enrollment from labd, or as
// setup recorded it when labd can't be reached.
func showStatus(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	e, from := cfg.Enrollment, ""
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var live api.AgentEnrollment
	if err := getJSON(ctx, http.DefaultClient, strings.TrimRight(cfg.Server, "/")+"/api/agent/enrollment", cfg.Secret, &live); err != nil {
		from = fmt.Sprintf(" (as recorded at setup; labd did not answer: %v)", err)
	} else {
		e = live
	}
	fmt.Fprintf(out, "%s, enrolled as %s%s\n", cfg.Name, kindName(e.Enrollment), from)
	if e.IsVolunteer() {
		fmt.Fprintf(out, "  ntfy topic:     %s\n", e.NtfyTopic)
		if e.NtfyURL != "" {
			fmt.Fprintf(out, "  subscribe to:   %s\n", e.NtfyURL)
		}
	}
	if e.Kind != api.KindLabOwned {
		w, _, err := loadWindow(cfg)
		if err != nil {
			fmt.Fprintf(out, "  Window:         can't be read: %v\n", err)
		} else {
			fmt.Fprintf(out, "  Window:         %s\n", describeWindow(w, cfg.clock().Now()))
		}
		if ac, err := loadAccess(cfg.workDir()); err != nil {
			fmt.Fprintf(out, "  Access level:   can't be read (lab-agent refuses exec and scripts): %v\n", err)
		} else {
			fmt.Fprintf(out, "  Access level:   %s\n", levelName(ac.Level))
			pub := "off"
			if ac.Publish {
				pub = "on (publish on lists the deletion links)"
			}
			fmt.Fprintf(out, "  Publishing:     %s\n", pub)
		}
	}
	if err := sys.SnapshotEligible(); err != nil {
		fmt.Fprintf(out, "  Installed runs: not eligible: %v\n", err)
	} else {
		fmt.Fprintf(out, "  Installed runs: eligible (@ can be snapshotted)\n")
	}
	if e.Kind != api.KindLabOwned {
		latest, err := latestAudit(cfg.workDir(), 5)
		switch {
		case err != nil:
			fmt.Fprintf(out, "  Audit log:      can't be read: %v\n", err)
		case len(latest) == 0:
			fmt.Fprintf(out, "  Audit log:      no Maintainer has done anything on this Mac yet\n")
		default:
			fmt.Fprintf(out, "  Audit log, latest (all of it: log):\n")
			for _, l := range latest {
				fmt.Fprintf(out, "    %s\n", l)
			}
		}
	}
	return nil
}

// kindName is how status and setup name a Mac's kind.
func kindName(e api.Enrollment) string {
	if e.IsVolunteer() {
		return fmt.Sprintf("a Volunteer's Mac (%s, %s)", e.VolunteerName, e.Contact)
	}
	return "a Lab-owned Mac"
}

// printTopicQR prints the Mac's ntfy topic (a bare topic or its URL) and a
// QR code of it, for the Volunteer to subscribe on their phone. The code is
// drawn light on dark, two rows of modules per line of text.
func printTopicQR(out io.Writer, topic string) error {
	c, err := qr.Encode(topic, qr.M)
	if err != nil {
		return err
	}
	const quiet = 2                                        // modules of margin a scanner needs around the code
	light := func(x, y int) bool { return !c.Black(x, y) } // outside the code is light too
	var b strings.Builder
	for y := -quiet; y < c.Size+quiet; y += 2 {
		for x := -quiet; x < c.Size+quiet; x++ {
			top, bottom := light(x, y), light(x, y+1) && y+1 < c.Size+quiet
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	_, err = fmt.Fprintf(out, "Your Mac's ntfy topic: %s\nSubscribe to it in the ntfy app (scan this):\n\n%s\n", topic, b.String())
	return err
}

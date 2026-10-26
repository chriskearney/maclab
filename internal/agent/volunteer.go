package agent

import (
	"context"
	"fmt"
	"io"
)

// A volunteerCommand is one of the commands a Volunteer types on their own
// Mac. It runs with the agent's enrolled config, the Mac, and the terminal.
type volunteerCommand func(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error

// volunteerCommands are `sudo lab-agent status`, `window`, `pause` and the
// rest, by name. The Volunteer tickets add them here.
var volunteerCommands = map[string]volunteerCommand{}

// Volunteer runs `sudo lab-agent <args>` for a Volunteer. The lab harness
// calls it today; lab-agent's command line routes here once commands exist.
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

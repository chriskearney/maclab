// lab-workflow is a local resumable coordinator. It uses the existing lab admin
// client only for explicit submit/wait phases; it installs no daemon or agent.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/iconidentify/maclab/internal/client"
	"github.com/iconidentify/maclab/internal/workflow"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lab-workflow:", err)
		os.Exit(1)
	}
}
func run() error {
	fs := flag.NewFlagSet("lab-workflow", flag.ContinueOnError)
	plan := fs.String("plan", "", "reviewed immutable JSON plan")
	state := fs.String("state", "", "private durable state directory")
	auth := fs.String("authorization", "", "retained scoped authorization receipt (not generated)")
	recovery := fs.Bool("recovery", false, "explicitly run only reviewed recovery phases")
	receipt := fs.String("receipt", "", "reviewed actual-outcome reconciliation receipt")
	sha := fs.String("receipt-sha256", "", "exact reviewed reconciliation receipt hash")
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: lab-workflow check|run|status|reconcile --plan P [--state DIR] [--authorization A]")
	}
	action := os.Args[1]
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	r, err := workflow.LoadPlan(*plan)
	if err != nil {
		return err
	}
	r.Dir = *state
	switch action {
	case "check":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "plan_sha256": r.PlanSHA, "device": r.Plan.Device, "phases": len(r.Plan.Phases), "execution": false})
	case "status":
		b, err := r.Status()
		if err != nil {
			return err
		}
		return workflow.PublishStatus(os.Stdout, b)
	case "reconcile":
		return r.Reconcile(*receipt, *sha)
	case "run":
		// Load credentials only if a declared API phase needs them. check, bind,
		// cache, helper-only plans and status never contact the controller.
		for _, p := range r.Plan.Phases {
			if p.Kind == "submit" || p.Kind == "wait" || p.Kind == "upload" {
				r.Backend, err = client.Load()
				if err != nil {
					return err
				}
				for _, phase := range r.Plan.Phases {
					if phase.M1Admission != nil {
						c := r.Backend.(*client.Client)
						r.Backend = &workflow.M1Backend{Backend: c, Client: c}
						break
					}
				}
				break
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer stop()
		err = r.Run(ctx, *auth, *recovery)
		if b, statusErr := r.Status(); statusErr == nil {
			_ = workflow.PublishStatus(os.Stdout, b)
		}
		return err
	default:
		return fmt.Errorf("unknown operation %q", action)
	}
}

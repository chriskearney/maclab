package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

// builderCmd handles `lab builder ...`: the named builder hosts, each with a
// token of its own that may only build. A builder's kernels boot as root on
// lab Macs, so add only builders whose operators you trust with that.
func builderCmd(ctx context.Context, c *client.Client, args []string) error {
	const use = "lab builder add <name> [--kinds kernel[,package]] [-o FILE] | remove <name> | list"
	if len(args) < 1 {
		return errors.New(use)
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("builder add", flag.ExitOnError)
		kinds := fs.String("kinds", api.BuilderKernel, "the builds it may take: kernel, package, or kernel,package")
		out := fs.String("o", "", "write the token to this new file (mode 0600) instead of printing it")
		pos := parse(fs, args[1:])
		if err := need(pos, 1, "lab builder add <name> [--kinds kernel[,package]] [-o FILE]"); err != nil {
			return err
		}
		return addBuilder(ctx, c, pos[0], strings.Split(*kinds, ","), *out, os.Stdout)
	case "remove":
		if err := need(args[1:], 1, "lab builder remove <name>"); err != nil {
			return err
		}
		r, err := c.RemoveBuilder(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Printf("removed builder %s; its token no longer works", r.Removed)
		if len(r.FailedBuilds) > 0 {
			fmt.Printf(", and the builds it was running failed: %s", strings.Join(r.FailedBuilds, ", "))
		}
		fmt.Println()
		return nil
	case "list":
		l, err := c.Builders(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "BUILDER\tKINDS\tADDED\tBY\tLAST SEEN\tBUILD")
		for _, b := range l {
			kinds, added := strings.Join(b.Kinds, ","), "-"
			if b.Shared {
				kinds = "shared token"
			} else {
				added = b.Added.Format(time.DateOnly)
			}
			seen := "never"
			if !b.LastSeen.IsZero() {
				seen = b.LastSeen.Format(time.DateTime)
				if b.Alive {
					seen = "online"
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", b.Host, kinds, added, orDash(b.AddedBy, "-"), seen, orDash(b.Build, "-"))
		}
		return w.Flush()
	}
	return errors.New(use)
}

// writeToken writes a new builder's token into its file, durably.
var writeToken = func(f *os.File, token string) error {
	if _, err := f.WriteString(token); err != nil {
		return err
	}
	return f.Sync()
}

// addBuilder adds a named builder. With file set, the token goes only into
// that new file. The file is made (mode 0600, never over an existing one)
// before labd makes the builder, so a file that can't be made costs nothing;
// if writing the token fails, the builder is removed again. No error carries
// the token.
func addBuilder(ctx context.Context, c *client.Client, name string, kinds []string, file string, stdout io.Writer) error {
	var f *os.File
	if file != "" {
		var err error
		if f, err = os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
			return err
		}
	}
	b, err := c.AddBuilder(ctx, name, kinds)
	if err != nil {
		if f != nil {
			f.Close()
			os.Remove(file)
		}
		return err
	}
	if f == nil {
		fmt.Fprintf(stdout, "Token for builder %s (%s), shown only this once; labd keeps only its hash:\n\n  %s\n\n",
			b.Name, strings.Join(b.Kinds, ","), b.Token)
	} else {
		werr := writeToken(f, b.Token)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(file)
			if _, rerr := c.RemoveBuilder(ctx, name); rerr != nil {
				return fmt.Errorf("writing the token to %s failed (%v), and removing builder %s again failed too (%v): remove it with lab builder remove %s",
					file, werr, name, rerr, name)
			}
			return fmt.Errorf("writing the token to %s failed (%v); builder %s was removed again", file, werr, name)
		}
		fmt.Fprintf(stdout, "Builder %s (%s) added. Its token is in %s (mode 0600) and nowhere else.\n\n",
			b.Name, strings.Join(b.Kinds, ","), file)
	}
	fmt.Fprintf(stdout, "On the builder Mac, keep the token in a file only root can read, and run lab-builder as root with\n\n"+
		"  --server %s --token-file <that file>\n\n"+
		"(see \"Builders\" in the README). Remove the builder with: lab builder remove %s\n", c.URL, b.Name)
	return nil
}

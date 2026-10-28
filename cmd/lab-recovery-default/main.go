// Command lab-recovery-default changes one pinned existing Limine default.
// It is a one-off root tool: it never installs/restarts the agent daemon.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/iconidentify/maclab/internal/agent"
)

func main() {
	var o agent.LimineDefaultOptions
	flag.StringVar(&o.ExpectedMenuSHA256, "expect-menu-sha256", "", "exact current limine.conf SHA256")
	flag.StringVar(&o.ExpectedDefault, "expect-default", "", "exact current global default name")
	flag.StringVar(&o.Entry, "entry", "", "existing top-level entry currently selected")
	flag.StringVar(&o.ExpectedUKISHA256, "expect-uki-sha256", "", "exact target UKI SHA256")
	flag.StringVar(&o.ExpectedKernel, "expect-kernel", "", "exact current kernel release")
	flag.StringVar(&o.Transaction, "transaction", "", "unique original-menu receipt name for apply")
	flag.BoolVar(&o.DryRun, "dry-run", false, "validate and show hashes without changing any file or variable")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "lab-recovery-default: unexpected positional arguments")
		os.Exit(2)
	}
	result, err := (&agent.Linux{WorkDir: "/var/lib/maclab"}).SetLimineDefault(o)
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab-recovery-default:", err)
		os.Exit(1)
	}
}

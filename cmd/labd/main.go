// Command labd is the Mac test lab controller.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/iconidentify/maclab/internal/server"
)

func main() {
	home, _ := os.UserHomeDir()
	listen := flag.String("listen", ":7770", "address to serve the API on (agents must reach it)")
	data := flag.String("data", filepath.Join(home, ".local/share/maclab"), "data directory")
	ntfy := flag.String("ntfy", os.Getenv("MACLAB_NTFY"), "ntfy topic URL for notifications, e.g. https://ntfy.sh/<secret-topic>")
	notifyCmd := flag.String("notify-cmd", os.Getenv("MACLAB_NOTIFY_CMD"), `shell command run per notification with $MACLAB_TITLE/$MACLAB_BODY, e.g. 'notify-send "$MACLAB_TITLE" "$MACLAB_BODY"'`)
	bootTimeout := flag.Duration("boot-timeout", 4*time.Minute, "default time a Mac gets to come back after a reboot")
	artifactGB := flag.Int64("artifact-budget-gb", 20, "cap on the kernel artifact store; unreferenced artifacts go first")
	tailscale := flag.Bool("tailscale", false, "let tailnet peers look at the lab by their Tailscale identity; changes still need a Maintainer's token")
	var allowHosts []string
	flag.Func("allow-host", "another name browsers reach labd by, e.g. labd.lan (repeatable). Access without a token (--tailscale) counts only "+
		"on requests to labd's own names: IP addresses, localhost, this machine's host name (short, fully qualified and .local) "+
		"and, with --tailscale, its MagicDNS name; any other name gets 403, so another site can't point its own name at labd (DNS rebinding)",
		func(v string) error {
			h, err := server.ParseAllowHost(v)
			allowHosts = append(allowHosts, h...)
			return err
		})
	maintainer := flag.String("maintainer", os.Getenv("USER"), "the first Maintainer's name, used once: on a fresh labd, or on the first start after upgrading from the single admin token")
	omt := flag.Bool("omt", true, "run omarchy-m-test (github.com/maralcbr/omarchy-m-testing) in every job on Macs with a desktop user, and compare it with the known-good kernel")
	omtSite := flag.String("omt-site", "https://omarchy-m-testing.org", "where omarchy-m-test reports are published (lab publish, --publish); empty never publishes")
	omtPublish := flag.Bool("omt-publish", false, "publish known-good omarchy-m-test runs (baselines and --omt-every runs) by themselves")
	omtEvery := flag.Duration("omt-every", 0, "re-run omarchy-m-test on each idle Mac's known-good kernel this often, e.g. 24h (reboots the Mac); 0 never")
	flag.Parse()

	if err := os.MkdirAll(*data, 0o700); err != nil {
		log.Fatal(err)
	}
	// labd announces the first Maintainer when it makes one.
	tok, _, err := server.FirstMaintainerToken(*data)
	if err != nil {
		log.Fatal(err)
	}

	btokPath := filepath.Join(*data, "builder.token")
	btok, err := os.ReadFile(btokPath)
	if os.IsNotExist(err) {
		btok = []byte("bld_" + randHex())
		if err := os.WriteFile(btokPath, btok, 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("created builder token in %s (give it to lab-builder)\n", btokPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *tailscale {
		log.Printf("tailnet peers may look without a token; changes need a Maintainer's token")
	}
	// ./volunteer downloads the lab-agent built alongside labd.
	exe, _ := os.Executable()
	s, err := server.New(ctx, server.Config{DataDir: *data, FirstMaintainer: *maintainer, FirstMaintainerToken: tok,
		Tailscale: *tailscale, AllowHosts: allowHosts,
		OMT: *omt, OMTSite: *omtSite, OMTPublish: *omtPublish, OMTEvery: *omtEvery,
		BootTimeout: *bootTimeout, NtfyURL: *ntfy, NotifyCmd: *notifyCmd,
		BuilderToken: strings.TrimSpace(string(btok)), ArtifactBudget: *artifactGB << 30,
		AgentBinary: filepath.Join(filepath.Dir(exe), "lab-agent-linux-arm64")}, nil)
	if err != nil {
		log.Fatal(err)
	}
	hs := &http.Server{Addr: *listen, Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	log.Printf("labd listening on %s, data in %s", *listen, *data)
	if err := hs.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func randHex() string {
	b := make([]byte, 20)
	f, _ := os.Open("/dev/urandom")
	f.Read(b)
	f.Close()
	return fmt.Sprintf("%x", b)
}

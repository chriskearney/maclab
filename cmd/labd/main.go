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
	trust := flag.String("trust", os.Getenv("MACLAB_TRUST"), "networks that get admin access without a token, e.g. 192.168.1.0/24,127.0.0.1 (anyone there can reboot Macs and run commands on them)")
	tailscale := flag.Bool("tailscale", false, "let tailnet peers in by their Tailscale identity: --admins get admin access, everyone else on the tailnet may only look")
	admins := flag.String("admins", "", "Tailscale logins with admin access, e.g. a@github,b@github (needs --tailscale)")
	omt := flag.Bool("omt", true, "run omarchy-m-test (github.com/maralcbr/omarchy-m-testing) in every job on Macs with a desktop user, and compare it with the known-good kernel")
	omtSite := flag.String("omt-site", "https://omarchy-m-testing.org", "where omarchy-m-test reports are published (lab publish, --publish); empty never publishes")
	omtPublish := flag.Bool("omt-publish", false, "publish known-good omarchy-m-test runs (baselines and --omt-every runs) by themselves")
	omtEvery := flag.Duration("omt-every", 0, "re-run omarchy-m-test on each idle Mac's known-good kernel this often, e.g. 24h (reboots the Mac); 0 never")
	flag.Parse()
	trusted, err := server.ParseTrust(*trust)
	if err != nil {
		log.Fatal(err)
	}
	if *admins != "" && !*tailscale {
		log.Fatal("--admins needs --tailscale")
	}

	if err := os.MkdirAll(*data, 0o700); err != nil {
		log.Fatal(err)
	}
	tokPath := filepath.Join(*data, "admin.token")
	tok, err := os.ReadFile(tokPath)
	if os.IsNotExist(err) {
		tok = []byte("adm_" + randHex())
		if err := os.WriteFile(tokPath, tok, 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("created admin token in %s\n  lab login http://<this-host>%s \"$(cat %s)\"\n", tokPath, *listen, tokPath)
	} else if err != nil {
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
	if len(trusted) > 0 {
		log.Printf("no token needed from %s", *trust)
	}
	if *tailscale {
		log.Printf("tailnet admins: %s; other tailnet peers may only look", strings.Join(server.ParseAdmins(*admins), ", "))
	}
	s, err := server.New(ctx, server.Config{DataDir: *data, AdminToken: strings.TrimSpace(string(tok)), Trust: trusted,
		Tailscale: *tailscale, Admins: server.ParseAdmins(*admins),
		OMT: *omt, OMTSite: *omtSite, OMTPublish: *omtPublish, OMTEvery: *omtEvery,
		BootTimeout: *bootTimeout, NtfyURL: *ntfy, NotifyCmd: *notifyCmd,
		BuilderToken: strings.TrimSpace(string(btok)), ArtifactBudget: *artifactGB << 30}, nil)
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

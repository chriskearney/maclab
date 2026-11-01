// Command lab-loop runs a night of Lab boots of one fault-injecting kernel
// on one Lab-owned Mac, and keeps a ledger of each: what was injected, what
// the lab said, and what a judge reading the evidence said
// (docs/research/agent-loop-week1.md). It uses lab's own login.
//
//	lab-loop --device m1 --kernel <sha256|file|build:ID> --codes loop/chaos-codes.json --judge scripts/loop-judge.sh
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
	"github.com/iconidentify/maclab/internal/loop"
)

var reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func main() {
	device := flag.String("device", "", "the Lab-owned Mac to run the night on")
	kernel := flag.String("kernel", "", "the chaos kernel: an uploaded artifact's sha256, a file to upload, or build:<id> for a finished lab build")
	codesFile := flag.String("codes", "loop/chaos-codes.json", "the codes tools/chaos/apply.sh drew for this kernel's faults; the answer key, never shown to the judge")
	planFlag := flag.String("plan", "", "boots per mode, e.g. none=4,marker=4,hang_late=2 (default: the research doc's 20-boot week 1)")
	seed := flag.Uint64("seed", 0, "shuffle seed, to replay a night's order (default: random, and recorded)")
	ledger := flag.String("ledger", "loop/ledger.jsonl", "JSON Lines file each boot is appended to")
	judge := flag.String("judge", "", "command that judges each finished job (MACLAB_JOB, MACLAB_DEVICE set), e.g. scripts/loop-judge.sh; empty for none")
	judgeTimeout := flag.Duration("judge-timeout", 10*time.Minute, "time one judging may take")
	maxBoots := flag.Int("max-boots", 30, "never boot more than this many times")
	jobTimeout := flag.Duration("job-timeout", 45*time.Minute, "time one job may take, recovery included")
	readyTimeout := flag.Duration("ready-timeout", 20*time.Minute, "time to wait for the Mac to be ready before a boot")
	dry := flag.Bool("dry-run", false, "print the schedule and exit")
	flag.Parse()

	plan := loop.Week1
	if *planFlag != "" {
		p, err := loop.ParsePlan(*planFlag)
		if err != nil {
			log.Fatal(err)
		}
		plan = p
	}
	if *seed == 0 {
		var b [8]byte
		rand.Read(b[:])
		*seed = binary.LittleEndian.Uint64(b[:]) >> 1
	}
	codes, err := readCodes(*codesFile, *dry)
	if err != nil {
		log.Fatal(err)
	}
	boots := loop.Schedule(plan, codes, *seed)
	if len(boots) > *maxBoots {
		boots = boots[:*maxBoots]
	}
	if *dry {
		fmt.Printf("seed %d, %d boots\n", *seed, len(boots))
		for _, b := range boots {
			fmt.Printf("%3d  %-11s %s\n", b.Iter, b.Mode, b.Cmdline)
		}
		return
	}
	if *device == "" || *kernel == "" {
		log.Fatal("need --device and --kernel")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	c, err := client.Load()
	if err != nil {
		log.Fatal(err)
	}
	sha, err := kernelSHA(ctx, c, *kernel)
	if err != nil {
		log.Fatal(err)
	}
	script, err := os.CreateTemp("", "chaos-check-*.sh")
	if err != nil {
		log.Fatal(err)
	}
	script.Write(loop.ChaosCheckScript)
	script.Close()
	defer os.Remove(script.Name())
	check, err := c.Upload(ctx, script.Name())
	if err != nil {
		log.Fatalf("uploading the chaos-check test: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*ledger), 0o755); err != nil {
		log.Fatal(err)
	}

	n := &loop.Night{Lab: c, Ledger: loop.Ledger{Path: *ledger}, Device: *device, Holder: holder(),
		Kernel: sha, ChaosCheck: check, Boots: boots, Seed: *seed,
		JobTimeout: *jobTimeout, ReadyTimeout: *readyTimeout, Poll: 15 * time.Second}
	if *judge != "" {
		n.Judge = loop.CommandJudge{Command: *judge, Timeout: *judgeTimeout,
			Tools: []string{"lab_job", "lab_log", "lab_serial", "lab_device"}}
	}
	log.Printf("lab-loop: %s, %d boots, seed %d, kernel %s, ledger %s", *device, len(boots), *seed, sha[:12], *ledger)
	err = n.Run(ctx)
	switch {
	case err == nil:
		log.Printf("night done: %d boots in %s", len(boots), *ledger)
	case loop.IsStop(err):
		log.Printf("night %v", err)
		os.Exit(2)
	default:
		log.Fatal(err)
	}
}

// readCodes reads apply.sh's codes.json. A dry run without one makes up
// codes, since it only shows the schedule.
func readCodes(path string, dry bool) (loop.Codes, error) {
	data, err := os.ReadFile(path)
	if err != nil && dry && os.IsNotExist(err) {
		codes := loop.Codes{}
		for i, m := range loop.Modes {
			codes[m] = fmt.Sprintf("%016x", i+1)
		}
		return codes, nil
	}
	if err != nil {
		return nil, err
	}
	return loop.ParseCodes(data)
}

// kernelSHA turns --kernel into an uploaded artifact's sha256.
func kernelSHA(ctx context.Context, c *client.Client, k string) (string, error) {
	if id, ok := strings.CutPrefix(k, "build:"); ok {
		b, err := c.GetBuild(ctx, id)
		if err != nil {
			return "", err
		}
		if b.State != api.BuildDone || b.Artifact == "" {
			return "", fmt.Errorf("build %s is %s and has no kernel to boot", b.ID, b.State)
		}
		return b.Artifact, nil
	}
	if reSHA256.MatchString(k) {
		return k, nil
	}
	return c.Upload(ctx, k)
}

func holder() string {
	if h := os.Getenv("MACLAB_HOLDER"); h != "" {
		return h
	}
	name := "someone"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return "lab-loop:" + name
}

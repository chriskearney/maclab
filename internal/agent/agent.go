// Package agent is lab-agent: it runs on each test Mac, heartbeats to labd,
// and executes the commands labd sends.
package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
)

const Version = "0.7.4"

type Config struct {
	Server   string `json:"server"`
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Secret   string `json:"secret"`
	GUIUser  string `json:"gui_user,omitempty"`
	WorkDir  string `json:"work_dir,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) Save(path string) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

type Agent struct {
	cfg  *Config
	sys  System
	http *http.Client
	log  *log.Logger

	repMu             sync.Mutex // one report in flight at a time
	mu                sync.Mutex
	seen              map[string]bool
	running           map[string]bool
	results           []api.CommandResult
	events            []api.KernelEvent
	factsRevision     uint64
	sentFactsRevision uint64
	lastFacts         time.Time
	after             []func() // actions to run once pending results reach labd
	wake              chan struct{}
	life              context.Context // commands outlive the poll that delivered them
	// wd is the watchdog, held on a test boot; nil otherwise, and until the
	// agent has opened it. It is set under mu, with the running tests'
	// budgets (armWatchdog).
	wd atomic.Pointer[labWatchdog]
	// tests are the tests running, under mu, so that a watchdog the agent
	// opens while one runs still holds it to its budget.
	tests []*testRun
	now   func() time.Time // the watchdog's clock; tests stand in for it
}

// testRun is a running test's watchdog budget.
type testRun struct {
	budget time.Duration
	start  time.Time // when its budget started; zero until then
	done   func()    // ends it on the watchdog; nil while the agent holds none
}

func New(cfg *Config, sys System, logger *log.Logger) *Agent {
	if logger == nil {
		logger = log.New(os.Stderr, "lab-agent: ", log.LstdFlags)
	}
	return &Agent{
		cfg:     cfg,
		sys:     sys,
		http:    &http.Client{Timeout: 30 * time.Second},
		log:     logger,
		seen:    map[string]bool{},
		running: map[string]bool{},
		wake:    make(chan struct{}, 1),
		now:     time.Now,
	}
}

// Enroll trades a one-time token for a device identity.
func Enroll(ctx context.Context, server, token string, facts api.Facts) (*api.EnrollResponse, error) {
	var resp api.EnrollResponse
	err := postJSON(ctx, http.DefaultClient, strings.TrimRight(server, "/")+"/api/agent/enroll", "", api.EnrollRequest{Token: token, Facts: facts}, &resp)
	return &resp, err
}

// Run heartbeats until ctx ends. The heartbeat is a long poll: labd holds it
// until it has a command for this Mac, so commands arrive at once. Results and
// kernel events go out on their own request the moment they exist.
func (a *Agent) Run(ctx context.Context) error {
	a.life = ctx
	a.holdWatchdog(ctx)
	go a.sys.WatchKernel(ctx, func(line string) {
		if k := detect.Classify(line); k != "" {
			bootID, _, _ := a.sys.Identity()
			a.mu.Lock()
			if len(a.events) < 500 {
				a.events = append(a.events, api.KernelEvent{Time: time.Now(), Kind: k, Source: "kmsg", BootID: bootID, Line: line})
			}
			a.mu.Unlock()
			a.poke()
		}
	})
	go a.sys.WatchSleep(ctx, a.sleeping)
	go a.reportLoop(ctx)
	var pollMu sync.Mutex
	var pollCancel context.CancelFunc
	if s, ok := a.sys.(*Sim); ok {
		s.OnBoot = func() {
			pollMu.Lock()
			if pollCancel != nil {
				pollCancel()
			}
			pollMu.Unlock()
		}
	}
	for ctx.Err() == nil {
		if !a.sys.Alive() {
			sleepCtx(ctx, 100*time.Millisecond)
			continue
		}
		pctx, cancel := context.WithCancel(ctx)
		pollMu.Lock()
		pollCancel = cancel
		pollMu.Unlock()
		err := a.poll(pctx)
		cancel()
		if pctx.Err() != nil && ctx.Err() == nil {
			continue // the machine rebooted under the long poll
		}
		if err != nil && ctx.Err() == nil {
			a.log.Printf("checkin: %v", err)
			sleepCtx(ctx, 5*time.Second)
		}
	}
	return ctx.Err()
}

// holdWatchdog takes the hardware watchdog on a test boot and feeds it until
// ctx ends, while PID 1 answers and each step is within its budget (see
// watchdog.go). If it can't open it at once, it tries again every
// watchdogRetry, while the agent checks in, until the boot's
// watchdog.open_timeout has passed since the kernel started: until then the
// kernel still pings the watchdog, and opening it keeps a healthy boot up.
// A boot that never opens it is still reset. On a boot whose command line
// leaves the watchdog to systemd (an installed-mode boot), systemd holding it
// is how it should be.
func (a *Agent) holdWatchdog(ctx context.Context) {
	_, _, cmdline := a.sys.Identity()
	if jobTag(cmdline) == "" {
		return
	}
	w, err := a.sys.OpenWatchdog()
	switch {
	case err == nil:
		a.feedWatchdog(ctx, w)
		return
	case errors.Is(err, unix.EBUSY) && !leavesWatchdog(cmdline):
		a.log.Printf("test boot: systemd holds the hardware watchdog and feeds it (this boot's command line leaves it to systemd)")
		return
	}
	deadline, retry := openDeadline(cmdline), watchdogRetry
	stop := time.Now().Add(deadline - watchdogUptime())
	a.log.Printf("test boot: can't open the hardware watchdog yet: %v; trying every %s until %s after boot", err, retry, deadline)
	go func() {
		for time.Now().Before(stop) {
			sleepCtx(ctx, retry)
			if ctx.Err() != nil {
				return
			}
			var w io.Writer
			if w, err = a.sys.OpenWatchdog(); err == nil {
				a.feedWatchdog(ctx, w)
				return
			}
		}
		a.log.Printf("test boot: can't open the hardware watchdog: %v. If it is running and nothing else feeds it, the Mac resets now that watchdog.open_timeout=%d has run out", err, int(deadline/time.Second))
	}()
}

// feedWatchdog holds the opened watchdog w until ctx ends.
func (a *Agent) feedWatchdog(ctx context.Context, w io.Writer) {
	d := newLabWatchdog(w, a.now)
	d.logf = a.log.Printf
	a.armWatchdog(d)
	go d.feed(ctx)
	go d.watchPID1(ctx, a.sys.PingInit)
	a.log.Printf("test boot: holding the hardware watchdog, fed while PID 1 answers and each step is within its budget")
}

// armWatchdog has budgets fed from d from now on. A test already running,
// because the agent opened the watchdog late, gets its budget counted from
// when it started, as it would have had with the watchdog held all along:
// its own timeout counts from then too, so a test past that budget is hung
// where its timeout can't reach it, and the Mac resets at once (within
// watchdogTimeout), while labd still waits for that test and blames it.
// Counting from now would give a hung test a whole budget more, and let
// check-ins carry it past labd's wait. A test whose script is still
// downloading starts its budget once it is in place, as usual.
func (a *Agent) armWatchdog(d *labWatchdog) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wd.Store(d)
	for _, tr := range a.tests {
		if !tr.start.IsZero() {
			tr.done = d.test(tr.start, tr.budget)
			a.log.Printf("test boot: a test was running for %s: it has what is left of its %s budget", a.now().Sub(tr.start).Round(time.Second), tr.budget)
		}
	}
	a.factsRevision++ // labd learns at the next check-in that the agent holds it
}

// beginTest notes a test starting, with its budget yet to start.
func (a *Agent) beginTest(budget time.Duration) *testRun {
	tr := &testRun{budget: budget}
	a.mu.Lock()
	a.tests = append(a.tests, tr)
	a.mu.Unlock()
	return tr
}

// startBudget starts tr's budget now, once: on the watchdog if the agent
// holds it, else on the one it opens later (armWatchdog).
func (a *Agent) startBudget(tr *testRun) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !tr.start.IsZero() {
		return
	}
	tr.start = a.now()
	if d := a.wd.Load(); d != nil {
		tr.done = d.test(tr.start, tr.budget)
	}
}

// endTest ends tr and its budget.
func (a *Agent) endTest(tr *testRun) {
	a.mu.Lock()
	a.tests = slices.DeleteFunc(a.tests, func(o *testRun) bool { return o == tr })
	done := tr.done
	a.mu.Unlock()
	if done != nil {
		done()
	}
}

// quiet tells labd that this boot is about to go off the network for up to
// d, or with d 0 that it is back, and returns once labd has heard it, or
// after a few seconds without.
func (a *Agent) quiet(ctx context.Context, d time.Duration) error {
	bootID, _, _ := a.sys.Identity()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	q := api.Quiet{BootID: bootID, Seconds: int((d + time.Second - 1) / time.Second)}
	return postJSON(ctx, a.http, a.url("/api/agent/report"), a.cfg.Secret, api.Report{Quiet: &q}, nil)
}

// sleeping tells labd the Mac is about to suspend, before it does, and that
// it has resumed. Anything still running (a test that suspends) carries on.
func (a *Agent) sleeping(asleep bool) {
	bootID, _, _ := a.sys.Identity()
	e := api.KernelEvent{Time: time.Now(), Kind: detect.Wake, Source: "logind", BootID: bootID, Line: "resumed from sleep"}
	if asleep {
		e.Kind, e.Line = detect.Sleep, "going to sleep"
	}
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
	a.log.Printf("%s", e.Line)
	if !asleep {
		a.poke() // the network may still be down; reportLoop keeps retrying
		return
	}
	ctx, cancel := context.WithTimeout(a.life, 4*time.Second)
	defer cancel()
	if err := a.report(ctx); err != nil {
		a.log.Printf("could not tell labd before sleeping: %v", err)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (a *Agent) poke() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Agent) poll(ctx context.Context) error {
	bootID, kernel, cmdline := a.sys.Identity()
	ci := api.Checkin{BootID: bootID, Kernel: kernel, Cmdline: cmdline, Health: a.sys.Health()}
	a.mu.Lock()
	factsRevision := a.factsRevision
	refreshFacts := a.lastFacts.IsZero() || a.sentFactsRevision != factsRevision || time.Since(a.lastFacts) >= time.Minute
	for id := range a.running {
		ci.Running = append(ci.Running, id)
	}
	a.mu.Unlock()
	if refreshFacts {
		f := a.sys.Facts()
		f.AgentVersion = Version
		if a.wd.Load() != nil {
			f.WatchdogArmed = true // systemd is off it on a test boot; the agent holds it
		}
		ci.Facts = &f
	}

	var resp api.CheckinResponse
	if err := postJSON(ctx, a.http, a.url("/api/agent/checkin?wait_ms=10000"), a.cfg.Secret, ci, &resp); err != nil {
		return err
	}
	a.wd.Load().idle() // labd is in touch
	a.mu.Lock()
	if ci.Facts != nil {
		// Cleanup can finish while this request is in flight. Acknowledge
		// only the revision sent, so that refresh is not lost.
		a.sentFactsRevision = factsRevision
		a.lastFacts = time.Now()
	}
	a.mu.Unlock()
	for _, c := range resp.Commands {
		a.start(a.life, c)
	}
	return nil
}

func (a *Agent) reportLoop(ctx context.Context) {
	retry := time.NewTicker(3 * time.Second)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.wake:
		case <-retry.C:
		}
		if a.sys.Alive() {
			if err := a.report(ctx); err != nil && ctx.Err() == nil {
				a.log.Printf("report: %v", err)
			}
		}
	}
}

// report sends finished results and new kernel events, then runs any action
// (a reboot) that had to wait until its result reached labd.
func (a *Agent) report(ctx context.Context) error {
	a.repMu.Lock()
	defer a.repMu.Unlock()
	a.mu.Lock()
	rep := api.Report{Results: append([]api.CommandResult(nil), a.results...), Events: append([]api.KernelEvent(nil), a.events...)}
	a.mu.Unlock()
	if len(rep.Results) == 0 && len(rep.Events) == 0 {
		return nil
	}
	if err := postJSON(ctx, a.http, a.url("/api/agent/report"), a.cfg.Secret, rep, nil); err != nil {
		return err
	}
	a.mu.Lock()
	a.results = a.results[len(rep.Results):]
	a.events = a.events[len(rep.Events):]
	var after []func()
	if len(a.results) == 0 {
		after, a.after = a.after, nil
	}
	a.mu.Unlock()
	for _, f := range after {
		f()
	}
	return nil
}

func (a *Agent) start(ctx context.Context, c api.Command) {
	a.mu.Lock()
	if a.seen[c.ID] {
		a.mu.Unlock()
		return
	}
	a.seen[c.ID] = true
	a.running[c.ID] = true
	a.mu.Unlock()
	a.log.Printf("command %s %s job=%s", c.ID, c.Kind, c.JobID)
	a.wd.Load().idle()
	go func() {
		out, after, err := a.exec(ctx, c)
		a.wd.Load().idle()
		r := api.CommandResult{ID: c.ID, OK: err == nil}
		if err != nil {
			r.Error = err.Error()
			a.log.Printf("command %s failed: %v", c.ID, err)
		}
		if out != nil {
			r.Output, _ = json.Marshal(out)
		}
		a.mu.Lock()
		delete(a.running, c.ID)
		a.results = append(a.results, r)
		if after != nil && err == nil {
			a.after = append(a.after, after)
		}
		a.mu.Unlock()
		a.poke()
	}()
}

// exec runs one command. The returned func runs only after the result reaches labd,
// so a reboot never swallows its own acknowledgement.
func (a *Agent) exec(ctx context.Context, c api.Command) (any, func(), error) {
	fetch := a.fetch
	switch c.Kind {
	case api.CmdStage:
		var args api.StageArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		res, err := a.sys.Stage(ctx, c.JobID, args, fetch)
		return res, nil, err
	case api.CmdBootOnce:
		var args api.BootOnceArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		if err := a.sys.BootOnce(args.Entry); err != nil {
			return nil, nil, err
		}
		return nil, a.rebootLater, nil
	case api.CmdReboot:
		return nil, a.rebootLater, nil
	case api.CmdCrash:
		var args api.CrashArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		return nil, func() {
			if err := a.sys.Crash(args.Mode); err != nil {
				a.log.Printf("crash: %v", err)
			}
		}, nil
	case api.CmdRunTest:
		var t api.TestSpec
		if err := json.Unmarshal(c.Args, &t); err != nil {
			return nil, nil, err
		}
		dir, err := a.outDir(c)
		if err != nil {
			return nil, nil, err
		}
		// The test's budget starts once its script is in place, as its own
		// timeout does: until then the download runs on the idle budget. A
		// builtin downloads nothing, Script or not: Builtin wins.
		tr := a.beginTest(testBudget(t))
		if t.Builtin != "" || t.Script == "" {
			a.startBudget(tr)
		}
		res := a.sys.RunTest(ctx, c.JobID, t, func(ctx context.Context, sha, dst string) error {
			defer a.startBudget(tr)
			return fetch(ctx, sha, dst)
		}, a.quiet, dir)
		a.endTest(tr)
		res.Files = a.uploadDir(ctx, c.JobID, "test-"+t.Name, dir)
		return res, nil, nil
	case api.CmdCollect:
		var args api.CollectArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		dir, err := a.outDir(c)
		if err != nil {
			return nil, nil, err
		}
		if err := a.sys.Collect(ctx, args.Boot, dir); err != nil {
			return nil, nil, err
		}
		prefix := "boot0"
		if args.Boot == "-1" {
			prefix = "prevboot"
		}
		return a.uploadDir(ctx, c.JobID, prefix, dir), nil, nil
	case api.CmdCleanup:
		var args api.CleanupArgs
		_ = json.Unmarshal(c.Args, &args)
		err := a.sys.Cleanup(c.JobID, args.All)
		// Even a partial cleanup can change free space and preflight.
		a.mu.Lock()
		a.factsRevision++
		a.mu.Unlock()
		return nil, nil, err
	case api.CmdScreen:
		var args api.ScreenArgs
		_ = json.Unmarshal(c.Args, &args)
		return a.screenshot(ctx, c, args)
	case api.CmdConfig:
		cfg, err := a.sys.KernelConfig()
		return cfg, nil, err
	case api.CmdExec:
		var args api.ExecArgs
		_ = json.Unmarshal(c.Args, &args)
		return a.sys.Exec(ctx, args), nil, nil
	case api.CmdRecordKnownGood:
		var args api.RecordKnownGoodArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		err := a.sys.RecordKnownGood(args.Kernel)
		a.mu.Lock()
		a.factsRevision++ // preflight reads the record
		a.mu.Unlock()
		return nil, nil, err
	case api.CmdLogs:
		var args api.LogsArgs
		_ = json.Unmarshal(c.Args, &args)
		out, err := a.sys.Logs(ctx, args)
		return out, nil, err
	}
	return nil, nil, fmt.Errorf("unknown command %q", c.Kind)
}

func (a *Agent) screenshot(ctx context.Context, c api.Command, args api.ScreenArgs) (any, func(), error) {
	dir, err := a.outDir(c)
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	wait := time.Duration(args.WaitSec) * time.Second
	if wait <= 0 {
		wait = 5 * time.Second
	}
	path := filepath.Join(dir, "screen.jpg")
	w, h, err := a.sys.Screenshot(ctx, path, wait)
	if err != nil {
		return nil, nil, err
	}
	res := api.ScreenResult{Time: time.Now(), Width: w, Height: h}
	if c.JobID != "" {
		label := args.Label
		if label == "" {
			label = res.Time.Format("150405")
		}
		res.Name = "screen/" + label + ".jpg"
		err = a.upload(ctx, c.JobID, res.Name, path)
	} else {
		res.Name, err = a.uploadScreen(ctx, path)
	}
	return res, nil, err
}

func (a *Agent) uploadScreen(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	req, _ := http.NewRequestWithContext(ctx, "POST", a.url("/api/agent/screen"), f)
	req.Header.Set("Authorization", "Bearer "+a.cfg.Secret)
	req.Header.Set("Content-Type", "image/jpeg")
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("screen upload: %s", strings.TrimSpace(string(b)))
	}
	return strings.TrimSpace(string(b)), nil
}

func (a *Agent) rebootLater() {
	a.log.Printf("rebooting")
	if err := a.sys.Reboot(); err != nil {
		a.log.Printf("reboot: %v", err)
	}
}

func (a *Agent) workDir() string {
	if a.cfg.WorkDir != "" {
		return a.cfg.WorkDir
	}
	return "/var/lib/maclab"
}

func (a *Agent) outDir(c api.Command) (string, error) {
	dir := filepath.Join(a.workDir(), "out", c.ID)
	os.RemoveAll(dir)
	return dir, os.MkdirAll(dir, 0o755)
}

func (a *Agent) url(p string) string { return strings.TrimRight(a.cfg.Server, "/") + p }

func (a *Agent) fetch(ctx context.Context, sha, dst string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", a.url("/api/agent/artifacts/"+sha), nil)
	req.Header.Set("Authorization", "Bearer "+a.cfg.Secret)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("artifact %s: %s: %s", sha, resp.Status, strings.TrimSpace(string(b)))
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		return fmt.Errorf("artifact %s: downloaded sha256 %s", sha, got)
	}
	return nil
}

// uploadDir sends every file under dir to labd as prefix/<relpath> and returns the names.
func (a *Agent) uploadDir(ctx context.Context, job, prefix, dir string) []string {
	var names []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		name := prefix + "/" + filepath.ToSlash(rel)
		if err := a.upload(ctx, job, name, p); err != nil {
			a.log.Printf("upload %s: %v", name, err)
			return nil
		}
		names = append(names, name)
		return nil
	})
	os.RemoveAll(dir)
	return names
}

// upload sends one file, retrying for a few minutes: after a resume, Wi-Fi
// takes a while to come back and the first attempts fail.
func (a *Agent) upload(ctx context.Context, job, name, path string) error {
	var err error
	wait := 2 * time.Second
	for try := 0; ; try++ {
		if err = a.uploadOnce(ctx, job, name, path); err == nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, errRefused) || try >= 8 {
			return err
		}
		a.log.Printf("upload %s: %v; retrying in %s", name, err, wait)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

func (a *Agent) uploadOnce(ctx context.Context, job, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	q := url.Values{"job": {job}, "name": {name}}
	req, _ := http.NewRequestWithContext(ctx, "POST", a.url("/api/agent/upload?"+q.Encode()), f)
	req.Header.Set("Authorization", "Bearer "+a.cfg.Secret)
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return fmt.Errorf("%w: %s", errRefused, resp.Status)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

// errRefused is labd turning a request down; trying again won't help.
var errRefused = errors.New("refused")

func postJSON(ctx context.Context, c *http.Client, u, secret string, in, out any) error {
	b, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

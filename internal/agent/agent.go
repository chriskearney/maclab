// Package agent is lab-agent: it runs on each test Mac, heartbeats to labd,
// and executes the commands labd sends.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/detect"
	"github.com/iconidentify/maclab/internal/labhttp"
)

const Version = "0.8.0"

type Config struct {
	Server   string `json:"server"`
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Secret   string `json:"secret"`
	GUIUser  string `json:"gui_user,omitempty"`
	WorkDir  string `json:"work_dir,omitempty"`
	// Enrollment is what labd said the Mac is, at setup.
	Enrollment api.AgentEnrollment `json:"enrollment"`
	// HTTPTimeoutSec bounds a check-in or report request, TransferTimeoutSec an
	// upload; a Mac far from labd needs both longer. Zero is the default.
	HTTPTimeoutSec     int `json:"http_timeout_sec,omitempty"`
	TransferTimeoutSec int `json:"transfer_timeout_sec,omitempty"`
	// ServerCA is PEM certificates trusted for labd's https besides the
	// system's (setup --ca-file). AllowPlainHTTP is whether an http:// labd on
	// another machine is allowed (setup --allow-plain-http); setup always
	// writes it, and its absence means agent.json predates https support
	// (see transport.go).
	ServerCA       string `json:"server_ca,omitempty"`
	AllowPlainHTTP *bool  `json:"allow_plain_http,omitempty"`
	// Clock is where lab-agent reads time; nil is the wall clock.
	Clock Clock `json:"-"`
}

func (c *Config) workDir() string {
	if c.WorkDir != "" {
		return c.WorkDir
	}
	return "/var/lib/maclab"
}

func (c *Config) clock() Clock {
	if c.Clock == nil {
		return WallClock
	}
	return c.Clock
}

func (c *Config) httpTimeout() time.Duration {
	if c.HTTPTimeoutSec > 0 {
		return time.Duration(c.HTTPTimeoutSec) * time.Second
	}
	return 2 * time.Minute
}

func (c *Config) transferTimeout() time.Duration {
	if c.TransferTimeoutSec > 0 {
		return time.Duration(c.TransferTimeoutSec) * time.Second
	}
	return 30 * time.Minute
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

// Save writes c to path in one rename, so a crash leaves the old file or the
// new one, never half of either.
func (c *Config) Save(path string) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return replaceFile(path, b)
}

type Agent struct {
	cfg  *Config
	sys  System
	rt   http.RoundTripper // every request to labd, with cfg's policy
	http *http.Client
	log  *log.Logger

	repMu             sync.Mutex // one report in flight at a time
	mu                sync.Mutex
	seen              map[string]bool
	running           map[string]runningCmd
	results           []api.CommandResult
	events            []api.KernelEvent
	factsRevision     uint64
	sentFactsRevision uint64
	lastFacts         time.Time
	after             []func() // actions to run once pending results reach labd
	contacted         string   // the Lab boot whose contact with labd is on record
	kind              string   // the Mac's kind, as labd's check-ins say
	held              bool     // a job or lease holds the Mac, as labd's latest answer says
	auditSent         int64    // how much of the Audit log labd's copy holds, in bytes
	awake             awakeHold
	wake              chan struct{}
	life              context.Context    // commands outlive the poll that delivered them
	stop              context.CancelFunc // ends Run: the Mac left the lab
	endedOnce         sync.Once
	hasLeft           atomic.Bool
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
	rt := cfg.transport()
	if _, legacy := cfg.transportPolicy(); legacy {
		logger.Print(legacyPlainWarning(cfg.Server))
	}
	return &Agent{
		cfg:     cfg,
		sys:     sys,
		rt:      rt,
		http:    labhttp.Client(rt, cfg.httpTimeout()),
		log:     logger,
		seen:    map[string]bool{},
		running: map[string]runningCmd{},
		wake:    make(chan struct{}, 1),
		now:     time.Now,
	}
}

func (a *Agent) clock() Clock { return a.cfg.clock() }

// Enroll trades a one-time token for a device identity, for a simulated Mac
// and tests: it reads labd's participation terms and accepts them, as the
// Mac's owner does at setup by typing yes, with a new activation key. It
// trusts the system's roots and allows plain http to loopback only.
func Enroll(ctx context.Context, server, token string, facts api.Facts) (*api.EnrollResponse, error) {
	var sum string
	if t, err := FetchTerms(ctx, server, token, labhttp.Policy{}); err == nil {
		sum = t.SHA256
	}
	return EnrollWith(ctx, server, token, facts, labhttp.Policy{}, Activation{Key: NewActivationKey(), TermsSHA256: sum})
}

// EnrollWith trades a one-time token for a device identity, reaching labd as
// p says, with act's activation key and accepted terms.
func EnrollWith(ctx context.Context, server, token string, facts api.Facts, p labhttp.Policy, act Activation) (*api.EnrollResponse, error) {
	if err := labhttp.CheckServer(server, p.AllowPlainHTTP); err != nil {
		return nil, err
	}
	c, err := p.Client(0)
	if err != nil {
		return nil, err
	}
	var resp api.EnrollResponse
	err = postJSON(ctx, c, strings.TrimRight(server, "/")+"/api/agent/enroll", "",
		api.EnrollRequest{Token: token, Facts: facts, ActivationKey: act.Key, TermsSHA256: act.TermsSHA256}, &resp)
	return &resp, err
}

// Run heartbeats until ctx ends. The heartbeat is a long poll: labd holds it
// until it has a command for this Mac, so commands arrive at once. Results and
// kernel events go out on their own request the moment they exist.
func (a *Agent) Run(ctx context.Context) error {
	ctx, a.stop = context.WithCancel(ctx)
	defer a.stop()
	a.life = ctx
	a.holdWatchdog(ctx)
	go a.sys.WatchKernel(ctx, func(line string) {
		if k := detect.Classify(line); k != "" {
			bootID, _, _ := a.sys.Identity()
			a.mu.Lock()
			if len(a.events) < 500 {
				a.events = append(a.events, api.KernelEvent{Time: a.clock().Now(), Kind: k, Source: "kmsg", BootID: bootID, Line: line})
			}
			a.mu.Unlock()
			a.poke()
		}
	})
	go a.sys.WatchSleep(ctx, a.sleeping)
	go a.reportLoop(ctx)
	go a.watchWindow(ctx)
	go a.watchLeft(ctx)
	var pollMu sync.Mutex
	var pollCancel context.CancelFunc
	var pollRebooted bool // the reboot, not a failure, cancelled the poll
	if s, ok := a.sys.(*Sim); ok {
		s.OnBoot = func() {
			pollMu.Lock()
			if pollCancel != nil {
				pollRebooted = true
				pollCancel()
			}
			pollMu.Unlock()
		}
		s.setEarlyUnit(func(ctx context.Context) {
			if err := enforceLabBootDeadlines(ctx, a.clock(), a.workDir(), s, a.log.Printf); err != nil {
				a.log.Printf("Lab boot deadlines: %v", err)
			}
		})
	}
	for ctx.Err() == nil {
		if a.hasLeft.Load() {
			sleepCtx(ctx, a.clock(), 100*time.Millisecond) // no more check-ins: the Mac left
			continue
		}
		if !a.sys.Alive() {
			sleepCtx(ctx, a.clock(), 100*time.Millisecond)
			continue
		}
		pctx, cancel := context.WithCancel(ctx)
		pollMu.Lock()
		pollCancel = cancel
		pollRebooted = false
		pollMu.Unlock()
		err := a.poll(pctx)
		pollMu.Lock()
		rebooted := pollRebooted
		pollMu.Unlock()
		cancel()
		if by, ok := endedBy(err); ok {
			a.enrollmentEnded(by)
			continue
		}
		if rebooted && ctx.Err() == nil {
			continue // the machine rebooted under the long poll
		}
		if err != nil && ctx.Err() == nil {
			a.log.Printf("checkin: %v%s", err, certTimeHint(err, a.clock().Now()))
			sleepCtx(ctx, a.clock(), 5*time.Second)
		}
	}
	if a.hasLeft.Load() {
		return nil
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
			sleepCtx(ctx, WallClock, retry) // against the real uptime, as stop is
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
	e := api.KernelEvent{Time: a.clock().Now(), Kind: detect.Wake, Source: "logind", BootID: bootID, Line: "resumed from sleep"}
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

func sleepCtx(ctx context.Context, c Clock, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-c.After(d):
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
	ci := api.Checkin{BootID: bootID, Kernel: kernel, Cmdline: cmdline, Health: a.sys.Health(),
		SnapshotEligible: a.sys.SnapshotEligible() == nil}
	a.mu.Lock()
	factsRevision := a.factsRevision
	refreshFacts := a.lastFacts.IsZero() || a.sentFactsRevision != factsRevision || a.clock().Now().Sub(a.lastFacts) >= time.Minute
	for id := range a.running {
		ci.Running = append(ci.Running, id)
	}
	a.mu.Unlock()
	// A Volunteer's Mac with no settings sends empty ones, so labd's copy
	// never outlives a deleted file. One that can't be read sends none: the
	// agent refuses lab commands while it can't read them anyway.
	if s, set, err := loadWindow(a.cfg); err != nil {
		a.log.Printf("Availability window: %v", err)
	} else if set || a.volunteer() {
		ci.Window = &s
	}
	if a.volunteer() {
		if u, err := loadNtfyTopic(a.cfg); err != nil {
			a.log.Printf("ntfy topic: %v", err)
		} else {
			ci.NtfyOwnURL = u
		}
		if on, err := loadJobNotices(a.cfg); err != nil {
			a.log.Printf("job notices: %v", err)
		} else {
			ci.JobNotices = &on
		}
		if ac, err := loadAccess(a.workDir()); err != nil {
			a.log.Printf("Access level: %v", err) // labd keeps its last copy; the agent reads it as Qualification
		} else {
			ci.AccessLevel, ci.Publish = ac.Level, ac.Publish
		}
	}
	if refreshFacts {
		f := a.sys.Facts()
		f.AgentVersion = Version
		_, f.MesaStaged = a.sys.(interface {
			StageMesa(context.Context, string, api.MesaStageArgs, Fetcher) (api.MesaStageResult, error)
		})
		f.MesaOfficial = false // integrated source remains disabled until explicit runtime qualification
		if a.wd.Load() != nil {
			f.WatchdogArmed = true // systemd is off it on a test boot; the agent holds it
		}
		ci.Facts = &f
	}

	// A Lab boot's first check-in doesn't wait: its no-contact deadline lifts
	// only once the answer is back.
	wait := 10000
	a.mu.Lock()
	if IsLabBoot(cmdline) && a.contacted != bootID {
		wait = 0
	}
	a.mu.Unlock()
	var resp api.CheckinResponse
	if err := postJSON(ctx, a.http, a.url(fmt.Sprintf("/api/agent/checkin?wait_ms=%d", wait)), a.cfg.Secret, ci, &resp); err != nil {
		return err
	}
	a.wd.Load().idle() // labd is in touch
	a.reachedLabd(bootID, cmdline)
	a.keepAwake()
	a.mu.Lock()
	a.kind, a.held, a.auditSent = resp.Kind, resp.Held, resp.AuditHave
	if ci.Facts != nil {
		// Cleanup can finish while this request is in flight. Acknowledge
		// only the revision sent, so that refresh is not lost.
		a.sentFactsRevision = factsRevision
		a.lastFacts = a.clock().Now()
	}
	a.mu.Unlock()
	for _, c := range resp.Commands {
		a.start(a.life, c)
	}
	return nil
}

func (a *Agent) reportLoop(ctx context.Context) {
	retry := a.clock().NewTicker(3 * time.Second)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.wake:
		case <-retry.C():
		}
		if a.sys.Alive() {
			if err := a.report(ctx); err != nil && ctx.Err() == nil {
				if by, ok := endedBy(err); ok {
					a.enrollmentEnded(by)
					continue
				}
				a.log.Printf("report: %v", err)
			}
		}
	}
}

// report sends finished results and new kernel events, then runs any action
// (a reboot) that had to wait until its result reached labd. A report labd
// refuses as too large (413) goes again one item at a time (sendEach), so
// one oversized result can't hold up everything after it.
func (a *Agent) report(ctx context.Context) error {
	a.repMu.Lock()
	defer a.repMu.Unlock()
	a.mu.Lock()
	rep := api.Report{Results: append([]api.CommandResult(nil), a.results...), Events: append([]api.KernelEvent(nil), a.events...)}
	auditSent := a.auditSent
	a.mu.Unlock()
	if a.volunteer() {
		var err error
		if rep.Audit, err = readAudit(a.workDir(), auditSent, 200); err != nil {
			a.log.Printf("Audit log: %v", err)
		}
	}
	if len(rep.Results) == 0 && len(rep.Events) == 0 && len(rep.Audit) == 0 {
		return nil
	}
	err := a.post(ctx, rep)
	audited := err == nil
	switch {
	case tooLarge(err):
		err = a.sendEach(ctx, rep)
	case err == nil:
		a.reported(len(rep.Results), len(rep.Events))
	}
	if err != nil {
		return err
	}
	a.mu.Lock()
	// sendEach sends no Audit log: it goes with the next whole report.
	if n := len(rep.Audit); n > 0 && audited && rep.Audit[n-1].End > a.auditSent {
		a.auditSent = rep.Audit[n-1].End
	}
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

func (a *Agent) post(ctx context.Context, rep api.Report) error {
	return postJSON(ctx, a.http, a.url("/api/agent/report"), a.cfg.Secret, rep, nil)
}

// reported takes the first n results and m events off the queue: labd has
// them. Only report, under repMu, takes any off, so they are the ones it sent.
func (a *Agent) reported(n, m int) {
	a.mu.Lock()
	a.results, a.events = a.results[n:], a.events[m:]
	a.mu.Unlock()
}

// reportFieldMax is how much of each long text in a result (a test's tail, a
// command's output, a journal) is kept when labd refuses the result as too
// large: its last reportFieldMax bytes. Tests shrink it.
var reportFieldMax = 1 << 20

// cutNote starts every text cut down to reportFieldMax.
const cutNote = "[truncated by lab-agent: report too large]\n"

// sendEach sends rep's results and events in reports of one each, after
// labd refused rep as too large, taking each off the queue as labd takes
// it. One still too large goes once more with its long texts cut down
// (cutResult); if labd refuses that too, it is dropped. A dropped result
// is replaced by a failed one that says why, so that what labd waits on (a
// test) still ends.
func (a *Agent) sendEach(ctx context.Context, rep api.Report) error {
	alone := len(rep.Results)+len(rep.Events) == 1 // refused already, by itself
	for _, r := range rep.Results {
		if err := a.sendResult(ctx, r, alone); err != nil {
			return err
		}
		a.reported(1, 0)
	}
	for _, e := range rep.Events {
		if err := a.sendEvent(ctx, e, alone); err != nil {
			return err
		}
		a.reported(0, 1)
	}
	return nil
}

// sendResult sends one result: as it is unless labd refused it as too large
// already, then cut down, then as a failed result in its place. It returns
// an error only for a send that may work if tried again.
func (a *Agent) sendResult(ctx context.Context, r api.CommandResult, refused bool) error {
	send := func(r api.CommandResult) error { return a.post(ctx, api.Report{Results: []api.CommandResult{r}}) }
	if !refused {
		if err := send(r); !tooLarge(err) {
			return err
		}
	}
	size := len(r.Output) + len(r.Error)
	if c, ok := cutResult(r); ok {
		a.log.Printf("report: labd refused the result of command %s (%d bytes) as too large; sending it with its long texts cut down", r.ID, size)
		if err := send(c); !tooLarge(err) {
			return err
		}
	}
	a.log.Printf("report: error: labd refused the result of command %s (%d bytes) as too large even cut down; dropping it", r.ID, size)
	err := send(api.CommandResult{ID: r.ID, Error: fmt.Sprintf("lab-agent dropped this command's result (%d bytes): labd refused it as too large, "+
		"even with its long texts cut down to their last %d bytes", size, reportFieldMax)})
	if tooLarge(err) {
		return nil // nothing smaller to send
	}
	return err
}

// sendEvent sends one kernel event, as sendResult sends a result; labd needs
// no word of one it doesn't get.
func (a *Agent) sendEvent(ctx context.Context, e api.KernelEvent, refused bool) error {
	send := func(e api.KernelEvent) error { return a.post(ctx, api.Report{Events: []api.KernelEvent{e}}) }
	if !refused {
		if err := send(e); !tooLarge(err) {
			return err
		}
	}
	if len(e.Line) > reportFieldMax {
		c := e
		c.Line = cutText(e.Line)
		if err := send(c); !tooLarge(err) {
			return err
		}
	}
	a.log.Printf("report: error: labd refused a %s kernel event (%d bytes) as too large; dropping it", e.Kind, len(e.Line))
	return nil
}

// cutResult is r with each text longer than reportFieldMax, its error and
// any string in its output, cut down to its end, after cutNote. ok is false
// when r has no such text.
func cutResult(r api.CommandResult) (api.CommandResult, bool) {
	cut := false
	if len(r.Error) > reportFieldMax {
		r.Error, cut = cutText(r.Error), true
	}
	if len(r.Output) > reportFieldMax {
		d := json.NewDecoder(bytes.NewReader(r.Output))
		d.UseNumber() // numbers go back as they came
		var v any
		if d.Decode(&v) == nil {
			if v, ok := cutTexts(v); ok {
				if b, err := json.Marshal(v); err == nil {
					r.Output, cut = b, true
				}
			}
		}
	}
	return r, cut
}

// cutTexts cuts down each string longer than reportFieldMax in v, decoded
// JSON, and says whether there was one.
func cutTexts(v any) (any, bool) {
	cut := false
	switch v := v.(type) {
	case string:
		if len(v) > reportFieldMax {
			return cutText(v), true
		}
	case []any:
		for i := range v {
			var c bool
			v[i], c = cutTexts(v[i])
			cut = cut || c
		}
	case map[string]any:
		for k := range v {
			var c bool
			v[k], c = cutTexts(v[k])
			cut = cut || c
		}
	}
	return v, cut
}

// cutText is cutNote and the last reportFieldMax bytes of s, from the start
// of a character.
func cutText(s string) string {
	t := s[len(s)-reportFieldMax:]
	for len(t) > 0 && !utf8.RuneStart(t[0]) {
		t = t[1:]
	}
	return cutNote + t
}

// runningCmd is a command lab-agent is executing.
type runningCmd struct {
	c      api.Command
	stop   context.CancelCauseFunc
	bootID string // the boot it runs on
}

func (a *Agent) start(ctx context.Context, c api.Command) {
	a.mu.Lock()
	if a.seen[c.ID] {
		a.mu.Unlock()
		return
	}
	a.seen[c.ID] = true
	ctx, stop := context.WithCancelCause(ctx)
	bootID, _, _ := a.sys.Identity()
	a.running[c.ID] = runningCmd{c: c, stop: stop, bootID: bootID}
	a.mu.Unlock()
	a.keepAwake()
	a.log.Printf("command %s %s job=%s", c.ID, c.Kind, c.JobID)
	a.wd.Load().idle()
	go func() {
		defer stop(nil)
		out, after, err := a.exec(ctx, c)
		a.wd.Load().idle()
		if cause := context.Cause(ctx); err != nil && errors.Is(cause, errStoppedAtWindowClose) {
			err = cause // whatever the command made of being stopped
		}
		if cause := context.Cause(ctx); errors.Is(cause, errAccessLevel) {
			err = cause // a test stopped this way ends the job, not the test alone
		}
		r := api.CommandResult{ID: c.ID, OK: err == nil,
			WindowClosed: errors.Is(err, errRefusedOutsideWindow) || errors.Is(err, errStoppedAtWindowClose),
			AccessLevel:  errors.Is(err, errAccessLevel)}
		if err != nil {
			r.Error = err.Error()
			a.log.Printf("command %s failed: %v", c.ID, err)
		}
		if out != nil {
			r.Output, _ = json.Marshal(out)
		}
		// A command whose boot ended died with it, as it does on a real Mac:
		// labd already counts it lost.
		now, _, _ := a.sys.Identity()
		a.mu.Lock()
		delete(a.running, c.ID)
		if now == bootID {
			a.results = append(a.results, r)
			if after != nil && err == nil {
				a.after = append(a.after, after)
			}
		}
		a.mu.Unlock()
		a.keepAwake()
		a.poke()
	}()
}

// exec runs one command. The returned func runs only after the result reaches labd,
// so a reboot never swallows its own acknowledgement.
func (a *Agent) exec(ctx context.Context, c api.Command) (any, func(), error) {
	refused := a.refuseOutsideWindow(c)
	if refused == nil {
		refused = a.refuseByAccess(c)
	}
	if err := a.audit(ctx, c, refused); err != nil {
		return nil, nil, err
	}
	if refused != nil {
		return nil, nil, refused
	}
	fetch := a.fetch
	switch c.Kind {
	case api.CmdMesaStage:
		var args api.MesaStageArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		ms, ok := a.sys.(interface {
			StageMesa(context.Context, string, api.MesaStageArgs, Fetcher) (api.MesaStageResult, error)
		})
		if !ok {
			return nil, nil, errors.New("agent system has no staged Mesa support")
		}
		res, err := ms.StageMesa(ctx, c.JobID, args, fetch)
		return res, nil, err
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
		if err := a.warnBeforeReboot(ctx, c, args); err != nil {
			return nil, nil, err
		}
		if err := a.armLabBoot(args); err != nil {
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
	case api.CmdInstall:
		var args api.InstallArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		if err := checkInstall(args); err != nil {
			return nil, nil, err
		}
		err := a.sys.Install(ctx, c.JobID, args, fetch)
		a.mu.Lock()
		a.factsRevision++ // preflight reads the installed kernels
		a.mu.Unlock()
		return nil, nil, err
	case api.CmdCollect:
		var args api.CollectArgs
		if err := json.Unmarshal(c.Args, &args); err != nil {
			return nil, nil, err
		}
		prefix := "boot0"
		if args.Boot == "-1" {
			prefix = "prevboot"
		}
		if args.Dir != "" {
			if !reCollectDir.MatchString(args.Dir) {
				return nil, nil, fmt.Errorf("bad collect dir %q", args.Dir)
			}
			prefix = args.Dir
		}
		dir, err := a.outDir(c)
		if err != nil {
			return nil, nil, err
		}
		if err := a.sys.Collect(ctx, args.Boot, dir); err != nil {
			return nil, nil, err
		}
		return a.uploadDir(ctx, c.JobID, prefix, dir), nil, nil
	case api.CmdCollectLost:
		dir, err := a.outDir(c)
		if err != nil {
			return nil, nil, err
		}
		return a.collectLost(ctx, c.JobID, dir), nil, nil
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

// reCollectDir is a job directory labd may collect logs into.
var reCollectDir = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

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
	res := api.ScreenResult{Time: a.clock().Now(), Width: w, Height: h}
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
	resp, err := labhttp.Client(a.rt, a.cfg.transferTimeout()).Do(req)
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

func (a *Agent) labBootDir() string { return filepath.Join(a.workDir(), labBootDir) }

// armLabBoot writes the deadline record the early unit enforces on the Lab
// boot labd is about to start, and forgets the last one.
func (a *Agent) armLabBoot(args api.BootOnceArgs) error {
	if args.BootTimeoutSec <= 0 || args.JobSec <= 0 {
		return errors.New("a Lab boot needs its deadlines: boot_timeout_sec and job_sec")
	}
	now := a.clock().Now()
	// The ceiling is the job's end, or on a Volunteer's Mac the Availability
	// window's end if that comes first.
	jobEnd := a.capAtWindowEnd(now.Add(time.Duration(args.JobSec) * time.Second))
	d := newLabBootDeadlines(now, time.Duration(args.BootTimeoutSec)*time.Second, jobEnd)
	d.WindowGated = a.volunteer()
	d.NeedsFull = a.volunteer() && testsNeedFull(args.Tests)
	dir := a.labBootDir()
	for _, f := range []string{labBootContactFile, labBootSeenFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("forget the last Lab boot: %w", err)
		}
	}
	if err := writeLabBootDeadlines(filepath.Join(dir, labBootDeadlineFile), d); err != nil {
		return fmt.Errorf("deadline record: %w", err)
	}
	a.log.Printf("Lab boot deadlines: no contact %s, ceiling %s", d.NoContact.Format(time.RFC3339), d.Ceiling.Format(time.RFC3339))
	return nil
}

// reachedLabd records that a Lab boot has reached labd, which lifts its
// no-contact deadline.
func (a *Agent) reachedLabd(bootID, cmdline string) {
	a.mu.Lock()
	done := a.contacted == bootID
	a.mu.Unlock()
	if done || !IsLabBoot(cmdline) {
		return
	}
	if err := os.MkdirAll(a.labBootDir(), 0o755); err != nil {
		a.log.Printf("Lab boot contact: %v", err)
		return
	}
	if err := writeAtomic(filepath.Join(a.labBootDir(), labBootContactFile), []byte(bootID+"\n")); err != nil {
		a.log.Printf("Lab boot contact: %v", err)
		return
	}
	a.mu.Lock()
	a.contacted = bootID
	a.mu.Unlock()
}

// collectLost uploads what is left of the Lab boot the Mac came back from: its
// journal by boot ID and any pstore/ramoops records, and says whether the
// early unit rebooted it at a deadline.
func (a *Agent) collectLost(ctx context.Context, job, dir string) api.LostBoot {
	var lost api.LostBoot
	ld := a.labBootDir()
	d, _ := readLabBootDeadlines(filepath.Join(ld, labBootDeadlineFile)) // none: any previous boot will do
	var seen labBootSeen
	if b, err := os.ReadFile(filepath.Join(ld, labBootSeenFile)); err == nil {
		if err := json.Unmarshal(b, &seen); err != nil {
			a.log.Printf("lost boot: %s: %v", labBootSeenFile, err)
		}
	}
	lost.BootID, lost.Deadline = seen.BootID, seen.Deadline
	if lost.BootID == "" {
		// The early unit never ran: the Lab boot went down before userspace.
		lost.BootID = a.sys.PreviousBoot(d.Armed)
	}
	// Whatever is missing, labd still needs to hear how the boot ended.
	if lost.BootID != "" {
		if err := a.sys.Collect(ctx, lost.BootID, dir); err != nil {
			a.log.Printf("lost boot %s: journal: %v", lost.BootID, err)
		}
	}
	if _, err := a.sys.CollectPstore(d.Armed, filepath.Join(dir, "pstore")); err != nil {
		a.log.Printf("lost boot %s: pstore: %v", lost.BootID, err)
	}
	lost.Files = a.uploadDir(ctx, job, "prevboot", dir)
	return lost
}

func (a *Agent) rebootLater() {
	a.log.Printf("rebooting")
	if err := a.sys.Reboot(); err != nil {
		a.log.Printf("reboot: %v", err)
	}
}

func (a *Agent) workDir() string { return a.cfg.workDir() }

func (a *Agent) outDir(c api.Command) (string, error) {
	dir := filepath.Join(a.workDir(), "out", c.ID)
	os.RemoveAll(dir)
	return dir, os.MkdirAll(dir, 0o755)
}

func (a *Agent) url(p string) string { return strings.TrimRight(a.cfg.Server, "/") + p }

// fetch downloads an artifact to dst, resuming with a Range request when the
// transfer drops: over a slow link a long download rarely survives one try. The
// bytes so far wait in dst+".part" until the whole file matches its sha256.
func (a *Agent) fetch(ctx context.Context, sha, dst string) error {
	part := dst + ".part"
	var err error
	wait := time.Second
	for try := 0; ; try++ {
		var permanent bool
		if permanent, err = a.fetchOnce(ctx, sha, part); err == nil {
			return os.Rename(part, dst)
		}
		if permanent || ctx.Err() != nil || try >= 8 {
			return err
		}
		a.log.Printf("fetch %s: %v; resuming in %s", short(sha), err, wait)
		select {
		case <-ctx.Done():
			return err
		case <-a.clock().After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

func short(s string) string { return s[:min(len(s), 12)] }

// fetchOnce continues the download in part. permanent means retrying can't help.
func (a *Agent) fetchOnce(ctx context.Context, sha, part string) (permanent bool, err error) {
	have := int64(0)
	if fi, err := os.Stat(part); err == nil {
		have = fi.Size()
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", a.url("/api/agent/artifacts/"+sha), nil)
	req.Header.Set("Authorization", "Bearer "+a.cfg.Secret)
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, err := labhttp.Client(a.rt, 0).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	flags := os.O_WRONLY | os.O_CREATE
	switch {
	case resp.StatusCode == http.StatusPartialContent:
		flags |= os.O_APPEND
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		// The partial file is as long as the artifact or longer: check it as it is.
		have = -1
	case resp.StatusCode == http.StatusOK:
		flags |= os.O_TRUNC // labd ignored the Range: start over
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp.StatusCode < 500, fmt.Errorf("artifact %s: %s: %s", sha, resp.Status, strings.TrimSpace(string(b)))
	}
	if have >= 0 {
		f, err := os.OpenFile(part, flags, 0o644)
		if err != nil {
			return true, err
		}
		_, err = io.Copy(f, resp.Body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return false, err
		}
	}
	got, err := fileSHA256(part)
	if err != nil {
		return true, err
	}
	if got != sha {
		os.Remove(part)
		// A bad prefix from an earlier attempt is gone now: one more go from the start.
		return have == 0, fmt.Errorf("artifact %s: downloaded sha256 %s", sha, got)
	}
	return false, nil
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
		case <-a.clock().After(wait):
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
	resp, err := labhttp.Client(a.rt, a.cfg.transferTimeout()).Do(req)
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

// statusError is labd answering with a status other than 200.
type statusError struct {
	Code   int
	Header http.Header
	msg    string // the status and what labd said
}

func (e *statusError) Error() string { return e.msg }

func postJSON(ctx context.Context, c *http.Client, u, secret string, in, out any) error {
	b, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return doJSON(c, req, secret, out)
}

func getJSON(ctx context.Context, c *http.Client, u, secret string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	return doJSON(c, req, secret, out)
}

func doJSON(c *http.Client, req *http.Request, secret string, out any) error {
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
		return &statusError{Code: resp.StatusCode, Header: resp.Header, msg: fmt.Sprintf("%s: %s", resp.Status, strings.TrimSpace(string(body)))}
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// tooLarge reports whether labd refused a request as too large (413).
func tooLarge(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.Code == http.StatusRequestEntityTooLarge
}

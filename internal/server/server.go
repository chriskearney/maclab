// Package server is labd: the controller that owns devices, leases, jobs
// and the recovery ladder. Agents, the lab CLI and the MCP bridge talk to it over HTTP.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/oob"
	"github.com/iconidentify/maclab/internal/web"
)

type Config struct {
	DataDir string
	// FirstMaintainer and FirstMaintainerToken name the Maintainer a labd
	// with none starts with: on upgrade, whoever held the old admin token.
	FirstMaintainer      string
	FirstMaintainerToken string
	Interval             time.Duration // agent heartbeat interval
	BootTimeout          time.Duration // default time for a Mac to come back after a reboot
	OfflineAfter         time.Duration
	// AliveWindow and QuietGrace are timeouts that assume a LAN, as
	// StageTimeout below does; a Mac far from labd needs them longer. Zero
	// keeps the LAN default; labd's flags default to remote-sized values.
	AliveWindow time.Duration // how stale a heartbeat may be before a Mac counts unresponsive
	QuietGrace  time.Duration // silence on the same boot before a command counts lost
	// WatchdogOpenTimeout is watchdog.open_timeout on every Lab boot's command
	// line; 0 leaves it to lab-agent: half the job's boot timeout, at least
	// 120 s.
	WatchdogOpenTimeout time.Duration
	// RebootWarning is how long before a Volunteer job's first reboot its Mac
	// shows the Volunteer a notice, and how long the job waits after it; 0 is
	// no notice and no wait. labd's flag defaults to 5m.
	RebootWarning time.Duration
	NtfyURL       string
	NotifyCmd     string
	// Tailscale lets tailnet peers look at the lab by identity; only a
	// Maintainer's token changes it.
	Tailscale bool
	// WhoIs names the peer behind a tailnet address; tests swap in fakes.
	WhoIs func(ctx context.Context, ip string) (*TailnetPeer, error)
	// AllowHosts are names labd answers to besides its own (--allow-host):
	// access without a token counts only on a request to one of labd's
	// names (see ownHost).
	AllowHosts []string
	// TailnetNames looks up this machine's MagicDNS names, with Tailscale
	// on; tests swap in fakes, and nil looks up none.
	TailnetNames func(ctx context.Context) ([]string, error)
	// OOBFactory builds a controller for a device; tests swap in fakes.
	OOBFactory func(*api.Device) (oob.Controller, error)
	// BuilderToken authenticates builder hosts; empty disables builds.
	BuilderToken string
	// ArtifactBudget caps the artifact store; unreferenced artifacts go first.
	ArtifactBudget int64
	// OMT runs omarchy-m-test in every job on Macs with a desktop user.
	OMT bool
	// OMTSite is where omarchy-m-test reports are published; empty never publishes.
	OMTSite string
	// OMTPublish publishes known-good runs (baselines and scheduled runs) by itself.
	OMTPublish bool
	// OMTEvery re-runs omarchy-m-test on each idle Mac's known-good kernel this often; 0 never.
	OMTEvery time.Duration
	// StageTimeout is how long labd waits for one staging attempt (default 20
	// minutes). Tests shorten it.
	StageTimeout time.Duration
	// TestGrace is how long past a test's timeout labd waits for its result
	// (default 2 minutes); GUIGrace is how much longer for a GUI test (default
	// 2 minutes, see guiWait). Tests shorten them.
	TestGrace, GUIGrace time.Duration
	// AgentBinary is the linux/arm64 lab-agent that ./volunteer and the join
	// command download.
	AgentBinary string
	// PublicURL is the URL people and Macs reach labd at, its path being
	// labd's prefix (--public-url, see edge.go). Nil serves at / and takes
	// each request's own origin.
	PublicURL *url.URL
	// TrustedProxies are the reverse proxies in front of labd
	// (--trusted-proxy, see edge.go). They need PublicURL, and rule out
	// Tailscale, whose identities are TCP peers.
	TrustedProxies []netip.Prefix
	// Terms is what a Mac's owner accepts before it joins the lab; empty is
	// DefaultTerms (see terms.go).
	Terms string
	// Clock is where labd reads time; nil is the wall clock.
	Clock agent.Clock
}

type Server struct {
	cfg   Config
	store *store
	log   *log.Logger
	ctx   context.Context
	start time.Time

	mu          sync.Mutex
	devs        map[string]*dev // by name
	cancels     map[string]context.CancelFunc
	hub         hub
	builds      *buildMgr
	notifyHooks []func(Notification)
	conns       maintainerConns
	bconns      maintainerConns // named builders' open requests, by generation
	serialMu    sync.Mutex
	whoMu       sync.Mutex
	whoCache    map[netip.Addr]whoisEntry
	whoCalls    map[netip.Addr]*whoisCall
	hosts       []string // its host names and --allow-host's (see ownHost); the MagicDNS ones are tsNames
	tsMu        sync.Mutex
	tsAt        time.Time // when tsNames were looked up
	tsNames     []string  // its MagicDNS names
}

// clock is where labd reads time: Config.Clock, or the wall clock when unset.
func (s *Server) clock() agent.Clock {
	if s.cfg.Clock == nil {
		return agent.WallClock
	}
	return s.cfg.Clock
}

func (s *Server) now() time.Time                  { return s.clock().Now() }
func (s *Server) since(t time.Time) time.Duration { return s.clock().Now().Sub(t) }

// withTimeout is context.WithTimeout on labd's clock.
func (s *Server) withTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	c := s.clock()
	if c == agent.WallClock {
		return context.WithTimeout(parent, d)
	}
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-ctx.Done():
		case <-c.After(d):
			cancel()
		}
	}()
	return ctx, cancel
}

// SetRebootWarning sets how long before a Volunteer job's first reboot labd
// has the Mac warn its Volunteer (Config.RebootWarning).
func (c *Config) SetRebootWarning(d time.Duration) { c.RebootWarning = d }

func New(ctx context.Context, cfg Config, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(os.Stderr, "labd: ", log.LstdFlags)
	}
	if cfg.Interval == 0 {
		cfg.Interval = 8 * time.Second
	}
	if cfg.BootTimeout == 0 {
		cfg.BootTimeout = 4 * time.Minute
	}
	if cfg.StageTimeout == 0 {
		cfg.StageTimeout = 20 * time.Minute
	}
	if cfg.TestGrace == 0 {
		cfg.TestGrace = 2 * time.Minute
	}
	if cfg.GUIGrace == 0 {
		cfg.GUIGrace = 2 * time.Minute
	}
	if cfg.OfflineAfter == 0 {
		cfg.OfflineAfter = time.Minute
	}
	if len(cfg.TrustedProxies) > 0 && cfg.PublicURL == nil {
		return nil, fmt.Errorf("--trusted-proxy needs --public-url: labd checks what a proxy forwards against it")
	}
	if len(cfg.TrustedProxies) > 0 && cfg.Tailscale {
		return nil, fmt.Errorf("--trusted-proxy and --tailscale don't go together: behind a proxy every request's tailnet identity would be the proxy's")
	}
	if cfg.Tailscale && cfg.WhoIs == nil {
		if _, err := exec.LookPath(tailscaleCLI()); err != nil {
			return nil, fmt.Errorf("--tailscale needs the tailscale CLI: %w", err)
		}
		cfg.WhoIs = tailscaleWhoIs
		if cfg.TailnetNames == nil {
			cfg.TailnetNames = tailscaleNames
		}
	}
	var hosts []string
	for _, h := range cfg.AllowHosts {
		hosts = append(hosts, hostName(h))
	}
	if cfg.Tailscale {
		hosts = append(hosts, localNames()...)
		logger.Printf("without a token, labd answers only to its own names: IP addresses, localhost, %s%s; --allow-host adds one",
			strings.Join(hosts, ", "), map[bool]string{true: " and its MagicDNS names"}[cfg.Tailscale])
	}
	// The LAN defaults are read once, here: labd's goroutines can outlive a
	// Server, and must not read them while a test sets them for the next one.
	if cfg.AliveWindow == 0 {
		cfg.AliveWindow = aliveWindow
	}
	if cfg.QuietGrace == 0 {
		cfg.QuietGrace = quietGrace
	}
	if cfg.OOBFactory == nil {
		cfg.OOBFactory = func(d *api.Device) (oob.Controller, error) { return oob.New(d.OOB) }
	}
	for _, d := range []string{"artifacts", "jobs", "serial", "baselines", "builds"} {
		if err := os.MkdirAll(filepath.Join(cfg.DataDir, d), 0o755); err != nil {
			return nil, err
		}
	}
	st, err := openStore(filepath.Join(cfg.DataDir, "labd.db"))
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: st, log: logger, ctx: ctx, devs: map[string]*dev{}, cancels: map[string]context.CancelFunc{}, hosts: hosts}
	s.start = s.now()
	if err := s.firstMaintainer(); err != nil {
		return nil, err
	}
	rows, err := st.devices()
	if err != nil {
		return nil, err
	}
	interrupted, err := st.jobs("", 1000, true)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		unused := neverUsed(st, row.d) // as stored, before the changes below
		d := row.d
		for _, j := range interrupted {
			if j.Spec.Device == d.Name && j.State != api.JobQueued && (j.Spec.RecoveryMode == api.RecoveryNetworkOnly || j.EffectiveRecoveryMode == api.RecoveryNetworkOnly) {
				d.EffectiveRecoveryMode = api.RecoveryNetworkOnly
				d.RecoveryModeJob = j.ID
			}
		}
		d.ActiveJob = ""
		if d.Kind == "" { // enrolled before Kinds existed: ./volunteer's Macs are Volunteers'
			d.Kind = map[bool]string{false: api.KindLabOwned, true: api.KindVolunteer}[d.Volunteer]
		}
		if d.IsVolunteer() && d.AccessLevel == "" {
			d.AccessLevel = api.AccessQualification // enrolled before Access levels existed
		}
		if d.State == api.StateBusy || d.State == api.StateRecovering {
			d.State = api.StateOffline
		}
		v := newDev(s, d, row.secretHash)
		v.dirty = !unused // labd may have stopped mid-job
		s.devs[d.Name] = v
		if l := s.screens(d.Name); len(l) > 0 {
			v.screenAt, v.screenName = l[0].Time, l[0].Name
		}
		s.attachOOB(v)
		go s.deviceLoop(v)
	}
	// Jobs that were running when labd stopped cannot be resumed.
	unfinished, _ := st.jobs("", 1000, true)
	sort.Slice(unfinished, func(i, k int) bool { return unfinished[i].Created.Before(unfinished[k].Created) })
	for _, j := range unfinished {
		if j.State == api.JobQueued {
			if v := s.devs[j.Spec.Device]; v != nil {
				v.queue <- j.ID
				continue
			}
		}
		j.State, j.Outcome, j.Summary = api.JobDone, api.OutcomeInfra, "labd restarted while the job was running"
		st.saveJob(j)
	}
	s.builds = newBuildMgr(s)
	s.reconcileRunningBuilds()
	go s.monitor()
	go s.buildMonitor()
	go s.gcLoop()
	go s.omtScheduler()
	return s, nil
}

// neverUsed reports whether a stored Mac has demonstrably never been used: it
// was New when labd stopped, with no known-good kernel and no active job, and
// no job of any state was ever recorded under its name. After a restart labd
// cleans up every other Mac, in case it stopped mid-job; a Mac never used has
// nothing of the lab's to clean, and the cleanup would still rewrite its boot
// entries. Any doubt, a failed lookup included, keeps the cleanup.
func neverUsed(st *store, d api.Device) bool {
	if d.Name == "" || d.State != api.StateNew || d.KnownGood != "" || d.ActiveJob != "" {
		return false
	}
	jobs, err := st.jobs(d.Name, 1, false)
	return err == nil && len(jobs) == 0
}

// OnNotify registers a hook, used by tests to observe notifications.
func (s *Server) OnNotify(f func(Notification)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyHooks = append(s.notifyHooks, f)
}

func (s *Server) monitor() {
	t := s.clock().NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C():
		}
		for _, v := range s.allDevs() {
			v.mu.Lock()
			// After a restart, agents need a moment to reconnect before silence means anything.
			idle := (v.d.State == api.StateReady || v.d.State == api.StateNew) && s.since(s.start) > s.cfg.OfflineAfter
			if idle && !v.d.LastSeen.IsZero() && s.since(v.d.LastSeen) > s.cfg.OfflineAfter && !v.quietLocked(s.now()) {
				v.restore = v.d.State
				why := "no heartbeat since " + v.d.LastSeen.Format(time.TimeOnly)
				if !v.asleep.IsZero() {
					why = "asleep since " + v.asleep.Format(time.TimeOnly) + "; a key press wakes it"
				}
				v.setStateLocked(api.StateOffline, why)
			}
			v.mu.Unlock()
		}
	}
}

func (s *Server) allDevs() []*dev {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*dev, 0, len(s.devs))
	for _, v := range s.devs {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].d.Name < out[j].d.Name })
	return out
}

func (s *Server) dev(name string) *dev {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devs[name]
}

// attachOOB (re)connects a device's out-of-band controller and serial stream.
func (s *Server) attachOOB(v *dev) {
	v.mu.Lock()
	if v.oobStop != nil {
		v.oobStop()
		v.oobStop, v.oob, v.serialUp = nil, nil, false
	}
	cfg := v.d.OOB
	if v.networkOnlyLocked() {
		cfg = nil
	}
	v.mu.Unlock()
	if cfg == nil {
		return
	}
	d := v.snapshot()
	ctl, err := s.cfg.OOBFactory(&d)
	if err != nil {
		s.log.Printf("%s: oob: %v", d.Name, err)
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	v.mu.Lock()
	if v.forgotten { // lab forget ran meanwhile
		v.mu.Unlock()
		cancel()
		return
	}
	if v.networkOnlyLocked() {
		v.mu.Unlock()
		cancel()
		return
	}
	done := make(chan struct{})
	v.oobSerialDone = done
	v.oob, v.oobStop = ctl, cancel
	v.mu.Unlock()
	go func() {
		defer close(done)
		backoff := time.Second
		for ctx.Err() == nil {
			v.mu.Lock()
			if v.networkOnlyLocked() {
				v.mu.Unlock()
				return
			}
			v.serialUp = true
			v.mu.Unlock()
			err := ctl.Serial(ctx, func(line string) {
				backoff = time.Second
				if strings.TrimSpace(line) == "" {
					return // oobd keepalive
				}
				v.mu.Lock()
				blocked := v.networkOnlyLocked()
				v.mu.Unlock()
				if blocked {
					return
				}
				s.appendSerial(d.Name, line)
				v.onSerial(line)
			})
			v.mu.Lock()
			v.serialUp = false
			v.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			s.log.Printf("%s: serial stream: %v (retrying in %s)", d.Name, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-s.clock().After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()
}

func (s *Server) serialPath(name string) string {
	return filepath.Join(s.cfg.DataDir, "serial", name+".log")
}

func (s *Server) appendSerial(name, line string) {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	f, err := os.OpenFile(s.serialPath(name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "%s %s\n", s.now().Format("2006-01-02T15:04:05.000"), line)
	f.Close()
}

func (s *Server) serialOffset(name string) int64 {
	st, err := os.Stat(s.serialPath(name))
	if err != nil {
		return 0
	}
	return st.Size()
}

// copySerial saves the serial console captured during a job alongside its logs.
func (s *Server) copySerial(name string, from int64, job string) {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	f, err := os.Open(s.serialPath(name))
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return
	}
	b, _ := io.ReadAll(f)
	if len(b) == 0 {
		return
	}
	os.MkdirAll(s.jobDir(job), 0o755)
	os.WriteFile(filepath.Join(s.jobDir(job), "serial.log"), b, 0o644)
	s.updateJobByID(job, func(j *api.Job) { j.Result.Logs = append(j.Result.Logs, "serial.log") })
}

func (s *Server) jobDir(id string) string { return filepath.Join(s.cfg.DataDir, "jobs", id) }
func (s *Server) baselinePath(name string) string {
	return filepath.Join(s.cfg.DataDir, "baselines", name+"-dmesg-errors.txt")
}

var jobMu sync.Mutex

// updateJob changes j with f and saves it. Only lab exclude (hExclude)
// changes a job's GateExclusion, through f; any other caller's copy of j may
// be older than that, so j takes the stored one first.
func (s *Server) updateJob(j *api.Job, f func(*api.Job)) {
	jobMu.Lock()
	defer jobMu.Unlock()
	j.GateExclusion = s.store.gateExclusion(j.ID)
	f(j)
	j.Updated = s.now()
	if err := s.store.saveJob(j); err != nil {
		s.log.Printf("save job %s: %v", j.ID, err)
	}
	s.hub.publish("job", j.Spec.Device, map[string]any{"id": j.ID, "device": j.Spec.Device, "state": j.State, "outcome": j.Outcome})
}

func (s *Server) updateJobByID(id string, f func(*api.Job)) {
	jobMu.Lock()
	j, err := s.store.job(id)
	jobMu.Unlock()
	if err == nil {
		s.updateJob(j, f)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ---- HTTP ----

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	for _, rt := range s.routes() {
		s.register(m, rt)
	}
	// The UI's own files and themes: no Mac's data, so anyone.
	web.Register(m, s.basePath())
	return s.edge(m)
}

// routes is every API route and who may reach it (see reach).
func (s *Server) routes() []route {
	return []route{
		{"POST /api/agent/enroll", anyone, s.hEnroll},
		{"POST /api/agent/checkin", ownMac, s.hCheckin},
		{"POST /api/agent/report", ownMac, s.hReport},
		{"GET /api/agent/enrollment", ownMac, s.hAgentEnrollment},
		{"POST /api/agent/left", ownMac, s.hAgentLeave},
		{"GET /api/agent/artifacts/{sha}", ownMac, s.hAgentArtifact},
		{"POST /api/agent/upload", ownMac, s.hUpload},
		{"POST /api/agent/leave", ownMac, s.hLeave},
		{"GET /api/agent/published", ownMac, s.hAgentPublished},

		{"GET /api/auth", anyone, s.hAuth},
		// healthz answers that labd is up, to anyone: a Kubernetes probe. It
		// says nothing else.
		{"GET /healthz", anyone, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") }},
		{"POST /api/devices/{name}/recovery-mode", maintainers, s.hRecoveryMode},
		{"GET /api/recovery", maintainers, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, api.RecoveryCapabilities{Schema: 1, Modes: []string{api.RecoveryNetworkOnly, api.RecoverySerialAssisted}, PerJobOOBIsolation: true, TransactionIsolation: true})
		}},
		{"GET /api/mesa", maintainers, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, api.MesaCapabilities{Schema: 1, Staged: true, OfficialGPU: false, AgentMin: mesaMinAgent})
		}},
		{"GET /api/devices", scoped, s.hDevices},
		{"GET /api/devices/{name}", macNamed, s.hDevice},
		{"PATCH /api/devices/{name}", maintainers, s.hPatchDevice},
		{"DELETE /api/devices/{name}", maintainers, s.hForgetDevice},
		{"POST /api/devices/{name}/end-enrollment", maintainers, s.hEndEnrollment},
		{"POST /api/devices/{name}/lease", maintainers, s.hLease},
		{"DELETE /api/devices/{name}/lease", maintainers, s.hRelease},
		{"POST /api/devices/{name}/reset", maintainers, s.hReset},
		{"GET /api/devices/{name}/serial", maintainers, s.hSerial},
		{"GET /api/devices/{name}/oob", macNamed, s.hOOBStatus},
		{"GET /api/stream", scoped, s.hStream},
		{"POST /api/devices/{name}/screenshot", maintainers, s.hScreenshot},
		{"GET /api/devices/{name}/screen", macNamed, s.hScreen},
		{"GET /api/devices/{name}/screens", macNamed, s.hScreens},
		{"GET /api/devices/{name}/screens/{file}", macNamed, s.hScreen},
		{"GET /api/devices/{name}/logs", macNamed, s.hLogs},
		{"GET /api/devices/{name}/console", maintainers, s.hConsoleRaw},
		{"POST /api/devices/{name}/console", maintainers, s.hConsoleWrite},
		{"POST /api/devices/{name}/console/arm", maintainers, s.hConsoleArm},
		{"POST /api/agent/screen", ownMac, s.hAgentScreen},
		{"POST /api/enroll-tokens", maintainers, s.hEnrollToken},
		{"POST /api/volunteer", people, s.hVolunteer},
		{"GET /api/volunteer/lab-agent", people, s.hVolunteerAgent},
		{"GET /api/join/lab-agent", invited, s.hVolunteerAgent},
		{"GET /api/join/terms", invited, s.hJoinTerms},
		{"DELETE /api/enroll-tokens/{name}", maintainers, s.hRevokeEnrollTokens},
		{"POST /api/devices/{name}/artifact-grants", maintainers, s.hArtifactGrants},
		{"POST /api/artifacts", maintainers, s.hPutArtifact},
		{"POST /api/mesa/jobs", maintainers, s.hSubmit},
		{"POST /api/jobs", maintainers, s.hSubmit},
		{"GET /api/jobs", scoped, s.hJobs},
		{"GET /api/jobs/{id}", jobNamed, s.hJob},
		{"GET /api/jobs/{id}/wait", jobNamed, s.hWait},
		{"POST /api/jobs/{id}/cancel", maintainers, s.hCancel},
		{"POST /api/jobs/{id}/retry", maintainers, s.hRetry},
		{"POST /api/jobs/{id}/publish", maintainers, s.hPublish},
		{"POST /api/jobs/{id}/exclude", maintainers, s.hExclude},
		{"DELETE /api/jobs/{id}/exclude", maintainers, s.hExclude},
		{"GET /api/jobs/{id}/files/{name...}", jobNamed, s.hJobFile},
		{"GET /api/gate/{kernel}", maintainers, s.hGate},
		{"POST /api/builder/poll", builder, s.hBuilderPoll},
		{"POST /api/builder/builds/{id}/progress", builder, s.hBuilderProgress},
		{"POST /api/builder/builds/{id}/done", builder, s.hBuilderDone},
		{"POST /api/builder/artifacts", builder, s.hBuilderArtifact},
		{"GET /api/builder/artifacts/{sha}", builder, s.hBuilderGetArtifact},
		{"GET /api/builder/self", builder, s.hBuilderSelf},
		{"POST /api/builds", maintainers, s.hCreateBuild},
		{"POST /api/installed/{release}/manifest", maintainers, s.hFreezeManifest},
		{"POST /api/installed/{release}/entry/{device}", maintainers, s.hFreezeEntry},
		{"POST /api/installed/{release}/promote", maintainers, s.hPromote},
		{"GET /api/installed/{release}", maintainers, s.hInstalledStatus},
		{"GET /api/builds", maintainers, s.hBuilds},
		{"GET /api/builds/{id}", maintainers, s.hBuild},
		{"GET /api/builds/{id}/log", maintainers, s.hBuildLog},
		{"GET /api/builds/{id}/files/{name}", maintainers, s.hBuildFile},
		{"POST /api/builds/{id}/cancel", maintainers, s.hCancelBuild},
		{"GET /api/builders", maintainers, s.hBuilders},
		{"POST /api/builders", maintainers, s.hAddBuilder},
		{"DELETE /api/builders/{name}", maintainers, s.hRemoveBuilder},
		{"POST /api/devices/{name}/exec", maintainers, s.hExec},
		{"GET /api/devices/{name}/audit", maintainers, s.hAudit},
		{"GET /api/maintainers", maintainers, s.hMaintainers},
		{"POST /api/maintainers", maintainers, s.hAddMaintainer},
		{"DELETE /api/maintainers/{name}", maintainers, s.hRemoveMaintainer},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, format string, args ...any) {
	http.Error(w, fmt.Sprintf(format, args...), code)
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// hAuth tells the UI whether this client needs a token at all, and whether
// it may only look. Sent with a Maintainer's token, it names its Maintainer.
// A request to a name labd doesn't know as its own needs a token, and
// refused says why. Without --tailscale nothing gets in without a token, so
// there is nothing to ask: labd answers 404, and the UI asks for the token.
func (s *Server) hAuth(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Tailscale {
		http.NotFound(w, r)
		return
	}
	a, who, foreign := s.accessHost(r)
	role := map[access]string{viewAccess: "viewer", adminAccess: "admin"}[a]
	resp := map[string]any{"trusted": a == adminAccess, "token_required": a == noAccess, "role": role, "login": who}
	if foreign {
		resp["refused"] = hostRefusal(r.Host)
	}
	writeJSON(w, resp)
}

type ctxKey struct{}

func (s *Server) agent(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := hashSecret(bearer(r))
		for _, v := range s.allDevs() {
			v.mu.Lock()
			ok := subtle.ConstantTimeCompare([]byte(hash), []byte(v.secretHash)) == 1
			v.mu.Unlock()
			if ok {
				h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, v)))
				return
			}
		}
		if s.ended(w, bearer(r)) {
			return
		}
		httpErr(w, 401, "unknown device secret")
	}
}

func agentDev(r *http.Request) *dev { return r.Context().Value(ctxKey{}).(*dev) }

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

func (s *Server) hEnrollToken(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if !reName.MatchString(req.Name) {
		httpErr(w, 400, "device name must be lowercase letters, digits and dashes")
		return
	}
	// Activation is one-time, so a Mac that enrolled but never checked in
	// still holds its name: a new token for it would only be refused.
	if v := s.dev(req.Name); v != nil {
		if v.checkedIn() {
			httpErr(w, 409, "device %s already enrolled", req.Name)
		} else {
			httpErr(w, 409, "device %s enrolled but never checked in: `lab forget %s`, then enroll it again", req.Name, req.Name)
		}
		return
	}
	s.issueToken(w, r, req, "")
}

// hRevokeEnrollTokens deletes the enrollment tokens for a name, used or not:
// an invite that hasn't been used stops working, and a used one can't be
// used again. A Mac that already enrolled with one stays until forgotten.
func (s *Server) hRevokeEnrollTokens(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	n, err := s.store.revokeTokens(name)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	s.log.Printf("Maintainer %s revoked %d enrollment token(s) for %s", maintainerName(r), n, name)
	writeJSON(w, map[string]any{"name": name, "revoked": n})
}

// issueToken answers with a one-use enrollment token for req, good for a day.
// A token for volunteer, a tailnet viewer's login, replaces any unused one
// they hold and counts toward maxVolunteerTokens (see addVolunteerToken).
func (s *Server) issueToken(w http.ResponseWriter, r *http.Request, req api.EnrollTokenRequest, volunteer string) {
	if req.Model == "" {
		req.Model = api.ModelLaptop
	}
	req.VolunteerName, req.Contact = strings.TrimSpace(req.VolunteerName), strings.TrimSpace(req.Contact)
	if (req.VolunteerName == "") != (req.Contact == "") {
		httpErr(w, 400, "a Volunteer's token needs both the Volunteer's name and their contact")
		return
	}
	req.Volunteer = req.Volunteer || req.VolunteerName != ""
	tok := "enr_" + randHex(16)
	exp := s.now().Add(24 * time.Hour)
	var err error
	if volunteer != "" {
		err = s.store.addVolunteerToken(hashSecret(tok), req, volunteer, exp, s.now(), maxVolunteerTokens)
	} else {
		err = s.store.addToken(hashSecret(tok), req, exp)
	}
	if errors.Is(err, errVolunteerTokens) {
		httpErr(w, 429, "%d volunteers are signing up already: try again in a while, or ask the lab's maintainer", maxVolunteerTokens)
		return
	} else if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	writeJSON(w, api.EnrollTokenResponse{Name: req.Name, Token: tok, Expires: exp, JoinCommand: s.joinCommand(r, tok)})
}

// A viewer holds at most one unused volunteer token, and at most
// maxVolunteerTokens viewers hold one, so tailnet peers can't fill labd's
// token table. One viewer's tokens enroll at most maxVolunteerMacs Macs, so
// one login can't fill the lab either. A request is a name and a model:
// volunteerBodyMax is plenty.
const (
	maxVolunteerTokens = 20
	maxVolunteerMacs   = 3
	volunteerBodyMax   = 4 << 10
)

// Agents' requests are small, except for command results. Real ones stay far
// below these limits: an enrollment or a check-in carries the Mac's facts, a
// few KB, which every viewer downloads again with /api/devices. A report
// carries command results, the largest an exec's output (1 MB per stream,
// which JSON's escapes can make 6 MB), a journal of up to 20000 lines or the
// kernel's .config, and up to 500 kernel events. Files go to
// /api/agent/upload and /api/agent/screen, which these don't limit.
// enrollBodyTimeout is how long an enrollment's body may take to arrive;
// tests shorten it.
var enrollBodyTimeout = 30 * time.Second

const (
	enrollBodyMax  = 256 << 10
	checkinBodyMax = 256 << 10
	reportBodyMax  = 64 << 20
)

// decodeBody decodes r's JSON body into v. A body over max bytes gets a 413,
// unread if its Content-Length says so, and a malformed one a 400;
// decodeBody answers the request then, and returns false.
func decodeBody(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	if r.ContentLength > max {
		httpErr(w, 413, "a request body of %d bytes is over labd's limit of %d", r.ContentLength, max)
		return false
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, max)).Decode(v)
	if err == nil {
		return true
	}
	code := 400
	if errors.As(err, new(*http.MaxBytesError)) {
		code = 413
	}
	httpErr(w, code, "%v", err)
	return false
}

// volunteerMacsLocked names the Macs that login's volunteer tokens enrolled,
// left ones included until lab forget drops them. The caller holds s.mu.
func (s *Server) volunteerMacsLocked(login string) []string {
	var names []string
	for name, v := range s.devs {
		if v.volunteeredBy == login {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// tooManyMacs is the answer to a volunteer who has maxVolunteerMacs already.
func tooManyMacs(w http.ResponseWriter, login string, names []string) {
	httpErr(w, 409, "%s has volunteered %d Macs already (%s), as many as one person may: to put in another, take one out first "+
		"(./volunteer leave on it, then the lab's maintainer runs `lab forget <name>`)", login, len(names), strings.Join(names, ", "))
}

// hVolunteer gives any person on the tailnet under --tailscale a token to
// enroll their own Mac: ./volunteer runs lab-agent setup with it. The Mac is
// named after what it sent, made into a free device name, labelled with the
// volunteer's tailnet login and marked a volunteer's. Tagged tailnet devices
// are machines, lab Macs among them, not people, so they never get here (see
// tokenless), and a person with maxVolunteerMacs Macs in the lab gets no
// token either. Maintainers may ask too, with their token, outside the
// limits: they can make any token with POST /api/enroll-tokens anyway.
func (s *Server) hVolunteer(w http.ResponseWriter, r *http.Request) {
	a, who := s.access(r)
	volunteer := ""
	if a == adminAccess {
		who = "" // a Maintainer, not a volunteer's tailnet login
	} else {
		if volunteer = strings.ToLower(who); volunteer == "" {
			httpErr(w, 403, "labd can't tell who you are on the tailnet")
			return
		}
		s.mu.Lock()
		names := s.volunteerMacsLocked(volunteer)
		s.mu.Unlock()
		if len(names) >= maxVolunteerMacs {
			tooManyMacs(w, who, names)
			return
		}
	}
	var req api.EnrollTokenRequest
	if !decodeBody(w, r, volunteerBodyMax, &req) {
		return
	}
	req.Label, req.Volunteer = who, true
	if volunteer != "" { // a tailnet login is all labd knows of the person
		req.VolunteerName, req.Contact = who, who
	}
	if req.Model != api.ModelDesktop {
		req.Model = api.ModelLaptop
	}
	if req.Name = s.freeName(req.Name); req.Name == "" {
		httpErr(w, 409, "no free device name")
		return
	}
	s.log.Printf("enroll token for %s, asked for by volunteer %s", req.Name, orStr(who, "(Maintainer "+maintainerName(r)+")"))
	s.issueToken(w, r, req, volunteer)
}

var reNameRun = regexp.MustCompile(`[^a-z0-9]+`)

// freeName turns raw into a device name no Mac has yet, adding -2, -3, ...
// on a clash; "" when even those are taken.
func (s *Server) freeName(raw string) string {
	base := strings.Trim(reNameRun.ReplaceAllString(strings.ToLower(raw), "-"), "-")
	if base == "" {
		base = "mac"
	}
	base = strings.TrimRight(base[:min(len(base), 28)], "-") // room for -99
	for i := 1; i < 100; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		if s.dev(name) == nil {
			return name
		}
	}
	return ""
}

// hVolunteerAgent hands out the lab-agent built with this labd.
func (s *Server) hVolunteerAgent(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(s.cfg.AgentBinary)
	if err != nil {
		httpErr(w, 404, "this lab has no lab-agent to hand out: build it with make, next to labd")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "lab-agent", st.ModTime(), f)
}

func (s *Server) tokenValid(hash string) bool {
	_, err := s.store.token(hash, s.now())
	return err == nil
}

// hEnroll turns an enrollment token into a device. It needs no secret, so
// its body is held to enrollBodyMax before the token is even looked at.
//
// Activation is one-time: the first enrollment with a token uses it up, for
// the activation key that Mac sent. Should the answer never reach the Mac,
// only that same activation key enrolls again with the token, and only until
// the Mac's first check-in: the token alone, copied to another Mac, is worth
// nothing once used. The owner must have accepted labd's current terms.
func (s *Server) hEnroll(w http.ResponseWriter, r *http.Request) {
	// Anyone may send this body, before labd knows who they are: it must
	// arrive soon, not trickle in to hold the connection.
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(enrollBodyTimeout))
	var req api.EnrollRequest
	if !decodeBody(w, r, enrollBodyMax, &req) {
		return
	}
	tokHash := hashSecret(req.Token)
	t, activatedBy, err := s.store.tokenState(tokHash, s.now())
	if err != nil {
		httpErr(w, 403, "enrollment token unknown, used or expired")
		return
	}
	if _, sum := s.terms(); req.TermsSHA256 != sum {
		httpErr(w, 409, "this Mac's owner hasn't accepted labd's current participation terms: lab-agent setup shows them")
		return
	}
	keyHash := ""
	if req.ActivationKey != "" {
		if len(req.ActivationKey) < 32 || len(req.ActivationKey) > 128 {
			httpErr(w, 400, "activation key: want 32 to 128 characters")
			return
		}
		keyHash = hashSecret(req.ActivationKey)
	}
	secret := "dev_" + randHex(24)
	if activatedBy != "" {
		s.enrollAgain(w, t, tokHash, keyHash, activatedBy, secret)
		return
	}
	if keyHash == "" { // an older lab-agent: no enrolling again with this token
		keyHash = "none-" + randHex(16)
	}
	d := api.Device{ID: "d-" + randHex(6), Name: t.Name, Label: t.Label, Model: t.Model, VolunteeredBy: t.VolunteeredBy,
		State: api.StateNew, StateReason: "enrolled; run a baseline job", Facts: req.Facts, Enrollment: enrollment(t, api.Enrollment{}),
		TermsSHA256: req.TermsSHA256, TermsAccepted: s.now()}
	d.Volunteer = d.IsVolunteer()
	if d.IsVolunteer() {
		d.AccessLevel = api.AccessQualification // until its Volunteer chooses
	}
	v := newDev(s, d, hashSecret(secret))
	v.enrolledWith = tokHash
	s.mu.Lock()
	if _, dup := s.devs[d.Name]; dup {
		s.mu.Unlock()
		httpErr(w, 409, "device %s already enrolled", d.Name)
		return
	}
	// hVolunteer counted this person's Macs when it handed out the token, but
	// a token asked for while another was being used here was counted one
	// Mac short. Counting again with the insert, under s.mu, settles it.
	if d.VolunteeredBy != "" {
		if names := s.volunteerMacsLocked(d.VolunteeredBy); len(names) >= maxVolunteerMacs {
			s.mu.Unlock()
			tooManyMacs(w, d.VolunteeredBy, names)
			return
		}
	}
	// Used up here, under s.mu, in one transaction with the device's row: of
	// two enrollments racing with one token, one gets the Mac and the other
	// a 403, and a crash leaves no used token without its Mac.
	if ok, err := s.store.activateAndSave(tokHash, keyHash, s.now(), &d, hashSecret(secret)); err != nil || !ok {
		s.mu.Unlock()
		httpErr(w, 403, "enrollment token unknown, used or expired")
		return
	}
	s.devs[d.Name] = v
	s.mu.Unlock()
	go s.deviceLoop(v)
	s.log.Printf("enrolled %s (%s, %s); terms %s accepted", d.Name, d.Kind, req.Facts.DTModel, short(req.TermsSHA256))
	writeJSON(w, api.EnrollResponse{DeviceID: d.ID, Name: d.Name, Secret: secret, AgentEnrollment: s.agentEnrollment(d.Enrollment)})
}

// enrollAgain answers an enrollment with a used token: the same activation
// enrolling again before its Mac's first check-in, because the first answer
// never reached it. The Mac keeps its enrollment and gets a new secret.
// Anything else is refused as an unknown token would be.
func (s *Server) enrollAgain(w http.ResponseWriter, t *api.EnrollTokenRequest, tokHash, keyHash, activatedBy, secret string) {
	v := s.dev(t.Name)
	if keyHash == "" || subtle.ConstantTimeCompare([]byte(keyHash), []byte(activatedBy)) != 1 || v == nil {
		httpErr(w, 403, "enrollment token unknown, used or expired")
		return
	}
	v.mu.Lock()
	ok := !v.forgotten && v.d.BootID == "" && v.enrolledWith == tokHash
	if ok {
		v.secretHash = hashSecret(secret)
		v.grants, v.fetchGrant = nil, nil
		v.saveLocked()
	}
	d := v.d
	v.mu.Unlock()
	if !ok {
		httpErr(w, 403, "enrollment token unknown, used or expired")
		return
	}
	s.log.Printf("enrolled %s again with its own activation, before its first check-in", t.Name)
	writeJSON(w, api.EnrollResponse{DeviceID: d.ID, Name: d.Name, Secret: secret, AgentEnrollment: s.agentEnrollment(d.Enrollment)})
}

// enrollment is what token t makes a Mac. A Volunteer's Mac enrolled again
// before its first check-in keeps the topic it was given (old).
func enrollment(t *api.EnrollTokenRequest, old api.Enrollment) api.Enrollment {
	if !t.Volunteer {
		return api.Enrollment{Kind: api.KindLabOwned}
	}
	e := api.Enrollment{Kind: api.KindVolunteer, VolunteerName: t.VolunteerName, Contact: t.Contact, NtfyTopic: old.NtfyTopic, NtfyOwnURL: old.NtfyOwnURL}
	if e.NtfyTopic == "" {
		e.NtfyTopic = newNtfyTopic()
	}
	return e
}

// newNtfyTopic is an unguessable ntfy topic for one Volunteer Mac: about 106
// random bits, in digits only so that no topic spells a word or a name.
func newNtfyTopic() string {
	n, _ := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(10), big.NewInt(32), nil))
	return fmt.Sprintf("maclab-%032d", n)
}

// macTopicURL is where a Volunteer Mac's own notices are posted: the topic
// the Volunteer chose, else the Mac's generated one on the lab's ntfy server.
func (s *Server) macTopicURL(e api.Enrollment) string { return s.agentEnrollment(e).NtfyURL }

// agentEnrollment is e as the Mac is told it, with its topic's URL on the
// lab's ntfy server (the one --ntfy posts to).
func (s *Server) agentEnrollment(e api.Enrollment) api.AgentEnrollment {
	ae := api.AgentEnrollment{Enrollment: e}
	if e.NtfyOwnURL != "" {
		ae.NtfyURL = e.NtfyOwnURL
		return ae
	}
	if u, err := url.Parse(s.cfg.NtfyURL); err == nil && e.NtfyTopic != "" && u.Host != "" {
		ae.NtfyURL = (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/" + e.NtfyTopic}).String()
	}
	return ae
}

// hAgentEnrollment tells a Mac what it is enrolled as, for `lab-agent status`.
func (s *Server) hAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	v := agentDev(r)
	v.mu.Lock()
	e := v.d.Enrollment
	v.mu.Unlock()
	writeJSON(w, s.agentEnrollment(e))
}

func (s *Server) hCheckin(w http.ResponseWriter, r *http.Request) {
	var ci api.Checkin
	if !decodeBody(w, r, checkinBodyMax, &ci) {
		return
	}
	v := agentDev(r)
	v.heartbeat(ci)
	// Long poll: hold the check-in until there is a command for this boot.
	hold, _ := strconv.Atoi(r.URL.Query().Get("wait_ms"))
	wait := min(time.Duration(hold)*time.Millisecond, s.cfg.Interval)
	if wait > 0 {
		v.waitFor(r.Context(), wait, func() bool { return len(v.pending) > 0 || v.d.BootID != ci.BootID })
	}
	resp := v.deliver(ci.BootID)
	resp.AuditHave = v.auditHaveNow()
	writeJSON(w, resp)
}

func (s *Server) hReport(w http.ResponseWriter, r *http.Request) {
	var rep api.Report
	if !decodeBody(w, r, reportBodyMax, &rep) {
		return
	}
	agentDev(r).report(rep)
	agentDev(r).copyAudit(rep.Audit)
	w.Write([]byte("ok"))
}

var reSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Server) artifactPath(sha string) string {
	return filepath.Join(s.cfg.DataDir, "artifacts", sha)
}

func (s *Server) hPutArtifact(w http.ResponseWriter, r *http.Request) {
	sha, n, err := s.storeArtifact(r.Body)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	writeJSON(w, map[string]any{"sha256": sha, "size": n})
}

// storeArtifact saves content under its sha256.
func (s *Server) storeArtifact(r io.Reader) (string, int64, error) {
	return storeArtifactIn(filepath.Join(s.cfg.DataDir, "artifacts"), r, artifactDiskOps())
}

// cleanName keeps uploaded file names inside the job directory.
func cleanName(name string) (string, bool) {
	c := filepath.ToSlash(filepath.Clean("/" + name))[1:]
	if c == "" || strings.HasPrefix(c, "..") {
		return "", false
	}
	return c, true
}

// DeviceView is a device plus what labd derives about it.
type DeviceView struct {
	api.Device
	Tier     int       `json:"tier"`
	Alive    bool      `json:"alive"`
	Queued   int       `json:"queued"`
	ScreenAt time.Time `json:"screen_at,omitempty"`
}

func (s *Server) view(v *dev) DeviceView {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.viewLocked()
}

// hDevices lists the Macs the caller sees.
func (s *Server) hDevices(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	out := []DeviceView{}
	for _, v := range s.allDevs() {
		if s.sees(c, v.d.Name) {
			out = append(out, s.view(v))
		}
	}
	writeJSON(w, out)
}

func (s *Server) devOr404(w http.ResponseWriter, r *http.Request) *dev {
	v := s.dev(r.PathValue("name"))
	if v == nil {
		httpErr(w, 404, "no device %q", r.PathValue("name"))
	}
	return v
}

func (s *Server) hDevice(w http.ResponseWriter, r *http.Request) {
	if v := s.devOr404(w, r); v != nil {
		writeJSON(w, struct {
			DeviceView
			Events []api.KernelEvent `json:"recent_events"`
		}{s.view(v), v.eventsSince(s.now().Add(-24 * time.Hour))})
	}
}

func (s *Server) hPatchDevice(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	var p api.DevicePatch
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	v.mu.Lock()
	if p.Label != nil {
		v.d.Label = *p.Label
	}
	if p.Model != nil {
		v.d.Model = *p.Model
	}
	oobChanged := p.OOB != nil || p.NoOOB
	if p.OOB != nil {
		v.d.OOB = p.OOB
	}
	if p.NoOOB {
		v.d.OOB = nil
	}
	v.saveLocked()
	v.mu.Unlock()
	if oobChanged {
		s.attachOOB(v)
	}
	writeJSON(w, s.view(v))
}

// hForgetDevice takes a Mac out of the lab: after `lab-agent uninstall`, or so
// it can enroll again under the same name. Its jobs stay in the history. A
// Mac with a job running, queued, or unfinished in the store is refused. So,
// unless ?force=1, is one someone other than ?holder= holds a lease on
// (forgetting it would end the lease and cut their lab shell), and one whose
// agent still checks in.
func (s *Server) hForgetDevice(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	force, _ := strconv.ParseBool(r.URL.Query().Get("force"))
	if code, err := s.forget(v, r.URL.Query().Get("holder"), force); err != nil {
		httpErr(w, code, "%v", err)
		return
	}
	s.log.Printf("forgot %s", r.PathValue("name"))
	writeJSON(w, map[string]string{"forgot": r.PathValue("name")})
}

// forget deletes v's row and drops it from devs, ending its device loop and
// out-of-band stream. It holds v.mu throughout, as every save of v does, and
// marks v forgotten before letting go: nothing still holding v can then
// write the row back, and Submit queues nothing more on it. A lease held by
// holder doesn't count; force skips the lease and live-agent checks, never
// the job check.
func (s *Server) forget(v *dev, holder string, force bool) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	name := v.d.Name
	if v.forgotten {
		return 404, fmt.Errorf("no device %q", name)
	}
	// A job queued while the Mac was offline waits in the store, not the queue,
	// and labd would hand it to whatever enrolls next under this name.
	open, err := s.store.jobs(name, 1, true)
	if err != nil {
		return 500, err
	}
	if v.d.State == api.StateBusy || v.d.State == api.StateRecovering || len(v.queue) > 0 || len(open) > 0 {
		return 409, fmt.Errorf("%s has a job running or queued; cancel it first", name)
	}
	if l := v.d.Lease; !force && l != nil && s.now().Before(l.Expires) && l.Holder != holder {
		return 409, fmt.Errorf("%s is leased by %s until %s: release the lease first (`lab release %s --holder %s`), or pass --force",
			name, l.Holder, l.Expires.Format(time.DateTime), name, l.Holder)
	}
	// An agent that told labd it is leaving may still check in until
	// uninstall has stopped it. Any other one that checks in is still set up,
	// and would only get 401s once its row is gone.
	if seen := v.d.LastSeen; !force && v.d.State != api.StateLeft && !seen.IsZero() && s.since(seen) < s.cfg.OfflineAfter {
		return 409, fmt.Errorf("%s's lab-agent checked in %s ago, so it is still set up: run `sudo lab-agent uninstall` on the Mac first, or pass --force",
			name, s.since(seen).Round(time.Second))
	}
	if err := s.store.deleteDevice(v.d.ID); err != nil {
		return 500, err
	}
	v.forgotten = true
	s.mu.Lock()
	if s.devs[name] == v {
		delete(s.devs, name)
	}
	s.mu.Unlock()
	if v.oobStop != nil {
		v.oobStop()
	}
	v.oobStop, v.oob, v.serialUp = nil, nil, false
	close(v.gone)
	return 200, nil
}

func (s *Server) hLease(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	var req api.LeaseRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.Holder == "" {
		httpErr(w, 400, "holder required")
		return
	}
	if req.TTLSec <= 0 {
		req.TTLSec = 3600
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if l := v.d.Lease; l != nil && s.now().Before(l.Expires) && l.Holder != req.Holder {
		httpErr(w, 409, "%s is leased by %s until %s", v.d.Name, l.Holder, l.Expires.Format(time.TimeOnly))
		return
	}
	if v.d.IsVolunteer() && v.openUntilLocked().IsZero() {
		httpErr(w, 409, "%s's Availability window is closed: a lease on a Volunteer's Mac lasts only inside it", v.d.Name)
		return
	}
	v.d.Lease = &api.Lease{Holder: req.Holder, Expires: s.now().Add(time.Duration(req.TTLSec) * time.Second)}
	v.capLeaseLocked()
	v.saveLocked()
	writeJSON(w, v.d.Lease)
}

func (s *Server) hRelease(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	holder := r.URL.Query().Get("holder")
	v.mu.Lock()
	defer v.mu.Unlock()
	if l := v.d.Lease; l != nil && holder != "" && l.Holder != holder && s.now().Before(l.Expires) {
		httpErr(w, 409, "leased by %s, not %s", l.Holder, holder)
		return
	}
	v.d.Lease = nil
	v.saveLocked()
	w.Write([]byte("ok"))
}

// hReset runs the recovery ladder by hand, e.g. for an idle Mac that is wedged.
// A Mac that left the lab (lab-agent uninstall) is put back in it first: a
// reset is how an admin recovers one that wedged mid-uninstall, or whose
// agent still runs after an uninstall that failed. Only automatic recovery
// leaves a Mac that left alone.
func (s *Server) hReset(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	by := r.URL.Query().Get("by")
	v.mu.Lock()
	busy := v.d.State == api.StateBusy || v.d.State == api.StateRecovering
	lease := v.d.Lease
	v.mu.Unlock()
	if busy {
		httpErr(w, 409, "%s is busy; cancel its job instead", v.d.Name)
		return
	}
	// A reset reboots the Mac, so a lease fences it like a job.
	if lease != nil && s.now().Before(lease.Expires) && lease.Holder != by {
		httpErr(w, 409, "%s is leased by %s until %s; only the lease holder can reset it", v.d.Name, lease.Holder, lease.Expires.Format(time.DateTime))
		return
	}
	back, err := s.rejoin(v, "reset requested by "+orStr(by, "an admin"))
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	go func() {
		steps, ok := v.ladder(s.ctx, "reset requested by "+by, s.cfg.BootTimeout, true)
		s.log.Printf("%s: manual reset: ok=%v steps=%v", v.d.Name, ok, steps)
	}()
	if back {
		w.Write([]byte(v.d.Name + " had left the lab (lab-agent uninstall); the reset puts it back in. "))
	}
	w.Write([]byte("recovery started; watch `lab status " + v.d.Name + "`\n"))
}

func (s *Server) hSerial(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if n <= 0 {
		n = 100
	}
	b, _ := os.ReadFile(s.serialPath(v.d.Name))
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, strings.Join(lines, "\n")+"\n")
}

func (s *Server) hOOBStatus(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	v.mu.Lock()
	ctl, up, last := v.effectiveOOBLocked(), v.serialUp, v.serialLast
	v.mu.Unlock()
	if ctl == nil {
		httpErr(w, 404, "%s has no out-of-band controller", v.d.Name)
		return
	}
	st, err := v.statusOOB(r.Context())
	out := map[string]any{"controller": ctl.Name(), "serial_connected": up, "serial_last": last, "status": st}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, out)
}

func (s *Server) hSubmit(w http.ResponseWriter, r *http.Request) {
	var spec api.JobSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if r.URL.Path == "/api/mesa/jobs" && spec.Mesa == nil {
		httpErr(w, 400, "Mesa endpoint requires an explicit Mesa package request")
		return
	}
	j, code, err := s.submit(maintainerName(r), spec, "")
	if err != nil {
		httpErr(w, code, "%v", err)
		return
	}
	writeJSON(w, j)
}

// Submit validates and queues a job that labd queues itself, for no Maintainer.
func (s *Server) Submit(spec api.JobSpec) (*api.Job, int, error) { return s.submit("", spec, "") }

// Retry queues a finished job again as a new job: the same Mac, kernel,
// tests and cmdline, recording which job it retries. holder, if given,
// replaces the first job's, so a lease is checked against whoever retries
// it. A source job boots the kernel the first one built; once that is
// collected, it builds again from the commit and the config that build
// recorded, never from wherever a branch points now or the Mac's config as
// it is now.
func (s *Server) Retry(id, holder string) (*api.Job, int, error) { return s.retry("", id, holder) }

// retry is Retry for the Maintainer who asked.
func (s *Server) retry(maintainer, id, holder string) (*api.Job, int, error) {
	old, err := s.store.job(id)
	if err != nil {
		return nil, 404, fmt.Errorf("no job %s", id)
	}
	if old.State != api.JobDone {
		return nil, 409, fmt.Errorf("job %s is still %s; only a finished job can be retried", id, old.State)
	}
	spec := old.Spec
	spec.Tests = slices.Clone(spec.Tests)
	spec.CmdlineStrip = slices.Clone(spec.CmdlineStrip)
	spec.OMTAllow = slices.Clone(spec.OMTAllow)
	if holder != "" {
		spec.Holder = holder
	}
	if spec.Source != "" && spec.Kernel != "" {
		// boot the kernel the first job built, unless it has been collected
		if _, err := os.Stat(s.artifactPath(spec.Kernel)); err != nil {
			spec.Kernel = ""
		}
	}
	var notes []string
	if spec.Source != "" && spec.Kernel == "" {
		src, err := s.pinnedSource(old)
		if err != nil {
			return nil, 409, err
		}
		cfg, note, err := s.pinnedConfig(old)
		if err != nil {
			return nil, 409, err
		}
		spec.Source, spec.Build, spec.Config = src, "", cfg
		if note != "" {
			notes = append(notes, note)
		}
	}
	return s.submit(maintainer, spec, old.ID, notes...)
}

// pinnedConfig is the config a retry of old builds its kernel again with: the
// one the first build used, as a config artifact, so the retry builds the
// same kernel and not one from the Mac's config as it is by now. A recorded
// config that has been collected since is refused rather than replaced: a
// build from another config is another kernel, which the retry would pass
// off as the first job's. note, if any, says where the config came from.
func (s *Server) pinnedConfig(old *api.Job) (cfg, note string, err error) {
	again := fmt.Sprintf("run it afresh with `lab run %s --kernel %s`", old.Spec.Device, old.Spec.Source)
	cfg = old.Spec.Config
	switch {
	case cfg != "":
		// built with an uploaded config, which the build request named
	case old.Spec.Build == "":
		// the first job never got as far as a build, so there is no config to keep
		return "", fmt.Sprintf("job %s recorded no build, so this one builds with %s's config as it is now", old.ID, old.Spec.Device), nil
	default:
		b, err := s.getBuild(old.Spec.Build)
		if err != nil || b.ConfigSHA == "" {
			return "", "", fmt.Errorf("job %s's build %s recorded no config, so a retry would build with %s's config as it is now; %s", old.ID, old.Spec.Build, old.Spec.Device, again)
		}
		cfg = b.ConfigSHA
		note = fmt.Sprintf("builds with the config build %s used (%s), not %s's as it is now", b.ID, short(cfg), old.Spec.Device)
	}
	if _, err := os.Stat(s.artifactPath(cfg)); err != nil {
		return "", "", fmt.Errorf("job %s's kernel was built with config %s, which has been collected since, so a retry can't build the same kernel; %s", old.ID, short(cfg), again)
	}
	return cfg, note, nil
}

// pinnedSource is the source a retry of old builds from: the exact commit its
// build resolved, as repo#sha. Its source may name a branch or pull request
// that has moved on since.
func (s *Server) pinnedSource(old *api.Job) (string, error) {
	if src, err := parseSource(old.Spec.Source); err == nil && reHex40.MatchString(src.Ref) {
		return old.Spec.Source, nil // a commit already
	}
	again := fmt.Sprintf("run it afresh with `lab run %s --kernel %s`", old.Spec.Device, old.Spec.Source)
	if old.Spec.Build == "" {
		return "", fmt.Errorf("job %s never resolved %s to a commit, so a retry would build whatever it points to now; %s", old.ID, old.Spec.Source, again)
	}
	b, err := s.getBuild(old.Spec.Build)
	if err != nil || b.Source.SHA == "" || b.Source.Repo == "" {
		return "", fmt.Errorf("job %s's build %s recorded no commit, so a retry would build whatever %s points to now; %s", old.ID, old.Spec.Build, old.Spec.Source, again)
	}
	return b.Source.Repo + "#" + b.Source.SHA, nil
}

// submit queues a job for the Maintainer who asked; retryOf names the job it retries, whose source may
// come with the kernel already built from it, and notes go in the job's
// events after the first. The job records what lab gate needs to know about
// its Mac as it is now.
func (s *Server) submit(maintainer string, spec api.JobSpec, retryOf string, notes ...string) (*api.Job, int, error) {
	v := s.dev(spec.Device)
	if v == nil {
		return nil, 404, fmt.Errorf("no device %q", spec.Device)
	}
	v.recoveryMu.Lock()
	defer v.recoveryMu.Unlock()
	if err := validateRecoveryTransaction(v.snapshot(), spec); err != nil {
		return nil, 409, err
	}
	if !api.ValidRecoveryMode(spec.RecoveryMode) {
		return nil, 400, errors.New("recovery_mode must be network-only or serial-assisted")
	}
	if spec.RecoveryMode == api.RecoverySerialAssisted && v.snapshot().OOB == nil {
		return nil, 409, errors.New("serial-assisted requested but no controller is configured")
	}
	if spec.Config != "" {
		if spec.Source == "" {
			return nil, 400, errors.New("--config applies to a kernel built from a source URL")
		}
		if !reSHA.MatchString(spec.Config) {
			return nil, 400, errors.New("config must be an artifact sha256 (upload it first)")
		}
		// a retry that boots the kernel its first job built doesn't build again
		if _, err := os.Stat(s.artifactPath(spec.Config)); err != nil && spec.Kernel == "" {
			return nil, 400, fmt.Errorf("config artifact %s not uploaded", spec.Config)
		}
	}
	if spec.Source != "" {
		if spec.Kernel != "" && retryOf == "" {
			return nil, 400, errors.New("give a kernel artifact or a source to build, not both")
		}
		if spec.Baseline || spec.Crash != "" {
			return nil, 400, errors.New("baseline and crash-test jobs run the known-good kernel; drop the source")
		}
		if _, err := parseSource(spec.Source); err != nil {
			return nil, 400, err
		}
	}
	if spec.Kernel != "" {
		if !reSHA.MatchString(spec.Kernel) {
			return nil, 400, errors.New("kernel must be an artifact sha256 (upload it first)")
		}
		if _, err := os.Stat(s.artifactPath(spec.Kernel)); err != nil {
			return nil, 400, fmt.Errorf("artifact %s not uploaded", spec.Kernel)
		}
	}
	for _, t := range spec.Tests {
		if t.Identity != nil {
			return nil, 400, fmt.Errorf("test %s: identity checks are the lab's own, part of an Installed run", t.Name)
		}
		if spec.Mesa == nil && t.Builtin == "mesa-provider" {
			return nil, 400, errors.New("mesa-provider requires a first-class Mesa package request")
		}
		if t.Script != "" {
			if _, err := os.Stat(s.artifactPath(t.Script)); err != nil {
				return nil, 400, fmt.Errorf("test %s: script artifact %s not uploaded", t.Name, t.Script)
			}
		}
		if t.Name == "" || strings.ContainsAny(t.Name, "/ ") {
			return nil, 400, fmt.Errorf("test name %q must be non-empty with no slashes or spaces", t.Name)
		}
	}
	if why := needsFull(spec); why != "" {
		if err := refuseAtAccessLevel(v.snapshot(), "Maintainer's script ("+why+")"); err != nil {
			return nil, 403, err
		}
	}
	if spec.Crash != "" && spec.Crash != "panic" {
		return nil, 400, fmt.Errorf("unknown crash mode %q", spec.Crash)
	}
	d := s.view(v)
	if d.State == api.StateLeft {
		return nil, 409, fmt.Errorf("%s left the lab (lab-agent uninstall): `lab forget %s` takes it off the list", d.Name, d.Name)
	}
	if spec.CmdlineBase != "" || len(spec.CmdlineStrip) > 0 {
		if spec.Baseline || spec.Crash != "" {
			return nil, 400, errors.New("baseline and crash-test jobs boot the known-good cmdline; drop --cmdline-base/--cmdline-strip")
		}
		if !versionAtLeast(d.Facts.AgentVersion, "0.5.0") {
			return nil, 409, fmt.Errorf("%s runs lab-agent %s, which ignores --cmdline-base/--cmdline-strip; update it to 0.5.0 or later", d.Name, orStr(d.Facts.AgentVersion, "(unknown)"))
		}
		for _, g := range spec.CmdlineStrip {
			if _, err := path.Match(g, ""); err != nil || strings.TrimSpace(g) == "" {
				return nil, 400, fmt.Errorf("--cmdline-strip pattern %q is not a valid glob", g)
			}
		}
	}
	if spec.Crash == "" {
		has := false
		for i, t := range spec.Tests {
			if t.Builtin == omtTest {
				has = true
				spec.Tests[i].GUI = true
				spec.Tests[i].SkipOnScreen = d.Enrollment.IsVolunteer()
				if t.TimeoutSec == 0 {
					spec.Tests[i].TimeoutSec = omtSpec().TimeoutSec
				}
			}
		}
		if !has && s.omtWanted(v.snapshot(), spec) {
			ts := omtSpec()
			ts.SkipOnScreen = d.Enrollment.IsVolunteer()
			spec.Tests = append(spec.Tests, ts)
		}
	}
	if d.KnownGood == "" && !spec.Baseline {
		return nil, 409, fmt.Errorf("%s has not passed a baseline yet: run `lab baseline %s` first", d.Name, d.Name)
	}
	if spec.InstalledManifest != "" {
		if code, err := s.validateInstalled(spec, d.Device); err != nil {
			return nil, code, err
		}
		if p := installedPreflight(d.Facts.Problems); !d.Facts.PreflightOK && len(p) > 0 {
			return nil, 409, fmt.Errorf("%s fails preflight: %s", d.Name, strings.Join(p, "; "))
		}
	} else if !d.Facts.PreflightOK {
		return nil, 409, fmt.Errorf("%s fails preflight: %s", d.Name, strings.Join(d.Facts.Problems, "; "))
	}
	if spec.Mesa != nil {
		if code, err := s.validateMesa(spec, d.Device); err != nil {
			return nil, code, err
		}
	}
	if l := d.Lease; l != nil && l.Holder != spec.Holder {
		return nil, 409, fmt.Errorf("%s is leased by %s until %s", d.Name, l.Holder, l.Expires.Format(time.TimeOnly))
	}
	now := s.now()
	msg := "queued"
	if retryOf != "" {
		msg = "queued: a retry of job " + retryOf
	}
	j := &api.Job{ID: "j" + now.Format("0102-150405") + "-" + randHex(2), Spec: spec, Maintainer: maintainer, DeviceID: d.ID, State: api.JobQueued, Created: now, Updated: now,
		Events: []api.JobEvent{{Time: now, Msg: msg}}, RetryOf: retryOf,
		DeviceAtSubmit: &api.DeviceSnapshot{Family: family(d.Facts), Volunteer: d.Volunteer, OMT: s.omtWanted(d.Device, api.JobSpec{})}}
	for _, n := range notes {
		j.Events = append(j.Events, api.JobEvent{Time: now, Msg: n})
	}
	j.EffectiveRecoveryMode = effectiveRecoveryMode(spec.RecoveryMode, d.EffectiveRecoveryMode)
	if err := s.store.saveJob(j); err != nil {
		return nil, 500, err
	}
	// lab forget may have dropped the Mac since it was looked up, and then
	// nothing would run the job. Past this check the saved job keeps forget
	// from dropping it.
	v.mu.Lock()
	gone := v.forgotten
	v.mu.Unlock()
	if gone {
		s.updateJob(j, func(j *api.Job) {
			j.State, j.Outcome, j.Summary = api.JobDone, api.OutcomeCanceled, spec.Device+" was forgotten (lab forget) before the job started"
		})
		return nil, 404, fmt.Errorf("no device %q", spec.Device)
	}
	v.queue <- j.ID
	return j, 200, nil
}

// hRetry submits a finished job again; ?holder= names who retries it.
func (s *Server) hRetry(w http.ResponseWriter, r *http.Request) {
	j, code, err := s.retry(maintainerName(r), r.PathValue("id"), r.URL.Query().Get("holder"))
	if err != nil {
		httpErr(w, code, "%v", err)
		return
	}
	writeJSON(w, j)
}

// hJobs lists the newest jobs on the Macs the caller sees; ?device= keeps
// to one of them.
func (s *Server) hJobs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = 20
	}
	c, device := callerOf(r), r.URL.Query().Get("device")
	var (
		jobs []*api.Job
		err  error
	)
	switch {
	case c.maintainer != "":
		jobs, err = s.store.jobs(device, n, false)
	case device != "":
		if s.sees(c, device) {
			jobs, err = s.store.jobs(device, n, false)
		}
	default:
		jobs, err = s.store.jobsOn(s.seenMacs(c), n)
	}
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if jobs == nil {
		jobs = []*api.Job{}
	}
	writeJSON(w, jobs)
}

func (s *Server) hJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.store.job(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, "no job %s", r.PathValue("id"))
		return
	}
	writeJSON(w, j)
}

// hWait long-polls until the job is done or the timeout passes.
func (s *Server) hWait(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sec, _ := strconv.Atoi(r.URL.Query().Get("timeout"))
	if sec <= 0 || sec > 3600 {
		sec = 60
	}
	deadline := s.now().Add(time.Duration(sec) * time.Second)
	for {
		j, err := s.store.job(id)
		if err != nil {
			httpErr(w, 404, "no job %s", id)
			return
		}
		if j.State == api.JobDone || s.now().After(deadline) {
			writeJSON(w, j)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-s.clock().After(500 * time.Millisecond):
		}
	}
}

// hPublish uploads a finished job's omarchy-m-test report to omarchy-m-testing.org.
func (s *Server) hPublish(w http.ResponseWriter, r *http.Request) {
	j, err := s.store.job(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, "no job %s", r.PathValue("id"))
		return
	}
	if j.State != api.JobDone {
		httpErr(w, 409, "job %s is still %s", j.ID, j.State)
		return
	}
	url, err := s.omtPublish(r.Context(), j)
	if err != nil {
		httpErr(w, 409, "not published: %v", err)
		return
	}
	writeJSON(w, map[string]string{"report_url": url})
}

func (s *Server) hCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	j, err := s.store.job(id)
	if err != nil {
		httpErr(w, 404, "no job %s", id)
		return
	}
	s.mu.Lock()
	cancel := s.cancels[id]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		w.Write([]byte("canceling; the Mac is being restored to its known-good kernel\n"))
		return
	}
	if j.State == api.JobQueued {
		s.updateJob(j, func(j *api.Job) {
			j.State, j.Outcome, j.Summary, j.Canceled = api.JobDone, api.OutcomeCanceled, "canceled before it started", true
		})
	}
	w.Write([]byte("canceled\n"))
}

func (s *Server) hJobFile(w http.ResponseWriter, r *http.Request) {
	name, ok := cleanName(r.PathValue("name"))
	if !ok || strings.ContainsAny(r.PathValue("id"), "/.") {
		httpErr(w, 400, "bad name")
		return
	}
	http.ServeFile(w, r, filepath.Join(s.jobDir(r.PathValue("id")), name))
}

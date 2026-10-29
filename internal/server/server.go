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
	// AgentBinary is the linux/arm64 lab-agent that ./volunteer downloads.
	AgentBinary string
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
		v.dirty = true // labd may have stopped mid-job
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
	go s.monitor()
	go s.buildMonitor()
	go s.gcLoop()
	go s.omtScheduler()
	return s, nil
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
	m.HandleFunc("POST /api/agent/enroll", s.hEnroll)
	m.HandleFunc("POST /api/agent/checkin", s.agent(s.hCheckin))
	m.HandleFunc("POST /api/agent/report", s.agent(s.hReport))
	m.HandleFunc("GET /api/agent/enrollment", s.agent(s.hAgentEnrollment))
	m.HandleFunc("POST /api/agent/left", s.agent(s.hAgentLeave))
	m.HandleFunc("GET /api/agent/artifacts/{sha}", s.agent(s.hAgentArtifact))
	m.HandleFunc("POST /api/agent/upload", s.agent(s.hUpload))
	m.HandleFunc("POST /api/agent/leave", s.agent(s.hLeave))
	m.HandleFunc("GET /api/agent/published", s.agent(s.hAgentPublished))

	m.HandleFunc("GET /api/auth", s.hAuth)
	m.HandleFunc("POST /api/devices/{name}/recovery-mode", s.maintainer(s.hRecoveryMode))
	m.HandleFunc("GET /api/recovery", s.viewer(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, api.RecoveryCapabilities{Schema: 1, Modes: []string{api.RecoveryNetworkOnly, api.RecoverySerialAssisted}, PerJobOOBIsolation: true, TransactionIsolation: true})
	}))
	m.HandleFunc("GET /api/mesa", s.viewer(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, api.MesaCapabilities{Schema: 1, Staged: true, OfficialGPU: false, AgentMin: mesaMinAgent})
	}))
	m.HandleFunc("GET /api/devices", s.viewer(s.hDevices))
	m.HandleFunc("GET /api/devices/{name}", s.viewer(s.hDevice))
	m.HandleFunc("PATCH /api/devices/{name}", s.maintainer(s.hPatchDevice))
	m.HandleFunc("DELETE /api/devices/{name}", s.maintainer(s.hForgetDevice))
	m.HandleFunc("POST /api/devices/{name}/end-enrollment", s.maintainer(s.hEndEnrollment))
	m.HandleFunc("POST /api/devices/{name}/lease", s.maintainer(s.hLease))
	m.HandleFunc("DELETE /api/devices/{name}/lease", s.maintainer(s.hRelease))
	m.HandleFunc("POST /api/devices/{name}/reset", s.maintainer(s.hReset))
	m.HandleFunc("GET /api/devices/{name}/serial", s.maintainer(s.hSerial))
	m.HandleFunc("GET /api/devices/{name}/oob", s.viewer(s.hOOBStatus))
	m.HandleFunc("GET /api/stream", s.viewer(s.hStream))
	m.HandleFunc("POST /api/devices/{name}/screenshot", s.maintainer(s.hScreenshot))
	m.HandleFunc("GET /api/devices/{name}/screen", s.viewer(s.hScreen))
	m.HandleFunc("GET /api/devices/{name}/screens", s.viewer(s.hScreens))
	m.HandleFunc("GET /api/devices/{name}/screens/{file}", s.viewer(s.hScreen))
	m.HandleFunc("GET /api/devices/{name}/logs", s.viewer(s.hLogs))
	m.HandleFunc("GET /api/devices/{name}/console", s.maintainer(s.hConsoleRaw))
	m.HandleFunc("POST /api/devices/{name}/console", s.maintainer(s.hConsoleWrite))
	m.HandleFunc("POST /api/devices/{name}/console/arm", s.maintainer(s.hConsoleArm))
	m.HandleFunc("POST /api/agent/screen", s.agent(s.hAgentScreen))
	m.HandleFunc("POST /api/enroll-tokens", s.maintainer(s.hEnrollToken))
	m.HandleFunc("POST /api/volunteer", s.viewer(s.hVolunteer))
	m.HandleFunc("GET /api/volunteer/lab-agent", s.viewer(s.hVolunteerAgent))
	m.HandleFunc("POST /api/artifacts", s.maintainer(s.hPutArtifact))
	m.HandleFunc("POST /api/mesa/jobs", s.maintainer(s.hSubmit))
	m.HandleFunc("POST /api/jobs", s.maintainer(s.hSubmit))
	m.HandleFunc("GET /api/jobs", s.viewer(s.hJobs))
	m.HandleFunc("GET /api/jobs/{id}", s.viewer(s.hJob))
	m.HandleFunc("GET /api/jobs/{id}/wait", s.viewer(s.hWait))
	m.HandleFunc("POST /api/jobs/{id}/cancel", s.maintainer(s.hCancel))
	m.HandleFunc("POST /api/jobs/{id}/retry", s.maintainer(s.hRetry))
	m.HandleFunc("POST /api/jobs/{id}/publish", s.maintainer(s.hPublish))
	m.HandleFunc("POST /api/jobs/{id}/exclude", s.maintainer(s.hExclude))
	m.HandleFunc("DELETE /api/jobs/{id}/exclude", s.maintainer(s.hExclude))
	m.HandleFunc("GET /api/jobs/{id}/files/{name...}", s.viewer(s.hJobFile))
	m.HandleFunc("GET /api/gate/{kernel}", s.maintainer(s.hGate))
	m.HandleFunc("POST /api/builder/poll", s.builderAuth(s.hBuilderPoll))
	m.HandleFunc("POST /api/builder/builds/{id}/progress", s.builderAuth(s.hBuilderProgress))
	m.HandleFunc("POST /api/builder/builds/{id}/done", s.builderAuth(s.hBuilderDone))
	m.HandleFunc("POST /api/builder/artifacts", s.builderAuth(s.hBuilderArtifact))
	m.HandleFunc("GET /api/builder/artifacts/{sha}", s.builderAuth(s.hAgentArtifact))
	m.HandleFunc("POST /api/builds", s.maintainer(s.hCreateBuild))
	m.HandleFunc("POST /api/installed/{release}/manifest", s.maintainer(s.hFreezeManifest))
	m.HandleFunc("POST /api/installed/{release}/entry/{device}", s.maintainer(s.hFreezeEntry))
	m.HandleFunc("POST /api/installed/{release}/promote", s.maintainer(s.hPromote))
	m.HandleFunc("GET /api/installed/{release}", s.viewer(s.hInstalledStatus))
	m.HandleFunc("GET /api/builds", s.viewer(s.hBuilds))
	m.HandleFunc("GET /api/builds/{id}", s.viewer(s.hBuild))
	m.HandleFunc("GET /api/builds/{id}/log", s.viewer(s.hBuildLog))
	m.HandleFunc("GET /api/builds/{id}/files/{name}", s.viewer(s.hBuildFile))
	m.HandleFunc("POST /api/builds/{id}/cancel", s.maintainer(s.hCancelBuild))
	m.HandleFunc("GET /api/builders", s.viewer(s.hBuilders))
	m.HandleFunc("POST /api/devices/{name}/exec", s.maintainer(s.hExec))
	m.HandleFunc("GET /api/devices/{name}/audit", s.maintainer(s.hAudit))
	m.HandleFunc("GET /api/maintainers", s.maintainer(s.hMaintainers))
	m.HandleFunc("POST /api/maintainers", s.maintainer(s.hAddMaintainer))
	m.HandleFunc("DELETE /api/maintainers/{name}", s.maintainer(s.hRemoveMaintainer))
	web.Register(m)
	return sameOrigin(m)
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
	// A Mac that never checked in hasn't taken the name: its enrollment failed,
	// and enrolling again with the new token replaces its secret.
	if v := s.dev(req.Name); v != nil && v.checkedIn() {
		httpErr(w, 409, "device %s already enrolled", req.Name)
		return
	}
	s.issueToken(w, req, "")
}

// issueToken answers with a one-use enrollment token for req, good for a day.
// A token for volunteer, a tailnet viewer's login, replaces any unused one
// they hold and counts toward maxVolunteerTokens (see addVolunteerToken).
func (s *Server) issueToken(w http.ResponseWriter, req api.EnrollTokenRequest, volunteer string) {
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
	writeJSON(w, api.EnrollTokenResponse{Name: req.Name, Token: tok, Expires: exp})
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

// hVolunteer gives anyone who may look at the lab, such as any tailnet peer
// under --tailscale, a token to enroll their own Mac: ./volunteer runs
// lab-agent setup with it. The Mac is named after what it sent, made into a
// free device name, labelled with the volunteer's tailnet login and marked a
// volunteer's. Tagged tailnet devices are machines, lab Macs among them, not
// people, so they get no token, and a person with maxVolunteerMacs Macs in
// the lab gets none either. Maintainers may ask too, with their token,
// outside the limits: they can make any token with POST /api/enroll-tokens
// anyway.
func (s *Server) hVolunteer(w http.ResponseWriter, r *http.Request) {
	a, who := s.access(r)
	volunteer := ""
	if a == adminAccess {
		who = "" // a Maintainer, not a volunteer's tailnet login
	} else {
		if s.taggedPeer(r) {
			httpErr(w, 403, "%s is a tagged tailnet device, a machine rather than a person: only a person may volunteer a Mac", who)
			return
		}
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
	s.issueToken(w, req, volunteer)
}

// taggedPeer reports whether r comes from a tagged tailnet device.
func (s *Server) taggedPeer(r *http.Request) bool {
	p := s.tailnetPeer(r)
	return p != nil && len(p.Tags) > 0
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
func (s *Server) hEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if !decodeBody(w, r, enrollBodyMax, &req) {
		return
	}
	t, err := s.store.token(hashSecret(req.Token), s.now())
	if err != nil {
		httpErr(w, 403, "enrollment token unknown, used or expired")
		return
	}
	secret := "dev_" + randHex(24)
	// The token is spent by the Mac's first check-in, not by this call: if the
	// answer never reached the Mac, enrolling again must work. Until then the
	// Mac it made gets a new secret.
	if v := s.dev(t.Name); v != nil {
		v.mu.Lock()
		// Its own token again, or a new one once the old one has run out.
		retry := v.d.BootID == "" && (v.enrolledWith == hashSecret(req.Token) || !s.tokenValid(v.enrolledWith))
		if retry {
			v.enrolledWith = hashSecret(req.Token)
			v.secretHash = hashSecret(secret)
			v.d.Enrollment = enrollment(t, v.d.Enrollment)
			v.d.Volunteer, v.d.VolunteeredBy = v.d.IsVolunteer(), t.VolunteeredBy
			v.saveLocked()
		}
		d := v.d
		v.mu.Unlock()
		if !retry {
			httpErr(w, 409, "device %s already enrolled", t.Name)
			return
		}
		s.log.Printf("enrolled %s again before its first check-in", t.Name)
		writeJSON(w, api.EnrollResponse{DeviceID: d.ID, Name: d.Name, Secret: secret, AgentEnrollment: s.agentEnrollment(d.Enrollment)})
		return
	}
	d := api.Device{ID: "d-" + randHex(6), Name: t.Name, Label: t.Label, Model: t.Model, VolunteeredBy: t.VolunteeredBy,
		State: api.StateNew, StateReason: "enrolled; run a baseline job", Facts: req.Facts, Enrollment: enrollment(t, api.Enrollment{})}
	d.Volunteer = d.IsVolunteer()
	if d.IsVolunteer() {
		d.AccessLevel = api.AccessQualification // until its Volunteer chooses
	}
	v := newDev(s, d, hashSecret(secret))
	v.enrolledWith = hashSecret(req.Token)
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
	s.devs[d.Name] = v
	s.mu.Unlock()
	v.mu.Lock()
	v.saveLocked()
	v.mu.Unlock()
	go s.deviceLoop(v)
	s.log.Printf("enrolled %s (%s, %s)", d.Name, d.Kind, req.Facts.DTModel)
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

func (s *Server) hAgentArtifact(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	if !reSHA.MatchString(sha) {
		httpErr(w, 400, "bad sha256")
		return
	}
	http.ServeFile(w, r, s.artifactPath(sha))
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

func (s *Server) hUpload(w http.ResponseWriter, r *http.Request) {
	job := r.URL.Query().Get("job")
	name, ok := cleanName(r.URL.Query().Get("name"))
	if !ok || strings.ContainsAny(job, "/.") || job == "" {
		httpErr(w, 400, "bad job or name")
		return
	}
	j, err := s.store.job(job)
	if err != nil || j.Spec.Device != agentDev(r).d.Name {
		httpErr(w, 404, "no such job for this device")
		return
	}
	p := filepath.Join(s.jobDir(job), name)
	os.MkdirAll(filepath.Dir(p), 0o755)
	f, err := os.Create(p)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	_, err = io.Copy(f, r.Body)
	f.Close()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	w.Write([]byte("ok"))
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

func (s *Server) hDevices(w http.ResponseWriter, r *http.Request) {
	out := []DeviceView{}
	for _, v := range s.allDevs() {
		out = append(out, s.view(v))
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
	if code, err := s.validatePayload(spec, d.Device); err != nil {
		return nil, code, err
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
	j := &api.Job{ID: "j" + now.Format("0102-150405") + "-" + randHex(2), Spec: spec, Maintainer: maintainer, State: api.JobQueued, Created: now, Updated: now,
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

func (s *Server) hJobs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = 20
	}
	jobs, err := s.store.jobs(r.URL.Query().Get("device"), n, false)
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

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// Tests stand in for sysfs, the kernel log and the waits.
var (
	drmClassDir        = "/sys/class/drm"
	platformDevicesDir = "/sys/bus/platform/devices"
	displayKernelLog   = func(ctx context.Context) (string, error) {
		return suspendCmd(ctx, "journalctl", "-k", "-b", "0", "-o", "cat", "--no-pager")
	}
	displayPoll       = 2 * time.Second
	displayEnableWait = 20 * time.Second
	listDisplayCards  = displayCards
)

// displayConnector is one DRM connector as display-check records it.
type displayConnector struct {
	Name        string   `json:"name"` // e.g. eDP-1, DP-1, HDMI-A-1
	Card        string   `json:"card"`
	Internal    bool     `json:"internal"`
	Status      string   `json:"status"` // connected, disconnected or unknown
	Enabled     bool     `json:"enabled"`
	CurrentMode string   `json:"current_mode,omitempty"` // the CRTC's mode, from debugfs
	CRTC        string   `json:"crtc,omitempty"`
	Modes       []string `json:"modes,omitempty"`
	EDID        edidInfo `json:"edid"`
}

// readConnectors lists the connectors under /sys/class/drm (card0-eDP-1 and
// the like).
func readConnectors(root string) []displayConnector {
	ents, _ := os.ReadDir(root)
	var cs []displayConnector
	for _, e := range ents {
		card, name, ok := strings.Cut(e.Name(), "-")
		if !ok || !strings.HasPrefix(card, "card") {
			continue
		}
		dir := filepath.Join(root, e.Name())
		status := readTrim(filepath.Join(dir, "status"))
		if status == "" {
			continue // not a connector
		}
		c := displayConnector{Name: name, Card: card, Internal: internalConnector(name), Status: status,
			Enabled: readTrim(filepath.Join(dir, "enabled")) == "enabled"}
		for _, m := range strings.Split(readTrim(filepath.Join(dir, "modes")), "\n") {
			if m = strings.TrimSpace(m); m != "" && !slices.Contains(c.Modes, m) {
				c.Modes = append(c.Modes, m)
			}
		}
		b, _ := os.ReadFile(filepath.Join(dir, "edid"))
		c.EDID = parseEDID(b)
		cs = append(cs, c)
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Internal != cs[j].Internal {
			return cs[i].Internal
		}
		return cs[i].Card+cs[i].Name < cs[j].Card+cs[j].Name
	})
	return cs
}

// displayDCP is one display co-processor's platform device.
type displayDCP struct {
	Device     string   `json:"device"` // e.g. 231c00000.dcp
	Compatible []string `json:"compatible"`
	External   bool     `json:"external"` // a dcpext
	Driver     string   `json:"driver,omitempty"`
	Bound      bool     `json:"bound"`
	Crashes    int      `json:"crashes"` // this boot
}

// readDCPs lists the platform devices whose device-tree node is a DCP or a
// dcpext, and whether a driver is bound to each. A disabled node has no
// device, so it isn't listed.
func readDCPs(root string) []displayDCP {
	ents, _ := os.ReadDir(root)
	var ds []displayDCP
	for _, e := range ents {
		dir := filepath.Join(root, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "of_node", "compatible"))
		if err != nil {
			continue
		}
		compat := strings.FieldsFunc(string(b), func(r rune) bool { return r == 0 })
		dcp, ext := false, false
		for _, c := range compat {
			switch {
			case c == "apple,dcpext" || strings.HasSuffix(c, "-dcpext"):
				dcp, ext = true, true
			case c == "apple,dcp" || strings.HasSuffix(c, "-dcp"):
				dcp = true
			}
		}
		if !dcp {
			continue
		}
		d := displayDCP{Device: e.Name(), Compatible: compat, External: ext}
		if t, err := os.Readlink(filepath.Join(dir, "driver")); err == nil {
			d.Driver, d.Bound = filepath.Base(t), true
		}
		ds = append(ds, d)
	}
	return ds
}

// displayFaults are the display faults in a kernel log.
type displayFaults struct {
	// DCPCrashes is RTKit's crash report from an apple-dcp device: one per
	// crash, by device.
	DCPCrashes map[string]int `json:"dcp_crashes"`
	// DARTFaults is translation faults and block exceptions, by DART. The
	// kernel rate-limits them, so a storm counts low.
	DARTFaults map[string]int `json:"dart_faults"`
}

func (f displayFaults) crashes() int { return sumCounts(f.DCPCrashes) }
func (f displayFaults) darts() int   { return sumCounts(f.DARTFaults) }

func sumCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

var (
	// dev_err's "driver device: message", as journalctl -o cat prints it.
	reDevLine   = regexp.MustCompile(`^(\S+) (\S+): (.*)$`)
	reDCPCrash  = regexp.MustCompile(`^RTKit: (co-processor has crashed|adopted co-processor crashed)`)
	reDARTFault = regexp.MustCompile(`^(translation fault|block exception)`)
)

// countDisplayFaults counts DCP crashes and DART faults in a kernel log.
func countDisplayFaults(log string) displayFaults {
	f := displayFaults{DCPCrashes: map[string]int{}, DARTFaults: map[string]int{}}
	for _, l := range strings.Split(log, "\n") {
		m := reDevLine.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		switch {
		case m[1] == "apple-dcp" && reDCPCrash.MatchString(m[3]):
			f.DCPCrashes[m[2]]++
		case m[1] == "apple-dart" && reDARTFault.MatchString(m[3]):
			f.DARTFaults[m[2]]++
		}
	}
	return f
}

// displayReport is display-check's display.json.
type displayReport struct {
	Time       time.Time          `json:"time"`
	Kernel     string             `json:"kernel"`
	Connectors []displayConnector `json:"connectors"`
	// Outputs are the active CRTCs and what each scans out: what the job's
	// per-display screenshots capture. Empty when debugfs can't tell.
	Outputs []drmOutput  `json:"outputs"`
	DCPs    []displayDCP `json:"dcps"`
	// DCPextBound: some dcpext has a driver bound. False with no dcpext.
	DCPextBound bool `json:"dcpext_bound"`
	// DCPCrashes and DARTFaults count this boot's, up to the end of the
	// check; NewDARTFaults those that came during it (the wait included).
	DCPCrashes    int            `json:"dcp_crashes"`
	DARTFaults    int            `json:"dart_faults"`
	NewDARTFaults int            `json:"new_dart_faults"`
	DARTByDevice  map[string]int `json:"dart_faults_by_device,omitempty"`
	KernelLogErr  string         `json:"kernel_log_error,omitempty"`
	Wait          *displayWait   `json:"wait,omitempty"`
	Failures      []string       `json:"failures,omitempty"`
	Passed        bool           `json:"passed"`
}

// displayWait is how the wait for an external connector went.
type displayWait struct {
	Expect    string  `json:"expect,omitempty"` // "" expected nothing
	WaitSec   float64 `json:"wait_sec"`
	Connected string  `json:"connected,omitempty"` // the connector that came up
	Enabled   bool    `json:"enabled,omitempty"`
	AfterSec  float64 `json:"after_sec,omitempty"`
}

// externalMatch is whether a connector is an external one the wait is for.
func externalMatch(expect string, c displayConnector) bool {
	if c.Internal || c.Status != "connected" {
		return false
	}
	if expect == "" || expect == "any" {
		return true
	}
	ok, _ := path.Match(expect, c.Name)
	return ok
}

// awaitExternal polls the connectors until one the wait is for is
// connected, then a little longer for it to be enabled (the compositor's
// modeset), within wait in all.
func awaitExternal(ctx context.Context, expect string, wait time.Duration, read func() []displayConnector, logf func(string, ...any)) *displayWait {
	w := &displayWait{Expect: expect, WaitSec: wait.Seconds()}
	start := time.Now()
	deadline := start.Add(wait)
	var connectedAt time.Time
	for {
		for _, c := range read() {
			if !externalMatch(expect, c) {
				continue
			}
			if w.Connected == "" {
				w.Connected, w.AfterSec, connectedAt = c.Name, time.Since(start).Seconds(), time.Now()
				logf("%s connected after %.0fs", c.Name, w.AfterSec)
			}
			if c.Name == w.Connected && c.Enabled {
				w.Enabled = true
				logf("%s enabled", c.Name)
				return w
			}
		}
		now := time.Now()
		if !now.Before(deadline) || ctx.Err() != nil || w.Connected != "" && now.Sub(connectedAt) >= displayEnableWait {
			return w
		}
		sleepCtx(ctx, WallClock, min(displayPoll, deadline.Sub(now)))
	}
}

// displayCheck runs the display-check builtin. It is informational: it fails
// only on a DCP crash this boot, a DART fault during the check, an expected
// external connector that didn't connect in time, or a kernel log it could
// not read (without it, neither crashes nor faults can be counted).
func displayCheck(ctx context.Context, t api.TestSpec, kernel, outDir string) api.TestResult {
	res := api.TestResult{Name: t.Name}
	if err := t.DisplayError(); err != nil {
		res.Error, res.ExitCode = err.Error(), -1
		return res
	}
	timeout := testTimeout(t)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	logPath := filepath.Join(outDir, "log.txt")
	f, err := os.Create(logPath)
	if err != nil {
		res.Error, res.ExitCode = err.Error(), -1
		return res
	}
	logf := func(format string, a ...any) { fmt.Fprintf(f, format+"\n", a...) }
	start := time.Now()
	r := displayReport{Kernel: kernel}

	before, berr := displayKernelLog(ctx)
	f0 := countDisplayFaults(before)
	if wait := t.Display.Wait(); wait > 0 {
		// Leave time to record after the wait.
		wait = min(wait, max(timeout-30*time.Second, timeout/2))
		logf("waiting up to %s for an external connector (%s)", wait.Round(time.Second), orStr(t.Display.Expect, "any, not required"))
		r.Wait = awaitExternal(ctx, t.Display.Expect, wait, func() []displayConnector { return readConnectors(drmClassDir) }, logf)
		if r.Wait.Connected == "" {
			logf("no external connector connected in %s", wait.Round(time.Second))
		}
	}

	r.Connectors = readConnectors(drmClassDir)
	r.Outputs = allOutputs(listDisplayCards())
	for i, c := range r.Connectors {
		for _, o := range r.Outputs {
			if o.Card == c.Card && o.Connector == c.Name {
				r.Connectors[i].CRTC, r.Connectors[i].CurrentMode = o.CRTC, o.Mode
			}
		}
	}
	after, aerr := displayKernelLog(ctx)
	fl := countDisplayFaults(after)
	r.DCPs = readDCPs(platformDevicesDir)
	for i, d := range r.DCPs {
		r.DCPs[i].Crashes = fl.DCPCrashes[d.Device]
		if d.External && d.Bound {
			r.DCPextBound = true
		}
	}
	r.DCPCrashes, r.DARTFaults, r.DARTByDevice = fl.crashes(), fl.darts(), fl.DARTFaults
	if berr == nil && aerr == nil {
		r.NewDARTFaults = max(0, fl.darts()-f0.darts())
	} else {
		r.KernelLogErr = fmt.Sprint(cmpOr(berr, aerr))
	}

	if r.DCPCrashes > 0 {
		r.Failures = append(r.Failures, fmt.Sprintf("%d DCP crash(es) this boot", r.DCPCrashes))
	}
	if r.NewDARTFaults > 0 {
		r.Failures = append(r.Failures, fmt.Sprintf("%d DART fault(s) during the check", r.NewDARTFaults))
	}
	if t.Display != nil && t.Display.Expect != "" && (r.Wait == nil || r.Wait.Connected == "") {
		r.Failures = append(r.Failures, fmt.Sprintf("expected external connector %s did not connect in time", t.Display.Expect))
	}
	if r.KernelLogErr != "" {
		r.Failures = append(r.Failures, "could not read the kernel log: "+r.KernelLogErr)
	}
	r.Passed = len(r.Failures) == 0
	r.Time = time.Now().UTC()

	b, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(outDir, "display.json"), append(b, '\n'), 0o644)
	sum := displaySummary(r)
	os.WriteFile(filepath.Join(outDir, "summary.txt"), []byte(sum), 0o644)
	f.WriteString(sum)
	f.Close()

	res.Passed = r.Passed
	if !r.Passed {
		res.ExitCode = 1
	}
	if ctx.Err() == context.DeadlineExceeded && !r.Passed {
		res.TimedOut, res.ExitCode = true, -1
	}
	res.Seconds = time.Since(start).Seconds()
	res.Tail = tail(logPath, 40)
	return res
}

func cmpOr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// displaySummary is display-check's summary.txt.
func displaySummary(r displayReport) string {
	var s strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&s, format+"\n", a...) }
	p("kernel %s", r.Kernel)
	if len(r.Connectors) == 0 {
		p("no DRM connectors")
	}
	for _, c := range r.Connectors {
		en := "disabled"
		if c.Enabled {
			en = "enabled"
		}
		line := fmt.Sprintf("%s %s: %s, %s", c.Card, c.Name, c.Status, en)
		if c.CurrentMode != "" {
			line += ", mode " + c.CurrentMode + " on " + c.CRTC
		}
		if len(c.Modes) > 0 {
			line += fmt.Sprintf(", %d modes (first %s)", len(c.Modes), c.Modes[0])
		}
		p("%s", line)
		e := c.EDID
		switch {
		case !e.Present:
			p("  EDID: none")
		default:
			parts := []string{fmt.Sprintf("%d bytes", e.Bytes)}
			for _, kv := range [][2]string{{"", e.Manufacturer}, {"product ", e.ProductCode}, {"", quoteIf(e.MonitorName)}, {"preferred ", e.PreferredMode}} {
				if kv[1] != "" {
					parts = append(parts, kv[0]+kv[1])
				}
			}
			if e.WidthMM > 0 {
				parts = append(parts, fmt.Sprintf("%dx%d mm", e.WidthMM, e.HeightMM))
			}
			if e.Problem != "" {
				parts = append(parts, e.Problem)
			}
			if e.SerialRedacted {
				parts = append(parts, "serial redacted")
			}
			p("  EDID: %s", strings.Join(parts, ", "))
		}
	}
	if len(r.Outputs) == 0 {
		p("active outputs: none known (debugfs state unreadable, or nothing scanned out)")
	}
	for _, o := range r.Outputs {
		p("active output %s: %s (crtc %d) plane %d, %s, fb %s", o.Connector, o.CRTC, o.CRTCID, o.PlaneID, orStr(o.Mode, "no mode"), orStr(o.FBSize, "?"))
	}
	if len(r.DCPs) == 0 {
		p("DCPs: none")
	}
	for _, d := range r.DCPs {
		kind := "dcp"
		if d.External {
			kind = "dcpext"
		}
		drv := "no driver bound"
		if d.Bound {
			drv = "bound to " + d.Driver
		}
		p("%s %s: %s, %d crash(es)", kind, d.Device, drv, d.Crashes)
	}
	p("dcpext bound: %v", r.DCPextBound)
	p("DCP crashes this boot: %d", r.DCPCrashes)
	p("DART faults this boot: %d (%d during the check)", r.DARTFaults, r.NewDARTFaults)
	if w := r.Wait; w != nil {
		switch {
		case w.Connected == "":
			p("wait: no external connector (%s) in %.0fs", orStr(w.Expect, "any"), w.WaitSec)
		default:
			p("wait: %s connected after %.0fs, enabled %v", w.Connected, w.AfterSec, w.Enabled)
		}
	}
	for _, f := range r.Failures {
		p("FAIL: %s", f)
	}
	if r.Passed {
		p("PASS")
	}
	return s.String()
}

func quoteIf(s string) string {
	if s == "" {
		return ""
	}
	return `"` + s + `"`
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

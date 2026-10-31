package server

// Live data for UIs: one server-sent event stream for everything that
// changes, screen captures from the GUI session, and logs read straight
// from a running Mac. The web UI and a future TUI use the same endpoints.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/oob"
)

type event struct {
	kind, device string
	data         []byte
}

type sub struct {
	ch     chan event
	device string
}

type hub struct {
	mu   sync.Mutex
	subs map[*sub]bool
}

// publish never blocks: a subscriber that can't keep up misses events and
// catches up from the REST endpoints.
func (h *hub) publish(kind, device string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.device != "" && device != "" && s.device != device {
			continue
		}
		select {
		case s.ch <- event{kind, device, b}:
		default:
		}
	}
}

func (h *hub) subscribe(device string) *sub {
	s := &sub{ch: make(chan event, 512), device: device}
	h.mu.Lock()
	if h.subs == nil {
		h.subs = map[*sub]bool{}
	}
	h.subs[s] = true
	h.mu.Unlock()
	return s
}

func (h *hub) unsubscribe(s *sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

// hStream serves server-sent events: device, job, serial, kevent, screen,
// build. ?device= limits it to one Mac. A caller gets only the events of the
// Macs they see (see sees), and the fleet's own (builds) only as a
// Maintainer. Browsers read it with fetch (EventSource cannot send the
// Authorization header).
func (s *Server) hStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		httpErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	// Serial lines carry the console (lab shell, serial lab exec), so only
	// Maintainers get them, as with the stored serial log.
	c := callerOf(r)
	serial := c.maintainer != ""
	sb := s.hub.subscribe(r.URL.Query().Get("device"))
	defer s.hub.unsubscribe(sb)
	fmt.Fprint(w, ": maclab stream\n\n")
	fl.Flush()
	keep := s.clock().NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.ctx.Done():
			return
		case <-keep.C():
			fmt.Fprint(w, ": keepalive\n\n")
		case e := <-sb.ch:
			if (e.kind == "serial" && !serial) || !s.sees(c, e.device) {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.kind, e.data)
		}
		fl.Flush()
	}
}

// viewLocked is view for callers already holding v.mu.
func (v *dev) viewLocked() DeviceView {
	d := v.d
	if d.Lease != nil && v.s.now().After(d.Lease.Expires) {
		d.Lease = nil
	}
	if d.OOB != nil {
		// The controller's token resets the Mac and opens its root console:
		// labd alone talks to the controller, clients only show the URL.
		oob := *d.OOB
		oob.Token = ""
		d.OOB = &oob
	}
	return DeviceView{Device: d, Tier: d.Tier(), Alive: v.aliveLocked(), Queued: len(v.queue), ScreenAt: v.screenAt}
}

// publishLocked sends the device to the web UI, which adds a device it
// hasn't seen: never one lab forget dropped.
func (v *dev) publishLocked() {
	if !v.forgotten {
		v.s.hub.publish("device", v.d.Name, v.viewLocked())
	}
}

// rearmSerial asks the controller to put the Mac's debug UART back into
// serial mode: the Mac drops out of it on every reboot.
func (v *dev) rearmSerial(window time.Duration) {
	go func() {
		ctx, cancel := context.WithTimeout(v.s.ctx, window+30*time.Second)
		defer cancel()
		if err := v.armOOB(ctx, window); err != nil {
			v.s.log.Printf("%s: serial re-arm: %v", v.d.Name, err)
		}
	}()
}

// ---- screens ----

func (s *Server) screenDir(name string) string { return filepath.Join(s.cfg.DataDir, "screens", name) }

type screenFile struct {
	Name string    `json:"name"`
	Time time.Time `json:"time"`
	Size int64     `json:"size"`
}

func (s *Server) screens(name string) []screenFile {
	ents, _ := os.ReadDir(s.screenDir(name))
	var out []screenFile
	for _, e := range ents {
		ms, err := strconv.ParseInt(strings.TrimSuffix(e.Name(), ".jpg"), 10, 64)
		if err != nil {
			continue
		}
		info, _ := e.Info()
		var size int64
		if info != nil {
			size = info.Size()
		}
		out = append(out, screenFile{Name: e.Name(), Time: time.UnixMilli(ms), Size: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

const keepScreens = 120

func (s *Server) hAgentScreen(w http.ResponseWriter, r *http.Request) {
	v := agentDev(r)
	dir := s.screenDir(v.d.Name)
	os.MkdirAll(dir, 0o755)
	now := s.now()
	name := fmt.Sprintf("%d.jpg", now.UnixMilli())
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	_, err = io.Copy(f, io.LimitReader(r.Body, 32<<20))
	f.Close()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	for _, old := range s.screens(v.d.Name)[min(keepScreens, len(s.screens(v.d.Name))):] {
		os.Remove(filepath.Join(dir, old.Name))
	}
	v.mu.Lock()
	v.screenAt, v.screenName = now, name
	v.mu.Unlock()
	w.Write([]byte(name))
}

// hScreenshot captures the Mac's screen now. Concurrent requests share one capture.
func (s *Server) hScreenshot(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	if why := v.refuseWatching(); why != "" {
		httpErr(w, 409, "%s", why)
		return
	}
	v.shotMu.Lock()
	defer v.shotMu.Unlock()
	v.mu.Lock()
	fresh := s.since(v.screenAt) < 1500*time.Millisecond
	alive := v.aliveLocked()
	v.mu.Unlock()
	var res api.ScreenResult
	if !fresh {
		if !alive {
			httpErr(w, 409, "%s is not responding", v.d.Name)
			return
		}
		if err := v.call(r.Context(), api.CmdScreen, "", api.ScreenArgs{WaitSec: 5}, 40*time.Second, &res); err != nil {
			httpErr(w, 502, "%v", err)
			return
		}
		s.hub.publish("screen", v.d.Name, map[string]any{"device": v.d.Name, "name": res.Name, "time": res.Time, "width": res.Width, "height": res.Height})
	}
	v.mu.Lock()
	res.Name, res.Time = v.screenName, v.screenAt
	v.mu.Unlock()
	writeJSON(w, res)
}

func (s *Server) hScreen(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	name := r.PathValue("file")
	if name == "" || name == "latest" {
		l := s.screens(v.d.Name)
		if len(l) == 0 {
			httpErr(w, 404, "no screen captured for %s yet", v.d.Name)
			return
		}
		name = l[0].Name
	}
	if strings.ContainsAny(name, "/\\") || strings.HasPrefix(name, ".") {
		httpErr(w, 400, "bad name")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Screen-Name", name)
	http.ServeFile(w, r, filepath.Join(s.screenDir(v.d.Name), name))
}

func (s *Server) hScreens(w http.ResponseWriter, r *http.Request) {
	if v := s.devOr404(w, r); v != nil {
		l := s.screens(v.d.Name)
		if l == nil {
			l = []screenFile{}
		}
		writeJSON(w, l)
	}
}

// hLogs reads the journal or kernel log live from the Mac.
func (s *Server) hLogs(w http.ResponseWriter, r *http.Request) {
	v := s.devOr404(w, r)
	if v == nil {
		return
	}
	if why := v.refuseWatching(); why != "" {
		httpErr(w, 409, "%s", why)
		return
	}
	v.mu.Lock()
	alive := v.aliveLocked()
	v.mu.Unlock()
	if !alive {
		httpErr(w, 409, "%s is offline, so its live logs can't be read. Job logs are still available.", v.d.Name)
		return
	}
	q := r.URL.Query()
	lines, _ := strconv.Atoi(q.Get("lines"))
	args := api.LogsArgs{Source: q.Get("source"), Lines: lines, Unit: q.Get("unit")}
	var out string
	if err := v.call(r.Context(), api.CmdLogs, "", args, 45*time.Second, &out); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, out)
}

// capture saves a screenshot into the job's files. It is best effort: a Mac
// without a GUI session just gets a note in the timeline.
func (r *jobRun) capture(label string) {
	if r.v.leaving() != "" {
		return // its agent is stopping: nothing would answer
	}
	var res api.ScreenResult
	ctx := r.s.ctx
	err := r.v.call(ctx, api.CmdScreen, r.j.ID, api.ScreenArgs{Label: label, WaitSec: 45}, 90*time.Second, &res)
	if err != nil {
		r.ev("no screenshot (%s): %v", label, err)
		return
	}
	r.s.updateJob(r.j, func(j *api.Job) { j.Result.Logs = append(j.Result.Logs, res.Name) })
	r.s.hub.publish("screen", r.j.Spec.Device, map[string]any{"device": r.j.Spec.Device, "job": r.j.ID, "name": res.Name, "time": res.Time})
}

// ---- console: an interactive shell over the out-of-band serial link ----

func (s *Server) consoleCtl(w http.ResponseWriter, r *http.Request) (*dev, oob.Controller) {
	v := s.devOr404(w, r)
	if v == nil {
		return nil, nil
	}
	v.mu.Lock()
	ctl := v.effectiveOOBLocked()
	v.mu.Unlock()
	if ctl == nil {
		httpErr(w, 409, "%s has no out-of-band controller, so there is no serial console", v.d.Name)
		return nil, nil
	}
	return v, ctl
}

// hConsoleRaw streams console bytes; it works whatever state the Mac's network is in.
func (s *Server) hConsoleRaw(w http.ResponseWriter, r *http.Request) {
	v, ctl := s.consoleCtl(w, r)
	if ctl == nil {
		return
	}
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	if fl != nil {
		fl.Flush()
	}
	v.rawOOB(r.Context(), flushWriter{w, fl})
}

type flushWriter struct {
	w  io.Writer
	fl http.Flusher
}

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if f.fl != nil {
		f.fl.Flush()
	}
	return n, err
}

func (s *Server) hConsoleWrite(w http.ResponseWriter, r *http.Request) {
	v, ctl := s.consoleCtl(w, r)
	if ctl == nil {
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if err := v.writeOOB(r.Context(), b); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	w.WriteHeader(204)
}

// hConsoleArm puts the Mac's UART into serial mode now (it leaves it on reboot).
func (s *Server) hConsoleArm(w http.ResponseWriter, r *http.Request) {
	v, ctl := s.consoleCtl(w, r)
	if ctl == nil {
		return
	}
	if err := v.armOOB(r.Context(), 0); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	// Switching the port into serial mode glitches the line, and the Mac's
	// shell reads the glitch as a stray 0xFF. Ctrl-U discards it.
	s.clock().Sleep(200 * time.Millisecond)
	v.writeOOB(r.Context(), []byte{0x15})
	w.Write([]byte("armed\n"))
}

package server

import (
	"context"
	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/oob"
	"io"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type modeCountOOB struct {
	base                                   *fakeOOB
	arm, reset, status, raw, write, serial atomic.Int64
}

func (c *modeCountOOB) Name() string { return c.base.Name() }
func (c *modeCountOOB) Arm(x context.Context, d time.Duration) error {
	c.arm.Add(1)
	return c.base.Arm(x, d)
}
func (c *modeCountOOB) Reset(x context.Context) error { c.reset.Add(1); return c.base.Reset(x) }
func (c *modeCountOOB) Status(x context.Context) (string, error) {
	c.status.Add(1)
	return c.base.Status(x)
}
func (c *modeCountOOB) Raw(x context.Context, w io.Writer) error {
	c.raw.Add(1)
	return c.base.Raw(x, w)
}
func (c *modeCountOOB) Write(x context.Context, b []byte) error {
	c.write.Add(1)
	return c.base.Write(x, b)
}
func (c *modeCountOOB) Serial(x context.Context, f func(string)) error {
	c.serial.Add(1)
	return c.base.Serial(x, f)
}
func (c *modeCountOOB) counts() [6]int64 {
	return [6]int64{c.arm.Load(), c.reset.Load(), c.status.Load(), c.raw.Load(), c.write.Load(), c.serial.Load()}
}
func countedModeLab(t *testing.T, name string) (*lab, *modeCountOOB) {
	l := newLabNamed(t, true, name)
	l.baseline()
	c := &modeCountOOB{base: l.oob}
	l.s.cfg.OOBFactory = func(*api.Device) (oob.Controller, error) { return c, nil }
	l.s.attachOOB(l.s.dev(name))
	until := time.Now().Add(time.Second)
	for c.serial.Load() == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	return l, c
}
func TestRecoveryNetworkJobNeverUsesStaleConfiguredController(t *testing.T) {
	l, c := countedModeLab(t, "m1-stale-oob")
	before := c.counts()
	j := l.run(api.JobSpec{RecoveryMode: api.RecoveryNetworkOnly, Kernel: l.artifact("krel=mode-network behavior=ok")})
	l.expect(j, api.OutcomePass)
	v := l.s.dev(l.name)
	v.rearmSerial(time.Millisecond)
	v.onSerial("Kernel panic - not syncing: FOREIGN_M3_SERIAL")
	time.Sleep(20 * time.Millisecond)
	if got := c.counts(); got != before {
		t.Fatalf("network-only used configured controller: before%v after%v", before, got)
	}
	if j.Spec.RecoveryMode != api.RecoveryNetworkOnly || j.EffectiveRecoveryMode != api.RecoveryNetworkOnly {
		t.Fatal("requested/effective mode lost", j)
	}
	d := v.snapshot()
	if d.OOB == nil || d.EffectiveRecoveryMode != api.RecoveryNetworkOnly || d.RecoveryModeJob != j.ID || d.Tier() > 1 {
		t.Fatal("config cleared or effective isolation lost", d)
	}
	if strings.Contains(modeMessages(j), "ttySAC0") {
		t.Fatal("network boot injected serial cmdline", modeMessages(j))
	}
	if _, e := l.s.store.job(j.ID); e != nil {
		t.Fatal(e)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/devices/x/oob", nil)
	req.SetPathValue("name", l.name)
	l.s.hOOBStatus(rec, req)
	if rec.Code != 404 {
		t.Fatal("masked OOB status admitted", rec.Code)
	}
	if got := c.counts(); got != before {
		t.Fatal("masked status called controller", got)
	}
	// An old/empty request inherits the network hold and cannot re-arm stale OOB.
	legacy := l.run(api.JobSpec{Kernel: l.artifact("krel=mode-legacy-inherits behavior=ok")})
	l.expect(legacy, api.OutcomePass)
	if legacy.Spec.RecoveryMode != "" || legacy.EffectiveRecoveryMode != api.RecoveryNetworkOnly || c.counts() != before {
		t.Fatal("empty request silently reenabled stale OOB", legacy.EffectiveRecoveryMode, c.counts())
	}
}
func TestRecoveryNetworkSilentLossIsUnknownAndNeverResets(t *testing.T) {
	l, c := countedModeLab(t, "m1-network-loss")
	before := c.counts()
	j := l.run(api.JobSpec{RecoveryMode: api.RecoveryNetworkOnly, Kernel: l.artifact("krel=mode-silent behavior=silent"), BootTimeoutSec: 2})
	l.expect(j, api.OutcomeUnknown)
	if l.s.dev(l.name).snapshot().State != api.StateNeedsHands {
		t.Fatal("unobserved loss not retained as needs_hands")
	}
	if c.counts() != before {
		t.Fatal("offline network mode touched stale controller", before, c.counts())
	}
	if j.Outcome == api.OutcomePass {
		t.Fatal("unknown loss became PASS")
	}
}
func TestRecoveryExplicitSerialJobStillUsesItsConfiguredRoute(t *testing.T) {
	l, c := countedModeLab(t, "m3pro")
	j := l.run(api.JobSpec{RecoveryMode: api.RecoverySerialAssisted, Kernel: l.artifact("krel=mode-serial behavior=ok")})
	l.expect(j, api.OutcomePass)
	if c.status.Load() == 0 || c.arm.Load() == 0 || j.Spec.RecoveryMode != api.RecoverySerialAssisted || j.EffectiveRecoveryMode != api.RecoverySerialAssisted {
		t.Fatal("serial-assisted route not validated/used", c.counts(), j.EffectiveRecoveryMode)
	}
	if !strings.Contains(modeMessages(j), "console=ttySAC0") {
		t.Fatal("serial stage capability lost", modeMessages(j))
	}
	l.waitDevice(func(d api.Device) bool { return d.Kernel == agent.SimKnownGood })
}
func TestRecoveryRejectsUnknownModeBeforeQueue(t *testing.T) {
	l := newLab(t, false)
	if _, code, e := l.s.Submit(api.JobSpec{Device: l.name, RecoveryMode: "typo"}); e == nil || code != 400 {
		t.Fatal(code, e)
	}
}
func TestRecoveryNetworkMarkerFiltersStaleSerialEvidence(t *testing.T) {
	l, c := countedModeLab(t, "m1-event-filter")
	v := l.s.dev(l.name)
	j := &api.Job{ID: "j-mode-filter", Spec: api.JobSpec{Device: l.name, RecoveryMode: api.RecoveryNetworkOnly}, State: api.JobQueued}
	if e := l.s.beginJobRecoveryMode(context.Background(), v, j); e != nil {
		t.Fatal(e)
	}
	before := c.counts()
	now := time.Now()
	v.mu.Lock()
	v.events = append(v.events, api.KernelEvent{Time: now, Kind: "panic", Source: "serial", Line: "foreign M3"}, api.KernelEvent{Time: now, Kind: "warning", Source: "kmsg", Line: "actual own agent"})
	v.mu.Unlock()
	events := v.eventsSince(now.Add(-time.Second))
	for _, e := range events {
		if e.Source == "serial" {
			t.Fatal("foreign serial event used as evidence")
		}
	}
	if c.counts() != before {
		t.Fatal("evidence read touched OOB")
	}
}

func modeMessages(j *api.Job) string {
	var out []string
	for _, e := range j.Events {
		out = append(out, e.Msg)
	}
	return strings.Join(out, "\n")
}

type modeBlockingOOB struct {
	*modeCountOOB
	entered, stopped chan struct{}
}

func (c *modeBlockingOOB) Arm(ctx context.Context, d time.Duration) error {
	close(c.entered)
	<-ctx.Done()
	close(c.stopped)
	return ctx.Err()
}
func TestRecoveryNetworkTransitionCancelsAndDrainsPriorControllerCall(t *testing.T) {
	l, c := countedModeLab(t, "mode-quiesce")
	v := l.s.dev(l.name)
	block := &modeBlockingOOB{modeCountOOB: c, entered: make(chan struct{}), stopped: make(chan struct{})}
	v.mu.Lock()
	v.oob = block
	v.mu.Unlock()
	armDone := make(chan error, 1)
	go func() { armDone <- v.armOOB(context.Background(), time.Minute) }()
	<-block.entered
	j := &api.Job{ID: "mode-quiesce-job", Spec: api.JobSpec{Device: l.name, RecoveryMode: api.RecoveryNetworkOnly}, State: api.JobQueued}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := l.s.beginJobRecoveryMode(ctx, v, j); e != nil {
		t.Fatal(e)
	}
	select {
	case <-block.stopped:
	default:
		t.Fatal("device commands could start before controller stopped")
	}
	if e := <-armDone; e == nil {
		t.Fatal("prior arm not canceled")
	}
	if e := v.resetOOB(ctx); e == nil {
		t.Fatal("masked reset admitted")
	}
}
func TestRecoveryNetworkMaskPersistsAcrossRestartUntilExplicitSerial(t *testing.T) {
	l, c := countedModeLab(t, "mode-restart")
	v := l.s.dev(l.name)
	j := &api.Job{ID: "mode-restart-job", Spec: api.JobSpec{Device: l.name, RecoveryMode: api.RecoveryNetworkOnly}, State: api.JobQueued}
	if e := l.s.beginJobRecoveryMode(context.Background(), v, j); e != nil {
		t.Fatal(e)
	}
	before := c.counts()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, e := New(ctx, l.s.cfg, nil)
	if e != nil {
		t.Fatal(e)
	}
	fresh := s.dev(l.name)
	if fresh.snapshot().EffectiveRecoveryMode != api.RecoveryNetworkOnly || fresh.snapshot().OOB == nil {
		t.Fatal("restart lost network hold or original route")
	}
	fresh.rearmSerial(time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if c.counts() != before {
		t.Fatal("restart touched isolated controller", before, c.counts())
	}
	serial := &api.Job{ID: "explicit-reenable", Spec: api.JobSpec{Device: l.name, RecoveryMode: api.RecoverySerialAssisted}, State: api.JobQueued}
	if e := s.beginJobRecoveryMode(ctx, fresh, serial); e != nil {
		t.Fatal(e)
	}
	if fresh.snapshot().EffectiveRecoveryMode != api.RecoverySerialAssisted || c.status.Load() <= before[2] {
		t.Fatal("explicit serial did not freshly validate")
	}
}

func TestRecoveryTransactionIsolatesExecBeforeAnyJob(t *testing.T) {
	l, c := countedModeLab(t, "pre-job-network")
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Lease = &api.Lease{Holder: "own", Expires: time.Now().Add(time.Hour)}
	v.mu.Unlock()
	before := c.counts()
	q := `{"mode":"network-only","holder":"own","transaction":"fresh-preparation"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(q))
	req.SetPathValue("name", l.name)
	l.s.hRecoveryMode(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if c.counts() != before {
		t.Fatal("network selection used stale configured route", c.counts())
	}
	d := v.snapshot()
	if d.RecoveryTransaction != "fresh-preparation" || d.RecoveryHolder != "own" || d.EffectiveRecoveryMode != api.RecoveryNetworkOnly {
		t.Fatal(d)
	}
	// Before a job exists, an offline /exec must not fall back to foreign serial.
	v.mu.Lock()
	v.d.LastSeen = time.Time{}
	v.mu.Unlock()
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/", strings.NewReader(`{"command":"DO_NOT_EXECUTE"}`))
	req.SetPathValue("name", l.name)
	l.s.hExec(rec, req)
	if rec.Code != 409 || c.counts() != before {
		t.Fatal("pre-job serial fallback escaped transaction", rec.Code, c.counts())
	}
	for _, spec := range []api.JobSpec{{Device: l.name, Holder: "own", RecoveryMode: api.RecoverySerialAssisted, RecoveryTransaction: "fresh-preparation"}, {Device: l.name, Holder: "own", RecoveryMode: api.RecoveryNetworkOnly, RecoveryTransaction: "foreign"}, {Device: l.name, Holder: "own", RecoveryMode: api.RecoveryNetworkOnly}} {
		if _, code, e := l.s.Submit(spec); e == nil || code != 409 {
			t.Fatal("mismatched transaction admitted", code, e)
		}
	}
	if e := validateRecoveryTransaction(d, api.JobSpec{Holder: "own", RecoveryMode: api.RecoveryNetworkOnly, RecoveryTransaction: "fresh-preparation"}); e != nil {
		t.Fatal(e)
	}
	if e := validateRecoveryTransaction(d, api.JobSpec{}); e != nil {
		t.Fatal("legacy inheritance should retain isolation", e)
	}
}
func TestRecoveryTransactionRefusesForeignLeaseBeforeControllerUse(t *testing.T) {
	l, c := countedModeLab(t, "transaction-lease")
	before := c.counts()
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Lease = &api.Lease{Holder: "actual-owner", Expires: time.Now().Add(time.Hour)}
	v.mu.Unlock()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"mode":"serial-assisted","holder":"foreign","transaction":"wrong"}`))
	req.SetPathValue("name", l.name)
	l.s.hRecoveryMode(rec, req)
	if rec.Code != 409 || c.counts() != before {
		t.Fatal("foreign lease touched controller", rec.Code, c.counts())
	}
}

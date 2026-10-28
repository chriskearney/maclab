package agent

import (
	"sync"
	"time"
)

// Clock is where labd and lab-agent read time: heartbeats, boot timeouts,
// leases and recovery all wait on it, so tests can drive them in milliseconds.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTicker(d time.Duration) Ticker
	Sleep(d time.Duration)
}

type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// WallClock is the real clock, what production runs on.
var WallClock Clock = wallClock{}

type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (wallClock) Sleep(d time.Duration)                  { time.Sleep(d) }
func (wallClock) NewTicker(d time.Duration) Ticker       { return wallTicker{time.NewTicker(d)} }

type wallTicker struct{ t *time.Ticker }

func (t wallTicker) C() <-chan time.Time { return t.t.C }
func (t wallTicker) Stop()               { t.t.Stop() }

// FakeClock stands still until a test advances it.
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*fakeWaiter
}

type fakeWaiter struct {
	at    time.Time
	every time.Duration // a ticker's period; 0 for a one-shot
	c     chan time.Time
}

func NewFakeClock(now time.Time) *FakeClock { return &FakeClock{now: now} }

func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *FakeClock) After(d time.Duration) <-chan time.Time { return f.wait(d, 0).c }

func (f *FakeClock) Sleep(d time.Duration) { <-f.After(d) }

func (f *FakeClock) NewTicker(d time.Duration) Ticker { return &fakeTicker{f, f.wait(d, d)} }

func (f *FakeClock) wait(d, every time.Duration) *fakeWaiter {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := &fakeWaiter{at: f.now.Add(d), every: every, c: make(chan time.Time, 1)}
	if d <= 0 && every == 0 {
		w.c <- f.now
		return w
	}
	f.waiters = append(f.waiters, w)
	return w
}

// Advance moves the clock on and fires every timer and ticker that falls due.
// Like a real ticker, a fake one drops ticks nobody has read.
func (f *FakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	keep := f.waiters[:0]
	for _, w := range f.waiters {
		if !w.at.After(f.now) {
			select {
			case w.c <- f.now:
			default:
			}
			if w.every == 0 {
				continue
			}
			for !w.at.After(f.now) {
				w.at = w.at.Add(w.every)
			}
		}
		keep = append(keep, w)
	}
	f.waiters = keep
}

type fakeTicker struct {
	f *FakeClock
	w *fakeWaiter
}

func (t *fakeTicker) C() <-chan time.Time { return t.w.c }

func (t *fakeTicker) Stop() {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	for i, w := range t.f.waiters {
		if w == t.w {
			t.f.waiters = append(t.f.waiters[:i], t.f.waiters[i+1:]...)
			return
		}
	}
}

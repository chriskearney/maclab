package server

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/agent"
	"github.com/iconidentify/maclab/internal/api"
)

// checkinGate fails the Mac's check-ins while down, with an error status or,
// when drop is set, a dropped connection, and counts the ones it fails.
type checkinGate struct {
	down, drop atomic.Bool
	failed     atomic.Int64
}

func (g *checkinGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.down.Load() && r.URL.Path == "/api/agent/checkin" {
			g.failed.Add(1)
			if g.drop.Load() {
				panic(http.ErrAbortHandler)
			}
			http.Error(w, "labd is down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// backoffLab is a lab on a fake clock whose Mac has checked in once. The
// clock then stands still until the test moves it, so only the test's fake
// time can space the Mac's check-ins.
func backoffLab(t *testing.T, g *checkinGate) (*lab, *agent.FakeClock) {
	t.Helper()
	clock := agent.NewFakeClock(time.Now())
	l := newLabWith(t, labConfig{clock: clock, wrap: g.wrap})
	var once sync.Once
	stopPump := pumpClock(clock)
	stop := func() { once.Do(stopPump) }
	t.Cleanup(stop)
	l.waitDevice(func(d api.Device) bool { return d.BootID != "" })
	stop()
	return l, clock
}

// crawl moves the fake clock on by d in one-second steps, a tenth of a
// second of wall time each: time enough for a Mac that backs off to make
// each check-in it owes, and for one in a tight loop to make hundreds.
func crawl(c *agent.FakeClock, d time.Duration) {
	for ; d > 0; d -= time.Second {
		c.Advance(time.Second)
		time.Sleep(100 * time.Millisecond)
	}
}

// checkinsAreSpaced asserts a Mac kept trying labd over 30 s of fake time
// with its check-ins failing, about one every 5 s.
func checkinsAreSpaced(t *testing.T, g *checkinGate, clock *agent.FakeClock) {
	t.Helper()
	g.down.Store(true)
	crawl(clock, 30*time.Second)
	// 30 s at one try per 5 s is about 6; 12 still means a backoff of
	// 2.5 s or more, and a tight loop makes hundreds in 3 s of wall time.
	if n := g.failed.Load(); n < 2 || n > 12 {
		t.Fatalf("%d failed check-ins in 30s of fake time with labd down, want about 6 (one per 5s backoff)", n)
	}
}

func TestFailedCheckinsBackOffWhenLabdAnswersWithAnError(t *testing.T) {
	g := &checkinGate{}
	_, clock := backoffLab(t, g)
	checkinsAreSpaced(t, g, clock)
}

func TestFailedCheckinsBackOffWhenLabdIsUnreachable(t *testing.T) {
	g := &checkinGate{}
	g.drop.Store(true)
	_, clock := backoffLab(t, g)
	checkinsAreSpaced(t, g, clock)
}

func TestEachFailedCheckinIsLogged(t *testing.T) {
	g := &checkinGate{}
	l, clock := backoffLab(t, g)
	before := len(l.logs.String())
	g.down.Store(true)
	crawl(clock, 20*time.Second)
	g.down.Store(false)
	time.Sleep(200 * time.Millisecond) // the last failure's log line
	failed := g.failed.Load()
	logged := strings.Count(l.logs.String()[before:], "checkin: ")
	if failed == 0 {
		t.Fatal("the Mac never tried labd while it was down")
	}
	if int64(logged) < failed {
		t.Fatalf("%d failed check-ins, %d logged as \"checkin: <err>\":\n%s", failed, logged, l.logs.String()[before:])
	}
}

func TestCheckinsResumeOnceLabdAnswersAgain(t *testing.T) {
	g := &checkinGate{}
	l, clock := backoffLab(t, g)
	g.down.Store(true)
	crawl(clock, 12*time.Second)
	if g.failed.Load() == 0 {
		t.Fatal("the Mac never tried labd while it was down")
	}
	g.down.Store(false)
	back := clock.Now()
	// The Mac's next try after its backoff gets through: within one 5 s
	// backoff, with slack.
	for waited := time.Duration(0); waited < 10*time.Second; waited += time.Second {
		crawl(clock, time.Second)
		if d := l.s.dev(l.name).snapshot(); d.LastSeen.After(back) {
			return
		}
	}
	d := l.s.dev(l.name).snapshot()
	t.Fatalf("labd has not seen the Mac in 10s of fake time since it came back: last seen %s, back at %s",
		d.LastSeen.Format(time.TimeOnly), back.Format(time.TimeOnly))
}

func TestRebootUnderALongPollChecksInAtOnce(t *testing.T) {
	clock := agent.NewFakeClock(time.Now())
	l := newLabWith(t, labConfig{clock: clock})
	t.Cleanup(pumpClock(clock))
	old := l.waitDevice(func(d api.Device) bool { return d.BootID != "" }).BootID
	time.Sleep(300 * time.Millisecond) // the Mac's long poll is in flight, held by labd
	start := clock.Now()
	l.sim.Reboot()
	d := l.waitDevice(func(d api.Device) bool { return d.BootID != "" && d.BootID != old })
	// The Mac is back 300 ms after the reboot; a check-in that first sat
	// out a 5 s backoff would reach labd no sooner than 5 s on.
	if took := d.LastSeen.Sub(start); took >= 4*time.Second {
		t.Fatalf("labd saw the new boot %s after the reboot under the long poll, want well under the 5s backoff", took)
	} else {
		t.Logf("new boot seen %s of fake time after the reboot", took)
	}
}

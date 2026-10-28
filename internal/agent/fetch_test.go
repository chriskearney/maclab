package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// artifactServer is labd's artifact route as a Mac sees it: it honours Range
// unless told not to, and can drop the connection part-way. It records every
// request with the time on the Mac's clock.
type artifactServer struct {
	content    []byte
	ignoreRng  bool // answer 200 with the whole file whatever the Range
	cutAfter   int  // drop the connection after this many body bytes; <0 never
	cutAlways  bool // cut every response, not just the first
	clock      Clock
	mu         sync.Mutex
	ranges     []string
	at         []time.Time
	cutAlready bool
}

func (a *artifactServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.ranges = append(a.ranges, r.Header.Get("Range"))
	if a.clock != nil {
		a.at = append(a.at, a.clock.Now())
	}
	cut := a.cutAfter >= 0 && (a.cutAlways || !a.cutAlready)
	a.cutAlready = true
	a.mu.Unlock()
	if a.ignoreRng {
		r.Header.Del("Range")
	}
	if !cut {
		http.ServeContent(w, r, "artifact", time.Time{}, bytes.NewReader(a.content))
		return
	}
	// serve what was asked for, but stop after cutAfter bytes of it
	rec := httptest.NewRecorder()
	http.ServeContent(rec, r, "artifact", time.Time{}, bytes.NewReader(a.content))
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes()[:min(a.cutAfter, rec.Body.Len())])
	w.(http.Flusher).Flush()
	panic(http.ErrAbortHandler)
}

func (a *artifactServer) requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.ranges...)
}

func shaOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func fetchFixture(t *testing.T, as *artifactServer, clock Clock) (*Agent, string) {
	t.Helper()
	srv := httptest.NewServer(as)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	a := New(&Config{Server: srv.URL, Secret: "dev_x", WorkDir: dir, Clock: clock}, NewSim(dir), log.New(io.Discard, "", 0))
	return a, filepath.Join(dir, "artifact")
}

func bigContent() []byte { return []byte("krel=7.2-big " + strings.Repeat("0123456789", 5000)) }

func TestFetchContinuesALeftoverPartFile(t *testing.T) {
	content := bigContent()
	as := &artifactServer{content: content, cutAfter: -1}
	a, dst := fetchFixture(t, as, nil)
	const have = 4000
	if err := os.WriteFile(dst+".part", content[:have], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.fetch(t.Context(), shaOf(content), dst); err != nil {
		t.Fatal(err)
	}
	if got := as.requests(); len(got) != 1 || got[0] != "bytes=4000-" {
		t.Fatalf("requests %q, want one asking for bytes=4000-", got)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, content) {
		t.Fatalf("the artifact on disk is %d bytes, want %d", len(got), len(content))
	}
	if _, err := os.Stat(dst + ".part"); !os.IsNotExist(err) {
		t.Fatalf("the .part file is still there: %v", err)
	}
}

func TestFetchStartsOverWhenTheServerIgnoresTheRange(t *testing.T) {
	content := bigContent()
	as := &artifactServer{content: content, cutAfter: -1, ignoreRng: true}
	a, dst := fetchFixture(t, as, nil)
	if err := os.WriteFile(dst+".part", []byte("stale bytes from some other transfer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.fetch(t.Context(), shaOf(content), dst); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, content) {
		t.Fatalf("a 200 to a Range request was appended: %d bytes on disk, want %d", len(got), len(content))
	}
}

func TestFetchRefusesAnArtifactWhoseShaDoesNotMatch(t *testing.T) {
	content := bigContent()
	as := &artifactServer{content: content, cutAfter: -1}
	a, dst := fetchFixture(t, as, NewFakeClock(time.Now()))
	err := a.fetch(t.Context(), shaOf([]byte("something else")), dst)
	if err == nil {
		t.Fatal("an artifact with the wrong sha256 was accepted")
	}
	for _, p := range []string{dst, dst + ".part"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s was left behind: %v", filepath.Base(p), err)
		}
	}
}

func TestFetchWaitsOnTheAgentClockThenContinuesADroppedBody(t *testing.T) {
	content := bigContent()
	clock := NewFakeClock(time.Now())
	as := &artifactServer{content: content, cutAfter: 3000}
	a, dst := fetchFixture(t, as, clock)
	done := make(chan error, 1)
	go func() { done <- a.fetch(t.Context(), shaOf(content), dst) }()

	waitFor := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for len(as.requests()) < n {
			if time.Now().After(deadline) {
				t.Fatalf("after the clock moved, the Mac made %d request(s), want %d", len(as.requests()), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor(1)
	time.Sleep(500 * time.Millisecond)
	clock.Advance(900 * time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	if n := len(as.requests()); n != 1 {
		t.Fatalf("the Mac retried after 0.9s, %d requests; the first back-off is 1s", n)
	}
	clock.Advance(100 * time.Millisecond)
	waitFor(2)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not finish after the retry")
	}
	if got := as.requests(); got[1] != "bytes=3000-" {
		t.Fatalf("the retry asked for %q, want bytes=3000-", got[1])
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, content) {
		t.Fatalf("the artifact on disk is %d bytes, want %d", len(got), len(content))
	}
}

func TestFetchGivesUpAfterEightRetriesWithGrowingBackOff(t *testing.T) {
	content := bigContent()
	clock := NewFakeClock(time.Now())
	as := &artifactServer{content: content, cutAfter: 0, cutAlways: true, clock: clock}
	a, dst := fetchFixture(t, as, clock)
	done := make(chan error, 1)
	go func() { done <- a.fetch(t.Context(), shaOf(content), dst) }()

	var err error
	giveUp := time.After(30 * time.Second)
loop:
	for {
		select {
		case err = <-done:
			break loop
		case <-giveUp:
			t.Fatal("fetch never gave up")
		case <-time.After(5 * time.Millisecond):
			clock.Advance(time.Second)
		}
	}
	if err == nil {
		t.Fatal("a transfer that always drops was reported as done")
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.at) != 9 {
		t.Fatalf("%d requests, want the first plus 8 retries", len(as.at))
	}
	waits := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i, w := range waits {
		w *= time.Second
		gap := as.at[i+1].Sub(as.at[i])
		if gap < w || gap > w+10*time.Second {
			t.Errorf("retry %d came %s after the last request, want about %s", i+1, gap, w)
		}
	}
}

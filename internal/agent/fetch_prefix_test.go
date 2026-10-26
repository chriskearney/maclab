package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fetchOnFakeClock runs fetch while the agent clock runs fast, so whatever
// back-off it takes costs nothing.
func fetchOnFakeClock(t *testing.T, a *Agent, clock *FakeClock, sha, dst string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- a.fetch(t.Context(), sha, dst) }()
	giveUp := time.After(30 * time.Second)
	for {
		select {
		case err := <-done:
			return err
		case <-giveUp:
			t.Fatal("fetch did not finish")
		case <-time.After(5 * time.Millisecond):
			clock.Advance(time.Second)
		}
	}
}

func TestFetchRestartsFromZeroWhenAResumedDownloadFailsItsSha(t *testing.T) {
	content := bigContent()
	clock := NewFakeClock(time.Now())
	as := &artifactServer{content: content, cutAfter: -1}
	a, dst := fetchFixture(t, as, clock)
	const have = 4000
	// a prefix that is not the artifact's, as a corrupted earlier transfer leaves
	if err := os.WriteFile(dst+".part", bytes.Repeat([]byte("Z"), have), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fetchOnFakeClock(t, a, clock, shaOf(content), dst); err != nil {
		t.Fatalf("a bad prefix was not recovered from: %v", err)
	}
	reqs := as.requests()
	if len(reqs) != 2 || reqs[0] != "bytes=4000-" || (reqs[1] != "" && reqs[1] != "bytes=0-") {
		t.Fatalf("requests %q, want a resume from 4000 and then one from byte 0", reqs)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, content) {
		t.Fatalf("the artifact on disk is %d bytes, want the good %d", len(got), len(content))
	}
	if _, err := os.Stat(dst + ".part"); !os.IsNotExist(err) {
		t.Fatalf("the .part file is still there: %v", err)
	}
}

func TestFetchDoesNotRetryAFullDownloadThatFailsItsSha(t *testing.T) {
	content := bigContent()
	clock := NewFakeClock(time.Now())
	as := &artifactServer{content: content, cutAfter: -1}
	a, dst := fetchFixture(t, as, clock)
	err := fetchOnFakeClock(t, a, clock, shaOf([]byte("something else")), dst)
	if err == nil {
		t.Fatal("an artifact with the wrong sha256 was accepted")
	}
	if n := len(as.requests()); n != 1 {
		t.Fatalf("%d requests; a mismatch on a download from 0 must not be retried", n)
	}
	for _, p := range []string{dst, dst + ".part"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s was left behind: %v", filepath.Base(p), err)
		}
	}
}

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// A report over labd's limit gets a 413, and sending it again gets the same:
// one oversized result must not keep the results and events after it from
// labd until the agent restarts. The agent sends them one by one, cuts a
// result that is still too large down, and replaces one that is too large
// even so with a failed result, so the test labd waits on ends.
func TestReportTooLarge(t *testing.T) {
	old := reportFieldMax
	reportFieldMax = 512
	t.Cleanup(func() { reportFieldMax = old })
	const limit = 4 << 10 // labd's limit, as the fake has it

	var (
		mu      sync.Mutex
		sends   int
		results []api.CommandResult
		events  []api.KernelEvent
	)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sends++
		if r.ContentLength > limit {
			http.Error(w, "a request body of that size is over labd's limit", http.StatusRequestEntityTooLarge)
			return
		}
		var rep api.Report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		results, events = append(results, rep.Results...), append(events, rep.Events...)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(hs.Close)
	var logged bytes.Buffer
	a := New(&Config{Server: hs.URL, Secret: "test"}, NewSim(t.TempDir()), log.New(&logged, "", 0))

	output := func(v any) json.RawMessage {
		b, _ := json.Marshal(v)
		return b
	}
	tail := strings.Repeat("kernel log line\n", 600) + "the end\n" // ~10 KB
	many := map[string]string{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		many[k] = strings.Repeat(k, 1000) // each cut to 512 bytes, still too large together
	}
	a.results = []api.CommandResult{
		{ID: "c1", OK: true, Output: output(api.TestResult{Name: "boot-health", ExitCode: 1, Seconds: 1234567, Tail: tail})},
		{ID: "c2", OK: true, Output: output(api.ExecResult{Stdout: "small"})},
		{ID: "c3", OK: true, Output: output(many)},
	}
	a.events = []api.KernelEvent{{Kind: "warn", Line: "a line"}}
	after := false
	a.after = []func(){func() { after = true }}

	if err := a.report(context.Background()); err != nil {
		t.Fatalf("report: %v\n%s", err, logged.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 3 || len(events) != 1 || len(a.results) != 0 || len(a.events) != 0 || !after {
		t.Fatalf("labd got %d results and %d events; %d and %d still queued; after ran: %v\n%s",
			len(results), len(events), len(a.results), len(a.events), after, logged.String())
	}
	byID := map[string]api.CommandResult{}
	for _, r := range results {
		byID[r.ID] = r
	}

	// cut down: its tail's end, after the note, and the rest as it was
	var tr api.TestResult
	if r := byID["c1"]; !r.OK || json.Unmarshal(r.Output, &tr) != nil {
		t.Fatalf("c1: %+v", r)
	}
	if !strings.HasPrefix(tr.Tail, cutNote) || !strings.HasSuffix(tr.Tail, "the end\n") || len(tr.Tail) != len(cutNote)+reportFieldMax ||
		tr.Name != "boot-health" || tr.ExitCode != 1 || tr.Seconds != 1234567 {
		t.Errorf("c1 cut down to %+v", tr)
	}
	if !strings.Contains(string(byID["c1"].Output), `"seconds":1234567,`) {
		t.Errorf("c1's numbers changed: %s", byID["c1"].Output)
	}
	// as it was
	if r := byID["c2"]; !r.OK || string(r.Output) != string(output(api.ExecResult{Stdout: "small"})) {
		t.Errorf("c2: %+v", r)
	}
	// dropped, and a failed result in its place
	if r := byID["c3"]; r.OK || len(r.Output) != 0 || !strings.Contains(r.Error, "labd refused it as too large") {
		t.Errorf("c3: %+v", r)
	}
	if !strings.Contains(logged.String(), "report: error: labd refused the result of command c3") {
		t.Errorf("no error logged for c3:\n%s", logged.String())
	}

	// Nothing is left to send.
	n := sends
	mu.Unlock()
	err := a.report(context.Background())
	mu.Lock()
	if err != nil || sends != n {
		t.Errorf("a second report: %v, %d more sends", err, sends-n)
	}
}

// A report labd refuses as too large that holds one result alone isn't
// sent as it is again.
func TestReportTooLargeAlone(t *testing.T) {
	old := reportFieldMax
	reportFieldMax = 512
	t.Cleanup(func() { reportFieldMax = old })
	var sizes []int64
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sizes = append(sizes, r.ContentLength)
		if r.ContentLength > 2<<10 {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(hs.Close)
	a := New(&Config{Server: hs.URL, Secret: "test"}, NewSim(t.TempDir()), log.New(&bytes.Buffer{}, "", 0))
	a.results = []api.CommandResult{{ID: "c1", OK: false, Error: strings.Repeat("x", 8<<10)}}
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 2 || sizes[1] > 2<<10 || len(a.results) != 0 {
		t.Errorf("sent %v; %d results left", sizes, len(a.results))
	}
}

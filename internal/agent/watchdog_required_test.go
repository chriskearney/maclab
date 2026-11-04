package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

func TestRequiredWatchdogRefusesBeforeTestStarts(t *testing.T) {
	h := unheldWDHarness(t)
	result := make(chan error, 1)
	go func() {
		_, _, err := h.a.exec(context.Background(), api.Command{
			ID: "required", JobID: "j1", Kind: api.CmdRunTest,
			Args: json.RawMessage(`{"name":"hold","builtin":"x","require_watchdog":true}`),
		})
		result <- err
	}()
	select {
	case <-h.sys.running:
		h.sys.finish <- struct{}{}
		<-result
		t.Fatal("test started without the required watchdog")
	case err := <-result:
		if err == nil || err.Error() != "test hold: agent-held watchdog required" {
			t.Fatalf("expected exact watchdog refusal, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent neither refused nor started the test")
	}
}

func TestRequiredWatchdogRunsAfterOpen(t *testing.T) {
	h := unheldWDHarness(t)
	_, _, err := h.a.exec(context.Background(), api.Command{
		ID: "before-open", JobID: "j1", Kind: api.CmdRunTest,
		Args: json.RawMessage(`{"name":"held","builtin":"x","require_watchdog":true}`),
	})
	if err == nil || err.Error() != "test held: agent-held watchdog required" {
		t.Fatalf("expected refusal before watchdog opened, got %v", err)
	}
	h.open()
	test := h.command(api.CmdRunTest, api.TestSpec{
		Name: "held", Builtin: "x", RequireWatchdog: true,
	})
	select {
	case <-h.sys.running:
		h.sys.finish <- struct{}{}
		h.finished(test)
	case <-time.After(5 * time.Second):
		t.Fatal("required test did not start after the watchdog opened")
	}
}

func TestRequiredWatchdogRunsWhenAlreadyHeld(t *testing.T) {
	h := newWDHarness(t)
	test := h.command(api.CmdRunTest, api.TestSpec{
		Name: "already-held", Builtin: "x", RequireWatchdog: true,
	})
	select {
	case <-h.sys.running:
		h.sys.finish <- struct{}{}
		h.finished(test)
	case <-time.After(5 * time.Second):
		t.Fatal("required test did not start with the watchdog already held")
	}
}

func TestOptionalWatchdogPreservesExistingJobs(t *testing.T) {
	h := unheldWDHarness(t)
	test := h.command(api.CmdRunTest, api.TestSpec{Name: "legacy", Builtin: "x"})
	select {
	case <-h.sys.running:
		h.sys.finish <- struct{}{}
		h.finished(test)
	case <-time.After(5 * time.Second):
		t.Fatal("existing test did not start without an agent-held watchdog")
	}
}

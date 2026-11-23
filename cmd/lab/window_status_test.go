package main

// Tests for the availability-window line in lab status (drill d-0062 p2).
// On 2026-11-20 ryan-m3max answered its heartbeat while its owner's window
// was closed and the row was called bookable: the helpers must print the
// window beside the heartbeat state, in both the table and the detail.

import (
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/window"
)

// weekly window: Mon 09:00-17:00
func weeklyWindow() *window.Settings {
	rule, err := window.ParseRule("mon 09:00-17:00")
	if err != nil {
		panic(err)
	}
	return &window.Settings{Rules: []window.Rule{rule}, Zone: "UTC"}
}

func closedDevice(now time.Time) api.Device {
	return api.Device{Name: "ryan-m3max", State: api.StateReady, LastSeen: now.Add(-2 * time.Second), Window: weeklyWindow()}
}

func openDevice(now time.Time) api.Device {
	return api.Device{Name: "ryan-m3max", State: api.StateReady, LastSeen: now.Add(-2 * time.Second), Window: weeklyWindow()}
}

func TestWindowStateForDeviceNamesClosedWithNextOpening(t *testing.T) {
	// a Saturday: the Mon 09:00-17:00 window is closed
	now := time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC) // Sat
	if got, want := windowStateForDevice(closedDevice(now).Window, now), "window CLOSED, next opens Mon 09:00"; !strings.Contains(got, want) {
		t.Fatalf("windowStateForDevice = %q, want it to contain %q", got, want)
	}
}

func TestWindowStateForDeviceSaysOpenInsideWindow(t *testing.T) {
	// Mon 10:00 inside the window; opens Monday 09:00, so "next" is not due
	now := time.Date(2026, time.November, 23, 10, 0, 0, 0, time.UTC) // Mon
	got := windowStateForDevice(openDevice(now).Window, now)
	if !strings.Contains(got, "window OPEN") {
		t.Fatalf("windowStateForDevice = %q, want OPEN", got)
	}
	if strings.Contains(got, "next opens") {
		t.Fatalf("windowStateForDevice = %q, want no next-opening inside an open window", got)
	}
}

func TestWindowStateForDeviceSaysUnset(t *testing.T) {
	now := time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)
	if got, want := windowStateForDevice(nil, now), "no availability window set (treated open)"; !strings.Contains(got, want) {
		t.Fatalf("windowStateForDevice = %q, want %q", got, want)
	}
}

func TestDevicesTableCarriesWindowBesideHeartbeat(t *testing.T) {
	now := time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC) // Sat, window closed
	devs := []api.Device{closedDevice(now), {Name: "m1", State: api.StateReady, LastSeen: now.Add(-time.Second)}}
	table := devicesTable(devs, now)
	lines := strings.Split(strings.TrimRight(table, "\n"), "\n")
	// header + two rows
	if len(lines) != 3 {
		t.Fatalf("devicesTable = %q", table)
	}
	if !strings.Contains(lines[1], "ryan-m3max") || !strings.Contains(lines[1], "window CLOSED, next opens Mon 09:00") {
		t.Fatalf("ryan-m3max row lost the window: %q", lines[1])
	}
	if !strings.Contains(lines[2], "m1") || !strings.Contains(lines[2], "no availability window set") {
		t.Fatalf("m1 row lost the window note: %q", lines[2])
	}
}

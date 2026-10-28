package agent

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// offlineMac is a Volunteer's Mac whose labd can't be reached, on a fake
// clock set to now in the Mac's local time. Its Volunteer commands are what
// `sudo lab-agent <args>` runs.
func offlineMac(t *testing.T, now time.Time) func(args ...string) (string, error) {
	t.Helper()
	cfg := &Config{Server: "http://127.0.0.1:1", DeviceID: "dev-1", Name: "ada-mbp", Secret: "dev_x",
		WorkDir: t.TempDir(), Clock: NewFakeClock(now)}
	sim := NewSim(t.TempDir())
	return func(args ...string) (string, error) {
		var out bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := Volunteer(ctx, cfg, sim, args, &out)
		return out.String(), err
	}
}

// monday6pm is Monday 2026-10-26 18:00 in the Mac's local time.
var monday6pm = time.Date(2026, 10, 26, 18, 0, 0, 0, time.Local)

func must(t *testing.T, run func(args ...string) (string, error), args ...string) string {
	t.Helper()
	out, err := run(args...)
	if err != nil {
		t.Fatalf("lab-agent %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func TestWindowCommandsAreVolunteerCommands(t *testing.T) {
	for _, name := range []string{"window", "pause", "open"} {
		if !IsVolunteerCommand(name) {
			t.Errorf("%q is not routed to the Volunteer commands", name)
		}
	}
}

func TestWindowAddShowAndRemoveChangeTheScheduleWithLabdDown(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "window", "add", "mon-fri", "19:00-07:00")
	must(t, run, "window", "add", "sat-sun", "09:00-17:00")
	out := must(t, run, "window", "show")
	if !strings.Contains(out, "mon-fri 19:00-07:00") || !strings.Contains(out, "sat-sun 09:00-17:00") {
		t.Fatalf("window show after two adds:\n%s", out)
	}
	must(t, run, "window", "remove", "mon-fri", "19:00-07:00")
	out = must(t, run, "window", "show")
	if strings.Contains(out, "mon-fri 19:00-07:00") || !strings.Contains(out, "sat-sun 09:00-17:00") {
		t.Fatalf("window show after removing mon-fri:\n%s", out)
	}
}

func TestWindowAddRefusesBadSyntax(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "window", "show")
	for _, args := range [][]string{
		{"window", "add"},
		{"window", "add", "mon-fri"},
		{"window", "add", "19:00-07:00"},
		{"window", "add", "funday", "19:00-07:00"},
		{"window", "add", "mon-fri", "25:00-07:00"},
		{"window", "add", "mon-fri", "7pm-7am"},
		{"window", "frobnicate"},
	} {
		if out, err := run(args...); err == nil {
			t.Errorf("lab-agent %s was accepted:\n%s", strings.Join(args, " "), out)
		}
	}
	if out := must(t, run, "window", "show"); strings.Contains(out, "funday") || strings.Contains(out, "25:00") || strings.Contains(out, "7pm") {
		t.Fatalf("a refused window was kept:\n%s", out)
	}
}

func TestWindowRemoveOfAWindowThatIsNotThereFails(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "window", "add", "mon-fri", "19:00-07:00")
	if _, err := run("window", "remove", "sat-sun", "09:00-17:00"); err == nil {
		t.Fatal("removing a window that was never added succeeded")
	}
	if out := must(t, run, "window", "show"); !strings.Contains(out, "mon-fri 19:00-07:00") {
		t.Fatalf("a failed remove changed the schedule:\n%s", out)
	}
}

func TestPauseAndOpenWorkWithLabdDown(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "window", "add", "mon-fri", "19:00-07:00")
	must(t, run, "open", "--until", "18:30")
	must(t, run, "pause")
	must(t, run, "pause", "--until", "2026-11-03")
}

func TestPauseUntilRefusesABadDate(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "pause", "--until", "2026-11-03")
	for _, date := range []string{"", "soon", "2026-13-01", "2026-02-30", "03/11/2026"} {
		if _, err := run("pause", "--until", date); err == nil {
			t.Errorf("pause --until %q was accepted", date)
		}
	}
}

func TestOpenNeedsAnUntilTime(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "open", "--until", "18:30")
	for _, args := range [][]string{
		{"open"},
		{"open", "--until"},
		{"open", "--until", "25:00"},
		{"open", "--until", "18:75"},
		{"open", "--until", "6pm"},
	} {
		if _, err := run(args...); err == nil {
			t.Errorf("lab-agent %s was accepted", strings.Join(args, " "))
		}
	}
}

func TestStatusShowsAClosedWindowAndTheNextOne(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "window", "add", "mon-fri", "19:00-07:00")
	out := strings.ToLower(must(t, run, "status"))
	if !strings.Contains(out, "closed") || !strings.Contains(out, "19:00") {
		t.Fatalf("status at 18:00 before a 19:00 window does not show it closed with the next window at 19:00:\n%s", out)
	}
}

func TestStatusShowsAnOpenWindowAndWhenItEnds(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "window", "add", "mon-fri", "19:00-07:00")
	must(t, run, "open", "--until", "18:30")
	out := strings.ToLower(must(t, run, "status"))
	if strings.Contains(out, "closed") || !strings.Contains(out, "open") || !strings.Contains(out, "18:30") {
		t.Fatalf("status after open --until 18:30 does not show the window open until 18:30:\n%s", out)
	}
}

func TestStatusShowsAPause(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "window", "add", "mon-fri", "19:00-07:00")
	must(t, run, "pause", "--until", "2026-11-03")
	out := strings.ToLower(must(t, run, "status"))
	if !strings.Contains(out, "paused") {
		t.Fatalf("status of a paused Mac:\n%s", out)
	}
}

func TestOpenAfterPauseOpensTheMac(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "pause", "--until", "2026-11-03")
	must(t, run, "open", "--until", "18:30")
	out := strings.ToLower(must(t, run, "status"))
	if strings.Contains(out, "closed") || !strings.Contains(out, "18:30") {
		t.Fatalf("status after pause then open --until 18:30:\n%s", out)
	}
}

func TestPauseAfterOpenClosesTheMac(t *testing.T) {
	run := offlineMac(t, monday6pm)
	must(t, run, "open", "--until", "18:30")
	must(t, run, "pause")
	out := strings.ToLower(must(t, run, "status"))
	if !strings.Contains(out, "closed") && !strings.Contains(out, "paused") {
		t.Fatalf("status after open then pause:\n%s", out)
	}
}

package window

import (
	"testing"
	"time"
	_ "time/tzdata" // the zones below, wherever the tests run
)

// The tests' Mac lives in New York. 2026-10-26 is a Monday; New York leaves
// daylight saving time at 02:00 on Sunday 2026-11-01.
const macZone = "America/New_York"

func zone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// at is a wall-clock time in the Mac's zone, "2026-10-27 06:00".
func at(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.ParseInLocation("2006-01-02 15:04", s, zone(t, macZone))
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func rules(t *testing.T, ss ...string) []Rule {
	t.Helper()
	var rs []Rule
	for _, s := range ss {
		r, err := ParseRule(s)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", s, err)
		}
		rs = append(rs, r)
	}
	return rs
}

func TestParseRuleReadsWeeklyWindows(t *testing.T) {
	for _, s := range []string{
		"mon-fri 19:00-07:00", // crosses midnight
		"sat-sun 09:00-17:00", // a day range
		"wed 12:00-13:00",     // one day
		"fri-mon 22:00-23:00", // a day range across the week's end
		"sun 00:00-04:00",
	} {
		r, err := ParseRule(s)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", s, err)
			continue
		}
		if r.String() != s {
			t.Errorf("ParseRule(%q).String() = %q", s, r.String())
		}
	}
}

func TestParseRuleRefusesBadSyntax(t *testing.T) {
	for _, s := range []string{
		"",
		"mon-fri",
		"19:00-07:00",
		"mon-fri 19:00",
		"mon-fri 19:00-",
		"funday 19:00-07:00",
		"mon-funday 19:00-07:00",
		"mon--fri 19:00-07:00",
		"mon-fri 25:00-07:00",
		"mon-fri 19:60-07:00",
		"mon-fri 7pm-7am",
		"mon-fri 19:00-19:00", // a window of no length
		"mon-fri 19:00-07:00 sat",
	} {
		if _, err := ParseRule(s); err == nil {
			t.Errorf("ParseRule(%q) accepted bad syntax", s)
		}
	}
}

func TestEvaluateAnswersOpenAttendedEndAndNext(t *testing.T) {
	never := time.Time{}
	cases := []struct {
		name    string
		rules   []string
		zone    string // the Mac's zone; "" is macZone
		paused  string // PausedUntil, in the Mac's zone
		open    string // OpenUntil, in the Mac's zone
		attend  bool
		now     time.Time
		want    bool // open
		attnd   bool
		end     time.Time
		next    time.Time
		nextNil bool
	}{
		{name: "inside a window that crosses midnight", rules: []string{"mon-fri 19:00-07:00"},
			now: at(t, "2026-10-27 06:00"), want: true, end: at(t, "2026-10-27 07:00"), next: at(t, "2026-10-27 19:00")},
		{name: "a window opens at its start", rules: []string{"mon-fri 19:00-07:00"},
			now: at(t, "2026-10-26 19:00"), want: true, end: at(t, "2026-10-27 07:00"), next: at(t, "2026-10-27 19:00")},
		{name: "a window is closed at its end", rules: []string{"mon-fri 19:00-07:00"},
			now: at(t, "2026-10-27 07:00"), next: at(t, "2026-10-27 19:00")},
		{name: "a crossing window belongs to the day it starts: Monday morning is Sunday night", rules: []string{"mon-fri 19:00-07:00"},
			now: at(t, "2026-10-26 06:00"), next: at(t, "2026-10-26 19:00")},
		{name: "Friday's window runs into Saturday morning", rules: []string{"mon-fri 19:00-07:00"},
			now: at(t, "2026-10-31 06:00"), want: true, end: at(t, "2026-10-31 07:00"), next: at(t, "2026-11-02 19:00")},
		{name: "closed over the weekend", rules: []string{"mon-fri 19:00-07:00"},
			now: at(t, "2026-10-31 12:00"), next: at(t, "2026-11-02 19:00")},
		{name: "a day range", rules: []string{"sat-sun 09:00-17:00"},
			now: at(t, "2026-11-01 10:00"), want: true, end: at(t, "2026-11-01 17:00"), next: at(t, "2026-11-07 09:00")},
		{name: "a day range across the week's end covers Sunday", rules: []string{"fri-mon 22:00-23:00"},
			now: at(t, "2026-11-01 22:30"), want: true, end: at(t, "2026-11-01 23:00"), next: at(t, "2026-11-02 22:00")},
		{name: "a day range across the week's end leaves Tuesday out", rules: []string{"fri-mon 22:00-23:00"},
			now: at(t, "2026-10-27 22:30"), next: at(t, "2026-10-30 22:00")},
		{name: "one day a week", rules: []string{"wed 12:00-13:00"},
			now: at(t, "2026-10-28 13:30"), next: at(t, "2026-11-04 12:00")},
		{name: "overlapping windows end with the later one", rules: []string{"mon 18:00-20:00", "mon 19:00-22:00"},
			now: at(t, "2026-10-26 19:30"), want: true, end: at(t, "2026-10-26 22:00"), next: at(t, "2026-11-02 18:00")},
		{name: "back-to-back windows are one window", rules: []string{"mon 18:00-20:00", "mon 20:00-22:00"},
			now: at(t, "2026-10-26 19:00"), want: true, end: at(t, "2026-10-26 22:00"), next: at(t, "2026-11-02 18:00")},
		{name: "the next window is the earliest of several", rules: []string{"sat 10:00-12:00", "wed 12:00-13:00"},
			now: at(t, "2026-10-27 09:00"), next: at(t, "2026-10-28 12:00")},
		{name: "no windows: closed, and nothing next",
			now: at(t, "2026-10-27 06:00"), nextNil: true},
		{name: "the schedule is in the Mac's time zone, whatever zone now is in", rules: []string{"mon-fri 19:00-07:00"},
			now: time.Date(2026, 10, 27, 10, 30, 0, 0, time.UTC), want: true, end: time.Date(2026, 10, 27, 11, 0, 0, 0, time.UTC), next: at(t, "2026-10-27 19:00")},
		{name: "the same moment on a Mac in UTC is outside the window", rules: []string{"mon-fri 19:00-07:00"}, zone: "UTC",
			now: time.Date(2026, 10, 27, 10, 30, 0, 0, time.UTC), next: time.Date(2026, 10, 27, 19, 0, 0, 0, time.UTC)},
		{name: "a window over the end of daylight saving time ends at its local time", rules: []string{"sun 00:00-04:00"},
			now: at(t, "2026-11-01 00:30"), want: true, end: at(t, "2026-11-01 04:00"), next: at(t, "2026-11-08 00:00")},
		{name: "Pause closes a window until it ends", rules: []string{"mon-fri 19:00-07:00"}, paused: "2026-10-26 23:00",
			now: at(t, "2026-10-26 20:00"), next: at(t, "2026-10-26 23:00")},
		{name: "a window reopens when its Pause ends", rules: []string{"mon-fri 19:00-07:00"}, paused: "2026-10-26 23:00",
			now: at(t, "2026-10-26 23:30"), want: true, end: at(t, "2026-10-27 07:00"), next: at(t, "2026-10-27 19:00")},
		{name: "Pause until a date skips every window before it", rules: []string{"mon-fri 19:00-07:00"}, paused: "2026-10-29 00:00",
			now: at(t, "2026-10-27 20:00"), next: at(t, "2026-10-29 00:00")},
		{name: "a Pause that has ended changes nothing", rules: []string{"mon-fri 19:00-07:00"}, paused: "2026-10-26 08:00",
			now: at(t, "2026-10-27 06:00"), want: true, end: at(t, "2026-10-27 07:00"), next: at(t, "2026-10-27 19:00")},
		{name: "open now opens the Mac outside its schedule", rules: []string{"mon-fri 19:00-07:00"}, open: "2026-10-31 14:00",
			now: at(t, "2026-10-31 12:00"), want: true, end: at(t, "2026-10-31 14:00"), next: at(t, "2026-11-02 19:00")},
		{name: "open now that runs into a window ends with the window", rules: []string{"mon-fri 19:00-07:00"}, open: "2026-10-26 20:00",
			now: at(t, "2026-10-26 17:00"), want: true, end: at(t, "2026-10-27 07:00"), next: at(t, "2026-10-27 19:00")},
		{name: "open now with no schedule", open: "2026-10-31 14:00",
			now: at(t, "2026-10-31 12:00"), want: true, end: at(t, "2026-10-31 14:00"), nextNil: true},
		{name: "open now has ended", rules: []string{"mon-fri 19:00-07:00"}, open: "2026-10-31 11:00",
			now: at(t, "2026-10-31 12:00"), next: at(t, "2026-11-02 19:00")},
		{name: "an Attended open now is attended", rules: []string{"mon-fri 19:00-07:00"}, open: "2026-10-31 14:00", attend: true,
			now: at(t, "2026-10-31 12:00"), want: true, attnd: true, end: at(t, "2026-10-31 14:00"), next: at(t, "2026-11-02 19:00")},
		{name: "a weekly window is not attended", rules: []string{"mon-fri 19:00-07:00"}, open: "2026-10-27 05:00", attend: true,
			now: at(t, "2026-10-27 06:00"), want: true, end: at(t, "2026-10-27 07:00"), next: at(t, "2026-10-27 19:00")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Settings{Rules: rules(t, c.rules...), Zone: c.zone, Attended: c.attend}
			if s.Zone == "" {
				s.Zone = macZone
			}
			if c.paused != "" {
				s.PausedUntil = at(t, c.paused)
			}
			if c.open != "" {
				s.OpenUntil = at(t, c.open)
			}
			got := Evaluate(s, c.now)
			if got.Open != c.want || got.Attended != c.attnd {
				t.Fatalf("at %s: open %v attended %v, want open %v attended %v", c.now, got.Open, got.Attended, c.want, c.attnd)
			}
			if c.want && !got.End.Equal(c.end) {
				t.Errorf("at %s: window ends %s, want %s", c.now, got.End, c.end)
			}
			if !c.want && !got.End.IsZero() {
				t.Errorf("at %s: closed, but a window end of %s", c.now, got.End)
			}
			want := c.next
			if c.nextNil {
				want = never
			}
			if !got.Next.Equal(want) {
				t.Errorf("at %s: next window %s, want %s", c.now, got.Next, want)
			}
		})
	}
}

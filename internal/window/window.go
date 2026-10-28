// Package window is the one Availability window evaluator, shared by
// lab-agent and labd's scheduler: given a Volunteer Mac's settings and a
// moment, it answers whether the Mac is open to the lab, until when, and when
// it next opens.
package window

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule is one weekly window as the Volunteer typed it, e.g. "mon-fri 19:00-07:00":
// it opens at Start on each day from First to Last (wrapping past Sunday) and
// closes at End, on the next day when End is not after Start. A window that
// crosses midnight belongs to the day it starts.
type Rule struct {
	First, Last time.Weekday
	Start, End  int // minutes after midnight, in the Mac's local time
}

var days = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

var reClock = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

// ParseRule reads a weekly window in `window add` syntax: a day or day range
// and a time range, "mon-fri 19:00-07:00".
func ParseRule(s string) (Rule, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return Rule{}, fmt.Errorf("%q: a window is days and a time range, like mon-fri 19:00-07:00", s)
	}
	var r Rule
	var err error
	if r.First, r.Last, err = parseDays(f[0]); err != nil {
		return Rule{}, err
	}
	from, to, ok := strings.Cut(f[1], "-")
	if !ok {
		return Rule{}, fmt.Errorf("%q: the times are a range, like 19:00-07:00", f[1])
	}
	if r.Start, err = ParseClock(from); err != nil {
		return Rule{}, err
	}
	if r.End, err = ParseClock(to); err != nil {
		return Rule{}, err
	}
	if r.Start == r.End {
		return Rule{}, fmt.Errorf("%q: a window can't start and end at the same time", f[1])
	}
	return r, nil
}

func parseDays(s string) (first, last time.Weekday, err error) {
	from, to, isRange := strings.Cut(s, "-")
	if first, err = parseDay(from); err != nil {
		return 0, 0, err
	}
	if !isRange {
		return first, first, nil
	}
	if last, err = parseDay(to); err != nil {
		return 0, 0, err
	}
	if first == last {
		return 0, 0, fmt.Errorf("%q: write one day on its own, like %s", s, days[first])
	}
	return first, last, nil
}

func parseDay(s string) (time.Weekday, error) {
	if i := slices.Index(days, s); i >= 0 {
		return time.Weekday(i), nil
	}
	return 0, fmt.Errorf("%q is not a day: use %s", s, strings.Join(days[1:], ", ")+", sun")
}

// ParseClock reads a 24-hour time of day, "19:00", as minutes after midnight.
func ParseClock(s string) (int, error) {
	m := reClock.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("%q is not a 24-hour time like 19:00", s)
	}
	h, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return h*60 + min, nil
}

// String is the rule as `window show` prints it.
func (r Rule) String() string {
	d := days[r.First]
	if r.Last != r.First {
		d += "-" + days[r.Last]
	}
	return fmt.Sprintf("%s %02d:%02d-%02d:%02d", d, r.Start/60, r.Start%60, r.End/60, r.End%60)
}

// MarshalText and UnmarshalText carry a rule as its typed text, in check-ins
// and in labd's copy of the Mac's settings.
func (r Rule) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Rule) UnmarshalText(b []byte) error {
	p, err := ParseRule(string(b))
	if err != nil {
		return err
	}
	*r = p
	return nil
}

// on is whether the rule opens on weekday d.
func (r Rule) on(d time.Weekday) bool {
	return (d-r.First+7)%7 <= (r.Last-r.First+7)%7
}

// Settings are a Volunteer Mac's window settings: the weekly schedule in the
// Mac's local time plus the Pause and Open now overrides. Only the Volunteer
// changes them, on the Mac.
type Settings struct {
	Rules       []Rule    `json:"rules"`
	Zone        string    `json:"zone,omitempty"`        // IANA name of the Mac's local time zone
	PausedUntil time.Time `json:"paused_until,omitzero"` // Pause: closed until then
	OpenUntil   time.Time `json:"open_until,omitzero"`   // Open now: open until then
	Attended    bool      `json:"attended,omitempty"`    // the Open now is an Attended window
}

// Location is the Mac's local time zone; time.Local when it has none or
// labd doesn't know it.
func (s Settings) Location() *time.Location {
	if s.Zone == "" {
		return time.Local
	}
	zones.Lock()
	defer zones.Unlock()
	if loc, ok := zones.m[s.Zone]; ok {
		return loc
	}
	loc, err := time.LoadLocation(s.Zone)
	if err != nil {
		loc = time.Local
	}
	zones.m[s.Zone] = loc
	return loc
}

var zones = struct {
	sync.Mutex
	m map[string]*time.Location
}{m: map[string]*time.Location{}}

// State is what the evaluator answers for one moment.
type State struct {
	Open     bool
	Attended bool      // the open window is an Attended window
	End      time.Time // when the current window ends; zero when closed
	Next     time.Time // when the next window opens; zero when none will
}

// Evaluate is the window state of a Mac with settings s at now. Windows that
// overlap or meet are one window, and so is an Open now that runs into a
// scheduled one. Pause closes every scheduled window until it ends; an
// Open now opens the Mac even then.
func Evaluate(s Settings, now time.Time) State {
	loc := s.Location()
	horizon := now
	for _, t := range []time.Time{s.PausedUntil, s.OpenUntil} {
		if t.After(horizon) {
			horizon = t
		}
	}
	horizon = horizon.AddDate(0, 0, 8)

	type span struct{ from, to time.Time }
	var spans []span
	local := now.In(loc)
	for day := time.Date(local.Year(), local.Month(), local.Day()-1, 0, 0, 0, 0, loc); day.Before(horizon); day = day.AddDate(0, 0, 1) {
		for _, r := range s.Rules {
			if !r.on(day.Weekday()) {
				continue
			}
			from := time.Date(day.Year(), day.Month(), day.Day(), 0, r.Start, 0, 0, loc)
			endDay := day.Day()
			if r.End <= r.Start {
				endDay++
			}
			to := time.Date(day.Year(), day.Month(), endDay, 0, r.End, 0, 0, loc)
			if !to.After(s.PausedUntil) {
				continue
			}
			if from.Before(s.PausedUntil) {
				from = s.PausedUntil
			}
			spans = append(spans, span{from, to})
		}
	}
	openNow := s.OpenUntil.After(now)
	if openNow {
		spans = append(spans, span{now, s.OpenUntil})
	}
	slices.SortFunc(spans, func(a, b span) int { return a.from.Compare(b.from) })
	var merged []span
	for _, sp := range spans {
		if n := len(merged); n > 0 && !sp.from.After(merged[n-1].to) {
			if sp.to.After(merged[n-1].to) {
				merged[n-1].to = sp.to
			}
			continue
		}
		merged = append(merged, sp)
	}

	var st State
	for i, sp := range merged {
		if !now.Before(sp.from) && now.Before(sp.to) {
			st.Open, st.End = true, sp.to
			st.Attended = openNow && s.Attended
			if i+1 < len(merged) {
				st.Next = merged[i+1].from
			}
			return st
		}
		if sp.from.After(now) {
			st.Next = sp.from
			return st
		}
	}
	return st
}

// Package loop drives Lab boots of one fault-injecting kernel overnight and
// keeps a ledger of what each one did, what the lab said, and what an agent
// judging the evidence said (docs/research/agent-loop-week1.md).
package loop

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// A Mode is one fault the night can inject. All but Netdown are chosen with
// maclab_chaos.mode= on the command line of a kernel built with
// tools/chaos/maclab_chaos.c.
type Mode string

const (
	None       Mode = "none"
	Marker     Mode = "marker"
	OopsLate   Mode = "oops_late"
	PanicLate  Mode = "panic_late"
	PanicEarly Mode = "panic_early"
	HangEarly  Mode = "hang_early"
	HangLate   Mode = "hang_late"
	Netdown    Mode = "netdown"
)

// Modes lists every mode, healthy ones first.
var Modes = []Mode{None, Marker, OopsLate, PanicLate, PanicEarly, HangEarly, HangLate, Netdown}

// Healthy modes break nothing: a boot of one that doesn't pass means the lab
// or the kernel is broken, and every later result is noise.
func (m Mode) Healthy() bool { return m == None || m == Marker }

// Week1 is the night the research doc plans: 20 boots, 12 of them broken.
var Week1 = map[Mode]int{None: 4, Marker: 4, OopsLate: 2, PanicLate: 2, PanicEarly: 2, HangEarly: 2, HangLate: 2, Netdown: 2}

// ParsePlan reads "none=4,marker=4,hang_late=2" into counts per mode.
func ParsePlan(s string) (map[Mode]int, error) {
	plan := map[Mode]int{}
	for _, part := range strings.Split(s, ",") {
		name, n, ok := strings.Cut(strings.TrimSpace(part), "=")
		var count int
		if _, err := fmt.Sscanf(n, "%d", &count); !ok || err != nil || count < 0 {
			return nil, fmt.Errorf("plan %q: want mode=count, comma-separated", part)
		}
		if !slices.Contains(Modes, Mode(name)) {
			return nil, fmt.Errorf("plan: unknown mode %q", name)
		}
		plan[Mode(name)] += count
	}
	return plan, nil
}

// Boot is one planned Lab boot.
type Boot struct {
	Iter    int    `json:"iter"`
	Mode    Mode   `json:"mode"`
	Marker  string `json:"marker,omitempty"`
	Cmdline string `json:"cmdline"`
}

// Schedule shuffles the plan with seed, so a night can be replayed, and puts
// a healthy boot first: until one passes, nothing else is worth reading.
func Schedule(plan map[Mode]int, seed uint64) []Boot {
	var modes []Mode
	for _, m := range Modes {
		for range plan[m] {
			modes = append(modes, m)
		}
	}
	r := mrand.New(mrand.NewPCG(seed, seed^0x6d61636c6162))
	r.Shuffle(len(modes), func(i, j int) { modes[i], modes[j] = modes[j], modes[i] })
	if i := slices.IndexFunc(modes, Mode.Healthy); i > 0 {
		modes[0], modes[i] = modes[i], modes[0]
	}
	boots := make([]Boot, len(modes))
	for i, m := range modes {
		b := Boot{Iter: i + 1, Mode: m}
		if m == Marker {
			b.Marker = randomMarker()
		}
		b.Cmdline = cmdline(b)
		boots[i] = b
	}
	return boots
}

func cmdline(b Boot) string {
	switch b.Mode {
	case Netdown:
		// A healthy kernel with no Wi-Fi: no chaos needed.
		return "maclab_chaos.mode=none modprobe.blacklist=brcmfmac"
	case Marker:
		return "maclab_chaos.mode=marker maclab_chaos.marker=" + b.Marker
	}
	return "maclab_chaos.mode=" + string(b.Mode)
}

func randomMarker() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Predicted is the outcomes the research doc expects for a mode, from reading
// labboot.go and the outcome definitions. serial says whether the Mac has an
// out-of-band serial console, which lets the lab see an early panic. An
// outcome outside these is a finding: the lab misreads a fault, or the
// prediction misread the lab.
func Predicted(m Mode, serial bool) []string {
	switch m {
	case None, Marker:
		return []string{api.OutcomePass}
	case OopsLate:
		return []string{api.OutcomePanicked, api.OutcomeUnhealthy}
	case PanicLate:
		return []string{api.OutcomePanicked, api.OutcomeCrashedOrHung}
	case PanicEarly:
		if serial {
			return []string{api.OutcomePanicked}
		}
		return []string{api.OutcomeBootFailed, api.OutcomePanicked}
	case HangEarly, HangLate:
		return []string{api.OutcomeBootFailed}
	case Netdown:
		return []string{api.OutcomeLostContact}
	}
	return nil
}

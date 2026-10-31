package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// nodesReport is a report whose hardware.drivers check fails with these
// compatibles' nodes unclaimed, as compatible, count pairs; a count of 0
// leaves it out, as omarchy-m-test before it counted nodes did.
func nodesReport(t *testing.T, pairs ...any) omtReport {
	t.Helper()
	var inv, ev []string
	for i := 0; i < len(pairs); i += 2 {
		c, n := pairs[i].(string), pairs[i+1].(int)
		count := ""
		if n > 0 {
			count = fmt.Sprintf(`"count":%d,`, n)
		}
		inv = append(inv, fmt.Sprintf(`{"compatible":%q,%s"outcome":"unknown-hardware"}`, c, count))
		nodes := "1 node"
		if n > 1 {
			nodes = fmt.Sprintf("%d nodes", n)
		}
		ev = append(ev, fmt.Sprintf(`"unclaimed: %s (%s): unknown hardware"`, c, nodes))
	}
	var rep omtReport
	data := fmt.Sprintf(`{"inventory":{"unclaimed":[%s]},"checks":[{"id":"hardware.drivers","status":"fail","evidence":[%s]}]}`,
		strings.Join(inv, ","), strings.Join(ev, ","))
	if err := json.Unmarshal([]byte(data), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// A test kernel that leaves 3 nodes of a compatible unclaimed, where the
// known-good kernel left 1, regresses that compatible. A reference from
// before nodes were counted has only the compatibles, and compares as before.
func TestOMTNodeCounts(t *testing.T) {
	failing := map[string]string{"hardware.drivers": "fail"}
	ref := func(nodes map[string]int) *omtBaseline {
		return &omtBaseline{Status: failing, Unclaimed: []string{"apple,dart", "apple,sep"}, UnclaimedNodes: nodes}
	}
	ids := func(cs []api.OMTCheck) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.ID+" ("+c.Evidence+")")
		}
		return strings.Join(out, ", ")
	}
	for _, c := range []struct {
		name            string
		base            *omtBaseline
		rep             omtReport
		regress, fixups string
	}{
		{"3 against 1", ref(map[string]int{"apple,dart": 1, "apple,sep": 1}), nodesReport(t, "apple,dart", 3, "apple,sep", 1),
			"hardware.drivers:apple,dart (3 nodes unclaimed, 1 on the known-good kernel; unclaimed: apple,dart (3 nodes): unknown hardware)", ""},
		{"the same counts", ref(map[string]int{"apple,dart": 3, "apple,sep": 1}), nodesReport(t, "apple,dart", 3, "apple,sep", 1), "", ""},
		{"fewer", ref(map[string]int{"apple,dart": 3, "apple,sep": 1}), nodesReport(t, "apple,dart", 1, "apple,sep", 1),
			"", "hardware.drivers:apple,dart (2 of its 3 nodes claimed by a driver now)"},
		{"a new compatible, one gone", ref(map[string]int{"apple,dart": 1, "apple,sep": 1}), nodesReport(t, "apple,dart", 1, "apple,ane", 1),
			"hardware.drivers:apple,ane (unclaimed: apple,ane (1 node): unknown hardware)", "hardware.drivers:apple,sep (claimed by a driver now)"},
		{"a report with no counts is one node each", ref(map[string]int{"apple,dart": 1, "apple,sep": 1}), nodesReport(t, "apple,dart", 0, "apple,sep", 0), "", ""},
		// references written before UnclaimedNodes
		{"old reference: 3 against 1", ref(nil), nodesReport(t, "apple,dart", 3, "apple,sep", 1), "", ""},
		{"old reference: fewer", ref(nil), nodesReport(t, "apple,dart", 1, "apple,sep", 1), "", ""},
		{"old reference: a new compatible, one gone", ref(nil), nodesReport(t, "apple,dart", 2, "apple,ane", 1),
			"hardware.drivers:apple,ane (unclaimed: apple,ane (1 node): unknown hardware)", "hardware.drivers:apple,sep (claimed by a driver now)"},
	} {
		regressed, fixed := omtNodes(c.base, failing, c.rep)
		if got := ids(regressed); got != c.regress {
			t.Errorf("%s: regressed %q, want %q", c.name, got, c.regress)
		}
		if got := ids(fixed); got != c.fixups {
			t.Errorf("%s: fixed %q, want %q", c.name, got, c.fixups)
		}
	}
	if got := unclaimedNodes(nodesReport(t, "apple,dart", 3, "apple,sep", 0)); !reflect.DeepEqual(got, map[string]int{"apple,dart": 3, "apple,sep": 1}) {
		t.Errorf("unclaimedNodes %v", got)
	}
}

// omtModeReport is a report of an attended run (video runs, brightness can
// fail) or an unattended one (both skipped), with Wi-Fi as given.
func omtModeReport(kernel string, unattended bool, wifi string) []byte {
	mode, video, brightness := "", "pass", "fail"
	if unattended {
		mode, video, brightness = `"unattended":true,`, "skip", "skip"
	}
	return []byte(fmt.Sprintf(`{"tool":{"version":"0.1.15"},"machine":{"kernel":%q},%s"checks":[
{"id":"wifi.connected","status":%q},{"id":"video.h264-on-screen","status":%q},{"id":"display.brightness-steps","status":%q}]}`,
		kernel, mode, wifi, video, brightness))
}

// The first unattended run on a lab kernel, against a reference an attended run
// left: what it newly skips is neither regressed nor fixed, the job isn't failed
// for it, and the comparison says what it didn't cover. A real regression in
// what it did run still fails the job.
func TestOMTUnattendedRunAgainstAttendedReference(t *testing.T) {
	l := newLab(t, true)
	l.s.cfg.OMT = true
	l.sim.OMTReport = func(kernel string) []byte {
		switch {
		case strings.HasPrefix(kernel, "7.2-attended"):
			return omtModeReport(kernel, false, "pass")
		case strings.HasPrefix(kernel, "7.2-bad"):
			return omtModeReport(kernel, true, "fail")
		case strings.HasPrefix(kernel, "7.2-"):
			return omtModeReport(kernel, true, "pass")
		}
		return omtModeReport(kernel, false, "pass")
	}
	l.waitDevice(func(d api.Device) bool { return d.Facts.AgentVersion != "" })
	l.baseline()

	j := l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-ok behavior=ok")})
	l.expect(j, api.OutcomePass)
	o := j.Result.OMT
	if len(o.Regressions) != 0 || len(o.Fixed) != 0 || o.Skip != 2 {
		t.Fatalf("unattended omt %+v", o)
	}
	if !omtCompared(j) || !strings.HasSuffix(o.ComparedTo, "skipped what that one passed: video.h264-on-screen") {
		t.Fatalf("compared to %q", o.ComparedTo)
	}

	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-bad behavior=ok")})
	l.expect(j, api.OutcomeTestsFailed)
	if o := j.Result.OMT; len(o.Regressions) != 1 || o.Regressions[0].ID != "wifi.connected" {
		t.Fatalf("regressed omt %+v", o)
	}

	j = l.run(api.JobSpec{Kernel: l.artifact("krel=7.2-attended behavior=ok")})
	l.expect(j, api.OutcomePass)
	if o := j.Result.OMT; strings.Contains(o.ComparedTo, "not compared") {
		t.Fatalf("an attended run says it skipped: %q", o.ComparedTo)
	}
}

func TestOMTNotRun(t *testing.T) {
	before := map[string]string{"a": "pass", "b": "pass", "c": "fail", "d": "skip", "e": "pass"}
	after := map[string]string{"a": "skip", "b": "pass", "c": "skip", "d": "skip", "z": "skip"}
	if got := omtNotRun(true, before, after); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("unattended: %v", got)
	}
	if got := omtNotRun(false, before, after); got != nil {
		t.Errorf("attended: %v", got)
	}
	regressed, fixed := omtDiff(before, after, nil)
	if len(regressed) != 0 || len(fixed) != 0 {
		t.Errorf("a skip changed the comparison: regressed %v, fixed %v", regressed, fixed)
	}
}

// An Installed run stays strict about a frozen pass that is now a skip. The note
// names those checks, and says to take the references again only when the frozen
// report was attended.
func TestOMTFrozenSkipNote(t *testing.T) {
	const again = "take the preinstall references again"
	skipped := []api.OMTCheck{{ID: "wifi.connected", Outcome: "pass -> skip"}, {ID: "audio.sound-cards", Outcome: "pass -> fail"}, {ID: "gpu.driver", Outcome: "pass -> skip"}}
	got := omtFrozenSkipNote(false, true, skipped)
	if !strings.Contains(got, ": wifi.connected, gpu.driver:") || !strings.Contains(got, again) {
		t.Errorf("attended frozen report: %q", got)
	}
	got = omtFrozenSkipNote(true, true, skipped)
	if !strings.Contains(got, ": wifi.connected, gpu.driver:") || strings.Contains(got, again) {
		t.Errorf("unattended frozen report: %q", got)
	}
	if got := omtFrozenSkipNote(false, false, skipped); got != "" {
		t.Errorf("attended run: %q", got)
	}
	if got := omtFrozenSkipNote(false, true, skipped[1:2]); got != "" {
		t.Errorf("a real failure: %q", got)
	}
}

// An unattended Installed run that skips a check the frozen report passed fails
// as a regression, and its error says what to do, by what the frozen report was.
func TestInstalledJobUnattendedSkip(t *testing.T) {
	const again = "take the preinstall references again"
	for _, c := range []struct {
		name             string
		frozenUnattended bool
	}{{"attended frozen report", false}, {"unattended frozen report", true}} {
		t.Run(c.name, func(t *testing.T) {
			l, msha, _ := installedLab(t, nil)
			if c.frozenUnattended {
				dir := l.s.frozenDir("9.9")
				p := filepath.Join(dir, "preinstall", "sim-mac", "omt-report.json")
				rep, _ := os.ReadFile(p)
				changed := bytes.Replace(rep, []byte(`{"schema_version"`), []byte(`{"unattended":true,"schema_version"`), 1)
				if bytes.Equal(rep, changed) {
					t.Fatalf("frozen report %s", rep)
				}
				pins := filepath.Join(dir, "PINS.preinstall")
				os.Remove(p)
				os.Remove(pins)
				os.WriteFile(p, changed, 0o444)
				os.WriteFile(pins, []byte(pinsFor(dir, "preinstall/sim-mac/omt-report.json", "preinstall/sim-mac/omt-status.json",
					"preinstall/sim-mac/dmesg-errors.txt", "preinstall/sim-mac/baseline-job.json")), 0o444)
			}
			l.sim.OMTReport = func(kernel string) []byte {
				return []byte(fmt.Sprintf(`{"tool":{"version":"0.1.15"},"machine":{"kernel":%q},"unattended":true,"checks":[
{"id":"boot.kernel-package","status":"pass"},{"id":"hardware.drivers","status":"pass"},{"id":"wifi.connected","status":"skip"},{"id":"system.snapshots","status":"fail"}]}`, kernel))
			}
			j := l.run(api.JobSpec{InstalledManifest: msha, Holder: "tester"})
			l.expect(j, api.OutcomeTestsFailed)
			if ir := j.Result.Installed; ir == nil || ir.OMT != "REGRESSION" {
				t.Fatalf("installed result %+v", ir)
			}
			var msg string
			for _, tr := range j.Result.Tests {
				if tr.Name == omtTest {
					msg = tr.Error
				}
			}
			if !strings.Contains(msg, "wifi.connected (pass -> skip)") || !strings.Contains(msg, "report passed: wifi.connected:") {
				t.Fatalf("test error %q", msg)
			}
			if strings.Contains(msg, again) == c.frozenUnattended {
				t.Fatalf("test error %q", msg)
			}
		})
	}
}

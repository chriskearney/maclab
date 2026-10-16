package server

import (
	"encoding/json"
	"fmt"
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

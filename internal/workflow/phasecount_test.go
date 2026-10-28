package workflow

import (
	"fmt"
	"testing"
)

// The assembled finite M1 transaction has 240 phases. This raises only the
// explicit graph count ceiling; state/binding/file bounds remain MaxJSON.
func TestReviewedFullGraphPhaseCountRemainsBounded(t *testing.T) {
	p := Plan{Schema: "maclab.workflow/1", ID: "finite-full", Device: "m1", Inputs: raw(map[string]any{})}
	for i := 0; i < 256; i++ {
		p.Phases = append(p.Phases, Phase{ID: fmt.Sprintf("phase-%03d", i), Kind: "bind", TimeoutSec: 1, Template: raw(map[string]any{"observational": true})})
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Phases = append(p.Phases, Phase{ID: "phase-256", Kind: "bind", TimeoutSec: 1, Template: raw(map[string]any{})})
	if err := p.Validate(); err == nil {
		t.Fatal("unbounded graph accepted")
	}
	if MaxJSON != 4*1024*1024 {
		t.Fatal("phase bound must not relax checkpoint/binding bound")
	}
}

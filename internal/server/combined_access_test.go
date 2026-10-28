package server

import (
	"github.com/iconidentify/maclab/internal/api"
	"testing"
)

// A newly combined job kind must not bypass the volunteer's chosen level.
func TestCombinedMesaQualificationRefusesBeforeAgentWork(t *testing.T) {
	l := newLab(t, false)
	v := l.s.dev(l.name)
	v.mu.Lock()
	v.d.Kind = api.KindVolunteer
	v.d.AccessLevel = api.AccessQualification
	v.mu.Unlock()
	spec := mesaSpec(l)
	if _, code, err := l.s.Submit(spec); code != 403 || err == nil {
		t.Fatalf("Mesa submission at Qualification: code=%d err=%v", code, err)
	}
	if code, err := l.s.validateMesa(spec, v.snapshot()); code != 403 || err == nil {
		t.Fatalf("stored Mesa request after access downgrade: code=%d err=%v", code, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.pending) != 0 || v.d.ActiveJob != "" {
		t.Fatal("refused request reached the agent")
	}
}

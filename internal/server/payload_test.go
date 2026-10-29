package server

import (
	"slices"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func TestPayloadFilesAreCheckedAtSubmit(t *testing.T) {
	l := newLab(t, false)
	script, mod := l.artifact("#!/bin/bash\ntrue\n"), l.artifact("module bytes")
	missing := strings.Repeat("ab", 32)
	ok := func() api.JobSpec {
		return api.JobSpec{Tests: []api.TestSpec{{Name: "probe", Script: script, Payload: []api.PayloadFile{{Name: "mod.ko", SHA256: mod}}}}}
	}
	able := api.Device{Name: "mac", Facts: api.Facts{AgentVersion: payloadMinAgent}}
	if code, err := l.s.validatePayload(ok(), able); err != nil {
		t.Fatalf("a well-formed payload is refused: %d %v", code, err)
	}
	cases := []struct {
		name string
		edit func(*api.TestSpec)
		want string
	}{
		{"builtin test", func(s *api.TestSpec) { s.Script, s.Builtin = "", "boot-health" }, "only with a --script test"},
		{"GUI script", func(s *api.TestSpec) { s.GUI = true }, "only with a --script test"},
		{"path in name", func(s *api.TestSpec) { s.Payload[0].Name = "../mod.ko" }, "payload name"},
		{"hidden name", func(s *api.TestSpec) { s.Payload[0].Name = ".mod.ko" }, "payload name"},
		{"empty name", func(s *api.TestSpec) { s.Payload[0].Name = "" }, "payload name"},
		{"named twice", func(s *api.TestSpec) { s.Payload = append(s.Payload, s.Payload[0]) }, "twice"},
		{"too many", func(s *api.TestSpec) {
			for i := range api.MaxPayloadFiles {
				s.Payload = append(s.Payload, api.PayloadFile{Name: "f" + string(rune('a'+i)), SHA256: mod})
			}
		}, "at most"},
		{"not a sha", func(s *api.TestSpec) { s.Payload[0].SHA256 = "mod.ko" }, "artifact sha256"},
		{"not uploaded", func(s *api.TestSpec) { s.Payload[0].SHA256 = missing }, "not uploaded"},
	}
	for _, c := range cases {
		spec := ok()
		c.edit(&spec.Tests[0])
		code, err := l.s.validatePayload(spec, able)
		if err == nil || code != 400 || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %d %v, want 400 %q", c.name, code, err, c.want)
		}
	}
}

func TestPayloadFilesNeedALabAgentThatKnowsThem(t *testing.T) {
	l := newLab(t, false)
	spec := api.JobSpec{Tests: []api.TestSpec{{Name: "probe", Script: l.artifact("#!/bin/bash\n"), Payload: []api.PayloadFile{{Name: "mod.ko", SHA256: l.artifact("module")}}}}}
	for _, v := range []string{"", "0.8.0"} {
		d := api.Device{Name: "mac", Facts: api.Facts{AgentVersion: v}}
		code, err := l.s.validatePayload(spec, d)
		if err == nil || code != 409 || !strings.Contains(err.Error(), "update it to "+payloadMinAgent) {
			t.Errorf("agent %q: got %d %v, want 409 telling the Maintainer to update lab-agent", v, code, err)
		}
	}
	spec.Tests[0].Payload = nil // a job with no payload runs on any agent
	if code, err := l.s.validatePayload(spec, api.Device{Name: "mac"}); err != nil {
		t.Errorf("a job without payload files was refused on an old agent: %d %v", code, err)
	}
}

func TestAJobsPayloadFilesAreKeptWhileTheJobIsUnfinished(t *testing.T) {
	spec := api.JobSpec{Kernel: "k", Tests: []api.TestSpec{{Name: "p", Script: "s", Payload: []api.PayloadFile{{Name: "mod.ko", SHA256: "m"}}}}}
	got := specRefs(spec)
	for _, want := range []string{"k", "s", "m"} {
		if !slices.Contains(got, want) {
			t.Errorf("artifact %q of the job is not kept: refs %v", want, got)
		}
	}
}

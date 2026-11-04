package server

import (
	"fmt"
	"os"

	"github.com/iconidentify/maclab/internal/api"
)

// payloadMinAgent is the first lab-agent that puts payload files in $MACLAB_IN;
// an older one would run the script without them.
const payloadMinAgent = "0.9.0"

// validatePayload checks the payload files of every test in a submitted job:
// well formed, uploaded, and understood by the Mac's lab-agent.
func (s *Server) validatePayload(spec api.JobSpec, d api.Device) (int, error) {
	for _, t := range spec.Tests {
		if err := t.PayloadError(); err != nil {
			return 400, fmt.Errorf("test %s: %w", t.Name, err)
		}
		for _, p := range t.Payload {
			if _, err := os.Stat(s.artifactPath(p.SHA256)); err != nil {
				return 400, fmt.Errorf("test %s: payload file %s: artifact %s not uploaded", t.Name, p.Name, p.SHA256)
			}
		}
		if len(t.Payload) > 0 && !versionAtLeast(d.Facts.AgentVersion, payloadMinAgent) {
			return 409, fmt.Errorf("%s runs lab-agent %s, which would run test %s without its payload files; update it to %s or later", d.Name, orStr(d.Facts.AgentVersion, "(unknown)"), t.Name, payloadMinAgent)
		}
	}
	return 0, nil
}

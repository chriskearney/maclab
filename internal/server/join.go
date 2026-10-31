package server

// Joining a Mac with an invite. A Maintainer makes an enrollment token
// (POST /api/enroll-tokens, lab enroll, the UI), and labd answers with a
// one-liner for the Mac's owner to run on it (joinCommand). The one-liner
// downloads lab-agent with the token (GET /api/join/lab-agent), checks the
// download's sha256 against the one written into it, and runs
// `sudo lab-agent setup`, the token going to it on stdin. Setup shows labd's
// participation terms (GET /api/join/terms), which the owner accepts by
// typing yes, before it changes anything; then the Mac enrolls, using the
// token up (see hEnroll).
//
// The token travels in the Authorization header and request bodies only,
// never in a URL, so neither labd's nor a proxy's access log records it. It
// reaches these two routes and the enrollment itself, nothing else.

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

var reEnrollToken = regexp.MustCompile(`^enr_[0-9a-f]{32}$`)

// joinToken admits a request carrying an unexpired enrollment token, used or
// not: setup reads the terms and downloads lab-agent again when it runs
// again after an interruption.
func (s *Server) joinToken(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if !strings.HasPrefix(tok, "enr_") || len(tok) > 200 || !s.tokenValid(hashSecret(tok)) {
			httpErr(w, 401, "enrollment token unknown or expired")
			return
		}
		h(w, r)
	}
}

func (s *Server) hJoinTerms(w http.ResponseWriter, r *http.Request) {
	text, sum := s.terms()
	writeJSON(w, api.JoinTerms{SHA256: sum, Text: text})
}

// agentSum caches the sha256 of the lab-agent labd hands out, by its size and
// modification time.
type agentSum struct {
	mu   sync.Mutex
	size int64
	mod  time.Time
	sum  string
}

var agentSums agentSum

// agentSHA256 is the sha256 of the lab-agent labd hands out, "" when it has
// none.
func (s *Server) agentSHA256() string {
	f, err := os.Open(s.cfg.AgentBinary)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	agentSums.mu.Lock()
	defer agentSums.mu.Unlock()
	if agentSums.sum != "" && agentSums.size == st.Size() && agentSums.mod.Equal(st.ModTime()) {
		return agentSums.sum
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	agentSums.size, agentSums.mod, agentSums.sum = st.Size(), st.ModTime(), hex.EncodeToString(h.Sum(nil))
	return agentSums.sum
}

// publicBase is labd's URL as a Mac reaches it: --public-url, else the
// origin r reached labd at.
func (s *Server) publicBase(r *http.Request) string {
	if s.cfg.PublicURL != nil {
		return s.cfg.PublicURL.String()
	}
	origin, _ := s.externalOrigin(r)
	return origin
}

// reShellSafe is what joinCommand puts in single quotes: URL and token
// characters, nothing a shell gives meaning to inside them.
var reShellSafe = regexp.MustCompile(`^[A-Za-z0-9:/._~\[\]-]+$`)

// joinCommand is the one-liner that joins a Mac with token, "" when labd has
// no lab-agent to hand out. Over https curl may use nothing else; over plain
// http setup must be told it is allowed (and only loopback is, by default).
func (s *Server) joinCommand(r *http.Request, token string) string {
	base, sum := s.publicBase(r), s.agentSHA256()
	if sum == "" || !reShellSafe.MatchString(base) || !reEnrollToken.MatchString(token) {
		return ""
	}
	curl, plain := "curl --proto '=https' --tlsv1.2 -fsS", ""
	if !strings.HasPrefix(base, "https://") {
		curl, plain = "curl -fsS", " --allow-plain-http"
	}
	// The token is in no process's arguments: printf is the shell's own, and
	// curl and setup read it on stdin. The leading space keeps the line out
	// of the shell's history where it ignores such lines.
	return " T='" + token + "' U='" + base + "' D=\"$(mktemp -d)\" && " +
		"printf 'Authorization: Bearer %s\\n' \"$T\" | " + curl + " -H @- -o \"$D/lab-agent\" \"$U/api/join/lab-agent\" && " +
		"echo '" + sum + "  '\"$D/lab-agent\" | sha256sum -c --quiet && chmod +x \"$D/lab-agent\" && " +
		"printf '%s\\n' \"$T\" | sudo \"$D/lab-agent\" setup --server \"$U\" --token-stdin --gui-user \"$USER\"" + plain
}

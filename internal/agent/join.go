package agent

// Joining the lab with an invite: the participation terms the Mac's owner
// accepts before setup changes anything, and the activation key that makes
// an enrollment token good for one Mac only (see labd's hEnroll).

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
)

// Activation is what an enrollment carries besides its token: the key that
// binds the token to this Mac, and the terms its owner accepted.
type Activation struct {
	Key         string
	TermsSHA256 string
}

// FetchTerms reads labd's participation terms with the enrollment token,
// and checks that the text is the one its sha256 names.
func FetchTerms(ctx context.Context, server, token string, p labhttp.Policy) (*api.JoinTerms, error) {
	if err := labhttp.CheckServer(server, p.AllowPlainHTTP); err != nil {
		return nil, err
	}
	c, err := p.Client(0)
	if err != nil {
		return nil, err
	}
	var t api.JoinTerms
	if err := getJSON(ctx, c, strings.TrimRight(server, "/")+"/api/join/terms", token, &t); err != nil {
		return nil, fmt.Errorf("labd's participation terms: %w", err)
	}
	sum := sha256.Sum256([]byte(t.Text))
	if t.Text == "" || hex.EncodeToString(sum[:]) != t.SHA256 {
		return nil, errors.New("labd's participation terms don't match their sha256")
	}
	return &t, nil
}

// errTermsDeclined is the owner not accepting the terms; setup stops.
var errTermsDeclined = errors.New("the participation terms were not accepted, so nothing was changed")

// acceptTerms shows t to the Mac's owner on tty and returns their acceptance:
// they must type yes. accept, when set, is acceptance given beforehand, for
// a run without a terminal: it must be the sha256 of these very terms. With
// neither, nothing is accepted.
func acceptTerms(t *api.JoinTerms, server, accept string, tty io.ReadWriter) error {
	if accept != "" {
		if !strings.EqualFold(accept, t.SHA256) {
			return fmt.Errorf("--accept-terms %s is not labd's current terms (%s): read them again (GET %s/api/join/terms)", accept, t.SHA256, server)
		}
		return nil
	}
	if tty == nil {
		return fmt.Errorf("accepting labd's participation terms needs a terminal: run setup in one, or pass --accept-terms %s after reading them", t.SHA256)
	}
	fmt.Fprintf(tty, "\n%s\n(terms %s)\n\nType yes to accept these terms and join the lab at %s; anything else stops: ", strings.TrimRight(t.Text, "\n"), t.SHA256, server)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return errTermsDeclined
	}
	if strings.TrimSpace(line) != "yes" {
		return errTermsDeclined
	}
	return nil
}

// openTTY is the controlling terminal, nil without one. Setup reads the
// owner's answer there, not on stdin, which may carry the token.
func openTTY() io.ReadWriteCloser {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil
	}
	return f
}

// activationFile is, under the work directory, the activation key of an
// enrollment in progress, kept until setup has saved the Mac's config: setup
// run again after an interruption enrolls with the same key, which labd
// accepts as the same activation.
const activationFile = "activation.json"

type activation struct {
	TokenSHA256 string `json:"token_sha256"` // which token it is for
	Key         string `json:"key"`
}

// activationKey is the key for enrolling with token: the one an earlier,
// interrupted setup kept for the same token, else a new one, kept before it
// is used.
func activationKey(workDir, token string) (string, error) {
	h := sha256.Sum256([]byte(token))
	th := hex.EncodeToString(h[:])
	p := filepath.Join(workDir, activationFile)
	if b, err := os.ReadFile(p); err == nil {
		var a activation
		if json.Unmarshal(b, &a) == nil && a.TokenSHA256 == th && len(a.Key) >= 32 {
			return a.Key, nil
		}
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	a := activation{TokenSHA256: th, Key: hex.EncodeToString(k)}
	b, _ := json.Marshal(a)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	return a.Key, os.Rename(tmp, p)
}

// activationDone forgets the activation key once the Mac is set up.
func activationDone(workDir string) {
	os.Remove(filepath.Join(workDir, activationFile))
}

// NewActivationKey is a key for an enrollment that never runs again: a
// simulated Mac's, or a test's.
func NewActivationKey() string {
	k := make([]byte, 32)
	rand.Read(k)
	return hex.EncodeToString(k)
}

// ReadToken reads an enrollment token from r, the first line: setup
// --token-stdin, so that the token is in no command line.
func ReadToken(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, 4096)).ReadString('\n')
	tok := strings.TrimSpace(line)
	if tok == "" {
		if err == nil {
			err = errors.New("empty")
		}
		return "", fmt.Errorf("no enrollment token on stdin: %w", err)
	}
	return tok, nil
}

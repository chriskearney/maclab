package server

// How labd listens: TLS itself, or plain http on loopback behind a reverse
// proxy, or plain http elsewhere only when told so.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// ListenConfig is how labd serves.
type ListenConfig struct {
	Addr string
	// CertFile and KeyFile serve TLS; both or neither. labd reads them again
	// when they change, so a renewed certificate needs no restart.
	CertFile, KeyFile string
	// AllowPlainHTTP serves plain http on an address other than loopback:
	// tokens and device secrets then cross that network in the clear.
	AllowPlainHTTP bool
}

// Check is why labd must not serve as lc says, or nil.
func (lc ListenConfig) Check() error {
	if (lc.CertFile == "") != (lc.KeyFile == "") {
		return errors.New("--tls-cert and --tls-key go together")
	}
	if lc.CertFile != "" || lc.AllowPlainHTTP {
		return nil
	}
	host, _, err := net.SplitHostPort(lc.Addr)
	if err != nil {
		return fmt.Errorf("--listen %q: %v", lc.Addr, err)
	}
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("--listen %s would serve plain http beyond this machine, where tokens and device secrets cross the network in the clear: "+
		"give --tls-cert and --tls-key, or listen on loopback behind an https reverse proxy, or pass --allow-plain-http on purpose", lc.Addr)
}

// Server limits. A request's headers must arrive within headerTimeout, and an
// idle keep-alive connection closes after idleTimeout. There is no overall
// read or write timeout: long polls, the event stream, the console, an exec
// of up to an hour and downloads of large artifacts all run longer.
const (
	headerTimeout = 10 * time.Second
	idleTimeout   = 2 * time.Minute
	maxHeaderSize = 64 << 10
)

// Server is an http.Server for h as lc says.
func (lc ListenConfig) Server(h http.Handler, logger *log.Logger) (*http.Server, error) {
	if err := lc.Check(); err != nil {
		return nil, err
	}
	hs := &http.Server{Addr: lc.Addr, Handler: h, ReadHeaderTimeout: headerTimeout, IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderSize}
	if lc.CertFile != "" {
		cr := &certReloader{certFile: lc.CertFile, keyFile: lc.KeyFile, log: logger}
		if err := cr.load(); err != nil {
			return nil, err
		}
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cr.get}
	}
	return hs, nil
}

// Serve serves hs on ln, with TLS when hs has a TLS config.
func Serve(hs *http.Server, ln net.Listener) error {
	if hs.TLSConfig != nil {
		return hs.ServeTLS(ln, "", "")
	}
	return hs.Serve(ln)
}

// certReloader hands out the certificate in its files, reading them again
// when either changes, at most every certCheck. A pair that doesn't load
// keeps the one labd has.
type certReloader struct {
	certFile, keyFile string
	log               *log.Logger

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   string
	checked time.Time
}

// certCheck is how often labd looks at the certificate files; tests shorten it.
var certCheck = 5 * time.Second

func (c *certReloader) stampNow() string {
	var s string
	for _, f := range []string{c.certFile, c.keyFile} {
		if st, err := os.Stat(f); err == nil {
			s += fmt.Sprintf("%d:%d;", st.Size(), st.ModTime().UnixNano())
		}
	}
	return s
}

func (c *certReloader) load() error {
	// The files' stamp is taken before they are read: a renewal landing
	// while they are read changes it, so the next look reads them again.
	stamp := c.stampNow()
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	c.cert, c.stamp, c.checked = &cert, stamp, time.Now()
	return nil
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checked) >= certCheck {
		c.checked = time.Now()
		if c.stampNow() != c.stamp {
			old := c.cert
			if err := c.load(); err != nil {
				c.cert = old
				if c.log != nil {
					c.log.Printf("%v; still serving the certificate labd had", err)
				}
			} else if c.log != nil {
				c.log.Printf("TLS certificate %s reloaded", c.certFile)
			}
		}
	}
	return c.cert, nil
}

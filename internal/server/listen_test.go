package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
	"github.com/iconidentify/maclab/internal/testpki"
)

// The whole path over https under a prefix: the simulated Mac reads the
// terms and enrolls with its activation key, checks in, downloads its kernel
// through the grant check, runs the job and uploads its files, all at
// https://127.0.0.1:<port>/maclab, trusting only the test CA.
func TestAMacOverHTTPSUnderAPrefixRunsAJob(t *testing.T) {
	l := newLabWith(t, labConfig{tls: testpki.NewCA(t), prefix: "/maclab"})
	if !strings.HasPrefix(l.url, "https://127.0.0.1:") || !strings.HasSuffix(l.url, "/maclab") {
		t.Fatalf("the lab's URL: %s", l.url)
	}
	l.baseline()
	kernel := l.artifact("krel=7.2-https behavior=ok")
	j := l.run(api.JobSpec{Kernel: kernel})
	l.expect(j, api.OutcomePass)
	got := l.waitJob(j.ID, func(j *api.Job) bool { return j.State == api.JobDone })
	if len(got.Result.Logs) == 0 {
		t.Fatal("no job files arrived over https")
	}
	if _, err := os.Stat(l.s.jobDir(j.ID) + "/" + got.Result.Logs[0]); err != nil {
		t.Errorf("job file %s: %v", got.Result.Logs[0], err)
	}
	if d := l.waitDevice(func(d api.Device) bool { return d.TermsSHA256 != "" }); d.TermsSHA256 != termsSum() {
		t.Errorf("the Mac's accepted terms: %q", d.TermsSHA256)
	}
	root := strings.TrimSuffix(l.url, "/maclab")
	req, _ := http.NewRequest("GET", root+"/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+harnessToken)
	if resp, err := l.client().Do(req); err != nil || resp.StatusCode != 404 {
		t.Errorf("the API outside the prefix: %v %v", resp, err)
	}
	// A client that doesn't trust the lab's CA gets nowhere, and sends nothing.
	plain, _ := labhttp.Policy{}.Client(5 * time.Second)
	if _, err := plain.Get(l.url + "/api/auth"); err == nil {
		t.Error("an untrusted certificate was accepted")
	}
}

func TestListenConfigServesPlainHTTPOnlyOnLoopbackUnlessTold(t *testing.T) {
	for _, c := range []struct {
		lc ListenConfig
		ok bool
	}{
		{ListenConfig{Addr: "127.0.0.1:7770"}, true},
		{ListenConfig{Addr: "[::1]:7770"}, true},
		{ListenConfig{Addr: "localhost:7770"}, true},
		{ListenConfig{Addr: "0.0.0.0:7770"}, false},
		{ListenConfig{Addr: ":7770"}, false},
		{ListenConfig{Addr: "10.1.1.55:7770"}, false},
		{ListenConfig{Addr: "100.64.0.1:7770"}, false},
		{ListenConfig{Addr: "labd.example.com:7770"}, false},
		{ListenConfig{Addr: "0.0.0.0:7770", AllowPlainHTTP: true}, true},
		{ListenConfig{Addr: "0.0.0.0:443", CertFile: "c", KeyFile: "k"}, true},
		{ListenConfig{Addr: "127.0.0.1:443", CertFile: "c"}, false},
	} {
		if err := c.lc.Check(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.lc, err)
		}
	}
	hs, err := ListenConfig{Addr: "127.0.0.1:0"}.Server(http.NotFoundHandler(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Headers have a deadline; nothing else does, so long polls, streams,
	// exec and downloads run as long as they need.
	if hs.ReadHeaderTimeout != 10*time.Second || hs.IdleTimeout != 2*time.Minute || hs.MaxHeaderBytes != 64<<10 || hs.ReadTimeout != 0 || hs.WriteTimeout != 0 || hs.TLSConfig != nil {
		t.Errorf("server limits: %+v", hs)
	}
}

// TLS from files: TLS 1.2 at least, and a certificate renewed in place is
// served without a restart; a broken one keeps the one labd had.
func TestTLSListenerReloadsItsCertificate(t *testing.T) {
	old := certCheck
	certCheck = 0
	defer func() { certCheck = old }()
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	first := ca.Leaf("127.0.0.1")
	certFile, keyFile := first.Files(t, dir)
	var logs bytes.Buffer
	hs, err := ListenConfig{Addr: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile}.Server(http.NotFoundHandler(), log.New(&logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if hs.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("min TLS version %x", hs.TLSConfig.MinVersion)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go Serve(hs, ln)
	defer hs.Close()
	served := func() *x509.Certificate {
		t.Helper()
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca.PEM)
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0]
	}
	if got := served(); got.SerialNumber.Cmp(first.Cert.Leaf.SerialNumber) != 0 {
		t.Fatalf("serving %v, want the first certificate", got.SerialNumber)
	}
	second := ca.Leaf("127.0.0.1")
	time.Sleep(10 * time.Millisecond) // a later modification time
	second.Files(t, dir)
	if got := served(); got.SerialNumber.Cmp(second.Cert.Leaf.SerialNumber) != 0 {
		t.Fatalf("serving %v after the renewal, want the second certificate", got.SerialNumber)
	}
	os.WriteFile(certFile, []byte("not a certificate"), 0o600)
	if got := served(); got.SerialNumber.Cmp(second.Cert.Leaf.SerialNumber) != 0 {
		t.Fatalf("a broken certificate file replaced the good one")
	}
	if !strings.Contains(logs.String(), "still serving") {
		t.Errorf("labd didn't say it kept the old certificate: %q", logs.String())
	}
	// An old protocol version is refused.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	// A client that really offers TLS 1.0 and 1.1 (Go's own floor is 1.2) is
	// refused by labd.
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if err == nil {
		c.Close()
		t.Error("TLS 1.1 was accepted")
	} else if !strings.Contains(err.Error(), "protocol version") {
		t.Errorf("TLS 1.1 refused, but not by labd's version floor: %v", err)
	}
}

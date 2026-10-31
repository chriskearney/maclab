// Package testpki makes throwaway certificates for tests: a private CA and
// the server certificates it signs. Only tests import it.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a private certificate authority.
type CA struct {
	t    testing.TB
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  []byte // the CA certificate, for a client's trust
}

// NewCA makes a CA valid from an hour ago for a day.
func NewCA(t testing.TB) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "maclab test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{t: t, cert: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Leaf is a server certificate for hosts (names or IP addresses), valid from
// notBefore until notAfter.
type Leaf struct {
	Cert    tls.Certificate
	CertPEM []byte
	KeyPEM  []byte
}

// Leaf signs a server certificate for hosts, valid now for a day.
func (ca *CA) Leaf(hosts ...string) *Leaf {
	return ca.LeafValid(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), hosts...)
}

// LeafValid signs a server certificate for hosts valid between from and to.
func (ca *CA) LeafValid(from, to time.Time, hosts ...string) *Leaf {
	ca.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ca.t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    from,
		NotAfter:     to,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		ca.t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		ca.t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		ca.t.Fatal(err)
	}
	return &Leaf{Cert: c, CertPEM: certPEM, KeyPEM: keyPEM}
}

// Files writes the leaf's certificate and key into dir and returns their paths.
func (l *Leaf) Files(t testing.TB, dir string) (certFile, keyFile string) {
	t.Helper()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, l.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, l.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// ServerTLS is a server-side tls.Config presenting l.
func (l *Leaf) ServerTLS() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{l.Cert}, MinVersion: tls.VersionTLS12}
}

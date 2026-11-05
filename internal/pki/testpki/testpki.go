// Package testpki builds a complete throwaway PKI for tests: root,
// intermediate, a gateway server certificate for localhost and helpers to
// issue agent certificates. Tests must use this instead of disabling
// verification (CLAUDE.md rule 2: never InsecureSkipVerify).
package testpki

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/pki"
)

// PKI is a test PKI.
type PKI struct {
	Root         *pki.CA
	Intermediate *pki.CA
	// Server is a localhost / 127.0.0.1 / ::1 server certificate.
	Server tls.Certificate
	// Roots trusts only Root.
	Roots *x509.CertPool
	Now   time.Time
}

// New creates a fresh PKI.
func New(t testing.TB) *PKI {
	t.Helper()
	now := time.Now()
	root, err := pki.NewRootCA("Stellwerk Test Root", pki.RootValidity, now)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.NewIntermediate("Stellwerk Test Agent CA", pki.IntermediateValidity, now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := inter.IssueServerCert(key.Public(), []string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, pki.ServerCertValidity, now)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := pki.TLSCertificate(inter.ChainDER(srv), key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	return &PKI{Root: root, Intermediate: inter, Server: tc, Roots: pool, Now: now}
}

// IssueAgent issues an agent client certificate for hostID.
func (p *PKI) IssueAgent(t testing.TB, hostID string) tls.Certificate {
	t.Helper()
	return p.IssueAgentWithValidity(t, hostID, pki.AgentCertValidity)
}

// IssueAgentWithValidity issues an agent certificate with a custom lifetime.
func (p *PKI) IssueAgentWithValidity(t testing.TB, hostID string, validity time.Duration) tls.Certificate {
	t.Helper()
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := p.Intermediate.IssueAgentCert(key.Public(), hostID, validity, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tc, err := pki.TLSCertificate(p.Intermediate.ChainDER(cert), key)
	if err != nil {
		t.Fatal(err)
	}
	return tc
}

// ServerTLS returns a TLS 1.3 server config with optional client cert verification.
func (p *PKI) ServerTLS() *tls.Config {
	return pki.ServerTLSConfig(p.Server, p.Roots)
}

// ClientTLS returns a TLS 1.3 client config trusting the test root,
// optionally presenting cert.
func (p *PKI) ClientTLS(cert *tls.Certificate) *tls.Config {
	var get func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	if cert != nil {
		get = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return pki.ClientTLSConfig(p.Roots, "localhost", get)
}

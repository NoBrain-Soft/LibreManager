package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/pki"
	"github.com/nobrain-soft/libremanager/internal/pki/testpki"
)

func TestChainVerifiesAndCarriesIdentity(t *testing.T) {
	p := testpki.New(t)
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "attacker-chosen-name")
	if err != nil {
		t.Fatal(err)
	}
	hostID := ids.New()
	cert, err := p.Intermediate.SignAgentCSR(csr, hostID, pki.AgentCertValidity, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cert.Subject.CommonName, "attacker") {
		t.Fatalf("CSR subject leaked into certificate: %q", cert.Subject.CommonName)
	}
	inter := x509.NewCertPool()
	inter.AddCert(p.Intermediate.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: p.Roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, err := pki.HostIDFromCert(cert)
	if err != nil || got != hostID {
		t.Fatalf("HostIDFromCert = %q, %v; want %q", got, err, hostID)
	}
	if len(p.Intermediate.ChainDER(cert)) != 2 {
		t.Fatalf("chain should be leaf+intermediate without root")
	}
	// Agent cert cannot act as a server certificate.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: p.Roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("agent certificate verified for server auth")
	}
}

func TestIntermediateCannotIssueCA(t *testing.T) {
	p := testpki.New(t)
	sub, err := p.Intermediate.NewIntermediate("sub", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err) // creation succeeds, but verification must fail
	}
	key, _ := pki.GenerateKey()
	leaf, err := sub.IssueAgentCert(key.Public(), ids.New(), time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inter := x509.NewCertPool()
	inter.AddCert(p.Intermediate.Cert)
	inter.AddCert(sub.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.Roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("path length constraint not enforced")
	}
}

func TestSignAgentCSRNegative(t *testing.T) {
	p := testpki.New(t)
	ecKey, _ := pki.GenerateKey()
	goodCSR, _ := pki.NewCSR(ecKey, "x")
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384CSR, _ := pki.NewCSR(p384, "x")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR, _ := pki.NewCSR(rsaKey, "x")
	tampered := append([]byte(nil), goodCSR...)
	tampered[len(tampered)-5] ^= 0xff

	cases := []struct {
		name   string
		csr    []byte
		hostID string
		want   error
	}{
		{"empty", nil, ids.New(), pki.ErrInvalidCSR},
		{"garbage", []byte("nope"), ids.New(), pki.ErrInvalidCSR},
		{"oversize", make([]byte, 9<<10), ids.New(), pki.ErrInvalidCSR},
		{"bad signature", tampered, ids.New(), pki.ErrInvalidCSR},
		{"rsa key", rsaCSR, ids.New(), pki.ErrKeyType},
		{"p384 key", p384CSR, ids.New(), pki.ErrKeyType},
		{"invalid host id", goodCSR, "../../etc", pki.ErrInvalidInput},
		{"nil host id", goodCSR, "00000000-0000-0000-0000-000000000000", pki.ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.Intermediate.SignAgentCSR(tc.csr, tc.hostID, time.Hour, time.Now())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHostIDFromCertRejectsForgedSANs(t *testing.T) {
	id := ids.New()
	mk := func(uris ...string) *x509.Certificate {
		c := &x509.Certificate{}
		for _, s := range uris {
			u, err := url.Parse(s)
			if err != nil {
				t.Fatal(err)
			}
			c.URIs = append(c.URIs, u)
		}
		return c
	}
	bad := []*x509.Certificate{
		nil,
		mk(),
		mk("spiffe://stellwerk/host/" + id, "spiffe://stellwerk/host/"+ids.New()),
		mk("spiffe://evil/host/" + id),
		mk("https://stellwerk/host/" + id),
		mk("spiffe://stellwerk/user/" + id),
		mk("spiffe://stellwerk/host/" + id + "/x"),
		mk("spiffe://stellwerk/host/" + id + "?a=b"),
		mk("spiffe://stellwerk/host/" + strings.ToUpper(id)),
		mk("spiffe://x@stellwerk/host/" + id),
	}
	for i, c := range bad {
		if _, err := pki.HostIDFromCert(c); !errors.Is(err, pki.ErrNoIdentity) {
			t.Errorf("case %d: err = %v, want ErrNoIdentity", i, err)
		}
	}
	if got, err := pki.HostIDFromCert(mk("spiffe://stellwerk/host/" + id)); err != nil || got != id {
		t.Fatalf("valid SAN rejected: %v", err)
	}
}

func TestVerifyPinnedRoot(t *testing.T) {
	p := testpki.New(t)
	other := testpki.New(t)
	rootPEM := pki.EncodeCertPEM(p.Root.Cert)
	fp := pki.Fingerprint(p.Root.Cert)
	if _, err := pki.VerifyPinnedRoot(rootPEM, fp); err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
	if _, err := pki.VerifyPinnedRoot(rootPEM, strings.ToLower(strings.ReplaceAll(fp, ":", ""))); err != nil {
		t.Fatalf("normalized pin rejected: %v", err)
	}
	if _, err := pki.VerifyPinnedRoot(rootPEM, pki.Fingerprint(other.Root.Cert)); !errors.Is(err, pki.ErrFingerprint) {
		t.Fatalf("wrong pin: err = %v", err)
	}
	if _, err := pki.VerifyPinnedRoot(rootPEM, ""); !errors.Is(err, pki.ErrFingerprint) {
		t.Fatalf("empty pin: err = %v", err)
	}
	// Intermediate pinned as "root" must be rejected (not self-signed).
	interPEM := pki.EncodeCertPEM(p.Intermediate.Cert)
	if _, err := pki.VerifyPinnedRoot(interPEM, pki.Fingerprint(p.Intermediate.Cert)); !errors.Is(err, pki.ErrNotCA) {
		t.Fatalf("intermediate as root: err = %v", err)
	}
}

func TestKeyPEMRoundTripAndMismatch(t *testing.T) {
	k1, _ := pki.GenerateKey()
	k2, _ := pki.GenerateKey()
	pemData, err := pki.EncodeKeyPEM(k1)
	if err != nil {
		t.Fatal(err)
	}
	back, err := pki.ParseKeyPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	p := testpki.New(t)
	cert, err := p.Intermediate.IssueAgentCert(k1.Public(), ids.New(), time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.KeyMatchesCert(back, cert); err != nil {
		t.Fatalf("matching key rejected: %v", err)
	}
	if err := pki.KeyMatchesCert(k2, cert); !errors.Is(err, pki.ErrKeyMismatch) {
		t.Fatalf("mismatched key: err = %v", err)
	}
}

// TestMutualTLS13 runs a real TLS handshake with the helper configs and
// checks TLS 1.3, client identity, and that a foreign CA is rejected.
func TestMutualTLS13(t *testing.T) {
	p := testpki.New(t)
	hostID := ids.New()
	agent := p.IssueAgent(t, hostID)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", p.ServerTLS())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		hostID string
		ver    uint16
		err    error
	}
	results := make(chan result, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					results <- result{err: err}
					return
				}
				st := tc.ConnectionState()
				r := result{ver: st.Version}
				if len(st.PeerCertificates) > 0 {
					r.hostID, r.err = pki.HostIDFromCert(st.PeerCertificates[0])
				}
				results <- r
			}(c)
		}
	}()

	dial := func(cfg *tls.Config) error {
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			return err
		}
		defer c.Close()
		return c.Handshake()
	}

	if err := dial(p.ClientTLS(&agent)); err != nil {
		t.Fatalf("mTLS dial: %v", err)
	}
	r := <-results
	if r.err != nil || r.hostID != hostID || r.ver != tls.VersionTLS13 {
		t.Fatalf("server saw %+v", r)
	}

	// Client cert from a foreign CA is rejected by the server.
	foreign := testpki.New(t)
	fcert := foreign.IssueAgent(t, ids.New())
	_ = dial(p.ClientTLS(&fcert))
	if r := <-results; r.err == nil {
		t.Fatal("foreign client certificate accepted")
	}

	// Client trusting another root rejects the server.
	if err := dial(foreign.ClientTLS(nil)); err == nil {
		t.Fatal("client accepted server from untrusted root")
	}
	<-results

	// TLS 1.2 client is refused.
	cfg := p.ClientTLS(nil)
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if err := dial(cfg); err == nil {
		t.Fatal("TLS 1.2 handshake succeeded")
	}
}

func TestExpiredAgentCertRejected(t *testing.T) {
	p := testpki.New(t)
	key, _ := pki.GenerateKey()
	past := time.Now().Add(-48 * time.Hour)
	cert, err := p.Intermediate.IssueAgentCert(key.Public(), ids.New(), time.Hour, past)
	if err != nil {
		t.Fatal(err)
	}
	inter := x509.NewCertPool()
	inter.AddCert(p.Intermediate.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: p.Roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("expired certificate verified")
	}
}

func TestServerCertNeedsSAN(t *testing.T) {
	p := testpki.New(t)
	key, _ := pki.GenerateKey()
	if _, err := p.Intermediate.IssueServerCert(key.Public(), nil, nil, time.Hour, time.Now()); !errors.Is(err, pki.ErrInvalidInput) {
		t.Fatalf("err = %v", err)
	}
}

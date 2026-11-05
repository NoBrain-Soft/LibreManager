package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newCA(t *testing.T, notAfter time.Time) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: t0.Add(-365 * day), NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pemCert(der)}
}

func (ca *testCA) leaf(t *testing.T, cn string, left time.Duration) (pemStr string, der []byte) {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: t0.Add(-30 * day), NotAfter: t0.Add(left), BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pemCert(der), der
}

func keyPEM(t *testing.T) string {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func TestCertificates(t *testing.T) {
	ca := newCA(t, t0.Add(2*day)) // CA certs (expiring or not) are ignored
	ok, _ := ca.leaf(t, "ok.example.com", 200*day)
	soon, _ := ca.leaf(t, "soon.example.com", 20*day)
	critical, _ := ca.leaf(t, "critical.example.com", 3*day)
	expired, _ := ca.leaf(t, "expired.example.com", -2*day)
	_, der := ca.leaf(t, "der.example.com", 25*day)

	tests := []struct {
		name  string
		files map[string]string
		dirs  []string
		want  agentv1.CheckStatus
		ev    map[string]string
	}{
		{"all fine", map[string]string{
			"etc/nginx/ssl/site.crt":            ok,
			"etc/nginx/ssl/site.key":            keyPEM(t),
			"etc/ssl/certs/ca-certificates.crt": soon + critical, // CA bundle dir: skipped
			"etc/pki/tls/certs/ca-bundle.crt":   expired,
			"etc/haproxy/ca.pem":                ca.pem,
		}, nil, PASS, map[string]string{"certificates": "1"}},
		{"expiring soon", map[string]string{
			"etc/nginx/site.pem":     ok,
			"etc/postfix/smtpd.cert": soon,
		}, nil, WARN, map[string]string{"cert.1": "/etc/postfix/smtpd.cert (CN=soon.example.com) expires in < 30 d", "expiring_30d": "1"}},
		{"critical and expired", map[string]string{
			"etc/apache2/ssl/a.crt": critical,
			"etc/apache2/ssl/b.crt": expired,
			"etc/apache2/ssl/c.crt": soon,
		}, nil, FAIL, map[string]string{"cert.1": "expired.example.com", "cert.2": "critical.example.com", "cert.3": "soon.example.com", "expired": "1", "expiring_7d": "1"}},
		{"chain and duplicates counted once", map[string]string{
			"etc/letsencrypt/live/x/cert.pem":      soon,
			"etc/letsencrypt/live/x/fullchain.pem": soon + ca.pem,
		}, nil, WARN, map[string]string{"certificates": "1", "expiring_30d": "1"}},
		{"combined pem with key", map[string]string{
			"etc/haproxy/site.pem": keyPEM(t) + critical,
		}, nil, FAIL, map[string]string{"cert.1": "critical.example.com"}},
		{"der", map[string]string{"etc/ssl/site.der": string(der)}, nil, WARN, map[string]string{"cert.1": "der.example.com"}},
		{"no certificates", map[string]string{"etc/nginx/nginx.conf": "events {}\n", "etc/ssl/junk.pem": "not a cert"}, nil, NA, nil},
		{"custom dirs; relative ignored", map[string]string{"srv/tls/a.crt": expired, "etc/nginx/b.crt": expired}, []string{"/srv/tls", "relative/dir"}, FAIL, map[string]string{"certificates": "1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: writeTree(t, tc.files), CertDirs: tc.dirs}, "CRT-001")
			expectStatus(t, r, tc.want)
			for k, v := range tc.ev {
				expectEvidence(t, r, k, v)
			}
			assertNoSecrets(t, r)
		})
	}
}

func TestCertificatesBounded(t *testing.T) {
	ca := newCA(t, t0.Add(365*day))
	files := map[string]string{}
	for i := range 20 {
		c, _ := ca.leaf(t, fmt.Sprintf("host%02d.example.com", i), time.Duration(i+1)*day)
		files[fmt.Sprintf("etc/nginx/c%02d.crt", i)] = c
	}
	r := runCheck(t, Env{Root: writeTree(t, files)}, "CRT-001")
	expectStatus(t, r, FAIL)
	expectEvidence(t, r, "files_scanned", "20")
	expectEvidence(t, r, "certificates", "20")
	expectEvidence(t, r, "expiring_7d", "6")
	expectEvidence(t, r, "expiring_30d", "14")
	expectEvidence(t, r, "cert.1", "host00.example.com")
	expectEvidence(t, r, "cert.16", "host15.example.com")
	if _, ok := r.GetEvidence()["cert.17"]; ok {
		t.Fatal("more than 16 certificates reported")
	}
	assertLimits(t, r)
}

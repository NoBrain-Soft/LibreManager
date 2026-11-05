// Package pki implements the built-in CA (ARCHITECTURE.md §6.2): root and
// intermediate creation, agent CSR signing with a SPIFFE URI SAN, server
// certificates, fingerprints, and TLS 1.3 configuration helpers.
//
// Host identity is carried exclusively in the URI SAN
// spiffe://stellwerk/host/<uuid> chosen by central at signing time. Subject
// and SANs requested in a CSR are ignored.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
)

// Lifetimes (ARCHITECTURE.md §6.2).
const (
	RootValidity         = 10 * 365 * 24 * time.Hour
	IntermediateValidity = 2 * 365 * 24 * time.Hour
	AgentCertValidity    = 30 * 24 * time.Hour
	ServerCertValidity   = 90 * 24 * time.Hour
	// Backdate certificates slightly to tolerate clock skew.
	backdate = 5 * time.Minute
)

// SPIFFE identity components.
const (
	SPIFFEScheme    = "spiffe"
	SPIFFETrustRoot = "stellwerk"
	hostPathPrefix  = "/host/"
)

// Errors.
var (
	ErrInvalidCSR   = errors.New("pki: invalid CSR")
	ErrKeyType      = errors.New("pki: unsupported key type")
	ErrNoIdentity   = errors.New("pki: certificate has no valid host identity")
	ErrNotCA        = errors.New("pki: certificate is not a CA")
	ErrFingerprint  = errors.New("pki: CA fingerprint mismatch")
	ErrKeyMismatch  = errors.New("pki: private key does not match certificate")
	ErrInvalidInput = errors.New("pki: invalid input")
)

// CA is a certificate authority (root or intermediate).
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	// Chain holds the issuing chain above Cert (empty for a root).
	Chain []*x509.Certificate
}

// GenerateKey creates an ECDSA P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate key: %w", err)
	}
	return k, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	// Ensure a positive, non-zero serial with full width.
	return s.Add(s, limit), nil
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

// NewRootCA creates a self-signed root CA.
func NewRootCA(commonName string, validity time.Duration, now time.Time) (*CA, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Stellwerk"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pki: create root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse root: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// NewIntermediate creates an intermediate CA signed by ca. The intermediate
// cannot issue further CAs (path length 0).
func (ca *CA) NewIntermediate(commonName string, validity time.Duration, now time.Time) (*CA, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Stellwerk"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        ca.Cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: create intermediate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse intermediate: %w", err)
	}
	chain := append([]*x509.Certificate{ca.Cert}, ca.Chain...)
	return &CA{Cert: cert, Key: key, Chain: chain}, nil
}

// HostURI returns spiffe://stellwerk/host/<hostID>.
func HostURI(hostID string) (*url.URL, error) {
	canon, err := ids.Canonical(hostID)
	if err != nil {
		return nil, fmt.Errorf("%w: host id: %w", ErrInvalidInput, err)
	}
	return &url.URL{Scheme: SPIFFEScheme, Host: SPIFFETrustRoot, Path: hostPathPrefix + canon}, nil
}

// HostIDFromCert extracts the host id from the certificate's single
// SPIFFE URI SAN. Any other URI SAN layout is rejected.
func HostIDFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", ErrNoIdentity
	}
	u := cert.URIs[0]
	if u.Scheme != SPIFFEScheme || u.Host != SPIFFETrustRoot || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || !strings.HasPrefix(u.Path, hostPathPrefix) {
		return "", ErrNoIdentity
	}
	id := strings.TrimPrefix(u.Path, hostPathPrefix)
	canon, err := ids.Canonical(id)
	if err != nil || canon != id {
		return "", ErrNoIdentity
	}
	return canon, nil
}

// ParseCSR parses and verifies a DER CSR and returns its public key, which
// must be ECDSA P-256 or Ed25519.
func ParseCSR(der []byte) (crypto.PublicKey, error) {
	if len(der) == 0 || len(der) > 8<<10 {
		return nil, ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature: %w", ErrInvalidCSR, err)
	}
	if err := checkKeyType(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr.PublicKey, nil
}

func checkKeyType(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("%w: ECDSA curve %s", ErrKeyType, k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
	default:
		return fmt.Errorf("%w: %T", ErrKeyType, pub)
	}
	return nil
}

// SignAgentCSR issues a client certificate for hostID from a CSR. Only the
// CSR's public key is used.
func (ca *CA) SignAgentCSR(csrDER []byte, hostID string, validity time.Duration, now time.Time) (*x509.Certificate, error) {
	pub, err := ParseCSR(csrDER)
	if err != nil {
		return nil, err
	}
	return ca.IssueAgentCert(pub, hostID, validity, now)
}

// IssueAgentCert issues a client certificate for hostID over pub.
func (ca *CA) IssueAgentCert(pub crypto.PublicKey, hostID string, validity time.Duration, now time.Time) (*x509.Certificate, error) {
	if err := checkKeyType(pub); err != nil {
		return nil, err
	}
	uri, err := HostURI(hostID)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: "host:" + uri.Path[len(hostPathPrefix):]},
		NotBefore:      now.Add(-backdate),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:           []*url.URL{uri},
		AuthorityKeyId: ca.Cert.SubjectKeyId,
	}
	return ca.create(tmpl, pub)
}

// IssueServerCert issues a TLS server certificate for the given DNS names / IPs.
func (ca *CA) IssueServerCert(pub crypto.PublicKey, dnsNames []string, ips []net.IP, validity time.Duration, now time.Time) (*x509.Certificate, error) {
	if err := checkKeyType(pub); err != nil {
		return nil, err
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, fmt.Errorf("%w: server certificate needs at least one SAN", ErrInvalidInput)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      now.Add(-backdate),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		AuthorityKeyId: ca.Cert.SubjectKeyId,
	}
	return ca.create(tmpl, pub)
}

func (ca *CA) create(tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}
	return cert, nil
}

// ChainDER returns [leaf, ca, ca.Chain...] minus the root (roots are pinned,
// not transmitted).
func (ca *CA) ChainDER(leaf *x509.Certificate) [][]byte {
	out := [][]byte{leaf.Raw}
	all := append([]*x509.Certificate{ca.Cert}, ca.Chain...)
	for _, c := range all {
		if isSelfSigned(c) {
			continue
		}
		out = append(out, c.Raw)
	}
	return out
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

// SerialHex returns the lowercase hex encoding of a certificate serial.
func SerialHex(c *x509.Certificate) string {
	return hex.EncodeToString(c.SerialNumber.Bytes())
}

// Fingerprint returns the SHA-256 fingerprint of a certificate in the
// "AB:CD:..." format used in agent.yaml.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// NormalizeFingerprint uppercases and strips separators so fingerprints
// can be compared regardless of formatting.
func NormalizeFingerprint(fp string) string {
	r := strings.NewReplacer(":", "", " ", "", "-", "")
	return strings.ToUpper(r.Replace(strings.TrimSpace(fp)))
}

// VerifyPinnedRoot parses a PEM root certificate and checks that it is a
// self-signed CA whose fingerprint matches the pinned one.
func VerifyPinnedRoot(pemData []byte, fingerprint string) (*x509.Certificate, error) {
	cert, err := ParseCertPEM(pemData)
	if err != nil {
		return nil, err
	}
	want := NormalizeFingerprint(fingerprint)
	if len(want) != 64 || NormalizeFingerprint(Fingerprint(cert)) != want {
		return nil, ErrFingerprint
	}
	if !cert.IsCA || !isSelfSigned(cert) {
		return nil, ErrNotCA
	}
	return cert, nil
}

// NewCSR creates a DER CSR for key. The subject is informational only.
func NewCSR(key crypto.Signer, commonName string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CSR: %w", err)
	}
	return der, nil
}

// EncodeCertPEM encodes a certificate as PEM.
func EncodeCertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// EncodeCertsPEM encodes DER certificates as concatenated PEM.
func EncodeCertsPEM(ders [][]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out
}

// ParseCertPEM parses exactly one PEM certificate (the first block).
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCertsPEM(data)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ParseCertsPEM parses all CERTIFICATE blocks.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no certificate in PEM", ErrInvalidInput)
	}
	return out, nil
}

// MarshalPrivateKey encodes a key as PKCS#8 DER.
func MarshalPrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %w", err)
	}
	return der, nil
}

// EncodeKeyPEM encodes a key as an unencrypted PKCS#8 PEM. Callers must
// write it with mode 0600 or wrap it with secretbox.
func EncodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKey parses a PKCS#8 DER key.
func ParsePrivateKey(der []byte) (crypto.Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrKeyType, k)
	}
	return s, nil
}

// ParseKeyPEM parses a PKCS#8 PEM key.
func ParseKeyPEM(data []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%w: no PRIVATE KEY block", ErrInvalidInput)
	}
	return ParsePrivateKey(b.Bytes)
}

// KeyMatchesCert reports whether key is the private key for cert.
func KeyMatchesCert(key crypto.Signer, cert *x509.Certificate) error {
	type eq interface{ Equal(crypto.PublicKey) bool }
	pk, ok := key.Public().(eq)
	if !ok || !pk.Equal(cert.PublicKey) {
		return ErrKeyMismatch
	}
	return nil
}

// TLS 1.3 only, everywhere (CLAUDE.md rule 2).

// ServerTLSConfig returns a TLS 1.3 server config presenting cert. If
// clientCAs is non-nil, client certificates are verified against it when
// presented (VerifyClientCertIfGiven); callers must enforce presence per RPC.
func ServerTLSConfig(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}
	if clientCAs != nil {
		cfg.ClientCAs = clientCAs
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg
}

// ClientTLSConfig returns a TLS 1.3 client config trusting only roots. If
// getCert is non-nil it supplies the client certificate (allowing rotation).
func ClientTLSConfig(roots *x509.CertPool, serverName string, getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		MaxVersion:           tls.VersionTLS13,
		RootCAs:              roots,
		ServerName:           serverName,
		GetClientCertificate: getCert,
		NextProtos:           []string{"h2"},
	}
}

// TLSCertificate assembles a tls.Certificate from a leaf, its key and the
// intermediate chain (DER).
func TLSCertificate(chainDER [][]byte, key crypto.Signer) (tls.Certificate, error) {
	if len(chainDER) == 0 {
		return tls.Certificate{}, fmt.Errorf("%w: empty chain", ErrInvalidInput)
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: parse leaf: %w", err)
	}
	if err := KeyMatchesCert(key, leaf); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: chainDER, PrivateKey: key, Leaf: leaf}, nil
}

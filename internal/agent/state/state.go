// Package state manages the agent's on-disk identity: private key and
// certificate chain (state dir, owned by the agent user), and the
// root-owned trust anchors written at enrollment (host id, pinned job keys).
package state

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/pki"
)

// Paths locates agent files.
type Paths struct {
	StateDir   string // /var/lib/stellwerk-agent
	HostIDFile string // /etc/stellwerk/host-id
	JobKeysDir string // /etc/stellwerk/jobkeys.d
	CAFile     string // /etc/stellwerk/ca.pem
}

// DefaultPaths returns the production layout for stateDir and caFile.
func DefaultPaths(stateDir, caFile string) Paths {
	return Paths{StateDir: stateDir, HostIDFile: "/etc/stellwerk/host-id", JobKeysDir: "/etc/stellwerk/jobkeys.d", CAFile: caFile}
}

func (p Paths) keyFile() string   { return filepath.Join(p.StateDir, "agent.key") }
func (p Paths) certFile() string  { return filepath.Join(p.StateDir, "agent.crt") }
func (p Paths) NonceFile() string { return filepath.Join(p.StateDir, "nonces") }
func (p Paths) SpoolDir() string  { return filepath.Join(p.StateDir, "spool") }

// ErrNotEnrolled is returned when no identity exists.
var ErrNotEnrolled = errors.New("agent is not enrolled (run `stellwerk-agent enroll`)")

// writeAtomic writes data to path via a temp file + rename.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	return nil
}

// SaveIdentity stores key + chain (0600).
func SaveIdentity(p Paths, key crypto.Signer, chainDER [][]byte) error {
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	kp, err := pki.EncodeKeyPEM(key)
	if err != nil {
		return err
	}
	// Write the certificate last: a crash in between leaves the old pair
	// mismatched, which LoadIdentity detects.
	if err := writeAtomic(p.keyFile()+".new", kp, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(p.certFile(), pki.EncodeCertsPEM(chainDER), 0o600); err != nil {
		return err
	}
	return os.Rename(p.keyFile()+".new", p.keyFile())
}

// LoadIdentity loads the TLS client certificate.
func LoadIdentity(p Paths) (tls.Certificate, error) {
	kp, err := os.ReadFile(p.keyFile())
	if errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, ErrNotEnrolled
	}
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("state: %w", err)
	}
	key, err := pki.ParseKeyPEM(kp)
	if err != nil {
		return tls.Certificate{}, err
	}
	cp, err := os.ReadFile(p.certFile())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("state: %w", err)
	}
	certs, err := pki.ParseCertsPEM(cp)
	if err != nil {
		return tls.Certificate{}, err
	}
	ders := make([][]byte, len(certs))
	for i, c := range certs {
		ders[i] = c.Raw
	}
	return pki.TLSCertificate(ders, key)
}

// WriteHostID writes the root-owned host identity file (enrollment, as root).
func WriteHostID(p Paths, hostID string) error {
	if !ids.Valid(hostID) {
		return errors.New("state: invalid host id")
	}
	if err := os.MkdirAll(filepath.Dir(p.HostIDFile), 0o755); err != nil { //nolint:gosec // /etc/stellwerk is world-readable by design
		return fmt.Errorf("state: %w", err)
	}
	return writeAtomic(p.HostIDFile, []byte(hostID+"\n"), 0o644)
}

// ReadHostID reads the host identity file.
func ReadHostID(p Paths) (string, error) {
	b, err := os.ReadFile(p.HostIDFile)
	if err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	id := strings.TrimSpace(string(b))
	if !ids.Valid(id) {
		return "", errors.New("state: invalid host id file")
	}
	return id, nil
}

// WriteJobKeys pins job-signing public keys (enrollment, as root).
func WriteJobKeys(p Paths, keys map[string][]byte) error {
	if err := os.MkdirAll(p.JobKeysDir, 0o755); err != nil { //nolint:gosec // public keys, root-owned
		return fmt.Errorf("state: %w", err)
	}
	for id, pub := range keys {
		if len(pub) != ed25519.PublicKeySize || envelope.KeyID(pub) != id {
			return fmt.Errorf("state: job key %q does not match its id", id)
		}
		if err := writeAtomic(filepath.Join(p.JobKeysDir, id+".pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LoadJobKeys reads pinned job keys.
func LoadJobKeys(p Paths) (envelope.KeyRing, error) {
	entries, err := os.ReadDir(p.JobKeysDir)
	if err != nil {
		return nil, fmt.Errorf("state: job keys: %w", err)
	}
	ring := envelope.KeyRing{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pub") || !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p.JobKeysDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("state: %w", err)
		}
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("state: job key %s: %w", e.Name(), err)
		}
		if _, err := ring.Add(pub); err != nil {
			return nil, err
		}
	}
	if len(ring) == 0 {
		return nil, errors.New("state: no pinned job keys")
	}
	return ring, nil
}

// LoadPinnedRoot loads the CA file and checks it against the pinned fingerprint.
func LoadPinnedRoot(p Paths, fingerprint string) (*x509.Certificate, *x509.CertPool, error) {
	b, err := os.ReadFile(p.CAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("state: CA file: %w", err)
	}
	root, err := pki.VerifyPinnedRoot(b, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return root, pool, nil
}

// Identity holds the current client certificate and supports rotation.
type Identity struct {
	mu   sync.RWMutex
	cert tls.Certificate
}

// NewIdentity wraps a certificate.
func NewIdentity(c tls.Certificate) *Identity { return &Identity{cert: c} }

// Get returns the current certificate (for tls.Config.GetClientCertificate).
func (i *Identity) Get(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	c := i.cert
	return &c, nil
}

// Set replaces the certificate.
func (i *Identity) Set(c tls.Certificate) {
	i.mu.Lock()
	i.cert = c
	i.mu.Unlock()
}

// Leaf returns the current leaf.
func (i *Identity) Leaf() *x509.Certificate {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cert.Leaf
}

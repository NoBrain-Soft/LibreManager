package inventory

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// SSHHostKeys returns fingerprints of /etc/ssh/ssh_host_*_key.pub in the
// "SHA256:<base64, unpadded>" format of ssh-keygen -l.
func (c *Collector) SSHHostKeys(_ context.Context) (*agentv1.InventorySection, error) {
	matches, _ := filepath.Glob(c.path("etc", "ssh", "ssh_host_*_key.pub"))
	sort.Strings(matches)
	keys := &agentv1.SshHostKeys{}
	for _, p := range matches {
		if len(keys.Keys) >= maxSSHKeys {
			break
		}
		data, err := osutil.ReadFileLimit(p, 16<<10)
		if err != nil {
			continue
		}
		typ, fp, err := sshFingerprint(data)
		if err != nil {
			c.log().Debug("skipping unparsable SSH host key", "path", p, "error", err)
			continue
		}
		keys.Keys = append(keys.Keys, &agentv1.SshHostKey{Type: typ, FingerprintSha256: fp})
	}
	return newSection(keys)
}

// sshFingerprint parses an authorized_keys-style public key line
// ("type base64 [comment]") and returns its type and SHA-256 fingerprint.
func sshFingerprint(line []byte) (string, string, error) {
	f := strings.Fields(string(line))
	if len(f) < 2 {
		return "", "", errors.New("malformed public key")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return "", "", errors.New("invalid base64 key blob")
	}
	// The blob starts with the length-prefixed key type, which must match.
	if len(blob) < 4 {
		return "", "", errors.New("short key blob")
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n)+4 > uint64(len(blob)) || string(blob[4:4+n]) != f[0] {
		return "", "", errors.New("key type mismatch")
	}
	sum := sha256.Sum256(blob)
	return osutil.Clean(f[0], maxShort), "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// certFileExts are the file extensions scanned for certificates. Private
// keys (*.key, privkey*.pem) are never opened.
var certFileExts = []string{".pem", ".crt", ".cer", ".cert"}

// bundleNames are CA bundles, never reported.
var bundleNames = map[string]bool{
	"ca-bundle.crt": true, "ca-bundle.trust.crt": true, "ca-certificates.crt": true,
	"tls-ca-bundle.pem": true, "chain.pem": true,
}

// Certificates returns local TLS certificates found in CertDirs: the first
// certificate (leaf) of every PEM file, deduplicated by fingerprint. Files
// holding many certificates (CA bundles), /etc/ssl/certs and private key
// files are skipped; scanning is bounded in depth, file count and size.
func (c *Collector) Certificates(_ context.Context) (*agentv1.InventorySection, error) {
	dirs := c.CertDirs
	if dirs == nil {
		dirs = DefaultCertDirs
	}
	seen := map[string]bool{}
	var certs []*agentv1.Certificate
	scanned := 0
	for _, dir := range dirs {
		dir = filepath.Clean("/" + dir)
		if dir == "/etc/ssl/certs" || strings.HasPrefix(dir, "/etc/ssl/certs/") {
			continue
		}
		base := c.path(dir)
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(base, p)
			if d.IsDir() {
				if rel != "." && strings.Count(rel, string(filepath.Separator)) >= maxCertDepth-1 {
					return fs.SkipDir
				}
				return nil
			}
			if scanned >= maxCertFiles || len(certs) >= maxCerts {
				return fs.SkipAll
			}
			if !certCandidate(d.Name()) {
				return nil
			}
			scanned++
			cert, err := c.readCert(p, filepath.Join(dir, rel))
			if err != nil || cert == nil || seen[cert.GetSha256Fingerprint()] {
				return nil //nolint:nilerr // unreadable/non-certificate files are skipped
			}
			seen[cert.GetSha256Fingerprint()] = true
			certs = append(certs, cert)
			return nil
		})
	}
	sort.SliceStable(certs, func(i, j int) bool { return certs[i].GetPath() < certs[j].GetPath() })
	out := &agentv1.Certificates{}
	out.Certificates, _ = capBySize(certs, budgetCerts)
	return newSection(out)
}

func certCandidate(name string) bool {
	lower := strings.ToLower(name)
	if bundleNames[lower] || strings.Contains(lower, "privkey") || (strings.Contains(lower, "key") && !strings.Contains(lower, "cert")) {
		return false
	}
	return slices.Contains(certFileExts, filepath.Ext(lower))
}

// readCert parses the first certificate of a PEM file. Symlinks to files
// are followed (Let's Encrypt live/ links into archive/).
func (c *Collector) readCert(p, display string) (*agentv1.Certificate, error) {
	data, err := osutil.ReadFileLimit(p, maxCertFileSize)
	if err != nil {
		return nil, err //nolint:wrapcheck // best effort
	}
	var first *x509.Certificate
	n := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		n++
		if n > maxCertsPerFile {
			return nil, errors.New("certificate bundle")
		}
		if first == nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err //nolint:wrapcheck // best effort
			}
			first = cert
		}
	}
	if first == nil {
		return nil, nil
	}
	return &agentv1.Certificate{
		Path:              osutil.Clean(display, maxPath),
		Subject:           osutil.Clean(first.Subject.String(), maxText),
		Issuer:            osutil.Clean(first.Issuer.String(), maxText),
		DnsNames:          cleanList(first.DNSNames, maxDNSNames, maxName),
		NotBeforeUnix:     first.NotBefore.Unix(),
		NotAfterUnix:      first.NotAfter.Unix(),
		Sha256Fingerprint: pki.Fingerprint(first),
	}, nil
}

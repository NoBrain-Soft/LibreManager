package checks

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	certFailWithin = 7 * 24 * time.Hour
	certWarnWithin = 30 * 24 * time.Hour
	maxCertFiles   = 2000
	maxCertFile    = 512 << 10
	maxCertBytes   = 32 << 20
	maxCertDepth   = 5
	maxCertReports = 16
)

// certSkipDirs hold CA bundles and private keys, not service certificates.
var certSkipDirs = []string{
	"/etc/ssl/certs", "/etc/ssl/private", "/etc/pki/ca-trust", "/etc/pki/tls/private",
	"/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/tls/certs/ca-bundle.trust.crt", "/etc/pki/tls/cert.pem",
	"/etc/ssl/cert.pem",
}

func certFile(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".pem", ".crt", ".cer", ".cert", ".der":
		return true
	}
	return false
}

type certFinding struct {
	path     string
	subject  string
	notAfter time.Time
}

type certScan struct {
	ctx       context.Context
	files     int
	bytes     int64
	truncated bool
	seen      map[[32]byte]bool
	visited   map[string]bool
	certs     []certFinding
}

func (s *certScan) skip(hostPath string) bool {
	for _, d := range certSkipDirs {
		if hostPath == d || strings.HasPrefix(hostPath, d+"/") {
			return true
		}
	}
	return false
}

func (s *certScan) walk(dir, hostDir string, depth int) {
	if s.skip(hostDir) || s.visited[hostDir] {
		return
	}
	s.visited[hostDir] = true
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // e.g. /etc/letsencrypt/live is root-only on some systems
	}
	for _, e := range entries {
		if s.files >= maxCertFiles || s.bytes >= maxCertBytes || s.ctx.Err() != nil {
			s.truncated = true
			return
		}
		full, host := filepath.Join(dir, e.Name()), path.Join(hostDir, e.Name())
		if s.skip(host) {
			continue
		}
		if e.IsDir() {
			if depth < maxCertDepth {
				s.walk(full, host, depth+1)
			}
			continue
		}
		if !certFile(e.Name()) {
			continue
		}
		// Follow file symlinks (letsencrypt live/ -> archive/), not directory ones.
		st, err := os.Stat(full)
		if err != nil || !st.Mode().IsRegular() || st.Size() > maxCertFile {
			continue
		}
		data, err := readCapped(full, maxCertFile)
		if err != nil {
			continue
		}
		s.files++
		s.bytes += int64(len(data))
		s.parse(host, data)
	}
}

// parse records the non-CA certificates of a PEM (or DER) file. Other PEM
// blocks — including private keys — are skipped and never retained.
func (s *certScan) parse(host string, data []byte) {
	var ders [][]byte
	rest := data
	for len(ders) < 64 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			ders = append(ders, b.Bytes)
		}
	}
	if len(ders) == 0 && !strings.Contains(string(data[:min(len(data), 64)]), "-----") {
		ders = append(ders, data)
	}
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil || (c.BasicConstraintsValid && c.IsCA) {
			continue
		}
		fp := sha256.Sum256(c.Raw)
		if s.seen[fp] {
			continue
		}
		s.seen[fp] = true
		subj := c.Subject.CommonName
		if subj == "" && len(c.DNSNames) > 0 {
			subj = c.DNSNames[0]
		}
		s.certs = append(s.certs, certFinding{path: host, subject: subj, notAfter: c.NotAfter})
	}
}

func checkCertificates(ctx context.Context, r *runState) result {
	s := &certScan{ctx: ctx, seen: map[[32]byte]bool{}, visited: map[string]bool{}}
	for _, d := range r.env.CertDirs {
		if !path.IsAbs(d) {
			continue
		}
		d = path.Clean(d)
		s.walk(r.rootPath(d), d, 0)
	}
	if len(s.certs) == 0 {
		return na("no local TLS certificates found", "files_scanned", fmt.Sprint(s.files))
	}
	slices.SortFunc(s.certs, func(a, b certFinding) int { return a.notAfter.Compare(b.notAfter) })
	var expired, critical, soon int
	kvs := []string{"files_scanned", fmt.Sprint(s.files), "certificates", fmt.Sprint(len(s.certs))}
	if s.truncated {
		kvs = append(kvs, "truncated", "true")
	}
	reported := 0
	for _, c := range s.certs {
		left := c.notAfter.Sub(r.now)
		var state string
		switch {
		case left <= 0:
			expired++
			state = "expired"
		case left < certFailWithin:
			critical++
			state = "expires in < 7 d"
		case left < certWarnWithin:
			soon++
			state = "expires in < 30 d"
		default:
			continue
		}
		if reported < maxCertReports {
			reported++
			kvs = append(kvs, fmt.Sprintf("cert.%d", reported),
				fmt.Sprintf("%s (CN=%s) %s: %s", c.path, c.subject, state, c.notAfter.UTC().Format(time.DateOnly)))
		}
	}
	kvs = append(kvs, "expired", fmt.Sprint(expired), "expiring_7d", fmt.Sprint(critical), "expiring_30d", fmt.Sprint(soon))
	switch {
	case expired+critical > 0:
		return fail(fmt.Sprintf("%d certificate(s) expired or expiring within 7 days", expired+critical), kvs...)
	case soon > 0:
		return warn(plural(soon, "certificate expires", "certificates expire")+" within 30 days", kvs...)
	}
	return pass(fmt.Sprintf("no certificate expires within 30 days (next: %s)", s.certs[0].notAfter.UTC().Format(time.DateOnly)), kvs...)
}

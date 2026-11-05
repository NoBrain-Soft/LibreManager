package inventory

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Package database locations (relative to Root).
var (
	dpkgStatusPath = []string{"var", "lib", "dpkg", "status"}
	rpmDBPaths     = [][]string{
		{"var", "lib", "rpm", "rpmdb.sqlite"},
		{"var", "lib", "rpm", "rpmdb.sqlite-wal"},
		{"var", "lib", "rpm", "Packages"},
		{"var", "lib", "rpm", "Packages.db"},
		{"usr", "lib", "sysimage", "rpm", "rpmdb.sqlite"},
		{"usr", "lib", "sysimage", "rpm", "rpmdb.sqlite-wal"},
		{"usr", "lib", "sysimage", "rpm", "Packages.db"},
	}
)

// pkgInfo is a parsed package before conversion to the proto.
type pkgInfo struct {
	name, version, arch string
	epoch, release      string // rpm only
	sourceName          string // source package if different
	sourceVersion       string // deb: source version if different
	sourceRPM           string // rpm: source rpm file name
}

// Packages returns the PackageList section from dpkg (parsed directly) or
// rpm (`rpm -qa --qf ...`).
func (c *Collector) Packages(ctx context.Context) (*agentv1.InventorySection, error) {
	osr := c.osRelease()
	var (
		pkgs    []pkgInfo
		manager string
		err     error
	)
	switch {
	case exists(c.path(dpkgStatusPath...)):
		manager = "dpkg"
		pkgs, err = c.dpkgPackages()
	case c.rpmDBPresent():
		manager = "rpm"
		pkgs, err = c.rpmPackages(ctx)
	default:
		return nil, fmt.Errorf("packages: no dpkg or rpm database: %w", ErrUnsupported)
	}
	if err != nil {
		return nil, err
	}
	slices.SortFunc(pkgs, func(a, b pkgInfo) int {
		return cmp.Or(strings.Compare(a.name, b.name), strings.Compare(a.arch, b.arch), strings.Compare(a.version, b.version))
	})
	pkgs = slices.CompactFunc(pkgs, func(a, b pkgInfo) bool { return a == b })
	list := &agentv1.PackageList{Manager: manager, Packages: make([]*agentv1.Package, 0, len(pkgs))}
	for _, p := range pkgs {
		list.Packages = append(list.Packages, toProtoPackage(manager, p, osr))
	}
	var truncated bool
	list.Packages, truncated = capBySize(list.Packages, budgetPackages)
	if truncated {
		c.log().Warn("package list truncated to size budget", "kept", len(list.Packages), "total", len(pkgs))
	}
	return newSection(list)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (c *Collector) rpmDBPresent() bool {
	for _, p := range rpmDBPaths {
		if exists(c.path(p...)) {
			return true
		}
	}
	return false
}

// PackageDBFingerprint returns a cheap fingerprint (path, size, mtime) of
// the package database files. The agent rescans packages when it changes.
// It returns "" when no package database exists.
func (c *Collector) PackageDBFingerprint() string {
	paths := append([][]string{dpkgStatusPath}, rpmDBPaths...)
	var b strings.Builder
	for _, p := range paths {
		full := c.path(p...)
		fi, err := os.Stat(full)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", strings.Join(p, "/"), fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

func (c *Collector) dpkgPackages() ([]pkgInfo, error) {
	f, err := osutil.OpenRegular(c.path(dpkgStatusPath...))
	if err != nil {
		return nil, fmt.Errorf("packages: %w", err)
	}
	defer func() { _ = f.Close() }()
	pkgs, err := parseDpkgStatus(io.LimitReader(f, maxDpkgStatus), maxPackages)
	if err != nil {
		return nil, fmt.Errorf("packages: parse dpkg status: %w", err)
	}
	return pkgs, nil
}

// dpkgPresentStates are dpkg status values whose files are on disk.
var dpkgPresentStates = map[string]bool{
	"installed": true, "half-configured": true, "unpacked": true,
	"triggers-awaiting": true, "triggers-pending": true,
}

// parseDpkgStatus streams /var/lib/dpkg/status (deb822 stanzas) and returns
// the packages whose files are present. Malformed stanzas are skipped.
func parseDpkgStatus(r io.Reader, max int) ([]pkgInfo, error) {
	var out []pkgInfo
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var cur pkgInfo
	var status string
	flush := func() {
		if cur.name != "" && cur.version != "" && dpkgInstalled(status) && len(out) < max {
			out = append(out, cur)
		}
		cur, status = pkgInfo{}, ""
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation (Description, Conffiles, ...)
		}
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		val := strings.TrimSpace(string(v))
		switch string(k) {
		case "Package":
			cur.name = val
		case "Status":
			status = val
		case "Version":
			cur.version = val
		case "Architecture":
			cur.arch = val
		case "Source":
			// "Source: name" or "Source: name (version)"
			name, ver, _ := strings.Cut(val, " ")
			cur.sourceName = name
			cur.sourceVersion = strings.Trim(strings.TrimSpace(ver), "()")
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("scan: %w", err)
	}
	for i := range out {
		p := &out[i]
		if p.sourceName == p.name {
			p.sourceName = ""
		}
		if p.sourceName == "" || p.sourceVersion == p.version {
			p.sourceVersion = ""
		}
	}
	return out, nil
}

func dpkgInstalled(status string) bool {
	f := strings.Fields(status)
	return len(f) == 3 && dpkgPresentStates[f[2]]
}

// rpmQueryFormat separates fields with 0x1f and records with 0x1e; neither
// can occur in package metadata. The argument is passed as one argv entry,
// never through a shell.
const rpmQueryFormat = "%{NAME}\x1f%{EPOCH}\x1f%{VERSION}\x1f%{RELEASE}\x1f%{ARCH}\x1f%{SOURCERPM}\x1e"

func (c *Collector) rpmPackages(ctx context.Context) ([]pkgInfo, error) {
	args := []string{"-qa", "--qf", rpmQueryFormat}
	if root := c.root(); root != "/" {
		args = append([]string{"--root", root}, args...)
	}
	out, err := c.exec().Run(ctx, "rpm", args...)
	if err != nil {
		return nil, fmt.Errorf("packages: rpm -qa: %w", err)
	}
	pkgs := parseRPMQuery(out, maxPackages)
	if len(pkgs) == 0 {
		return nil, errors.New("packages: rpm returned no packages")
	}
	return pkgs, nil
}

// parseRPMQuery parses output produced with rpmQueryFormat. Records with the
// wrong field count are skipped, as are gpg-pubkey pseudo packages.
func parseRPMQuery(data []byte, max int) []pkgInfo {
	var out []pkgInfo
	for rec := range bytes.SplitSeq(data, []byte{0x1e}) {
		if len(out) >= max {
			break
		}
		f := bytes.Split(bytes.TrimLeft(rec, "\r\n"), []byte{0x1f})
		if len(f) != 6 {
			continue
		}
		p := pkgInfo{
			name:      string(f[0]),
			epoch:     string(f[1]),
			version:   string(f[2]),
			release:   string(f[3]),
			arch:      string(f[4]),
			sourceRPM: string(f[5]),
		}
		if p.name == "" || p.version == "" || p.name == "gpg-pubkey" {
			continue
		}
		if p.epoch == "(none)" || p.epoch == "0" {
			p.epoch = ""
		}
		if p.arch == "(none)" {
			p.arch = ""
		}
		if p.sourceRPM == "(none)" {
			p.sourceRPM = ""
		}
		if src := rpmSourceName(p.sourceRPM); src != p.name {
			p.sourceName = src
		}
		out = append(out, p)
	}
	return out
}

// rpmSourceName extracts the name from "openssl-3.0.7-24.el9.src.rpm".
func rpmSourceName(srpm string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(srpm, ".src.rpm"), ".nosrc.rpm")
	if s == srpm {
		return ""
	}
	// name-version-release: strip the last two dash-separated parts.
	for range 2 {
		i := strings.LastIndexByte(s, '-')
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}

func toProtoPackage(manager string, p pkgInfo, osr osRelease) *agentv1.Package {
	pkg := &agentv1.Package{
		Name:       osutil.Clean(p.name, maxName),
		Arch:       osutil.Clean(p.arch, maxShort),
		SourceName: osutil.Clean(p.sourceName, maxName),
	}
	switch manager {
	case "dpkg":
		pkg.Version = osutil.Clean(p.version, maxName)
		pkg.Purl = osutil.Clean(debPURL(p, osr), maxText)
	case "rpm":
		evr := p.version + "-" + p.release
		if p.epoch != "" {
			evr = p.epoch + ":" + evr
		}
		pkg.Version = osutil.Clean(evr, maxName)
		pkg.Purl = osutil.Clean(rpmPURL(p, osr), maxText)
	}
	return pkg
}

// debPURL builds pkg:deb/<vendor>/<name>@<version>?arch=..&distro=..&upstream=..
// (qualifiers sorted by key, as the purl spec's canonical form requires).
func debPURL(p pkgInfo, osr osRelease) string {
	ns := "debian"
	if osr.ID == "ubuntu" || (osr.ID != "debian" && slices.Contains(osr.IDLike, "ubuntu")) {
		ns = "ubuntu"
	}
	q := purlQualifiers{}
	q.add("arch", p.arch)
	q.add("distro", distroQualifier(osr))
	if p.sourceName != "" {
		up := p.sourceName
		if p.sourceVersion != "" {
			up += "@" + p.sourceVersion
		}
		q.add("upstream", up)
	}
	return "pkg:deb/" + ns + "/" + purlEscape(p.name) + "@" + purlEscape(p.version) + q.String()
}

// rpmVendors maps os-release IDs to purl namespaces.
var rpmVendors = map[string]string{
	"rhel": "redhat", "centos": "centos", "rocky": "rocky", "almalinux": "almalinux",
	"ol": "oracle", "fedora": "fedora", "amzn": "amazon", "opensuse-leap": "opensuse",
	"opensuse-tumbleweed": "opensuse", "opensuse": "opensuse", "sles": "suse", "sled": "suse",
}

// rpmPURL builds pkg:rpm/<vendor>/<name>@<version>-<release>?arch=..&distro=..&epoch=..&upstream=..
func rpmPURL(p pkgInfo, osr osRelease) string {
	ns := rpmVendors[osr.ID]
	if ns == "" {
		ns = osr.ID
	}
	if ns == "" {
		ns = "redhat"
	}
	q := purlQualifiers{}
	q.add("arch", p.arch)
	q.add("distro", distroQualifier(osr))
	q.add("epoch", p.epoch)
	q.add("upstream", p.sourceRPM)
	return "pkg:rpm/" + purlEscape(ns) + "/" + purlEscape(p.name) + "@" + purlEscape(p.version+"-"+p.release) + q.String()
}

func distroQualifier(osr osRelease) string {
	switch {
	case osr.ID == "":
		return ""
	case osr.VersionID == "":
		return osr.ID
	}
	return osr.ID + "-" + osr.VersionID
}

type purlQualifiers [][2]string

func (q *purlQualifiers) add(k, v string) {
	if v != "" {
		*q = append(*q, [2]string{k, v})
	}
}

func (q purlQualifiers) String() string {
	if len(q) == 0 {
		return ""
	}
	slices.SortFunc(q, func(a, b [2]string) int { return strings.Compare(a[0], b[0]) })
	var b strings.Builder
	for i, kv := range q {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(purlEscapeQualifier(kv[1]))
	}
	return b.String()
}

// purlEscape percent-encodes a purl namespace/name/version segment: every
// byte except RFC 3986 unreserved characters and ':' is encoded (so "+"
// becomes %2B, as packageurl-go/syft emit it).
func purlEscape(s string) string { return percentEncode(s, true) }

// purlEscapeQualifier encodes a qualifier value (':' is encoded too).
func purlEscapeQualifier(s string) string { return percentEncode(s, false) }

func percentEncode(s string, allowColon bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == ':' && allowColon:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

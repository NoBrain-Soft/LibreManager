package checks

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxSmallFile  = 64 << 10
	maxConfigFile = 1 << 20
	maxPasswd     = 4 << 20
	maxAccounts   = 10000
)

var errTooLarge = errors.New("checks: file too large")

func (r *runState) rootPath(p string) string { return filepath.Join(r.env.Root, p) }
func (r *runState) procPath(p string) string { return filepath.Join(r.env.ProcRoot, p) }
func (r *runState) sysPath(p string) string  { return filepath.Join(r.env.SysRoot, p) }

// readCapped reads at most max bytes; a larger file is an error.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // paths are fixed or derived from fixed roots
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s", errTooLarge, path)
	}
	return data, nil
}

// readTrim reads a small file (sysfs/procfs value) and trims whitespace.
func readTrim(path string) (string, error) {
	b, err := readCapped(path, 4096)
	return strings.TrimSpace(string(b)), err
}

func exists(path string) bool {
	_, err := os.Stat(path) //nolint:gosec // paths are fixed or derived from fixed roots
	return err == nil
}

func isDir(path string) bool {
	st, err := os.Stat(path) //nolint:gosec // paths are fixed or derived from fixed roots
	return err == nil && st.IsDir()
}

// eachLine calls fn for every line of data (lines longer than 64 KiB end
// the scan) until fn returns false.
func eachLine(data []byte, fn func(string) bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		if !fn(sc.Text()) {
			return
		}
	}
}

// nonEmptyLines returns the trimmed, non-empty lines of data.
func nonEmptyLines(data []byte) []string {
	var out []string
	eachLine(data, func(l string) bool {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
		return true
	})
	return out
}

// --- os-release --------------------------------------------------------------

type osRelease struct {
	id, versionID, prettyName string
	idLike                    []string
}

// family returns "debian", "rhel", "suse" or "".
func (o osRelease) family() string {
	for _, id := range append([]string{o.id}, o.idLike...) {
		switch id {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "fedora", "centos":
			return "rhel"
		case "suse", "opensuse", "sles":
			return "suse"
		}
	}
	return ""
}

func parseOSRelease(data []byte) osRelease {
	var o osRelease
	eachLine(data, func(l string) bool {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.HasPrefix(k, "#") {
			return true
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			o.id = strings.ToLower(v)
		case "ID_LIKE":
			o.idLike = strings.Fields(strings.ToLower(v))
		case "VERSION_ID":
			o.versionID = v
		case "PRETTY_NAME":
			o.prettyName = v
		}
		return true
	})
	return o
}

func (r *runState) osRelease() (osRelease, error) {
	r.osOnce.Do(func() {
		data, err := readCapped(r.rootPath("/etc/os-release"), maxSmallFile)
		if errors.Is(err, os.ErrNotExist) {
			data, err = readCapped(r.rootPath("/usr/lib/os-release"), maxSmallFile)
		}
		if err != nil {
			r.osErr = err
			return
		}
		r.osRel = parseOSRelease(data)
	})
	return r.osRel, r.osErr
}

func (r *runState) osFamily() string {
	o, err := r.osRelease()
	if err != nil {
		return ""
	}
	return o.family()
}

// --- passwd ------------------------------------------------------------------

type passwdEntry struct {
	name        string
	uid, gid    uint32
	home, shell string
}

// parsePasswd reads /etc/passwd lines. The password field is never kept.
func parsePasswd(data []byte) []passwdEntry {
	var out []passwdEntry
	eachLine(data, func(l string) bool {
		if l == "" || l[0] == '#' || l[0] == '+' || l[0] == '-' {
			return true
		}
		f := strings.Split(l, ":")
		if len(f) < 7 || f[0] == "" {
			return true
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			return true
		}
		out = append(out, passwdEntry{name: f[0], uid: uint32(uid), gid: uint32(gid), home: f[5], shell: f[6]})
		return len(out) < maxAccounts
	})
	return out
}

func (r *runState) passwd() ([]passwdEntry, error) {
	r.pwOnce.Do(func() {
		data, err := readCapped(r.rootPath("/etc/passwd"), maxPasswd)
		if err != nil {
			r.pwErr = err
			return
		}
		r.pw = parsePasswd(data)
	})
	return r.pw, r.pwErr
}

// loginDefsInt returns an integer setting from /etc/login.defs.
func (r *runState) loginDefsInt(key string, def int64) int64 {
	data, err := readCapped(r.rootPath("/etc/login.defs"), maxSmallFile)
	if err != nil {
		return def
	}
	val := def
	eachLine(data, func(l string) bool {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == key {
			if n, err := strconv.ParseInt(f[1], 10, 64); err == nil && n >= 0 {
				val = n
			}
		}
		return true
	})
	return val
}

// --- versions ----------------------------------------------------------------

// compareVersions compares dotted/dashed version strings segment by
// segment: digit runs numerically, other runs lexically. It is meant for
// kernel releases of the same shape (see versionShape).
func compareVersions(a, b string) int {
	for a != "" || b != "" {
		sa, ra := nextSegment(a)
		sb, rb := nextSegment(b)
		if c := compareSegment(sa, sb); c != 0 {
			return c
		}
		a, b = ra, rb
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func nextSegment(s string) (seg, rest string) {
	if s == "" {
		return "", ""
	}
	d := isDigit(s[0])
	i := 1
	for i < len(s) && isDigit(s[i]) == d {
		i++
	}
	return s[:i], s[i:]
}

func compareSegment(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	if isDigit(a[0]) && isDigit(b[0]) {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			if len(a) < len(b) {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

// versionShape replaces every digit run with '#', so "6.1.0-27-amd64" and
// "6.1.0-28-amd64" share a shape but "6.1.0-27-cloud-amd64" does not.
func versionShape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			if i == 0 || !isDigit(s[i-1]) {
				b.WriteByte('#')
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

package helper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/common/framing"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

// Limits for privileged reads.
const (
	maxNames      = 10000
	maxSudoRules  = 2000
	maxSudoFiles  = 128
	maxSudoDepth  = 8
	maxValueLen   = 1024
	maxProcPIDs   = 1 << 16
	maxFDsPerProc = 1 << 16
)

func (s *Server) readPrivileged(ctx context.Context, w *responder, kind helperv1.PrivilegedKind) {
	pol, err := s.policy()
	if err != nil {
		w.fail(err.Error())
		return
	}
	if !pol.Capabilities.SecurityChecks && !pol.Capabilities.Inventory {
		w.fail("policy: denied: security checks and inventory disabled")
		return
	}
	d := &helperv1.PrivilegedData{Kind: kind}
	switch kind {
	case helperv1.PrivilegedKind_PRIVILEGED_KIND_SHADOW_FLAGS:
		d.EmptyPasswordUsers, d.LockedUsers, err = shadowFlags(s.cfg.Paths.Shadow)
	case helperv1.PrivilegedKind_PRIVILEGED_KIND_SSHD_EFFECTIVE_CONFIG:
		d.Values, err = s.sshdConfig(ctx)
	case helperv1.PrivilegedKind_PRIVILEGED_KIND_SUDOERS:
		d.SudoRules, err = sudoRules(s.cfg.Paths.Sudoers)
	case helperv1.PrivilegedKind_PRIVILEGED_KIND_SOCKET_OWNERS:
		d.Values, err = socketOwners(s.cfg.Paths.Proc)
	default:
		err = errors.New("unknown privileged kind")
	}
	if err != nil {
		w.fail(err.Error())
		return
	}
	if err := w.send(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_Privileged{Privileged: d}}); errors.Is(err, framing.ErrFrameTooLarge) {
		w.fail("privileged data too large")
	}
}

func readFileCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // fixed system paths
	if err != nil {
		return nil, fmt.Errorf("helper: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("helper: %w", err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("helper: %s too large", path)
	}
	return data, nil
}

func eachLine(data []byte, fn func(string)) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		fn(sc.Text())
	}
}

// saneName accepts account names for reporting (not for use in commands).
func saneName(n string) bool {
	return n != "" && len(n) <= 64 && clean(n, 64) == n && !strings.ContainsAny(n, " :")
}

// shadowFlags reports which accounts have an empty or locked password
// field. Hashes never leave this function.
func shadowFlags(path string) (empty, locked []string, err error) {
	data, err := readFileCapped(path, 4<<20)
	if err != nil {
		return nil, nil, err
	}
	eachLine(data, func(line string) {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || !saneName(name) {
			return
		}
		hash, _, _ := strings.Cut(rest, ":")
		switch {
		case hash == "" && len(empty) < maxNames:
			empty = append(empty, name)
		case hash != "" && (hash[0] == '!' || hash[0] == '*') && len(locked) < maxNames:
			locked = append(locked, name)
		}
	})
	return empty, locked, nil
}

func sshdKeyAllowed(k string) bool {
	switch k {
	case "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
		"challengeresponseauthentication", "maxauthtries", "x11forwarding", "ciphers", "macs",
		"kexalgorithms", "logingracetime", "permitemptypasswords", "pubkeyauthentication",
		"allowtcpforwarding", "clientaliveinterval":
		return true
	}
	return false
}

func (s *Server) sshdConfig(ctx context.Context) (map[string]string, error) {
	data, code, err := runner.Output(ctx, s.cfg.Runner, runner.Cmd{Name: "sshd", Args: []string{"-T"}}, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("sshd -T exited with %d", code)
	}
	return parseSSHDConfig(data), nil
}

func parseSSHDConfig(data []byte) map[string]string {
	out := map[string]string{}
	eachLine(data, func(line string) {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		if k = strings.ToLower(k); sshdKeyAllowed(k) {
			out[k] = clean(strings.Join(strings.Fields(v), " "), maxValueLen)
		}
	})
	return out
}

// sudoParser collects rule lines from sudoers, following #include(dir)
// and @include(dir) like sudo does.
type sudoParser struct {
	rules []string
	seen  map[string]bool
}

func sudoRules(path string) ([]string, error) {
	p := &sudoParser{seen: map[string]bool{}}
	if err := p.file(path, 0); err != nil {
		return nil, err
	}
	return p.rules, nil
}

func (p *sudoParser) file(path string, depth int) error {
	// Each file is read once: include loops and duplicates add nothing.
	if depth > maxSudoDepth || len(p.seen) >= maxSudoFiles || p.seen[path] {
		return nil
	}
	p.seen[path] = true
	data, err := readFileCapped(path, 1<<20)
	if err != nil {
		if depth == 0 {
			return err
		}
		return nil // missing include: sudo itself would complain
	}
	var logical strings.Builder
	eachLine(data, func(line string) {
		if strings.HasSuffix(line, "\\") {
			logical.WriteString(strings.TrimSuffix(line, "\\") + " ")
			return
		}
		logical.WriteString(line)
		p.line(strings.TrimSpace(logical.String()), path, depth)
		logical.Reset()
	})
	return nil
}

func (p *sudoParser) line(t, path string, depth int) {
	if dir, ok := directive(t, "includedir"); ok {
		entries, err := os.ReadDir(resolveInclude(dir, path))
		if err != nil {
			return
		}
		for _, e := range entries {
			// sudo skips names ending in '~' or containing '.'.
			if n := e.Name(); e.Type().IsRegular() && !strings.HasSuffix(n, "~") && !strings.Contains(n, ".") {
				_ = p.file(filepath.Join(resolveInclude(dir, path), n), depth+1)
			}
		}
		return
	}
	if f, ok := directive(t, "include"); ok {
		_ = p.file(resolveInclude(f, path), depth+1)
		return
	}
	t = stripSudoComment(t)
	if t == "" || strings.HasPrefix(t, "Defaults") || len(p.rules) >= maxSudoRules {
		return
	}
	p.rules = append(p.rules, clean(strings.Join(strings.Fields(t), " "), maxValueLen))
}

func directive(t, kw string) (string, bool) {
	for _, pre := range []string{"#" + kw, "@" + kw} {
		if rest, ok := strings.CutPrefix(t, pre); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			return strings.Trim(strings.TrimSpace(rest), `"`), true
		}
	}
	return "", false
}

func resolveInclude(p, from string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(filepath.Dir(from), p)
}

// stripSudoComment removes a '#' comment; "#<digits>" is a uid, not a comment.
func stripSudoComment(t string) string {
	for i := 0; i < len(t); i++ {
		if t[i] != '#' || (i > 0 && t[i-1] != ' ' && t[i-1] != '\t') {
			continue
		}
		if i+1 < len(t) && t[i+1] >= '0' && t[i+1] <= '9' {
			continue
		}
		return strings.TrimSpace(t[:i])
	}
	return t
}

// socketOwners maps the inodes of listening sockets (decimal, as in
// /proc/net/*) to their owning process in netstat style ("812/sshd") by
// matching /proc/net/* inodes with /proc/*/fd. The agent core merges this
// with its own unprivileged view by inode.
func socketOwners(proc string) (map[string]string, error) {
	inodes := map[string]string{} // inode -> key
	for _, t := range []struct{ file, proto, state string }{
		{"net/tcp", "tcp", "0A"}, {"net/tcp6", "tcp6", "0A"}, {"net/udp", "udp", "07"}, {"net/udp6", "udp6", "07"},
	} {
		data, err := readFileCapped(filepath.Join(proc, t.file), 64<<20)
		if err != nil {
			continue
		}
		eachLine(data, func(line string) {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != t.state || f[9] == "0" {
				return
			}
			if addr, ok := parseProcAddr(f[1]); ok {
				inodes[f[9]] = t.proto + ":" + addr
			}
		})
	}
	out := map[string]string{}
	if len(inodes) == 0 {
		return out, nil
	}
	pids, err := os.ReadDir(proc)
	if err != nil {
		return nil, fmt.Errorf("helper: %w", err)
	}
	for i, p := range pids {
		if i >= maxProcPIDs || len(out) == len(inodes) {
			break
		}
		pid := p.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(proc, pid, "fd"))
		if err != nil {
			continue
		}
		for j, fd := range fds {
			if j >= maxFDsPerProc {
				break
			}
			link, err := os.Readlink(filepath.Join(proc, pid, "fd", fd.Name()))
			if err != nil {
				continue
			}
			ino, ok := strings.CutPrefix(link, "socket:[")
			if !ok {
				continue
			}
			inode := strings.TrimSuffix(ino, "]")
			if _, ok := inodes[inode]; ok && out[inode] == "" {
				comm, _ := readFileCapped(filepath.Join(proc, pid, "comm"), 64)
				out[inode] = pid + "/" + clean(strings.TrimSpace(string(comm)), 32)
			}
		}
	}
	return out, nil
}

// parseProcAddr decodes "0100007F:0016" (IPv4) or a 32-hex-digit IPv6
// address; each 32-bit word is printed in host byte order by the kernel.
func parseProcAddr(s string) (string, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok || (len(h) != 8 && len(h) != 32) {
		return "", false
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), true
}

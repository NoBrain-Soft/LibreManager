package checks

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// --- NET-001 -----------------------------------------------------------------

const maxProcNetLines = 1 << 20

type socket struct {
	proto  string // "tcp" or "udp"
	ip     net.IP
	port   uint16
	kernel bool // inode 0: kernel socket (WireGuard, NFS, ...)
}

func (s socket) String() string {
	return s.proto + " " + net.JoinHostPort(s.ip.String(), strconv.Itoa(int(s.port)))
}

// parseProcNetAddr decodes "0100007F:0016" (IPv4) or a 32-hex-digit IPv6
// address; the kernel prints each 32-bit word in host byte order.
func parseProcNetAddr(s string) (net.IP, uint16, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok || (len(h) != 8 && len(h) != 32) || len(p) != 4 {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	return ip, uint16(port), true
}

// parseProcNetLine returns the local socket of a /proc/net/{tcp,udp}[6]
// line if it is in state.
func parseProcNetLine(line, proto, state string) (socket, bool) {
	f := strings.Fields(line)
	if len(f) < 10 || f[3] != state {
		return socket{}, false
	}
	ip, port, ok := parseProcNetAddr(f[1])
	if !ok {
		return socket{}, false
	}
	return socket{proto: proto, ip: ip, port: port, kernel: f[9] == "0"}, true
}

// readListeners returns listening TCP and unconnected UDP sockets.
func (r *runState) readListeners(ctx context.Context) ([]socket, error) {
	var out []socket
	read := 0
	for _, t := range []struct{ file, proto, state string }{
		{"net/tcp", "tcp", "0A"}, {"net/tcp6", "tcp", "0A"}, {"net/udp", "udp", "07"}, {"net/udp6", "udp", "07"},
	} {
		f, err := os.Open(r.procPath(t.file))
		if err != nil {
			continue // e.g. IPv6 disabled
		}
		read++
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 4096), 64<<10)
		for n := 0; sc.Scan() && n < maxProcNetLines; n++ {
			if n%4096 == 0 && ctx.Err() != nil {
				_ = f.Close()
				return nil, ctx.Err()
			}
			if s, ok := parseProcNetLine(sc.Text(), t.proto, t.state); ok {
				out = append(out, s)
			}
		}
		_ = f.Close()
	}
	if read == 0 {
		return nil, errors.New("no /proc/net socket tables readable")
	}
	return out, nil
}

type portRange struct {
	proto  string
	lo, hi uint16
}

// parseAllowEntry parses "tcp:22", "udp:53", "tcp:8000-8100" or "tcp:*".
func parseAllowEntry(s string) (portRange, bool) {
	proto, ports, ok := strings.Cut(strings.ToLower(strings.TrimSpace(s)), ":")
	proto = strings.TrimSuffix(proto, "6")
	if !ok || (proto != "tcp" && proto != "udp") {
		return portRange{}, false
	}
	if ports == "*" {
		return portRange{proto, 0, 65535}, true
	}
	lo, hi, isRange := strings.Cut(ports, "-")
	if !isRange {
		hi = lo
	}
	l, err1 := strconv.ParseUint(lo, 10, 16)
	h, err2 := strconv.ParseUint(hi, 10, 16)
	if err1 != nil || err2 != nil || l > h {
		return portRange{}, false
	}
	return portRange{proto, uint16(l), uint16(h)}, true
}

// builtinClientPorts are client sockets that look like listeners: DHCPv4
// and DHCPv6 clients.
var builtinClientPorts = []portRange{{"udp", 68, 68}, {"udp", 546, 546}}

func (r *runState) ephemeralRange() (uint16, uint16) {
	v, err := readTrim(r.procPath("sys/net/ipv4/ip_local_port_range"))
	if err == nil {
		if n, err := parseSysctlInts(v); err == nil && len(n) == 2 && n[0] > 0 && n[0] <= n[1] && n[1] <= 65535 {
			return uint16(n[0]), uint16(n[1]) //nolint:gosec // bounds checked above
		}
	}
	return 32768, 60999
}

func checkListeners(ctx context.Context, r *runState) result {
	socks, err := r.readListeners(ctx)
	if err != nil {
		return errResult("cannot read listening sockets", err)
	}
	allow := slices.Clone(builtinClientPorts)
	var invalid []string
	for _, e := range r.env.ListenAllowlist {
		if pr, ok := parseAllowEntry(e); ok {
			allow = append(allow, pr)
		} else {
			invalid = append(invalid, e)
		}
	}
	ephLo, ephHi := r.ephemeralRange()
	seen := map[string]bool{}
	var unexpected []string
	exposed := 0
	for _, s := range socks {
		if s.ip.IsLoopback() {
			continue
		}
		// Userspace UDP sockets in the ephemeral range are client sockets
		// (resolvers, NTP clients); kernel UDP sockets there (WireGuard) are not.
		if s.proto == "udp" && !s.kernel && s.port >= ephLo && s.port <= ephHi {
			continue
		}
		key := s.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		exposed++
		if !slices.ContainsFunc(allow, func(p portRange) bool { return p.proto == s.proto && s.port >= p.lo && s.port <= p.hi }) {
			unexpected = append(unexpected, key)
		}
	}
	slices.Sort(unexpected)
	kvs := []string{"non_loopback_listeners", fmt.Sprint(exposed), "allowlist", joinCapped(r.env.ListenAllowlist)}
	if len(invalid) > 0 {
		kvs = append(kvs, "invalid_allowlist_entries", joinCapped(invalid))
	}
	if len(unexpected) > 0 {
		kvs = append(kvs, "unexpected", joinCapped(unexpected))
		return warn(plural(len(unexpected), "listener is", "listeners are")+" not on the allow-list", kvs...)
	}
	return pass("all non-loopback listeners are on the allow-list", kvs...)
}

// --- NET-002 -----------------------------------------------------------------

var (
	dropRule        = regexp.MustCompile(`\b(drop|reject)\b`)
	nftChainStart   = regexp.MustCompile(`^\s*chain\s+\S+\s*\{`)
	nftInputHook    = regexp.MustCompile(`\bhook\s+input\b`)
	iptInputDefault = regexp.MustCompile(`(?m)^:INPUT\s+(DROP|REJECT)\b`)
	iptInputRule    = regexp.MustCompile(`(?m)^-A\s+INPUT\b.*-j\s+(DROP|REJECT)\b`)
	ufwEnabled      = regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*"?yes"?\s*$`)
	nftInclude      = regexp.MustCompile(`(?m)^\s*include\s+"([^"]+)"`)
)

// stripHashComments removes "# ..." comments (nftables syntax).
func stripHashComments(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// nftFilters reports whether an nftables ruleset (`nft list ruleset` or
// nftables.conf syntax) has an input-hook chain that drops or rejects
// traffic. Rulesets without recognizable chains fall back to any
// drop/reject statement.
func nftFilters(ruleset string) bool {
	ruleset = strings.ToLower(stripHashComments(ruleset))
	lines := strings.Split(ruleset, "\n")
	chains := 0
	for i := 0; i < len(lines); i++ {
		if !nftChainStart.MatchString(lines[i]) {
			continue
		}
		chains++
		depth, body := 0, strings.Builder{}
		j := i
		for ; j < len(lines); j++ {
			depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
			body.WriteString(lines[j])
			body.WriteByte('\n')
			if depth <= 0 {
				break
			}
		}
		if b := body.String(); nftInputHook.MatchString(b) && dropRule.MatchString(b) {
			return true
		}
		i = j // unbalanced braces: j == len(lines) ends the scan
	}
	return chains == 0 && dropRule.MatchString(ruleset)
}

// iptablesFilters reports whether iptables-save output filters INPUT.
func iptablesFilters(rules string) bool {
	return iptInputDefault.MatchString(rules) || iptInputRule.MatchString(rules)
}

// systemctlActive returns the is-active state of each unit.
func (r *runState) systemctlActive(ctx context.Context, units ...string) (map[string]string, error) {
	out, code, err := r.env.Exec.Run(ctx, "systemctl", append([]string{"is-active", "--"}, units...)...)
	if err != nil {
		return nil, err
	}
	lines := nonEmptyLines(out)
	if len(lines) != len(units) {
		return nil, fmt.Errorf("systemctl is-active: unexpected output (exit %d)", code)
	}
	m := make(map[string]string, len(units))
	for i, u := range units {
		m[u] = lines[i]
	}
	return m, nil
}

// systemdBooted mirrors sd_booted(3).
func (r *runState) systemdBooted() bool { return isDir(r.rootPath("/run/systemd/system")) }

func (r *runState) fileMatches(paths []string, fn func(string) bool) (string, bool) {
	for _, p := range paths {
		if data, err := readCapped(r.rootPath(p), maxConfigFile); err == nil {
			return p, fn(string(data))
		}
	}
	return "", false
}

const maxNftFiles = 16

// nftConfig returns an nftables configuration file with its include
// statements (globs allowed) expanded, two levels deep and at most
// maxNftFiles files.
func (r *runState) nftConfig(p string) (string, bool) {
	var b strings.Builder
	files := 0
	root := filepath.Clean(r.env.Root)
	var load func(p string, depth int) bool
	load = func(p string, depth int) bool {
		data, err := readCapped(r.rootPath(p), maxConfigFile)
		if err != nil {
			return false
		}
		files++
		s := stripHashComments(string(data))
		b.WriteString(s)
		b.WriteByte('\n')
		if depth >= 2 {
			return true
		}
		for _, m := range nftInclude.FindAllStringSubmatch(s, maxNftFiles) {
			pat := m[1]
			if !filepath.IsAbs(pat) {
				pat = filepath.Join(filepath.Dir(p), pat)
			}
			matches, _ := filepath.Glob(r.rootPath(pat))
			for _, mm := range matches {
				if files >= maxNftFiles {
					return true
				}
				host := mm
				if root != "/" {
					host = strings.TrimPrefix(mm, root)
				}
				load(host, depth+1)
			}
		}
		return true
	}
	ok := load(p, 0)
	return b.String(), ok
}

func checkFirewall(ctx context.Context, r *runState) result {
	// Only works with CAP_NET_ADMIN (e.g. a development agent running as
	// root); unprivileged agents fall through to service state.
	if out, code, err := r.env.Exec.Run(ctx, "nft", "list", "ruleset"); err == nil && code == 0 && len(out) > 0 {
		if nftFilters(string(out)) {
			return pass("nftables ruleset filters inbound traffic", "source", "nft list ruleset")
		}
	}
	units := []string{"firewalld.service", "ufw.service", "nftables.service", "iptables.service", "netfilter-persistent.service"}
	if !r.systemdBooted() {
		return na("firewall state cannot be determined without systemd or CAP_NET_ADMIN")
	}
	st, err := r.systemctlActive(ctx, units...)
	if err != nil {
		return errResult("cannot query firewall services", err)
	}
	kvs := []string{}
	for _, u := range units {
		kvs = append(kvs, u, st[u])
	}
	var weak []string
	if st["firewalld.service"] == "active" {
		return pass("firewalld is active", kvs...)
	}
	if st["ufw.service"] == "active" {
		if p, ok := r.fileMatches([]string{"/etc/ufw/ufw.conf"}, ufwEnabled.MatchString); ok {
			return pass("ufw is enabled", append(kvs, "config", p)...)
		}
		weak = append(weak, "ufw.service is active but ufw is not enabled (ENABLED=no)")
	}
	if st["nftables.service"] == "active" {
		for _, p := range []string{"/etc/nftables.conf", "/etc/sysconfig/nftables.conf"} {
			if conf, ok := r.nftConfig(p); ok && nftFilters(conf) {
				return pass("nftables is active with an input filter", append(kvs, "config", p)...)
			}
		}
		weak = append(weak, "nftables.service is active but its configuration has no input drop/reject rule")
	}
	if st["iptables.service"] == "active" || st["netfilter-persistent.service"] == "active" {
		if p, ok := r.fileMatches([]string{"/etc/sysconfig/iptables", "/etc/iptables/rules.v4"}, iptablesFilters); ok {
			return pass("iptables rules filter inbound traffic", append(kvs, "config", p)...)
		}
		weak = append(weak, "iptables service is active but its saved rules do not filter INPUT")
	}
	if len(weak) > 0 {
		return warn(strings.Join(weak, "; "), kvs...)
	}
	return fail("no host firewall is active", kvs...)
}

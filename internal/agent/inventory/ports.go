package inventory

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

const (
	tcpListen = 0x0A
	udpClose  = 0x07
)

// socketEntry is one listening socket from /proc/net.
type socketEntry struct {
	proto string
	addr  netip.Addr
	port  uint16
	inode string
}

// Ports returns the ListeningPorts section: TCP sockets in LISTEN and bound,
// unconnected UDP sockets. Owners are found by scanning /proc/<pid>/fd for
// processes the agent may inspect, merged with PrivilegedReader.SocketOwners.
func (c *Collector) Ports(ctx context.Context) (*agentv1.InventorySection, error) {
	var socks []socketEntry
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := osutil.ReadFileLimit(c.proc("net", proto), 64<<20)
		if err != nil {
			continue
		}
		socks = append(socks, parseListeningSockets(data, proto)...)
	}
	owners := c.socketOwnersFromProc(ctx, socks)
	if c.Privileged != nil {
		if priv, err := c.Privileged.SocketOwners(ctx); err == nil {
			for inode, owner := range priv {
				if _, ok := owners[inode]; !ok {
					owners[inode] = parseOwner(owner)
				}
			}
		} else {
			c.log().Debug("privileged socket owners unavailable", "error", err)
		}
	}
	seen := make(map[string]bool)
	var ports []*agentv1.ListeningPort
	for _, s := range socks {
		key := s.proto + "|" + s.addr.String() + "|" + strconv.Itoa(int(s.port))
		if seen[key] {
			continue
		}
		seen[key] = true
		p := &agentv1.ListeningPort{Protocol: s.proto, Address: s.addr.String(), Port: uint32(s.port)}
		if o, ok := owners[s.inode]; ok {
			p.Process, p.Pid = o.name, o.pid
		}
		ports = append(ports, p)
		if len(ports) >= maxPorts {
			break
		}
	}
	slices.SortFunc(ports, func(a, b *agentv1.ListeningPort) int {
		return cmp.Or(strings.Compare(a.GetProtocol(), b.GetProtocol()), cmp.Compare(a.GetPort(), b.GetPort()), strings.Compare(a.GetAddress(), b.GetAddress()))
	})
	list := &agentv1.ListeningPorts{}
	list.Ports, _ = capBySize(ports, budgetPorts)
	return newSection(list)
}

// parseListeningSockets parses a /proc/net/{tcp,udp}[6] table.
func parseListeningSockets(data []byte, proto string) []socketEntry {
	var out []socketEntry
	udp := strings.HasPrefix(proto, "udp")
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		st, err := strconv.ParseUint(f[3], 16, 8)
		if err != nil {
			continue
		}
		local, lport, ok1 := parseSockAddr(f[1])
		_, rport, ok2 := parseSockAddr(f[2])
		if !ok1 || !ok2 {
			continue
		}
		switch {
		case !udp && st == tcpListen:
		case udp && st == udpClose && rport == 0 && lport != 0 && remoteZero(f[2]):
		default:
			continue
		}
		out = append(out, socketEntry{proto: proto, addr: local, port: lport, inode: f[9]})
	}
	return out
}

func remoteZero(s string) bool { return strings.Trim(s, "0:") == "" }

// parseSockAddr decodes "0100007F:0016" (IPv4) or a 32-hex-digit IPv6
// address; each 32-bit word is in host (little-endian) byte order.
func parseSockAddr(s string) (netip.Addr, uint16, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	b, err := hex.DecodeString(a)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	switch len(b) {
	case 4:
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], binary.LittleEndian.Uint32(b))
		return netip.AddrFrom4(v), uint16(port), true
	case 16:
		var v [16]byte
		for i := 0; i < 16; i += 4 {
			binary.BigEndian.PutUint32(v[i:], binary.LittleEndian.Uint32(b[i:]))
		}
		return netip.AddrFrom16(v).Unmap(), uint16(port), true
	}
	return netip.Addr{}, 0, false
}

type sockOwner struct {
	name string
	pid  int32
}

// parseOwner parses netstat-style "PID/name" or a bare name.
func parseOwner(s string) sockOwner {
	if pid, name, ok := strings.Cut(s, "/"); ok {
		if n, err := strconv.ParseInt(pid, 10, 32); err == nil && n > 0 {
			return sockOwner{name: osutil.Clean(name, maxShort), pid: int32(n)}
		}
	}
	return sockOwner{name: osutil.Clean(s, maxShort)}
}

// socketOwnersFromProc maps socket inodes to processes by reading the fd
// symlinks of every process the agent may inspect (its own, without
// privileges). Bounded in processes and fds per process.
func (c *Collector) socketOwnersFromProc(ctx context.Context, socks []socketEntry) map[string]sockOwner {
	owners := make(map[string]sockOwner)
	if len(socks) == 0 {
		return owners
	}
	want := make(map[string]bool, len(socks))
	for _, s := range socks {
		want[s.inode] = true
	}
	procDir := c.proc()
	d, err := os.Open(procDir)
	if err != nil {
		return owners
	}
	defer func() { _ = d.Close() }()
	names, _ := d.Readdirnames(-1)
	scanned := 0
	for _, name := range names {
		if ctx.Err() != nil || scanned >= maxFDScanPIDs || len(owners) == len(want) {
			break
		}
		pid, err := strconv.ParseInt(name, 10, 32)
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procDir, name, "fd")
		f, err := os.Open(fdDir)
		if err != nil {
			continue // not ours: EACCES
		}
		scanned++
		fds, _ := f.Readdirnames(maxFDsPerPID)
		_ = f.Close()
		var comm string
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd))
			if err != nil {
				continue
			}
			inode, ok := strings.CutPrefix(target, "socket:[")
			if !ok {
				continue
			}
			inode = strings.TrimSuffix(inode, "]")
			if !want[inode] {
				continue
			}
			if _, done := owners[inode]; done {
				continue
			}
			if comm == "" {
				comm, _ = osutil.ReadString(filepath.Join(procDir, name, "comm"), 64)
			}
			owners[inode] = sockOwner{name: osutil.Clean(comm, maxShort), pid: int32(pid)}
		}
	}
	return owners
}

package inventory

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

const (
	iffUp      = 0x1
	rtfUp      = 0x0001
	rtfGateway = 0x0002
	rtfReject  = 0x0200
)

// Network returns the NetworkInfo section.
func (c *Collector) Network(_ context.Context) (*agentv1.InventorySection, error) {
	info := &agentv1.NetworkInfo{}
	info.Interfaces, _ = capBySize(c.interfaces(), budgetInterfaces)
	routes := append(c.routesV4(), c.routesV6()...)
	if len(routes) > maxRoutes {
		routes = routes[:maxRoutes]
	}
	info.Routes, _ = capBySize(routes, budgetRoutes)
	info.DnsServers, info.DnsSearch = c.dns()
	return newSection(info)
}

func (c *Collector) interfaces() []*agentv1.NetInterface {
	dir := c.sys("class", "net")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	addrs := map[string][]string{}
	addrFn := c.InterfaceAddrs
	if addrFn == nil {
		addrFn = systemInterfaceAddrs
	}
	if a, err := addrFn(); err == nil {
		addrs = a
	}
	var out []*agentv1.NetInterface
	for _, e := range entries {
		if len(out) >= maxInterfaces {
			break
		}
		name := e.Name()
		d := filepath.Join(dir, name)
		ifc := &agentv1.NetInterface{Name: osutil.Clean(name, maxShort)}
		if mac, err := osutil.ReadString(filepath.Join(d, "address"), 128); err == nil {
			ifc.Mac = osutil.Clean(mac, maxShort)
		}
		if mtu, err := osutil.ReadUint(filepath.Join(d, "mtu")); err == nil {
			ifc.Mtu = uint32(min(mtu, 1<<31)) //nolint:gosec // bounded
		}
		oper, _ := osutil.ReadString(filepath.Join(d, "operstate"), 64)
		flagStr, _ := osutil.ReadString(filepath.Join(d, "flags"), 64)
		flags, _ := strconv.ParseUint(strings.TrimPrefix(flagStr, "0x"), 16, 64)
		ifc.Up = oper == "up" || (oper == "unknown" && flags&iffUp != 0)
		ifc.Addresses = cleanList(addrs[name], maxAddrs, maxShort)
		out = append(out, ifc)
	}
	return out
}

// systemInterfaceAddrs uses net.Interfaces (netlink) for addresses, since
// IPv4 addresses are not available from /proc or /sys.
func systemInterfaceAddrs() (map[string][]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err //nolint:wrapcheck // best effort
	}
	out := make(map[string][]string, len(ifs))
	for _, ifc := range ifs {
		as, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			out[ifc.Name] = append(out[ifc.Name], a.String())
		}
	}
	return out, nil
}

// routesV4 parses /proc/net/route (little-endian hex addresses).
func (c *Collector) routesV4() []*agentv1.Route {
	data, err := osutil.ReadFileLimit(c.proc("net", "route"), 4<<20)
	if err != nil {
		return nil
	}
	return parseRoutesV4(data)
}

func parseRoutesV4(data []byte) []*agentv1.Route {
	var out []*agentv1.Route
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 32)
		dst, ok1 := hexIPv4(f[1])
		gw, ok2 := hexIPv4(f[2])
		mask, ok3 := hexIPv4(f[7])
		metric, err2 := strconv.ParseUint(f[6], 10, 32)
		if err1 != nil || err2 != nil || !ok1 || !ok2 || !ok3 || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		ones, _ := net.IPMask(mask.AsSlice()).Size()
		r := &agentv1.Route{
			Destination: netip.PrefixFrom(dst, ones).String(),
			Interface:   osutil.Clean(f[0], maxShort),
			Metric:      uint32(metric),
		}
		if flags&rtfGateway != 0 {
			r.Gateway = gw.String()
		}
		out = append(out, r)
		if len(out) >= maxRoutes {
			break
		}
	}
	return out
}

func hexIPv4(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, false
	}
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(b))
	return netip.AddrFrom4(a), true
}

// routesV6 parses /proc/net/ipv6_route, skipping local, multicast and
// loopback routes (the kernel also lists the local table here).
func (c *Collector) routesV6() []*agentv1.Route {
	data, err := osutil.ReadFileLimit(c.proc("net", "ipv6_route"), 4<<20)
	if err != nil {
		return nil
	}
	return parseRoutesV6(data)
}

func parseRoutesV6(data []byte) []*agentv1.Route {
	var out []*agentv1.Route
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		// dst dst_len src src_len next_hop metric refcnt use flags iface
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[9] == "lo" {
			continue
		}
		dst, ok1 := hexIPv6(f[0])
		plen, err1 := strconv.ParseUint(f[1], 16, 8)
		nh, ok2 := hexIPv6(f[4])
		metric, err2 := strconv.ParseUint(f[5], 16, 32)
		flags, err3 := strconv.ParseUint(f[8], 16, 32)
		if !ok1 || !ok2 || err1 != nil || err2 != nil || err3 != nil || plen > 128 || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		if dst.IsMulticast() {
			continue
		}
		r := &agentv1.Route{
			Destination: netip.PrefixFrom(dst, int(plen)).String(),
			Interface:   osutil.Clean(f[9], maxShort),
			Metric:      uint32(metric),
		}
		if !nh.IsUnspecified() {
			r.Gateway = nh.String()
		}
		out = append(out, r)
		if len(out) >= maxRoutes {
			break
		}
	}
	return out
}

func hexIPv6(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16([16]byte(b)), true
}

// dns parses resolv.conf. When systemd-resolved's stub (127.0.0.53) is the
// only server, the upstream servers are taken from resolved's own file.
func (c *Collector) dns() (servers, search []string) {
	servers, search = parseResolvConf(c.path("etc", "resolv.conf"))
	if len(servers) == 1 && (servers[0] == "127.0.0.53" || servers[0] == "127.0.0.54") {
		if up, upSearch := parseResolvConf(c.path("run", "systemd", "resolve", "resolv.conf")); len(up) > 0 {
			servers = up
			if len(search) == 0 {
				search = upSearch
			}
		}
	}
	return servers, search
}

func parseResolvConf(path string) (servers, search []string) {
	data, err := osutil.ReadFileLimit(path, maxSmallFile)
	if err != nil {
		return nil, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if a, err := netip.ParseAddr(f[1]); err == nil && len(servers) < maxDNS {
				servers = append(servers, a.String())
			}
		case "search", "domain":
			// The last search/domain directive wins (resolv.conf(5)).
			search = cleanList(f[1:], maxDNS, maxName)
		}
	}
	return servers, dedupe(search)
}

// dedupe removes duplicates, keeping the first occurrence (search order
// matters).
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

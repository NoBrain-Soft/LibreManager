package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
)

// maxNetDevices bounds the number of reported interfaces.
const maxNetDevices = 64

// netdevCollector reads /proc/net/dev. Label: device. Skips lo and veth*
// (per-container veth pairs churn and are covered by the bridge counters).
//
//	stellwerk_network_{receive,transmit}_{bytes,packets,errs,drop}_total  counter
type netdevCollector struct{ procRoot string }

func newNetdevCollector(o Options) *netdevCollector { return &netdevCollector{o.ProcRoot} }

func (c *netdevCollector) Name() string { return "netdev" }

// netdevColumns maps /proc/net/dev value columns to metric names.
var netdevColumns = []struct {
	idx  int
	name string
}{
	{0, "stellwerk_network_receive_bytes_total"},
	{1, "stellwerk_network_receive_packets_total"},
	{2, "stellwerk_network_receive_errs_total"},
	{3, "stellwerk_network_receive_drop_total"},
	{8, "stellwerk_network_transmit_bytes_total"},
	{9, "stellwerk_network_transmit_packets_total"},
	{10, "stellwerk_network_transmit_errs_total"},
	{11, "stellwerk_network_transmit_drop_total"},
}

func (c *netdevCollector) Collect(_ context.Context, emit func(Sample)) error {
	data, err := readProc(c.procRoot, "net", "dev")
	if err != nil {
		return fmt.Errorf("read /proc/net/dev: %w", err)
	}
	n := 0
	var f [][]byte
	eachLine(data, func(line []byte) {
		name, rest, ok := bytes.Cut(line, []byte(":"))
		if !ok || n >= maxNetDevices {
			return
		}
		dev := string(bytes.TrimSpace(name))
		if dev == "" || dev == "lo" || strings.HasPrefix(dev, "veth") {
			return
		}
		f = fieldsN(f, rest)
		if len(f) < 16 {
			return
		}
		n++
		dev = osutil.Clean(dev, 64)
		for _, col := range netdevColumns {
			if v, ok := parseUint(f[col.idx]); ok {
				emit(sample(col.name, float64(v), "device", dev))
			}
		}
	})
	return nil
}

// tcpStates are the kernel TCP states (include/net/tcp_states.h) indexed by
// their numeric value.
var tcpStates = [...]string{
	1: "established", 2: "syn_sent", 3: "syn_recv", 4: "fin_wait1", 5: "fin_wait2",
	6: "time_wait", 7: "close", 8: "close_wait", 9: "last_ack", 10: "listen",
	11: "closing", 12: "new_syn_recv",
}

const (
	tcpListen  = 10
	udpUnconn  = 7 // TCP_CLOSE: unconnected UDP socket
	maxSockets = 2_000_000
)

// socketCollector counts sockets from /proc/net/{tcp,tcp6,udp,udp6}.
//
//	stellwerk_tcp_connections{state}  gauge (every state, zeros included)
//	stellwerk_listening_sockets       gauge (TCP LISTEN + bound unconnected UDP)
//
// The files are streamed and only the state column is parsed, so even hosts
// with 100k sockets stay cheap. (A sock_diag netlink implementation would be
// cheaper still; see the package report.)
type socketCollector struct{ procRoot string }

func newSocketCollector(o Options) *socketCollector { return &socketCollector{o.ProcRoot} }

func (c *socketCollector) Name() string { return "sockets" }

func (c *socketCollector) Collect(_ context.Context, emit func(Sample)) error {
	var counts [len(tcpStates)]int
	listening := 0
	found := false
	for _, file := range []string{"tcp", "tcp6"} {
		err := c.scan(file, func(state int, _ []byte) {
			if state > 0 && state < len(counts) {
				counts[state]++
			}
			if state == tcpListen {
				listening++
			}
		})
		if err == nil {
			found = true
		} else if !isNotExist(err) {
			return err
		}
	}
	for _, file := range []string{"udp", "udp6"} {
		err := c.scan(file, func(state int, remote []byte) {
			if state == udpUnconn && isZeroAddr(remote) {
				listening++
			}
		})
		if err != nil && !isNotExist(err) {
			return err
		}
	}
	if !found {
		return nil
	}
	for st := 1; st < len(tcpStates); st++ {
		emit(sample("stellwerk_tcp_connections", float64(counts[st]), "state", tcpStates[st]))
	}
	emit(sample("stellwerk_listening_sockets", float64(listening)))
	return nil
}

// scan streams one /proc/net socket table and calls fn with each entry's
// state and remote address column.
func (c *socketCollector) scan(file string, fn func(state int, remote []byte)) error {
	f, err := osutil.OpenRegular(filepath.Join(c.procRoot, "net", file))
	if err != nil {
		return fmt.Errorf("open /proc/net/%s: %w", file, err)
	}
	defer func() { _ = f.Close() }()
	return scanSocketTable(f, fn)
}

func scanSocketTable(r io.Reader, fn func(state int, remote []byte)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	header := true
	var fields [][]byte
	for n := 0; n < maxSockets; n++ {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 && !header {
			//   sl  local_address rem_address   st ...
			fields = fieldsN(fields, bytes.TrimRight(line[:min(len(line), 128)], "\r\n"))
			if len(fields) >= 4 {
				if st, ok := parseHexByte(fields[3]); ok {
					fn(st, fields[2])
				}
			}
		}
		header = false
		if err != nil {
			if err == io.EOF || err == bufio.ErrBufferFull {
				return nil
			}
			return fmt.Errorf("read socket table: %w", err)
		}
	}
	return nil
}

func parseHexByte(b []byte) (int, bool) {
	if len(b) == 0 || len(b) > 2 {
		return 0, false
	}
	v := 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + int(c-'0')
		case c >= 'A' && c <= 'F':
			v = v*16 + int(c-'A'+10)
		case c >= 'a' && c <= 'f':
			v = v*16 + int(c-'a'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// isZeroAddr reports whether a /proc/net "ADDR:PORT" column is all zeros.
func isZeroAddr(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c != '0' && c != ':' {
			return false
		}
	}
	return true
}

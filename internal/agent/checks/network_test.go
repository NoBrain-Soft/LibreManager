package checks

import (
	"errors"
	"strings"
	"testing"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func TestListeners(t *testing.T) {
	tests := []struct {
		name  string
		proc  string
		allow []string
		want  agentv1.CheckStatus
		ev    map[string]string
	}{
		{"hardened default allow-list", "proc/hardened", nil, PASS, map[string]string{"non_loopback_listeners": "3", "allowlist": "tcp:22"}},
		{"weak default allow-list", "proc/weak", nil, WARN, map[string]string{
			"unexpected": "tcp 0.0.0.0:3306, tcp [::]:80, udp 0.0.0.0:51820, udp 0.0.0.0:53",
		}},
		{"weak with allow-list", "proc/weak", []string{"tcp:22", "tcp:3306", "tcp6:80", "udp:53", "udp:51000-52000"}, PASS, nil},
		{"invalid entries reported", "proc/weak", []string{"tcp:22", "tcp:3306", "tcp:80", "udp:53", "udp:51820", "icmp:1", "tcp:99999", "tcp:9-1", "garbage"}, PASS,
			map[string]string{"invalid_allowlist_entries": "icmp:1, tcp:99999, tcp:9-1, garbage"}},
		{"wildcard", "proc/weak", []string{"tcp:*", "udp:*"}, PASS, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: t.TempDir(), ProcRoot: td(t, tc.proc), ListenAllowlist: tc.allow}, "NET-001")
			expectStatus(t, r, tc.want)
			for k, v := range tc.ev {
				expectEvidence(t, r, k, v)
			}
		})
	}
	// Loopback, established connections, ephemeral client UDP sockets and
	// DHCP clients are never reported.
	r := runCheck(t, Env{ProcRoot: td(t, "proc/weak")}, "NET-001")
	for _, bad := range []string{"5432", "631", "45000", ":68", "323", "10.0.0.5"} {
		if strings.Contains(r.GetEvidence()["unexpected"], bad) {
			t.Errorf("%s reported: %q", bad, r.GetEvidence()["unexpected"])
		}
	}
	expectStatus(t, runCheck(t, Env{ProcRoot: t.TempDir()}, "NET-001"), ERROR)
}

func TestParseProcNet(t *testing.T) {
	for _, tc := range []struct {
		in   string
		addr string
		ok   bool
	}{
		{"0100007F:0016", "127.0.0.1:22", true},
		{"00000000:0050", "0.0.0.0:80", true},
		{"0500000A:01BB", "10.0.0.5:443", true},
		{"00000000000000000000000000000000:0016", "[::]:22", true},
		{"00000000000000000000000001000000:0019", "[::1]:25", true},
		{"0000000000000000FFFF00000100007F:1F90", "127.0.0.1:8080", true}, // IPv4-mapped
		{"0100007F", "", false},
		{"0100007F:16", "", false},
		{"0100007G:0016", "", false},
		{"01007F:0016", "", false},
		{"0100007F:ZZZZ", "", false},
	} {
		ip, port, ok := parseProcNetAddr(tc.in)
		if ok != tc.ok {
			t.Errorf("%q: ok=%v", tc.in, ok)
			continue
		}
		if ok {
			if got := (socket{ip: ip, port: port}).String(); got != " "+tc.addr {
				t.Errorf("%q: %q, want %q", tc.in, got, tc.addr)
			}
		}
	}
	if _, ok := parseProcNetLine("  sl  local_address rem_address   st", "tcp", "0A"); ok {
		t.Error("header parsed")
	}
	s, ok := parseProcNetLine("   3: 00000000:CA6C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 0 2 0000000000000000 0", "udp", "07")
	if !ok || !s.kernel || s.port != 51820 {
		t.Errorf("kernel socket: %+v %v", s, ok)
	}
}

func TestParseAllowEntry(t *testing.T) {
	for in, want := range map[string]*portRange{
		"tcp:22":        {"tcp", 22, 22},
		" TCP6:443 ":    {"tcp", 443, 443},
		"udp:1000-2000": {"udp", 1000, 2000},
		"udp:*":         {"udp", 0, 65535},
		"tcp:":          nil,
		"tcp:-1":        nil,
		"tcp:2-1":       nil,
		"sctp:22":       nil,
		"22":            nil,
		"tcp:65536":     nil,
	} {
		got, ok := parseAllowEntry(in)
		if (want == nil) == ok || (ok && got != *want) {
			t.Errorf("%q: %+v %v", in, got, ok)
		}
	}
}

const fwUnits = "systemctl is-active -- firewalld.service ufw.service nftables.service iptables.service netfilter-persistent.service"

func fwStates(firewalld, ufw, nft, ipt, persistent string) map[string]cmdResp {
	return map[string]cmdResp{fwUnits: {out: strings.Join([]string{firewalld, ufw, nft, ipt, persistent}, "\n") + "\n", code: 3}}
}

func TestFirewall(t *testing.T) {
	debian, rhel := td(t, "root/debian"), td(t, "root/rhel")
	tests := []struct {
		name  string
		root  string
		files map[string]string
		exec  map[string]cmdResp
		want  agentv1.CheckStatus
	}{
		{"firewalld", rhel, nil, fwStates("active", "inactive", "inactive", "inactive", "inactive"), PASS},
		{"ufw enabled", debian, nil, fwStates("inactive", "active", "inactive", "inactive", "inactive"), PASS},
		{"ufw disabled", debian, map[string]string{"etc/ufw/ufw.conf": "ENABLED=no\n"}, fwStates("inactive", "active", "inactive", "inactive", "inactive"), WARN},
		{"nftables drop policy", debian, nil, fwStates("inactive", "inactive", "active", "inactive", "inactive"), PASS},
		{"nftables via include", rhel, nil, fwStates("inactive", "inactive", "active", "inactive", "inactive"), PASS},
		{"nftables accept-all default", debian, map[string]string{"etc/nftables.conf": "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter;\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n"},
			fwStates("inactive", "inactive", "active", "inactive", "inactive"), WARN},
		{"iptables saved rules", debian, map[string]string{"etc/iptables/rules.v4": "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"},
			fwStates("inactive", "inactive", "inactive", "inactive", "active"), PASS},
		{"iptables accept", debian, map[string]string{"etc/iptables/rules.v4": "*filter\n:INPUT ACCEPT [0:0]\n-A FORWARD -j DROP\nCOMMIT\n"},
			fwStates("inactive", "inactive", "inactive", "inactive", "active"), WARN},
		{"nothing active", debian, nil, fwStates("inactive", "inactive", "inactive", "inactive", "inactive"), FAIL},
		{"nft ruleset readable", t.TempDir(), nil, map[string]cmdResp{"nft list ruleset": {out: "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"}}, PASS},
		{"systemctl fails", debian, nil, map[string]cmdResp{fwUnits: {err: errors.New("dbus: connection refused")}}, ERROR},
		{"systemctl garbage", debian, nil, map[string]cmdResp{fwUnits: {out: "active\n", code: 0}}, ERROR},
		{"no systemd", t.TempDir(), nil, nil, NA},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.root
			if tc.files != nil {
				root = copyTree(t, tc.root)
				addFiles(t, root, tc.files)
			}
			expectStatus(t, runCheck(t, Env{Root: root, Exec: newExec(tc.exec)}, "NET-002"), tc.want)
		})
	}
}

func TestNftFilters(t *testing.T) {
	for _, tc := range []struct {
		name, rules string
		want        bool
	}{
		{"input policy drop", "table inet f {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}", true},
		{"input reject rule", "table ip f {\n chain in {\n  type filter hook input priority 0;\n  tcp dport 23 reject\n }\n}", true},
		{"docker forward only", "table ip filter {\n chain DOCKER-USER {\n  drop\n }\n chain FORWARD {\n  type filter hook forward priority filter; policy drop;\n }\n}", false},
		{"commented drop", "table inet f {\n chain input {\n  type filter hook input priority 0; # policy drop;\n }\n}", false},
		{"one-line chain", "table inet f { chain input { type filter hook input priority 0; policy drop; } }", true},
		{"no chains", "add rule inet filter input drop", true},
		{"empty", "", false},
		{"unbalanced", "chain input {\n type filter hook input priority 0;\nchain x {\n", false},
		{"dropped word inside name", "table inet f {\n chain input {\n  type filter hook input priority 0;\n  counter name dropped_pkts\n }\n}", false},
	} {
		if got := nftFilters(tc.rules); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if !iptablesFilters("-A INPUT -s 10.0.0.0/8 -j REJECT --reject-with icmp-host-prohibited\n") || iptablesFilters("-A OUTPUT -j DROP\n") {
		t.Error("iptablesFilters")
	}
}

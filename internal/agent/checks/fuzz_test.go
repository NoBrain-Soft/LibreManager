package checks

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func validStatus(r result) bool {
	switch r.status {
	case PASS, FAIL, WARN, NA, ERROR:
		return true
	}
	return false
}

// FuzzSSHDConfig feeds arbitrary `sshd -T` output through the parser and
// every SSH evaluator.
func FuzzSSHDConfig(f *testing.F) {
	for _, name := range []string{"hardened.txt", "weak.txt", "legacy.txt"} {
		data, err := os.ReadFile("testdata/sshd/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte("logingracetime 1w2d3h4m5s\nmaxauthtries 99999999999999999999\nciphers ,,,\n"))
	f.Add([]byte("PERMITROOTLOGIN\tYES\r\n\x00\xff"))
	evals := []func(map[string]string) result{
		evalPermitRootLogin, evalMaxAuthTries, evalLoginGraceTime,
		sshNo("a", "passwordauthentication"), sshNo("b", "kbdinteractiveauthentication", "challengeresponseauthentication"),
		sshNo("c", "x11forwarding"), sshNo("d", "permitemptypasswords"),
		sshAlgorithms("ciphers", "cipher", weakCipher), sshAlgorithms("macs", "MAC", weakMAC),
		sshAlgorithms("kexalgorithms", "kex", weakKex),
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := ParseSSHDConfig(data)
		if len(cfg) > 512 {
			t.Fatalf("%d keys", len(cfg))
		}
		for k, v := range cfg {
			if k != strings.ToLower(k) || len(k) > 64 || len(v) > maxSSHDValue || strings.ContainsAny(v, "\n") {
				t.Fatalf("bad entry %q=%q", k, v)
			}
		}
		d := &Definition{ID: "SSH-001", Title: "t", Severity: sevHigh}
		for _, ev := range evals {
			r := ev(cfg)
			if !validStatus(r) {
				t.Fatalf("status %v", r.status)
			}
			out := d.finalize(r)
			assertLimits(t, out)
			for _, v := range out.GetEvidence() {
				if !utf8.ValidString(v) {
					t.Fatalf("invalid UTF-8 evidence %q", v)
				}
			}
		}
	})
}

func FuzzSSHDuration(f *testing.F) {
	for _, s := range []string{"0", "120", "1m30s", "2h", "1w", "", "x", "99999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := parseSSHDuration(s)
		if err == nil && (n < 0 || n > 2<<32) {
			t.Fatalf("%q -> %d", s, n)
		}
	})
}

// FuzzSysctl checks the /proc/sys value parser and the KRN-001 evaluation
// with an arbitrary value for one key.
func FuzzSysctl(f *testing.F) {
	for _, s := range []string{"1", "0\n", "32768\t60999", "-1", "", "x", "1 2 3", "9223372036854775808"} {
		f.Add(s)
	}
	proc := copyTree(f, "testdata/proc/hardened")
	f.Fuzz(func(t *testing.T, s string) {
		v, err := parseSysctlInts(s)
		if err == nil && (len(v) == 0 || len(v) > 16) {
			t.Fatalf("%q -> %v", s, v)
		}
		if len(s) > 4096 {
			return
		}
		if err := os.WriteFile(proc+"/sys/kernel/dmesg_restrict", []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		rs := newRunState(Env{ProcRoot: proc}.withDefaults())
		if r := checkSysctl(t.Context(), rs); !validStatus(r) {
			t.Fatalf("status %v", r.status)
		}
	})
}

func FuzzAptConf(f *testing.F) {
	for _, p := range []string{
		"testdata/root/debian/etc/apt/apt.conf.d/20auto-upgrades",
		"testdata/root/debian/etc/apt/apt.conf.d/50unattended-upgrades",
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`A { B { C "1"; }; }; /* x */ #include "y"; "q" "v";`))
	f.Fuzz(func(t *testing.T, data []byte) {
		n := 0
		parseAptConf(data, func(k, v string) {
			n++
			if len(k) > len(data)+2*33 { // each token once, plus "::" per (capped) scope
				t.Fatalf("key too long: %d", len(k))
			}
		})
		if n > len(data) {
			t.Fatalf("%d assignments from %d bytes", n, len(data))
		}
	})
}

func FuzzProcNetLine(f *testing.F) {
	for _, p := range []string{"testdata/proc/weak/net/tcp", "testdata/proc/hardened/net/tcp6", "testdata/proc/weak/net/udp"} {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		for _, l := range strings.Split(string(data), "\n") {
			f.Add(l)
		}
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, st := range []string{"0A", "07"} {
			if s, ok := parseProcNetLine(line, "tcp", st); ok && len(s.ip) != 4 && len(s.ip) != 16 {
				t.Fatalf("ip %v", s.ip)
			}
		}
		_, _ = parseAllowEntry(line)
	})
}

func FuzzMountinfo(f *testing.F) {
	for _, p := range []string{"testdata/proc/hardened/1/mountinfo", "testdata/proc/weak/1/mountinfo"} {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`1 2 3 4 /a\04 o - x`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, m := range parseMountinfo(data) {
			if m.fstype == "" {
				t.Fatalf("empty fstype: %+v", m)
			}
		}
	})
}

func FuzzSudoRule(f *testing.F) {
	for _, s := range []string{"%sudo ALL=(ALL:ALL) NOPASSWD: ALL", "u ALL=(ALL) NOPASSWD: /bin/ls, PASSWD: ALL", "Defaults x", "u h = (", "a=b:c:d:"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_ = nopasswdAll(s)
	})
}

func FuzzNftFilters(f *testing.F) {
	for _, p := range []string{"testdata/root/debian/etc/nftables.conf", "testdata/root/rhel/etc/nftables/main.nft"} {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(data))
	}
	f.Add("chain a {\nchain b {\n{{{{\n}}}}}}\n")
	f.Fuzz(func(_ *testing.T, s string) {
		_ = nftFilters(s)
		_ = iptablesFilters(s)
	})
}

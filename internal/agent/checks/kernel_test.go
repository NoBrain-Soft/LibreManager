package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSysctl(t *testing.T) {
	r := runCheck(t, Env{ProcRoot: td(t, "proc/hardened")}, "KRN-001")
	expectStatus(t, r, PASS)
	expectEvidence(t, r, "checked", "14")

	r = runCheck(t, Env{ProcRoot: td(t, "proc/weak")}, "KRN-001")
	expectStatus(t, r, FAIL)
	for k, v := range map[string]string{
		"kernel.kptr_restrict":               "0 (expected >= 1)",
		"kernel.dmesg_restrict":              "0 (expected 1)",
		"kernel.unprivileged_bpf_disabled":   "0 (expected >= 1)",
		"kernel.randomize_va_space":          "1 (expected 2)",
		"fs.protected_symlinks":              "0 (expected 1)",
		"fs.suid_dumpable":                   "2 (expected 0)",
		"net.ipv4.conf.all.rp_filter":        "0 (expected 1 or 2)",
		"net.ipv4.conf.all.accept_redirects": "1 (expected 0)",
		"net.ipv4.conf.all.send_redirects":   "1 (expected 0)",
		"net.ipv4.ip_forward":                "1 (expected 0)",
		"not_present":                        "net.ipv6.conf.all.accept_redirects",
	} {
		expectEvidence(t, r, k, v)
	}
	for _, ok := range []string{"fs.protected_hardlinks", "net.ipv4.tcp_syncookies", "net.ipv4.conf.all.accept_source_route"} {
		if _, bad := r.GetEvidence()[ok]; bad {
			t.Errorf("%s reported although compliant", ok)
		}
	}
	if !strings.Contains(r.GetSummary(), "kernel.kptr_restrict") || strings.Contains(r.GetSummary(), "ip_forward") {
		t.Errorf("summary %q", r.GetSummary())
	}
}

func TestSysctlVariants(t *testing.T) {
	set := func(t *testing.T, proc, key, val string) {
		t.Helper()
		p := filepath.Join(proc, "sys", strings.ReplaceAll(key, ".", "/"))
		if err := os.WriteFile(p, []byte(val), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("forwarding only warns", func(t *testing.T) {
		proc := copyTree(t, td(t, "proc/hardened"))
		set(t, proc, "net.ipv4.ip_forward", "1\n")
		r := runCheck(t, Env{ProcRoot: proc}, "KRN-001")
		expectStatus(t, r, WARN)
		expectEvidence(t, r, "net.ipv4.ip_forward", "1 (expected 0)")
	})
	t.Run("rp_filter all=1 without interfaces", func(t *testing.T) {
		proc := copyTree(t, td(t, "proc/hardened"))
		set(t, proc, "net.ipv4.conf.all.rp_filter", "1\n")
		if err := os.RemoveAll(filepath.Join(proc, "sys/net/ipv4/conf/eth0")); err != nil {
			t.Fatal(err)
		}
		expectStatus(t, runCheck(t, Env{ProcRoot: proc}, "KRN-001"), PASS)
	})
	t.Run("rp_filter all=0 and one interface unfiltered", func(t *testing.T) {
		proc := copyTree(t, td(t, "proc/hardened"))
		addFiles(t, proc, map[string]string{"sys/net/ipv4/conf/eth1/rp_filter": "0\n"})
		r := runCheck(t, Env{ProcRoot: proc}, "KRN-001")
		expectStatus(t, r, FAIL)
		expectEvidence(t, r, "net.ipv4.conf.all.rp_filter", "0")
	})
	t.Run("malformed value", func(t *testing.T) {
		proc := copyTree(t, td(t, "proc/hardened"))
		set(t, proc, "kernel.kptr_restrict", "one\n")
		expectStatus(t, runCheck(t, Env{ProcRoot: proc}, "KRN-001"), ERROR)
	})
	t.Run("no /proc/sys", func(t *testing.T) {
		expectStatus(t, runCheck(t, Env{ProcRoot: t.TempDir()}, "KRN-001"), ERROR)
	})
}

func TestParseSysctlInts(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []int64
	}{
		{"1", []int64{1}}, {" 2\n", []int64{2}}, {"32768\t60999", []int64{32768, 60999}}, {"-1", []int64{-1}},
		{"", nil}, {"abc", nil}, {"1 x", nil}, {"99999999999999999999", nil}, {strings.Repeat("1 ", 17), nil},
	} {
		got, err := parseSysctlInts(tc.in)
		if (err == nil) != (tc.want != nil) || !slices.Equal(got, tc.want) {
			t.Errorf("%q: %v %v, want %v", tc.in, got, err, tc.want)
		}
	}
}

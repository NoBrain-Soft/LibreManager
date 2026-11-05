package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// parseSysctlInts parses a /proc/sys value: one or more whitespace
// separated integers (at most 16).
func parseSysctlInts(s string) ([]int64, error) {
	f := strings.Fields(s)
	if len(f) == 0 || len(f) > 16 {
		return nil, fmt.Errorf("unexpected sysctl value %q", truncate(s, 32))
	}
	out := make([]int64, 0, len(f))
	for _, x := range f {
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected sysctl value %q", truncate(s, 32))
		}
		out = append(out, n)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type sysctlRule struct {
	key    string
	expect string
	ok     func(int64) bool
	// warnOnly marks settings with legitimate exceptions (routers).
	warnOnly bool
}

func eq(v int64) func(int64) bool { return func(n int64) bool { return n == v } }
func ge(v int64) func(int64) bool { return func(n int64) bool { return n >= v } }

func sysctlRules() []sysctlRule {
	return []sysctlRule{
		{key: "kernel.kptr_restrict", expect: ">= 1", ok: ge(1)},
		{key: "kernel.dmesg_restrict", expect: "1", ok: eq(1)},
		{key: "kernel.unprivileged_bpf_disabled", expect: ">= 1", ok: ge(1)},
		{key: "kernel.randomize_va_space", expect: "2", ok: eq(2)},
		{key: "fs.protected_hardlinks", expect: "1", ok: eq(1)},
		{key: "fs.protected_symlinks", expect: "1", ok: eq(1)},
		{key: "fs.suid_dumpable", expect: "0", ok: eq(0)},
		{key: "net.ipv4.conf.all.rp_filter", expect: "1 or 2", ok: func(n int64) bool { return n == 1 || n == 2 }},
		{key: "net.ipv4.conf.all.accept_redirects", expect: "0", ok: eq(0)},
		{key: "net.ipv4.conf.all.send_redirects", expect: "0", ok: eq(0)},
		{key: "net.ipv4.conf.all.accept_source_route", expect: "0", ok: eq(0)},
		{key: "net.ipv6.conf.all.accept_redirects", expect: "0", ok: eq(0)},
		{key: "net.ipv4.tcp_syncookies", expect: "1", ok: eq(1)},
		{key: "net.ipv4.ip_forward", expect: "0", ok: eq(0), warnOnly: true},
	}
}

func (r *runState) sysctlPath(key string) string {
	return r.procPath(filepath.Join("sys", strings.ReplaceAll(key, ".", "/")))
}

func (r *runState) sysctl(key string) (int64, error) {
	s, err := readTrim(r.sysctlPath(key))
	if err != nil {
		return 0, err
	}
	n, err := parseSysctlInts(s)
	if err != nil {
		return 0, err
	}
	return n[0], nil
}

// rpFilterEffective reports whether every interface filters: the kernel
// uses max(conf.all.rp_filter, conf.<if>.rp_filter), and systemd sets the
// per-interface value instead of "all".
func (r *runState) rpFilterEffective() bool {
	dir := r.procPath("sys/net/ipv4/conf")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if name == "all" || name == "default" || name == "lo" {
			continue
		}
		s, err := readTrim(filepath.Join(dir, name, "rp_filter"))
		if err != nil {
			return false
		}
		v, err := parseSysctlInts(s)
		if err != nil || (v[0] != 1 && v[0] != 2) {
			return false
		}
		n++
	}
	return n > 0
}

func checkSysctl(_ context.Context, r *runState) result {
	var fails, warns, missing []string
	var offenders []string // key, value pairs for evidence
	checked := 0
	for _, rule := range sysctlRules() {
		v, err := r.sysctl(rule.key)
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, rule.key) // older kernel or module not loaded
			continue
		}
		if err != nil {
			return errResult("cannot read "+rule.key, err)
		}
		checked++
		if rule.ok(v) || (rule.key == "net.ipv4.conf.all.rp_filter" && r.rpFilterEffective()) {
			continue
		}
		offenders = append(offenders, rule.key, fmt.Sprintf("%d (expected %s)", v, rule.expect))
		if rule.warnOnly {
			warns = append(warns, rule.key)
		} else {
			fails = append(fails, rule.key)
		}
	}
	if checked == 0 {
		return errResult("no sysctl values readable below "+r.procPath("sys"), nil)
	}
	kvs := append([]string{"checked", fmt.Sprint(checked)}, offenders...)
	if len(missing) > 0 {
		kvs = append(kvs, "not_present", joinCapped(missing))
	}
	switch {
	case len(fails) > 0:
		return fail(plural(len(fails), "sysctl setting is", "sysctl settings are")+" weaker than recommended: "+strings.Join(fails, ", "), kvs...)
	case len(warns) > 0:
		return warn(strings.Join(warns, ", ")+" enabled (expected only on routers and container hosts)", kvs...)
	}
	return pass("kernel sysctl settings are hardened", kvs...)
}

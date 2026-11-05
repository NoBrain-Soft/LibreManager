package checks

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SSH-001..010 evaluate the effective sshd configuration (`sshd -T`, via the
// helper). Only the global configuration is evaluated; Match blocks are not.

var sshdBinaries = []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd"}

const maxSSHDValue = 4096

// ParseSSHDConfig parses `sshd -T` output into lowercase keys with
// whitespace-normalized values. The first occurrence of a key wins.
func ParseSSHDConfig(data []byte) map[string]string {
	out := map[string]string{}
	eachLine(data, func(line string) bool {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		k = strings.ToLower(k)
		if k == "" || len(k) > 64 || strings.HasPrefix(k, "#") {
			return true
		}
		if _, dup := out[k]; !dup {
			v = strings.Join(strings.Fields(v), " ")
			if len(v) > maxSSHDValue {
				v = v[:maxSSHDValue]
			}
			out[k] = v
		}
		return len(out) < 512
	})
	return out
}

func (r *runState) sshdInstalled() bool {
	for _, p := range sshdBinaries {
		if exists(r.rootPath(p)) {
			return true
		}
	}
	return false
}

// sshdConfig returns the effective configuration, or the result every SSH
// check reports when it is not available.
func (r *runState) sshdConfig(ctx context.Context) (map[string]string, *result) {
	installed := r.sshdInstalled()
	notInstalled := na("OpenSSH server is not installed")
	if r.priv == nil {
		if !installed {
			return nil, &notInstalled
		}
		res := errResult("cannot read the effective sshd configuration", errUnavailable())
		return nil, &res
	}
	cfg, err := r.priv.SshdConfig(ctx)
	switch {
	case errors.Is(err, ErrNotInstalled), err != nil && !installed:
		return nil, &notInstalled
	case err != nil:
		res := errResult("cannot read the effective sshd configuration", err)
		return nil, &res
	case len(cfg) == 0:
		res := errResult("sshd -T reported no settings", nil)
		return nil, &res
	}
	return cfg, nil
}

func sshCheck(eval func(map[string]string) result) checkFunc {
	return func(ctx context.Context, r *runState) result {
		cfg, res := r.sshdConfig(ctx)
		if res != nil {
			return *res
		}
		return eval(cfg)
	}
}

func sshMissing(key string) result {
	return errResult(fmt.Sprintf("sshd -T did not report %q", key), nil)
}

// sshValue returns the first of keys present in cfg.
func sshValue(cfg map[string]string, keys ...string) (key, val string, ok bool) {
	for _, k := range keys {
		if v, ok := cfg[k]; ok {
			return k, v, true
		}
	}
	return "", "", false
}

func evalPermitRootLogin(cfg map[string]string) result {
	k, v, ok := sshValue(cfg, "permitrootlogin")
	if !ok {
		return sshMissing("permitrootlogin")
	}
	switch strings.ToLower(v) {
	case "no":
		return pass("root cannot log in over SSH", k, v)
	case "prohibit-password", "without-password", "forced-commands-only":
		return warn("root can log in over SSH with a key", k, v)
	case "yes":
		return fail("root can log in over SSH with a password", k, v)
	}
	return warn("unrecognized PermitRootLogin value", k, v)
}

// sshNo builds an evaluator for a yes/no option that must be "no". Later
// keys are fallbacks for older OpenSSH releases.
func sshNo(what string, keys ...string) func(map[string]string) result {
	return func(cfg map[string]string) result {
		k, v, ok := sshValue(cfg, keys...)
		if !ok {
			return sshMissing(keys[0])
		}
		switch strings.ToLower(v) {
		case "no":
			return pass(what+" is disabled", k, v)
		case "yes":
			return fail(what+" is enabled", k, v)
		}
		return warn(fmt.Sprintf("unrecognized value for %s", k), k, v)
	}
}

func evalMaxAuthTries(cfg map[string]string) result {
	k, v, ok := sshValue(cfg, "maxauthtries")
	if !ok {
		return sshMissing("maxauthtries")
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil || n < 0:
		return warn("unrecognized MaxAuthTries value", k, v)
	case n <= 4:
		return pass(fmt.Sprintf("MaxAuthTries is %d", n), k, v)
	}
	return fail(fmt.Sprintf("MaxAuthTries is %d (more than 4)", n), k, v)
}

// parseSSHDuration parses sshd time values ("120", "2m", "1h30m"); a bare
// number means seconds. Results are capped at 1<<31 seconds.
func parseSSHDuration(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty time value")
	}
	var total, num int64
	digits := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isDigit(c) {
			num = num*10 + int64(c-'0')
			if num > 1<<31 {
				return 0, errors.New("time value too large")
			}
			digits = true
			continue
		}
		if !digits {
			return 0, fmt.Errorf("invalid time value %q", s)
		}
		var mul int64
		switch c {
		case 's', 'S':
			mul = 1
		case 'm', 'M':
			mul = 60
		case 'h', 'H':
			mul = 3600
		case 'd', 'D':
			mul = 86400
		case 'w', 'W':
			mul = 604800
		default:
			return 0, fmt.Errorf("invalid time unit in %q", s)
		}
		total += num * mul
		num, digits = 0, false
		if total > 1<<31 {
			return 0, errors.New("time value too large")
		}
	}
	return total + num, nil
}

func evalLoginGraceTime(cfg map[string]string) result {
	k, v, ok := sshValue(cfg, "logingracetime")
	if !ok {
		return sshMissing("logingracetime")
	}
	secs, err := parseSSHDuration(v)
	switch {
	case err != nil:
		return warn("unrecognized LoginGraceTime value", k, v)
	case secs == 0:
		return fail("LoginGraceTime is unlimited", k, v)
	case secs > 60:
		return fail(fmt.Sprintf("LoginGraceTime is %d s (more than 60 s)", secs), k, v)
	}
	return pass(fmt.Sprintf("LoginGraceTime is %d s", secs), k, v)
}

func weakCipher(a string) bool {
	return a == "none" || strings.Contains(a, "cbc") || strings.Contains(a, "arcfour") ||
		strings.Contains(a, "3des") || strings.Contains(a, "blowfish") || strings.Contains(a, "cast128")
}

// weakMAC flags MD5, RIPEMD-160, truncated (-96) MACs and SHA-1 MACs that
// are not encrypt-then-MAC.
func weakMAC(a string) bool {
	switch {
	case a == "none", strings.Contains(a, "md5"), strings.Contains(a, "ripemd160"), strings.Contains(a, "-96"):
		return true
	case strings.HasPrefix(a, "hmac-sha1") && !strings.Contains(a, "-etm@"):
		return true
	}
	return false
}

// weakKex flags SHA-1 based and 1024-bit group key exchanges
// (diffie-hellman-group1-sha1, diffie-hellman-group14-sha1,
// diffie-hellman-group-exchange-sha1, gss-*-sha1-*, rsa1024-sha1).
func weakKex(a string) bool {
	return strings.Contains(a, "sha1") || strings.Contains(a, "group1-")
}

// splitAlgorithms splits a comma-separated algorithm list (lowercased).
func splitAlgorithms(v string) []string {
	var out []string
	for _, a := range strings.Split(v, ",") {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			out = append(out, a)
		}
		if len(out) >= 256 {
			break
		}
	}
	return out
}

func sshAlgorithms(key, what string, weak func(string) bool) func(map[string]string) result {
	return func(cfg map[string]string) result {
		_, v, ok := sshValue(cfg, key)
		if !ok {
			return sshMissing(key)
		}
		algs := splitAlgorithms(v)
		if len(algs) == 0 {
			return errResult(fmt.Sprintf("sshd -T reported an empty %s list", key), nil)
		}
		var bad []string
		for _, a := range algs {
			if weak(a) {
				bad = append(bad, a)
			}
		}
		if len(bad) > 0 {
			return fail(plural(len(bad), "weak "+what, "weak "+what+"s")+" enabled",
				"weak", joinCapped(bad), key, v)
		}
		return pass("no weak "+what+"s enabled", key, v)
	}
}

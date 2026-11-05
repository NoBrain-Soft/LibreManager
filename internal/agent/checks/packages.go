package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// staleUpdates is the age after which an update report no longer proves
// "no pending security updates".
const staleUpdates = 7 * 24 * time.Hour

// --- PKG-001 -----------------------------------------------------------------

func checkSecurityUpdates(_ context.Context, r *runState) result {
	u := r.env.Updates
	if u == nil {
		return na("no pending-updates report available yet")
	}
	if e := u.GetError(); e != "" {
		return errResult("the package manager reported an error", errors.New(e))
	}
	var names, advisories []string
	for _, p := range u.GetUpdates() {
		if !p.GetIsSecurity() {
			continue
		}
		names = append(names, p.GetName())
		for _, a := range p.GetAdvisories() {
			if !slices.Contains(advisories, a) && len(advisories) < 64 {
				advisories = append(advisories, a)
			}
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	kvs := []string{
		"security_updates", fmt.Sprint(len(names)),
		"total_updates", fmt.Sprint(len(u.GetUpdates())),
		"manager", u.GetManager(),
	}
	checked := time.UnixMilli(u.GetCheckedAtMs())
	if u.GetCheckedAtMs() > 0 {
		kvs = append(kvs, "checked_at", checked.UTC().Format(time.RFC3339))
	}
	if len(names) > 0 {
		kvs = append(kvs, "packages", joinCapped(names))
		if len(advisories) > 0 {
			kvs = append(kvs, "advisories", joinCapped(advisories))
		}
		return fail(plural(len(names), "pending security update", "pending security updates"), kvs...)
	}
	if u.GetCheckedAtMs() <= 0 || r.now.Sub(checked) > staleUpdates {
		return warn("no pending security updates reported, but the update information is older than 7 days", kvs...)
	}
	return pass("no pending security updates", kvs...)
}

// --- PKG-002 -----------------------------------------------------------------

// installedKernels returns kernel releases with a package-owned modules
// directory (modules.builtin or vmlinuz present).
func (r *runState) installedKernels() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range []string{"/lib/modules", "/usr/lib/modules"} {
		entries, err := os.ReadDir(r.rootPath(d))
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if seen[name] || len(out) >= 64 {
				continue
			}
			dir := filepath.Join(r.rootPath(d), name)
			if exists(filepath.Join(dir, "modules.builtin")) || exists(filepath.Join(dir, "vmlinuz")) {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// newerKernel returns the newest installed kernel of the running kernel's
// shape if it is newer than running. Nothing is returned unless the running
// kernel itself is installed (containers see unrelated /lib/modules).
func newerKernel(running string, installed []string) string {
	if running == "" || !slices.Contains(installed, running) {
		return ""
	}
	newest := running
	shape := versionShape(running)
	for _, k := range installed {
		if versionShape(k) == shape && compareVersions(k, newest) > 0 {
			newest = k
		}
	}
	if newest == running {
		return ""
	}
	return newest
}

func checkRebootRequired(_ context.Context, r *runState) result {
	var reasons []string
	required, known := false, false
	if u := r.env.Updates; u != nil && u.GetError() == "" {
		known = true
		if u.GetRebootRequired() {
			required = true
			reasons = append(reasons, u.GetRebootReasons()...)
		}
	}
	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if !exists(r.rootPath(p)) {
			continue
		}
		required, known = true, true
		if data, err := readCapped(r.rootPath(p+".pkgs"), maxSmallFile); err == nil {
			for _, l := range nonEmptyLines(data) {
				reasons = append(reasons, "package "+l)
			}
		}
		break
	}
	running, _ := readTrim(r.procPath("sys/kernel/osrelease"))
	installed := r.installedKernels()
	if slices.Contains(installed, running) {
		known = true
		if k := newerKernel(running, installed); k != "" {
			required = true
			reasons = append(reasons, fmt.Sprintf("kernel %s installed, running %s", k, running))
		}
	}
	if r.osFamily() == "debian" {
		// Debian/Ubuntu signal pending reboots via /run/reboot-required,
		// so its absence is meaningful.
		known = true
	}
	kvs := []string{}
	if running != "" {
		kvs = append(kvs, "running_kernel", running)
	}
	switch {
	case required:
		slices.Sort(reasons)
		reasons = slices.Compact(reasons)
		if len(reasons) > 0 {
			kvs = append(kvs, "reasons", joinCapped(reasons))
		}
		return warn("a reboot is required to activate installed updates", kvs...)
	case !known:
		return na("reboot state cannot be determined (no update report)", kvs...)
	}
	return pass("no reboot pending", kvs...)
}

// --- PKG-003 -----------------------------------------------------------------

func checkAutoUpdates(ctx context.Context, r *runState) result {
	switch r.osFamily() {
	case "debian":
		return r.checkUnattendedUpgrades(ctx)
	case "rhel":
		return r.checkDnfAutomatic(ctx)
	}
	return na("automatic updates are only evaluated on Debian/Ubuntu and RHEL-family systems")
}

// aptIgnored mirrors apt's Dir::Ignore-Files-Silently and its file name rule.
var (
	aptPartName   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	aptIgnoredExt = regexp.MustCompile(`(~|\.disabled|\.bak|\.dpkg-[a-z]+|\.ucf-[a-z]+|\.save|\.orig|\.distUpgrade)$`)
)

// aptConfig returns the effective (last assigned) value of key, read like
// apt does: /etc/apt/apt.conf.d/* in lexical order, then /etc/apt/apt.conf.
func (r *runState) aptConfig(key string) (string, bool) {
	key = strings.ToLower(key)
	var files []string
	if entries, err := os.ReadDir(r.rootPath("/etc/apt/apt.conf.d")); err == nil {
		for _, e := range entries {
			if n := e.Name(); !e.IsDir() && aptPartName.MatchString(n) && !aptIgnoredExt.MatchString(n) && len(files) < 256 {
				files = append(files, filepath.Join(r.rootPath("/etc/apt/apt.conf.d"), n))
			}
		}
	}
	files = append(files, r.rootPath("/etc/apt/apt.conf"))
	val, found := "", false
	for _, f := range files {
		data, err := readCapped(f, maxConfigFile)
		if err != nil {
			continue
		}
		parseAptConf(data, func(k, v string) {
			if strings.ToLower(k) == key {
				val, found = v, true
			}
		})
	}
	return val, found
}

type aptTok struct {
	kind byte // 'w' word, 's' quoted string, '{', '}', ';'
	s    string
}

const maxAptTokens = 100000

func aptTokens(data []byte) []aptTok {
	var toks []aptTok
	for i := 0; i < len(data) && len(toks) < maxAptTokens; {
		c := data[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return toks
			}
			i += end + 4
		case c == '#':
			j := i
			for j < len(data) && data[j] != ' ' && data[j] != '\t' && data[j] != '\n' {
				j++
			}
			if w := string(data[i:j]); w == "#include" || w == "#clear" {
				toks = append(toks, aptTok{'w', w})
				i = j
				continue
			}
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case c == '"':
			end := bytes.IndexByte(data[i+1:], '"')
			if end < 0 {
				return toks
			}
			toks = append(toks, aptTok{'s', string(data[i+1 : i+1+end])})
			i += end + 2
		case c == '{' || c == '}' || c == ';':
			toks = append(toks, aptTok{c, ""})
			i++
		default:
			j := i
			for j < len(data) && !strings.ContainsRune(" \t\r\n{};\"", rune(data[j])) {
				j++
			}
			toks = append(toks, aptTok{'w', string(data[i:j])})
			i = j
		}
	}
	return toks
}

// parseAptConf calls set for every "key value;" assignment in apt.conf
// syntax, with nested scopes flattened to "A::B::key". List items, #include
// and #clear are ignored.
func parseAptConf(data []byte, set func(key, value string)) {
	toks := aptTokens(data)
	var scope []string
	full := func(k string) string {
		if len(scope) == 0 {
			return k
		}
		return strings.Join(scope, "::") + "::" + k
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case 'w', 's':
			if t.kind == 'w' && (t.s == "#include" || t.s == "#clear") {
				for i < len(toks) && toks[i].kind != ';' {
					i++
				}
				continue
			}
			if i+1 >= len(toks) {
				return
			}
			switch next := toks[i+1]; next.kind {
			case '{':
				if len(scope) < 32 {
					scope = append(scope, t.s)
				}
				i++
			case 'w', 's':
				set(full(t.s), next.s)
				i++
			}
		case '{':
			if len(scope) < 32 {
				scope = append(scope, "")
			}
		case '}':
			if len(scope) > 0 {
				scope = scope[:len(scope)-1]
			}
		}
	}
}

// periodicEnabled interprets an APT::Periodic interval: "always", a
// positive number of days, or a number with an s/m/h/d suffix.
func periodicEnabled(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "always" {
		return true
	}
	v = strings.TrimRight(v, "smhd")
	n, err := strconv.Atoi(v)
	return err == nil && n > 0
}

// unitEnabled runs `systemctl is-enabled UNIT` and returns its state
// ("enabled", "disabled", "masked", "static", ...).
func (r *runState) unitEnabled(ctx context.Context, unit string) (string, error) {
	out, _, err := r.env.Exec.Run(ctx, "systemctl", "is-enabled", "--", unit)
	if err != nil {
		return "", err
	}
	lines := nonEmptyLines(out)
	if len(lines) != 1 {
		return "not-found", nil
	}
	return lines[0], nil
}

func enabledState(s string) bool {
	switch s {
	case "enabled", "enabled-runtime", "static", "alias", "indirect", "generated":
		return true
	}
	return false
}

func (r *runState) checkUnattendedUpgrades(ctx context.Context) result {
	if !exists(r.rootPath("/usr/bin/unattended-upgrade")) {
		return fail("unattended-upgrades is not installed")
	}
	v, ok := r.aptConfig("APT::Periodic::Unattended-Upgrade")
	if !ok || !periodicEnabled(v) {
		if !ok {
			v = "unset"
		}
		return fail("unattended-upgrades is installed but APT::Periodic::Unattended-Upgrade is not enabled",
			"apt_periodic_unattended_upgrade", v)
	}
	kvs := []string{"apt_periodic_unattended_upgrade", v}
	state, err := r.unitEnabled(ctx, "apt-daily-upgrade.timer")
	switch {
	case err != nil:
		kvs = append(kvs, "apt_daily_upgrade_timer", "unknown")
	case state == "disabled" || state == "masked":
		return fail("unattended-upgrades is configured but apt-daily-upgrade.timer is "+state,
			append(kvs, "apt_daily_upgrade_timer", state)...)
	default:
		kvs = append(kvs, "apt_daily_upgrade_timer", state)
	}
	return pass("unattended security upgrades are enabled", kvs...)
}

// parseINI calls set(section, key, value) for "key = value" lines.
func parseINI(data []byte, set func(section, key, value string)) {
	section := ""
	eachLine(data, func(l string) bool {
		l = strings.TrimSpace(l)
		switch {
		case l == "" || l[0] == '#' || l[0] == ';':
		case l[0] == '[' && strings.HasSuffix(l, "]"):
			section = strings.ToLower(strings.TrimSpace(l[1 : len(l)-1]))
		default:
			if k, v, ok := strings.Cut(l, "="); ok {
				set(section, strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v))
			}
		}
		return true
	})
}

func iniBool(v string) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

func (r *runState) checkDnfAutomatic(ctx context.Context) result {
	var conf []byte
	for _, p := range []string{"/etc/dnf/automatic.conf", "/etc/dnf/dnf5-plugins/automatic.conf"} {
		if data, err := readCapped(r.rootPath(p), maxConfigFile); err == nil {
			conf = data
			break
		}
	}
	if conf == nil && !exists(r.rootPath("/usr/bin/dnf-automatic")) {
		return fail("dnf-automatic is not installed")
	}
	apply, upgradeType := false, "default"
	parseINI(conf, func(sec, k, v string) {
		if sec != "commands" {
			return
		}
		switch k {
		case "apply_updates":
			apply = iniBool(v)
		case "upgrade_type":
			upgradeType = v
		}
	})
	kvs := []string{"apply_updates", strconv.FormatBool(apply), "upgrade_type", upgradeType}
	timers := map[string]string{}
	unknown := false
	for _, t := range []string{"dnf-automatic-install.timer", "dnf-automatic.timer", "dnf5-automatic.timer"} {
		state, err := r.unitEnabled(ctx, t)
		if err != nil {
			unknown = true
			continue
		}
		timers[t] = state
		kvs = append(kvs, t, state)
	}
	switch {
	case enabledState(timers["dnf-automatic-install.timer"]):
		return pass("dnf-automatic installs updates automatically", kvs...)
	case enabledState(timers["dnf-automatic.timer"]) || enabledState(timers["dnf5-automatic.timer"]):
		if apply {
			return pass("dnf-automatic installs updates automatically", kvs...)
		}
		return warn("dnf-automatic runs but only downloads/notifies (apply_updates = no)", kvs...)
	case unknown:
		return errResult("cannot query dnf-automatic timer state", nil, kvs...)
	}
	return fail("no dnf-automatic timer is enabled", kvs...)
}

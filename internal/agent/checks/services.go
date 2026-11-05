package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/common/validate"
)

// --- SVC-001 -----------------------------------------------------------------

const maxRequiredUnits = 64

// unitName appends ".service" to a bare name; it returns "" for names that
// are not valid unit names (and so could never reach argv as an option).
func unitName(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, ".") || !validate.UnitName(s) {
		s += ".service"
	}
	if !validate.UnitName(s) {
		return ""
	}
	return s
}

func checkRequiredServices(ctx context.Context, r *runState) result {
	if len(r.env.RequiredServices) == 0 {
		return na("no required services configured")
	}
	if !r.systemdBooted() {
		return na("systemd is not running")
	}
	type group struct {
		spec  string
		units []string
	}
	var groups []group
	var units, invalid []string
	for _, spec := range r.env.RequiredServices {
		g := group{spec: spec}
		for _, alt := range strings.Split(spec, "|") {
			u := unitName(alt)
			if u == "" {
				invalid = append(invalid, alt)
				continue
			}
			g.units = append(g.units, u)
			if !slices.Contains(units, u) && len(units) < maxRequiredUnits {
				units = append(units, u)
			}
		}
		groups = append(groups, g)
	}
	kvs := []string{}
	if len(invalid) > 0 {
		kvs = append(kvs, "invalid_unit_names", joinCapped(invalid))
	}
	if len(units) == 0 {
		return errResult("no valid unit names in the required services", nil, kvs...)
	}
	st, err := r.systemctlActive(ctx, units...)
	if err != nil {
		return errResult("cannot query service state", err, kvs...)
	}
	var missing []string
	for _, g := range groups {
		active := slices.ContainsFunc(g.units, func(u string) bool { return st[u] == "active" })
		var states []string
		for _, u := range g.units {
			states = append(states, u+"="+st[u])
		}
		kvs = append(kvs, validate.Text(g.spec, MaxEvidenceKey), strings.Join(states, ", "))
		if !active {
			missing = append(missing, g.spec)
		}
	}
	if len(missing) > 0 {
		return fail(plural(len(missing), "required service is", "required services are")+" not running: "+strings.Join(missing, "; "), kvs...)
	}
	return pass("all required services are running", kvs...)
}

// --- SVC-002 -----------------------------------------------------------------

func checkFailedUnits(ctx context.Context, r *runState) result {
	if !r.systemdBooted() {
		return na("systemd is not running")
	}
	out, code, err := r.env.Exec.Run(ctx, "systemctl", "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return errResult("cannot list failed units", err)
	}
	if code != 0 {
		return errResult(fmt.Sprintf("systemctl list-units exited with %d", code), nil)
	}
	var failed []string
	for _, l := range nonEmptyLines(out) {
		f := strings.Fields(strings.TrimPrefix(l, "●"))
		if len(f) > 0 && validate.UnitName(f[0]) {
			failed = append(failed, f[0])
		}
	}
	slices.Sort(failed)
	if len(failed) > 0 {
		return fail(plural(len(failed), "systemd unit has", "systemd units have")+" failed",
			"units", joinCapped(failed), "count", fmt.Sprint(len(failed)))
	}
	return pass("no failed systemd units")
}

// --- TIME-001 ----------------------------------------------------------------

func checkTimeSync(ctx context.Context, r *runState) result {
	if r.env.Adjtimex != nil {
		var tx unix.Timex
		state, err := r.env.Adjtimex(&tx)
		if err == nil {
			kvs := []string{"source", "adjtimex", "maxerror_us", fmt.Sprint(tx.Maxerror)}
			if state == unix.TIME_ERROR || tx.Status&unix.STA_UNSYNC != 0 {
				return fail("the kernel clock is not synchronized", kvs...)
			}
			return pass("the kernel clock is synchronized", kvs...)
		}
	}
	var tried []string
	if out, code, err := r.env.Exec.Run(ctx, "timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized"); err == nil && code == 0 {
		props := map[string]string{}
		for _, l := range nonEmptyLines(out) {
			if k, v, ok := strings.Cut(l, "="); ok {
				props[k] = v
			}
		}
		kvs := []string{"source", "timedatectl", "ntp_enabled", props["NTP"], "ntp_synchronized", props["NTPSynchronized"]}
		switch props["NTPSynchronized"] {
		case "yes":
			return pass("the system clock is synchronized", kvs...)
		case "no":
			return fail("the system clock is not synchronized", kvs...)
		}
	} else {
		tried = append(tried, "timedatectl")
	}
	if out, _, err := r.env.Exec.Run(ctx, "chronyc", "-n", "tracking"); err == nil {
		for _, l := range nonEmptyLines(out) {
			k, v, ok := strings.Cut(l, ":")
			if !ok || strings.TrimSpace(k) != "Leap status" {
				continue
			}
			v = strings.TrimSpace(v)
			kvs := []string{"source", "chronyc", "leap_status", v}
			if v == "Not synchronised" {
				return fail("chrony is not synchronized", kvs...)
			}
			return pass("chrony is synchronized", kvs...)
		}
	}
	tried = append(tried, "chronyc")
	if exists(r.rootPath("/run/systemd/timesync/synchronized")) {
		return pass("systemd-timesyncd is synchronized", "source", "/run/systemd/timesync/synchronized")
	}
	return errResult("time synchronization state could not be determined", nil, "tried", strings.Join(tried, ", "))
}

// --- LOG-001 -----------------------------------------------------------------

// journaldStorage returns the effective Storage= of journald: the main file
// first, then drop-ins sorted by name, where /etc overrides /run overrides
// /usr/local/lib overrides /usr/lib for the same name.
func (r *runState) journaldStorage() string {
	storage := "auto"
	apply := func(p string) {
		data, err := readCapped(r.rootPath(p), maxConfigFile)
		if err != nil {
			return
		}
		parseINI(data, func(sec, k, v string) {
			if sec == "journal" && k == "storage" {
				storage = strings.ToLower(v)
			}
		})
	}
	if exists(r.rootPath("/etc/systemd/journald.conf")) {
		apply("/etc/systemd/journald.conf")
	} else {
		apply("/usr/lib/systemd/journald.conf")
	}
	dropins := map[string]string{}
	for _, d := range []string{"/usr/lib/systemd/journald.conf.d", "/usr/local/lib/systemd/journald.conf.d", "/run/systemd/journald.conf.d", "/etc/systemd/journald.conf.d"} {
		entries, err := os.ReadDir(r.rootPath(d))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") && len(dropins) < 256 {
				dropins[e.Name()] = filepath.Join(d, e.Name())
			}
		}
	}
	names := make([]string, 0, len(dropins))
	for n := range dropins {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		apply(dropins[n])
	}
	return storage
}

func checkLogging(ctx context.Context, r *runState) result {
	storage := r.journaldStorage()
	journalDir := isDir(r.rootPath("/var/log/journal"))
	persistent := storage == "persistent" || (storage == "auto" && journalDir)
	kvs := []string{"journald_storage", storage, "var_log_journal", fmt.Sprint(journalDir)}

	auditd, syslog := "unknown", false
	if r.systemdBooted() {
		st, err := r.systemctlActive(ctx, "auditd.service", "rsyslog.service", "syslog-ng.service")
		if err == nil {
			auditd = st["auditd.service"]
			syslog = st["rsyslog.service"] == "active" || st["syslog-ng.service"] == "active"
			kvs = append(kvs, "rsyslog", st["rsyslog.service"], "syslog_ng", st["syslog-ng.service"])
		} else if !errors.Is(err, ErrCommandNotFound) {
			kvs = append(kvs, "systemctl_error", err.Error())
		}
	}
	kvs = append(kvs, "auditd", auditd)
	switch {
	case !persistent && !syslog:
		return fail("logs are not persisted across reboots (journald storage is "+storage+", no syslog daemon)", kvs...)
	case auditd != "active":
		return warn("logs are persisted, but auditd is not active", kvs...)
	}
	return pass("logs are persisted and auditd is active", kvs...)
}

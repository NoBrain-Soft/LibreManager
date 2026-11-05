package checks

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/validate"
)

// DormantAfter is the ACC-004 threshold.
const DormantAfter = 90 * 24 * time.Hour

func accountName(n string) string { return validate.Text(n, 64) }

// --- ACC-001 -----------------------------------------------------------------

func checkUID0(_ context.Context, r *runState) result {
	pw, err := r.passwd()
	if err != nil {
		return errResult("cannot read /etc/passwd", err)
	}
	var extra []string
	for _, e := range pw {
		if e.uid == 0 && e.name != "root" {
			extra = append(extra, accountName(e.name))
		}
	}
	if len(extra) > 0 {
		return fail(plural(len(extra), "account other than root has", "accounts other than root have")+" UID 0",
			"accounts", joinCapped(extra))
	}
	return pass("only root has UID 0")
}

// --- ACC-002 -----------------------------------------------------------------

func checkEmptyPasswords(ctx context.Context, r *runState) result {
	if r.priv == nil {
		return errResult("cannot read password flags", errUnavailable())
	}
	empty, locked, err := r.priv.ShadowFlags(ctx)
	if err != nil {
		return errResult("cannot read password flags", err)
	}
	names := make([]string, 0, len(empty))
	for _, n := range empty {
		names = append(names, accountName(n))
	}
	slices.Sort(names)
	if len(names) > 0 {
		return fail(plural(len(names), "account has", "accounts have")+" an empty password",
			"accounts", joinCapped(names), "locked_accounts", fmt.Sprint(len(locked)))
	}
	return pass("no account has an empty password", "locked_accounts", fmt.Sprint(len(locked)))
}

// --- ACC-003 -----------------------------------------------------------------

func checkSudoNopasswd(ctx context.Context, r *runState) result {
	if !exists(r.rootPath("/etc/sudoers")) && !exists(r.rootPath("/usr/bin/sudo")) {
		return na("sudo is not installed")
	}
	if r.priv == nil {
		return errResult("cannot read sudoers", errUnavailable())
	}
	rules, err := r.priv.SudoRules(ctx)
	if errors.Is(err, ErrNotInstalled) {
		return na("sudo is not installed")
	}
	if err != nil {
		return errResult("cannot read sudoers", err)
	}
	var bad []string
	for _, rule := range rules {
		if nopasswdAll(rule) {
			bad = append(bad, validate.Text(rule, 200))
		}
	}
	if len(bad) > 0 {
		return fail(plural(len(bad), "sudo rule grants", "sudo rules grant")+" all commands without a password",
			"rules", strings.Join(bad, " | "), "count", fmt.Sprint(len(bad)))
	}
	return pass("no sudo rule grants all commands without a password", "rules_checked", fmt.Sprint(len(rules)))
}

func isSudoTag(t string) (nopasswd, passwd, ok bool) {
	switch t {
	case "NOPASSWD":
		return true, false, true
	case "PASSWD":
		return false, true, true
	case "NOEXEC", "EXEC", "SETENV", "NOSETENV", "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT",
		"MAIL", "NOMAIL", "FOLLOW", "NOFOLLOW", "INTERCEPT", "NOINTERCEPT":
		return false, false, true
	}
	return false, false, false
}

func sudoOption(o string) bool {
	switch o {
	case "ROLE", "TYPE", "CWD", "CHROOT", "NOTBEFORE", "NOTAFTER", "TIMEOUT", "APPARMOR_PROFILE":
		return true
	}
	return false
}

// nopasswdAll reports whether a sudoers rule lets its users run ALL
// commands without a password. Tags carry over to later commands of the
// same list, as in sudo.
func nopasswdAll(rule string) bool {
	rule = strings.TrimSpace(rule)
	for _, p := range []string{"Defaults", "Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias"} {
		if strings.HasPrefix(rule, p) {
			return false
		}
	}
	_, cmds, ok := strings.Cut(rule, "=")
	if !ok {
		return false
	}
	nopw := false
	for _, spec := range strings.Split(cmds, ",") {
		s := strings.TrimSpace(spec)
		if strings.HasPrefix(s, "(") {
			i := strings.IndexByte(s, ')')
			if i < 0 {
				continue
			}
			s = s[i+1:]
		}
		for {
			s = strings.TrimSpace(s)
			if tag, rest, found := strings.Cut(s, ":"); found {
				if np, p, isTag := isSudoTag(strings.TrimSpace(tag)); isTag {
					nopw = (nopw || np) && !p
					s = rest
					continue
				}
			}
			// Options such as ROLE=x, CWD=/dir, TIMEOUT=10.
			if word, rest, found := strings.Cut(s, " "); found {
				if opt, _, isOpt := strings.Cut(word, "="); isOpt && sudoOption(opt) {
					s = rest
					continue
				}
			}
			break
		}
		f := strings.Fields(s)
		if nopw && len(f) > 0 && f[0] == "ALL" && (len(f) == 1 || f[1] == ":") {
			return true
		}
	}
	return false
}

// --- ACC-004 -----------------------------------------------------------------

const (
	utmpRecordSize    = 384 // glibc struct utmp on x86_64 and aarch64
	utUserOffset      = 44
	utUserLen         = 32
	utTvSecOffset     = 340
	utUserProcess     = 7
	lastlogRecordSize = 292 // int32 time + line[32] + host[256]
	maxWtmpBytes      = 32 << 20
)

var nonInteractiveShells = map[string]bool{
	"nologin": true, "false": true, "sync": true, "shutdown": true, "halt": true, "true": true,
}

func interactiveShell(sh string) bool {
	return sh != "" && !nonInteractiveShells[path.Base(sh)]
}

type loginData struct {
	last     map[string]time.Time
	earliest time.Time
}

// readWtmp scans utmp records (the last maxBytes of the file) for
// USER_PROCESS entries.
func readWtmp(file string, maxBytes int64, ld *loginData) error {
	f, err := os.Open(file) //nolint:gosec // fixed path below Root
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size() - st.Size()%utmpRecordSize
	if size <= 0 {
		return io.EOF
	}
	if size > maxBytes {
		if _, err := f.Seek(size-(maxBytes/utmpRecordSize)*utmpRecordSize, io.SeekStart); err != nil {
			return err
		}
	}
	br := bufio.NewReaderSize(f, 64<<10)
	var rec [utmpRecordSize]byte
	for {
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			return nil
		}
		sec := binary.NativeEndian.Uint32(rec[utTvSecOffset:])
		if sec == 0 {
			continue
		}
		t := time.Unix(int64(sec), 0)
		if ld.earliest.IsZero() || t.Before(ld.earliest) {
			ld.earliest = t
		}
		if binary.NativeEndian.Uint16(rec[0:]) != utUserProcess {
			continue
		}
		user := rec[utUserOffset : utUserOffset+utUserLen]
		if i := slices.Index(user, 0); i >= 0 {
			user = user[:i]
		}
		name := string(user)
		if name == "" {
			continue
		}
		if prev, ok := ld.last[name]; (ok && t.After(prev)) || (!ok && len(ld.last) < maxAccounts) {
			ld.last[name] = t
		}
	}
}

// lastlogTime returns the last login of uid from a lastlog file (zero when
// never logged in).
func lastlogTime(f *os.File, uid uint32) time.Time {
	var b [4]byte
	if _, err := f.ReadAt(b[:], int64(uid)*lastlogRecordSize); err != nil {
		return time.Time{}
	}
	if sec := binary.NativeEndian.Uint32(b[:]); sec != 0 {
		return time.Unix(int64(sec), 0)
	}
	return time.Time{}
}

func modTime(p string) time.Time {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func checkDormantAccounts(ctx context.Context, r *runState) result {
	pw, err := r.passwd()
	if err != nil {
		return errResult("cannot read /etc/passwd", err)
	}
	uidMin := r.loginDefsInt("UID_MIN", 1000)
	var accounts []passwdEntry
	for _, e := range pw {
		if int64(e.uid) >= uidMin && e.uid != 65534 && e.name != "nobody" && interactiveShell(e.shell) {
			accounts = append(accounts, e)
		}
	}
	if len(accounts) == 0 {
		return pass("no interactive local accounts")
	}

	ld := &loginData{last: map[string]time.Time{}}
	wtmpOK := false
	var legacy time.Time
	for _, p := range []string{"/var/log/wtmp.1", "/var/log/wtmp"} {
		if err := readWtmp(r.rootPath(p), maxWtmpBytes, ld); err == nil {
			wtmpOK = true
			if m := modTime(r.rootPath(p)); m.After(legacy) {
				legacy = m
			}
		}
		if ctx.Err() != nil {
			return errResult("reading login records", ctx.Err())
		}
	}
	var ll *os.File
	if f, err := os.Open(r.rootPath("/var/log/lastlog")); err == nil { //nolint:gosec // fixed path below Root
		defer func() { _ = f.Close() }()
		if st, err := f.Stat(); err == nil && st.Size() > 0 {
			ll = f
			if st.ModTime().After(legacy) {
				legacy = st.ModTime()
			}
		}
	}
	// Newer distributions keep login history in SQLite databases (wtmpdb,
	// lastlog2) that this check does not read; stale legacy files would
	// make every account look dormant.
	for _, db := range []string{"/var/lib/wtmpdb/wtmp.db", "/var/lib/lastlog/lastlog2.db"} {
		if m := modTime(r.rootPath(db)); !m.IsZero() && m.After(legacy.Add(24*time.Hour)) {
			return na("login history is kept in wtmpdb/lastlog2, which this check cannot read", "database", db)
		}
	}
	if !wtmpOK && ll == nil {
		return na("no login records (wtmp, lastlog) available")
	}

	cutoff := r.now.Add(-DormantAfter)
	// lastlog keeps every user's last login; wtmp only covers its
	// rotation window, so "never seen" is meaningful only if it reaches
	// back past the cutoff.
	fullHistory := ll != nil || (!ld.earliest.IsZero() && !ld.earliest.After(cutoff))
	var dormant []string
	undetermined := 0
	for _, a := range accounts {
		last := ld.last[a.name]
		if ll != nil {
			if t := lastlogTime(ll, a.uid); t.After(last) {
				last = t
			}
		}
		switch {
		case !last.IsZero() && last.Before(cutoff):
			dormant = append(dormant, fmt.Sprintf("%s (last login %s)", accountName(a.name), last.UTC().Format(time.DateOnly)))
		case last.IsZero() && fullHistory:
			dormant = append(dormant, accountName(a.name)+" (never logged in)")
		case last.IsZero():
			undetermined++
		}
	}
	kvs := []string{"interactive_accounts", fmt.Sprint(len(accounts))}
	if undetermined > 0 {
		kvs = append(kvs, "undetermined", fmt.Sprint(undetermined))
	}
	if len(dormant) > 0 {
		kvs = append(kvs, "accounts", joinCapped(dormant))
		return warn(plural(len(dormant), "interactive account has", "interactive accounts have")+" not logged in for more than 90 days", kvs...)
	}
	if undetermined == len(accounts) {
		return na("login records do not reach back 90 days", kvs...)
	}
	return pass("all interactive accounts logged in within 90 days", kvs...)
}

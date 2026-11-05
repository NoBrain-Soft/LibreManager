package checks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func TestUID0(t *testing.T) {
	r := runCheck(t, Env{Root: td(t, "root/debian")}, "ACC-001")
	expectStatus(t, r, PASS)

	r = runCheck(t, Env{Root: td(t, "root/rhel")}, "ACC-001")
	expectStatus(t, r, FAIL)
	expectEvidence(t, r, "accounts", "toor")
	// toor's passwd entry carries a hash in the password field.
	assertNoSecrets(t, r)

	expectStatus(t, runCheck(t, Env{Root: t.TempDir()}, "ACC-001"), ERROR)
}

func TestEmptyPasswords(t *testing.T) {
	root := td(t, "root/debian")
	tests := []struct {
		name string
		priv Privileged
		want agentv1.CheckStatus
	}{
		{"none", &fakePriv{locked: []string{"daemon", "bin"}}, PASS},
		{"some", &fakePriv{empty: []string{"guest", "test"}, locked: []string{"daemon"}}, FAIL},
		{"no helper", nil, ERROR},
		{"helper error", &fakePriv{shadowErr: errors.New("helper error: open /etc/shadow: permission denied")}, ERROR},
		{"helper not installed", &fakePriv{shadowErr: fmt.Errorf("%w: x", ErrNotInstalled)}, ERROR},
		{"helper panics", &fakePriv{panics: true}, ERROR},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: root, Privileged: tc.priv}, "ACC-002")
			expectStatus(t, r, tc.want)
			assertNoSecrets(t, r)
			if tc.want == FAIL {
				expectEvidence(t, r, "accounts", "guest, test")
				expectEvidence(t, r, "locked_accounts", "1")
			}
		})
	}

	// A buggy helper that leaks hash material in the name list must not
	// get it into evidence.
	r := runCheck(t, Env{Root: root, Privileged: &fakePriv{empty: []string{"user:$6$saltsalt$Zx3KoMkF"}}}, "ACC-002")
	expectStatus(t, r, FAIL)
	assertNoSecrets(t, r)
}

func TestSudoNopasswd(t *testing.T) {
	root := td(t, "root/debian")
	tests := []struct {
		name string
		root string
		priv Privileged
		want agentv1.CheckStatus
	}{
		{"restricted", root, &fakePriv{sudo: []string{"%sudo ALL=(ALL:ALL) ALL", "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app.service"}}, PASS},
		{"nopasswd all", root, &fakePriv{sudo: []string{"%sudo ALL=(ALL:ALL) ALL", "ansible ALL=(ALL) NOPASSWD: ALL"}}, FAIL},
		{"no rules", root, &fakePriv{}, PASS},
		{"sudo not installed", t.TempDir(), &fakePriv{sudo: []string{"x ALL=(ALL) NOPASSWD: ALL"}}, NA},
		{"sudoers missing per helper", root, &fakePriv{sudoErr: fmt.Errorf("%w: sudoers", ErrNotInstalled)}, NA},
		{"no helper", root, nil, ERROR},
		{"helper error", root, &fakePriv{sudoErr: errors.New("helper: sudoers too large")}, ERROR},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: tc.root, Privileged: tc.priv}, "ACC-003")
			expectStatus(t, r, tc.want)
			if tc.want == FAIL {
				expectEvidence(t, r, "rules", "ansible ALL=(ALL) NOPASSWD: ALL")
				expectEvidence(t, r, "count", "1")
			}
		})
	}
}

func TestNopasswdAll(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want bool
	}{
		{"%sudo ALL=(ALL:ALL) NOPASSWD: ALL", true},
		{"ansible ALL=(ALL) NOPASSWD:ALL", true},
		{"ansible ALL = (root) NOPASSWD : ALL", true},
		{"ops ALL=(ALL) NOPASSWD: /usr/bin/ls, ALL", true},
		{"ops ALL=(ALL) NOPASSWD: ALL, !/usr/bin/su", true},
		{"ops ALL=(ALL) NOPASSWD: SETENV: ALL", true},
		{"ops ALL=(ALL) SETENV: NOPASSWD: ALL", true},
		{"ops ALL=(ALL) NOPASSWD: ROLE=unconfined_r ALL", true},
		{"ops hostA = NOPASSWD: ALL : hostB = /bin/ls", true},
		{"ops ALL=(ALL) NOPASSWD: /usr/bin/foo, (root) ALL", true},
		{"%admin ALL=(ALL) ALL", false},
		{"%wheel ALL=(ALL) PASSWD: ALL", false},
		{"ops ALL=(ALL) NOPASSWD: /usr/bin/foo, PASSWD: ALL", false},
		{"deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app.service", false},
		{"deploy ALL=(root) NOPASSWD: /usr/bin/ALL", false},
		{"Defaults !authenticate", false},
		{"Cmnd_Alias ALLCMDS = ALL", false},
		{"User_Alias ADMINS = alice, bob", false},
		{"garbage without equals NOPASSWD: ALL", false},
		{"ops ALL=(ALL NOPASSWD: ALL", false},
		{"", false},
	} {
		if got := nopasswdAll(tc.rule); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.rule, got, tc.want)
		}
	}
}

// --- ACC-004 --------------------------------------------------------------------

func utmpRecord(typ uint16, user string, at time.Time) []byte {
	b := make([]byte, utmpRecordSize)
	binary.NativeEndian.PutUint16(b[0:], typ)
	copy(b[8:40], "pts/0")
	copy(b[utUserOffset:utUserOffset+utUserLen], user)
	copy(b[76:], "203.0.113.7")
	binary.NativeEndian.PutUint32(b[utTvSecOffset:], uint32(at.Unix()))
	return b
}

type login struct {
	typ  uint16
	user string
	ago  time.Duration
}

func wtmp(logins ...login) string {
	var b strings.Builder
	for _, l := range logins {
		b.Write(utmpRecord(l.typ, l.user, t0.Add(-l.ago)))
	}
	return b.String()
}

func lastlog(entries map[uint32]time.Duration) string {
	var maxUID uint32
	for uid := range entries {
		maxUID = max(maxUID, uid)
	}
	b := make([]byte, (int(maxUID)+1)*lastlogRecordSize)
	for uid, ago := range entries {
		binary.NativeEndian.PutUint32(b[int(uid)*lastlogRecordSize:], uint32(t0.Add(-ago).Unix()))
	}
	return string(b)
}

const day = 24 * time.Hour

// dormantRoot builds a root with the debian passwd (interactive: alice
// 1000, bob 1001) plus the given files.
func dormantRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	passwd, err := os.ReadFile(td(t, "root/debian/etc/passwd"))
	if err != nil {
		t.Fatal(err)
	}
	files["etc/passwd"] = string(passwd)
	files["etc/login.defs"] = "UID_MIN 1000\n"
	return writeTree(t, files)
}

func TestDormantAccounts(t *testing.T) {
	const boot, user, dead = 2, 7, 8
	tests := []struct {
		name     string
		files    map[string]string
		want     agentv1.CheckStatus
		evidence string
		absent   string
	}{
		{"recent logins", map[string]string{"var/log/wtmp": wtmp(
			login{boot, "reboot", 200 * day}, login{user, "alice", 10 * day}, login{user, "bob", 2 * day})}, PASS, "", ""},
		{"bob dormant", map[string]string{"var/log/wtmp": wtmp(
			login{user, "bob", 200 * day}, login{dead, "", 199 * day}, login{user, "alice", 10 * day})}, WARN, "bob (last login", "alice"},
		{"rotated wtmp counts", map[string]string{
			"var/log/wtmp.1": wtmp(login{user, "bob", 120 * day}, login{user, "alice", 100 * day}),
			"var/log/wtmp":   wtmp(login{user, "alice", 1 * day}),
		}, WARN, "bob (last login 2026-07-08)", "alice"},
		{"lastlog wins over old wtmp", map[string]string{
			"var/log/wtmp":    wtmp(login{user, "bob", 200 * day}, login{user, "alice", 1 * day}),
			"var/log/lastlog": lastlog(map[uint32]time.Duration{1001: 3 * day}),
		}, PASS, "", ""},
		{"never logged in (lastlog)", map[string]string{
			"var/log/lastlog": lastlog(map[uint32]time.Duration{1000: 1 * day}),
		}, WARN, "bob (never logged in)", "alice"},
		{"short wtmp leaves bob undetermined", map[string]string{"var/log/wtmp": wtmp(
			login{user, "alice", 5 * day})}, PASS, "", ""},
		{"no user records", map[string]string{"var/log/wtmp": wtmp(login{boot, "reboot", 5 * day})}, NA, "", ""},
		{"no records at all", map[string]string{}, NA, "", ""},
		{"empty files", map[string]string{"var/log/wtmp": "", "var/log/lastlog": ""}, NA, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: dormantRoot(t, tc.files)}, "ACC-004")
			expectStatus(t, r, tc.want)
			if tc.evidence != "" {
				expectEvidence(t, r, "accounts", tc.evidence)
			}
			if tc.absent != "" && strings.Contains(r.GetEvidence()["accounts"], tc.absent) {
				t.Fatalf("%s reported: %v", tc.absent, r.GetEvidence())
			}
			// Remote host names from wtmp never appear in evidence.
			assertNoSecrets(t, r)
			for _, v := range r.GetEvidence() {
				if strings.Contains(v, "203.0.113.7") {
					t.Fatalf("login source leaked: %q", v)
				}
			}
		})
	}
}

func TestDormantAccountsEdgeCases(t *testing.T) {
	// Only service accounts: nothing to evaluate.
	root := writeTree(t, map[string]string{"etc/passwd": "root:x:0:0::/root:/bin/bash\nwww:x:33:33::/var/www:/usr/sbin/nologin\n"})
	expectStatus(t, runCheck(t, Env{Root: root}, "ACC-004"), PASS)

	// Missing passwd.
	expectStatus(t, runCheck(t, Env{Root: t.TempDir()}, "ACC-004"), ERROR)

	// wtmpdb newer than the legacy files: legacy data is stale.
	root = dormantRoot(t, map[string]string{
		"var/log/wtmp":           wtmp(login{7, "bob", 200 * day}),
		"var/lib/wtmpdb/wtmp.db": "SQLite format 3",
	})
	old := t0.Add(-200 * day)
	if err := os.Chtimes(filepath.Join(root, "var/log/wtmp"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(root, "var/lib/wtmpdb/wtmp.db"), t0, t0); err != nil {
		t.Fatal(err)
	}
	r := runCheck(t, Env{Root: root}, "ACC-004")
	expectStatus(t, r, NA)
	expectEvidence(t, r, "database", "wtmpdb")

	// UID_MIN from login.defs is honoured.
	root = writeTree(t, map[string]string{
		"etc/passwd":     "carol:x:500:500::/home/carol:/bin/bash\n",
		"etc/login.defs": "UID_MIN 500\n",
		"var/log/wtmp":   wtmp(login{7, "carol", 300 * day}),
	})
	r = runCheck(t, Env{Root: root}, "ACC-004")
	expectStatus(t, r, WARN)
	expectEvidence(t, r, "accounts", "carol")

	// Truncated trailing record and a huge file tail are handled.
	root = dormantRoot(t, map[string]string{"var/log/wtmp": wtmp(login{7, "alice", 1 * day}, login{7, "bob", 1 * day}) + "partial"})
	expectStatus(t, runCheck(t, Env{Root: root}, "ACC-004"), PASS)
}

func TestReadWtmpTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wtmp")
	data := wtmp(login{7, "old", 300 * day}, login{7, "mid", 200 * day}, login{7, "new", 1 * day})
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	ld := &loginData{last: map[string]time.Time{}}
	if err := readWtmp(p, 2*utmpRecordSize, ld); err != nil {
		t.Fatal(err)
	}
	if _, ok := ld.last["old"]; ok || ld.last["new"].IsZero() || ld.last["mid"].IsZero() {
		t.Fatalf("tail read: %v", ld.last)
	}
	if !ld.earliest.Equal(t0.Add(-200 * day).Truncate(time.Second)) {
		t.Fatalf("earliest = %v", ld.earliest)
	}
}

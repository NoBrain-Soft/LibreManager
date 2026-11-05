package checks

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/validate"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

var wantIDs = []string{
	"SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005", "SSH-006", "SSH-007", "SSH-008", "SSH-009", "SSH-010",
	"ACC-001", "ACC-002", "ACC-003", "ACC-004",
	"PKG-001", "PKG-002", "PKG-003",
	"NET-001", "NET-002",
	"KRN-001",
	"FS-001", "FS-002",
	"SVC-001", "SVC-002",
	"TIME-001", "LOG-001", "CRT-001", "MAC-001", "AGT-001",
}

func TestCatalog(t *testing.T) {
	defs := Catalog()
	var ids []string
	for _, d := range defs {
		ids = append(ids, d.ID)
		if !validate.CheckID(d.ID) {
			t.Errorf("invalid check id %q", d.ID)
		}
		if d.Title == "" || d.Rationale == "" || d.Remediation == "" || len(d.Title) > maxTitle {
			t.Errorf("%s: incomplete definition", d.ID)
		}
		if d.Severity == agentv1.Severity_SEVERITY_UNSPECIFIED {
			t.Errorf("%s: no severity", d.ID)
		}
	}
	if !slices.Equal(ids, wantIDs) {
		t.Fatalf("catalog ids = %v\nwant %v", ids, wantIDs)
	}
	// Catalog returns a copy.
	defs[0].Title = "changed"
	if Catalog()[0].Title == "changed" {
		t.Fatal("Catalog exposes internal state")
	}
}

func TestRunSelection(t *testing.T) {
	env := Env{Root: t.TempDir(), ProcRoot: t.TempDir(), SysRoot: t.TempDir(), Exec: newExec(nil), Now: fixedNow}
	rep := Run(context.Background(), env, nil)
	if rep.GetCollectedAtMs() != t0.UnixMilli() {
		t.Fatalf("collected_at = %d", rep.GetCollectedAtMs())
	}
	var got []string
	for _, r := range rep.GetResults() {
		got = append(got, r.GetCheckId())
	}
	if !slices.Equal(got, wantIDs) {
		t.Fatalf("all checks: %v", got)
	}

	rep = Run(context.Background(), env, []string{"AGT-001", "NOPE-001", "SSH-001", "AGT-001", ""})
	got = got[:0]
	for _, r := range rep.GetResults() {
		got = append(got, r.GetCheckId())
	}
	if !slices.Equal(got, []string{"SSH-001", "AGT-001"}) {
		t.Fatalf("selected checks: %v (want catalog order, unknown ignored, no duplicates)", got)
	}
	if rep := Run(context.Background(), env, []string{"NOPE-001"}); len(rep.GetResults()) != 0 {
		t.Fatalf("unknown only: %v", rep.GetResults())
	}
}

// TestRunRobust runs every check against empty trees, a runner that fails
// every command and both no helper and a panicking helper: no check may
// panic or report an unspecified status.
func TestRunRobust(t *testing.T) {
	failing := &errExec{err: errors.New("exec failed")}
	for _, tc := range []struct {
		name string
		priv Privileged
		exec CommandRunner
	}{
		{"no helper", nil, failing},
		{"panicking helper", &fakePriv{panics: true}, failing},
		{"helper errors", &fakePriv{sshdErr: errors.New("x"), shadowErr: errors.New("x"), sudoErr: errors.New("x")}, newExec(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := Env{Root: t.TempDir(), ProcRoot: t.TempDir(), SysRoot: t.TempDir(), Exec: tc.exec, Privileged: tc.priv, Now: fixedNow}
			for _, r := range Run(context.Background(), env, nil).GetResults() {
				switch r.GetStatus() {
				case PASS, FAIL, WARN, NA, ERROR:
				default:
					t.Errorf("%s: status %v", r.GetCheckId(), r.GetStatus())
				}
				if r.GetSummary() == "" {
					t.Errorf("%s: empty summary", r.GetCheckId())
				}
				// Nothing to look at must never look "clean" for checks
				// that depend on the helper.
				if strings.HasPrefix(r.GetCheckId(), "ACC-002") && r.GetStatus() == PASS {
					t.Errorf("ACC-002 passed without shadow data")
				}
				assertLimits(t, r)
			}
		})
	}
}

type errExec struct{ err error }

func (e *errExec) Run(context.Context, string, ...string) ([]byte, int, error) { return nil, -1, e.err }

func TestPanickingPrivilegedIsError(t *testing.T) {
	env := Env{Root: td(t, "root/debian"), Privileged: &fakePriv{panics: true}}
	res := runIDs(t, env, "ACC-002", "ACC-003", "SSH-001", "SSH-002")
	for id, r := range res {
		if r.GetStatus() != ERROR {
			t.Errorf("%s: %s, want ERROR after helper panic", id, r.GetStatus())
		}
	}
}

func TestRunOneIsolation(t *testing.T) {
	rs := newRunState(Env{}.withDefaults())
	ctx := context.Background()

	panicky := &check{Definition: Definition{ID: "TST-001"}, run: func(context.Context, *runState) result {
		panic("boom")
	}}
	if r := runOne(ctx, rs, panicky, time.Second); r.status != ERROR || !strings.Contains(r.summary, "panicked") {
		t.Fatalf("panic: %+v", r)
	}

	block := make(chan struct{})
	defer close(block)
	stuck := &check{Definition: Definition{ID: "TST-002"}, run: func(context.Context, *runState) result {
		<-block // ignores its context
		return pass("late")
	}}
	start := time.Now()
	if r := runOne(ctx, rs, stuck, 50*time.Millisecond); r.status != ERROR || !strings.Contains(r.summary, "timed out") {
		t.Fatalf("timeout: %+v", r)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if r := runOne(cctx, rs, stuck, time.Second); r.status != ERROR || !strings.Contains(r.summary, "cancelled") {
		t.Fatalf("cancelled: %+v", r)
	}

	failing := &check{Definition: Definition{ID: "TST-003"}, run: func(context.Context, *runState) result {
		return errResult("reading x", errors.New("permission denied"))
	}}
	if r := runOne(ctx, rs, failing, time.Second); r.status != ERROR || r.summary != "reading x: permission denied" {
		t.Fatalf("error: %+v", r)
	}
}

func TestRunCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := Run(ctx, Env{Root: t.TempDir(), Exec: newExec(nil), Now: fixedNow}, []string{"ACC-001", "AGT-001"})
	for _, r := range rep.GetResults() {
		expectStatus(t, r, ERROR)
	}
}

func TestFinalizeLimits(t *testing.T) {
	d := &Definition{ID: "TST-001", Title: strings.Repeat("t", 400), Severity: sevLow}
	r := pass(strings.Repeat("s", 2000))
	for i := range 40 {
		r = r.with(fmt.Sprintf("key%02d", i), strings.Repeat("v", 1000))
	}
	r = r.with(strings.Repeat("k", 100), "long key")
	r = r.with("", "dropped")
	out := d.finalize(r)
	assertLimits(t, out)
	if len(out.GetEvidence()) != MaxEvidenceEntries || out.GetEvidence()["evidence_truncated"] == "" {
		t.Fatalf("evidence: %d entries, truncated=%q", len(out.GetEvidence()), out.GetEvidence()["evidence_truncated"])
	}
	if out.GetStatus() != PASS || out.GetCheckId() != "TST-001" || out.GetSeverity() != sevLow {
		t.Fatalf("result: %v", out)
	}
	if bad := d.finalize(result{summary: "x"}); bad.GetStatus() != ERROR {
		t.Fatalf("unspecified status became %v", bad.GetStatus())
	}
	if bad := d.finalize(result{status: 99, summary: "x"}); bad.GetStatus() != ERROR {
		t.Fatalf("invalid status became %v", bad.GetStatus())
	}
	ctl := d.finalize(pass("a\x00b\nc", "k\x1b", "v\x07"))
	if strings.ContainsAny(ctl.GetSummary(), "\x00\n") || ctl.GetEvidence()["k?"] != "v?" {
		t.Fatalf("control characters not sanitized: %q %v", ctl.GetSummary(), ctl.GetEvidence())
	}
}

func TestRedaction(t *testing.T) {
	d := &Definition{ID: "TST-001", Title: "t", Severity: sevLow}
	for _, v := range []string{
		"$6$saltsalt$abcdefghijklmnop", "user:$y$j9T$abc$def:19000", "$2b$12$abc", "$argon2id$v=19$m=65536",
		"$1$abc$def", "-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		out := d.finalize(fail("summary "+v, "accounts", v, "k", "fine"))
		if out.GetEvidence()["accounts"] != "[redacted]" || out.GetSummary() != "[redacted]" || out.GetEvidence()["k"] != "fine" {
			t.Errorf("%q not redacted: %q / %v", v, out.GetSummary(), out.GetEvidence())
		}
		assertNoSecrets(t, out)
	}
	if got := redact("hmac-sha1-etm@openssh.com, $HOME"); got != "hmac-sha1-etm@openssh.com, $HOME" {
		t.Errorf("benign value redacted: %q", got)
	}
}

func TestJoinCapped(t *testing.T) {
	if got := joinCapped([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("got %q", got)
	}
	if got := joinCapped(nil); got != "" {
		t.Fatalf("got %q", got)
	}
	var items []string
	for i := range 500 {
		items = append(items, fmt.Sprintf("/usr/bin/program-%03d", i))
	}
	got := joinCapped(items)
	if len(got) > MaxEvidenceValue || !strings.HasPrefix(got, "/usr/bin/program-000, ") || !strings.HasSuffix(got, " more)") {
		t.Fatalf("got %d bytes: %q", len(got), got)
	}
	huge := joinCapped([]string{strings.Repeat("x", 600), "y"})
	if len(huge) > MaxEvidenceValue || huge != "(+2 more)" {
		t.Fatalf("oversized first item: %q", huge)
	}
}

func TestEnvDefaults(t *testing.T) {
	e := Env{}.withDefaults()
	if e.Root != "/" || e.ProcRoot != "/proc" || e.SysRoot != "/sys" || e.Exec == nil || e.Now == nil ||
		e.CheckTimeout != DefaultCheckTimeout {
		t.Fatalf("defaults: %+v", e)
	}
	if !slices.Equal(e.RequiredServices, DefaultRequiredServices()) || !slices.Equal(e.ListenAllowlist, []string{"tcp:22"}) ||
		!slices.Equal(e.CertDirs, DefaultCertDirs()) {
		t.Fatalf("list defaults: %+v", e)
	}
	// An explicitly empty list is kept (disables SVC-001).
	if e := (Env{RequiredServices: []string{}}).withDefaults(); e.RequiredServices == nil || len(e.RequiredServices) != 0 {
		t.Fatal("empty RequiredServices replaced by default")
	}
}

// TestOnlyReadOnlyCommands runs every check with a recording runner and
// asserts that only the closed set of read-only programs is invoked, with
// argv arrays and no shell.
func TestOnlyReadOnlyCommands(t *testing.T) {
	ex := newExec(nil)
	env := Env{Root: td(t, "root/debian"), ProcRoot: td(t, "proc/hardened"), SysRoot: td(t, "sys/apparmor"), Exec: ex}
	runIDs(t, env)
	calls := ex.allCalls()
	if len(calls) == 0 {
		t.Fatal("no commands recorded")
	}
	for _, argv := range calls {
		if !readOnlyProgram(argv[0]) {
			t.Errorf("unexpected program %v", argv)
		}
		for _, a := range argv[1:] {
			if a == "-c" || strings.ContainsAny(a, ";|&`$") {
				t.Errorf("suspicious argument in %v", argv)
			}
		}
		if argv[0] == "systemctl" && !slices.Contains([]string{"is-active", "is-enabled", "list-units"}, argv[1]) {
			t.Errorf("systemctl verb %v is not read-only", argv)
		}
	}
}

// TestFullRunNoSecrets runs everything on the weak RHEL fixture whose
// /etc/passwd carries a password hash in the password field and whose
// helper data contains hash-like strings.
func TestFullRunNoSecrets(t *testing.T) {
	priv := &fakePriv{
		sshd:  sshdFixture(t, "weak.txt"),
		empty: []string{"guest", "$6$saltsalt$Zx3KoMkF"},
		sudo:  []string{"toor ALL=(ALL) NOPASSWD: ALL", "%wheel ALL=(ALL) ALL"},
	}
	env := Env{Root: td(t, "root/rhel"), ProcRoot: td(t, "proc/weak"), SysRoot: td(t, "sys/none"), Privileged: priv,
		Exec: newExec(nil), AgentVersion: "0.1.0", LatestAgentVersion: "0.2.0"}
	res := runIDs(t, env)
	if len(res) != len(wantIDs) {
		t.Fatalf("%d results", len(res))
	}
	for _, r := range res {
		assertNoSecrets(t, r)
		assertLimits(t, r)
	}
	expectStatus(t, res["ACC-001"], FAIL)
	expectEvidence(t, res["ACC-001"], "accounts", "toor")
	expectStatus(t, res["ACC-002"], FAIL)
	if priv.sshdCalls.Load() != 1 {
		t.Fatalf("sshd -T fetched %d times, want once per run", priv.sshdCalls.Load())
	}
}

type fakeReader struct {
	data *helperv1.PrivilegedData
	err  error
	kind helperv1.PrivilegedKind
}

func (f *fakeReader) ReadPrivileged(_ context.Context, kind helperv1.PrivilegedKind) (*helperv1.PrivilegedData, error) {
	f.kind = kind
	return f.data, f.err
}

func TestHelperPrivileged(t *testing.T) {
	ctx := context.Background()
	r := &fakeReader{data: &helperv1.PrivilegedData{
		Values:             map[string]string{"PermitRootLogin": "no"},
		EmptyPasswordUsers: []string{"guest"}, LockedUsers: []string{"daemon", "bin"},
		SudoRules: []string{"%sudo ALL=(ALL:ALL) ALL"},
	}}
	p := HelperPrivileged(r)
	cfg, err := p.SshdConfig(ctx)
	if err != nil || cfg["permitrootlogin"] != "no" || r.kind != helperv1.PrivilegedKind_PRIVILEGED_KIND_SSHD_EFFECTIVE_CONFIG {
		t.Fatalf("sshd: %v %v %v", cfg, err, r.kind)
	}
	empty, locked, err := p.ShadowFlags(ctx)
	if err != nil || !slices.Equal(empty, []string{"guest"}) || len(locked) != 2 || r.kind != helperv1.PrivilegedKind_PRIVILEGED_KIND_SHADOW_FLAGS {
		t.Fatalf("shadow: %v %v %v", empty, locked, err)
	}
	rules, err := p.SudoRules(ctx)
	if err != nil || len(rules) != 1 || r.kind != helperv1.PrivilegedKind_PRIVILEGED_KIND_SUDOERS {
		t.Fatalf("sudo: %v %v", rules, err)
	}

	r.err = errors.New("helper error: sshd -T: runner: program not found in trusted directories: sshd")
	if _, err := p.SshdConfig(ctx); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("missing sshd: %v", err)
	}
	r.err = errors.New("helper error: helper: open /etc/sudoers: no such file or directory")
	if _, err := p.SudoRules(ctx); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("missing sudoers: %v", err)
	}
	r.err = errors.New("helper error: policy: denied: security checks and inventory disabled")
	if _, _, err := p.ShadowFlags(ctx); err == nil || errors.Is(err, ErrNotInstalled) {
		t.Fatalf("denied: %v", err)
	}
	if _, err := p.SshdConfig(ctx); err == nil || errors.Is(err, ErrNotInstalled) {
		t.Fatalf("denied sshd: %v", err)
	}
	if _, err := HelperPrivileged(nil).SshdConfig(ctx); err == nil {
		t.Fatal("nil client accepted")
	}
}

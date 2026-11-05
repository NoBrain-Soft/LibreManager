package checks

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const (
	PASS  = agentv1.CheckStatus_CHECK_STATUS_PASS
	FAIL  = agentv1.CheckStatus_CHECK_STATUS_FAIL
	WARN  = agentv1.CheckStatus_CHECK_STATUS_WARN
	NA    = agentv1.CheckStatus_CHECK_STATUS_NA
	ERROR = agentv1.CheckStatus_CHECK_STATUS_ERROR
)

// --- fake command runner -------------------------------------------------------

type cmdResp struct {
	out  string
	code int
	err  error
}

// fakeExec answers commands by their full argv joined with spaces; unknown
// commands behave like missing programs.
type fakeExec struct {
	mu    sync.Mutex
	resp  map[string]cmdResp
	calls [][]string
}

func newExec(resp map[string]cmdResp) *fakeExec { return &fakeExec{resp: resp} }

func (f *fakeExec) Run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	argv := append([]string{name}, args...)
	f.mu.Lock()
	f.calls = append(f.calls, argv)
	r, ok := f.resp[strings.Join(argv, " ")]
	f.mu.Unlock()
	if !ok {
		return nil, -1, fmt.Errorf("%w: %s", ErrCommandNotFound, name)
	}
	return []byte(r.out), r.code, r.err
}

func (f *fakeExec) allCalls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}

// --- fake privileged -------------------------------------------------------------

type fakePriv struct {
	sshd          map[string]string
	sshdErr       error
	empty, locked []string
	shadowErr     error
	sudo          []string
	sudoErr       error
	panics        bool
	sshdCalls     atomic.Int32
}

func (p *fakePriv) ShadowFlags(context.Context) ([]string, []string, error) {
	if p.panics {
		panic("shadow boom")
	}
	return p.empty, p.locked, p.shadowErr
}

func (p *fakePriv) SshdConfig(context.Context) (map[string]string, error) {
	p.sshdCalls.Add(1)
	if p.panics {
		panic("sshd boom")
	}
	return p.sshd, p.sshdErr
}

func (p *fakePriv) SudoRules(context.Context) ([]string, error) {
	if p.panics {
		panic("sudo boom")
	}
	return p.sudo, p.sudoErr
}

// --- fixtures ----------------------------------------------------------------------

// td returns the absolute path of a testdata fixture.
func td(t testing.TB, p string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", p))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// writeTree creates files (path -> content) below a new temp dir. A path
// ending in "/" creates a directory.
func writeTree(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	addFiles(t, dir, files)
	return dir
}

func addFiles(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(dir, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// copyTree copies a testdata tree into a temp dir for modification.
func copyTree(t testing.TB, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p) //nolint:gosec // test fixture
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func sshdFixture(t testing.TB, name string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(td(t, "sshd/"+name))
	if err != nil {
		t.Fatal(err)
	}
	return ParseSSHDConfig(data)
}

// --- running -----------------------------------------------------------------------

func fixedNow() time.Time { return t0 }

func runIDs(t testing.TB, env Env, ids ...string) map[string]*agentv1.CheckResult {
	t.Helper()
	if env.Now == nil {
		env.Now = fixedNow
	}
	if env.Exec == nil {
		env.Exec = newExec(nil)
	}
	rep := Run(context.Background(), env, ids)
	out := map[string]*agentv1.CheckResult{}
	for _, r := range rep.GetResults() {
		out[r.GetCheckId()] = r
	}
	if len(ids) > 0 && len(out) != len(ids) {
		t.Fatalf("got %d results for %v", len(out), ids)
	}
	return out
}

func runCheck(t testing.TB, env Env, id string) *agentv1.CheckResult {
	t.Helper()
	return runIDs(t, env, id)[id]
}

func expectStatus(t testing.TB, r *agentv1.CheckResult, want agentv1.CheckStatus) {
	t.Helper()
	if r.GetStatus() != want {
		t.Fatalf("%s: status %s, want %s (summary %q, evidence %v)", r.GetCheckId(), r.GetStatus(), want, r.GetSummary(), r.GetEvidence())
	}
}

func expectEvidence(t testing.TB, r *agentv1.CheckResult, key, substr string) {
	t.Helper()
	v, ok := r.GetEvidence()[key]
	if !ok || !strings.Contains(v, substr) {
		t.Fatalf("%s: evidence[%q] = %q (present %v), want it to contain %q; all: %v", r.GetCheckId(), key, v, ok, substr, r.GetEvidence())
	}
}

// secretMarkers must never appear in results: crypt(3) hash prefixes, PEM
// private keys and the fake hash material planted in fixtures.
var secretMarkers = []string{"$1$", "$5$", "$6$", "$y$", "$2b$", "$argon2", "PRIVATE KEY", "saltsalt", "Zx3KoMkF"}

func assertNoSecrets(t testing.TB, results ...*agentv1.CheckResult) {
	t.Helper()
	for _, r := range results {
		texts := []string{r.GetSummary(), r.GetTitle()}
		for k, v := range r.GetEvidence() {
			texts = append(texts, k, v)
		}
		for _, s := range texts {
			for _, m := range secretMarkers {
				if strings.Contains(s, m) {
					t.Fatalf("%s: result contains secret marker %q: %q", r.GetCheckId(), m, s)
				}
			}
		}
	}
}

func assertLimits(t testing.TB, r *agentv1.CheckResult) {
	t.Helper()
	if len(r.GetEvidence()) > MaxEvidenceEntries {
		t.Fatalf("%s: %d evidence entries", r.GetCheckId(), len(r.GetEvidence()))
	}
	for k, v := range r.GetEvidence() {
		if len(k) > MaxEvidenceKey || len(v) > MaxEvidenceValue {
			t.Fatalf("%s: evidence %q (%d bytes) exceeds limits", r.GetCheckId(), k, len(v))
		}
	}
	if len(r.GetSummary()) > maxSummary || len(r.GetTitle()) > maxTitle {
		t.Fatalf("%s: summary/title too long", r.GetCheckId())
	}
}

// Package checks implements the agent's built-in security checks
// (ARCHITECTURE.md §7.1).
//
// The agent core runs unprivileged and sandboxed (ProtectSystem=strict,
// ProtectHome=yes), so checks only
//   - read world-readable files below Env.Root, Env.ProcRoot and Env.SysRoot,
//   - run a fixed set of read-only programs through Env.Exec (argv only,
//     never a shell), and
//   - obtain root-only facts (shadow flags, `sshd -T`, sudoers) exclusively
//     through Env.Privileged, which is backed by the helper's typed
//     ReadPrivileged RPC.
//
// Evidence is kept small (≤ 32 entries, values ≤ 512 bytes, the gateway's
// limits) and never contains secrets: shadow data arrives as account names
// only, and every evidence value passes a redaction filter for password-hash
// and private-key material before it leaves the package.
package checks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/common/validate"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Limits mirrored from the gateway (internal/server/gateway/ingest.go),
// which truncates anything larger.
const (
	MaxEvidenceEntries = 32
	MaxEvidenceKey     = 64
	MaxEvidenceValue   = 512
	maxTitle           = 256
	maxSummary         = 1024
)

// DefaultCheckTimeout bounds a single check when Env.CheckTimeout is unset.
const DefaultCheckTimeout = 10 * time.Second

// Definition describes one check (ARCHITECTURE.md §7.1).
type Definition struct {
	ID          string
	Title       string
	Severity    agentv1.Severity
	Rationale   string
	Remediation string
}

// Privileged provides facts only root can read. It is implemented by an
// adapter over the helper client (see HelperPrivileged). Any method may fail
// (helper unavailable, policy denied); the affected checks then report
// status ERROR, or NA when the error wraps ErrNotInstalled.
type Privileged interface {
	// ShadowFlags returns account names with an empty or locked password
	// field. Implementations must never return hashes.
	ShadowFlags(ctx context.Context) (emptyPassword, locked []string, err error)
	// SshdConfig returns the effective sshd configuration with lowercase
	// keys, as printed by `sshd -T`.
	SshdConfig(ctx context.Context) (map[string]string, error)
	// SudoRules returns sudoers rule summaries such as
	// "%sudo ALL=(ALL:ALL) NOPASSWD: ALL".
	SudoRules(ctx context.Context) ([]string, error)
}

// ErrNotInstalled is wrapped by Privileged implementations when the
// component they read (sshd, sudo) is not installed; checks report NA.
var ErrNotInstalled = errors.New("checks: component not installed")

// Env is everything a check run may look at. The zero value inspects the
// local host with the defaults documented per field.
type Env struct {
	// Root, ProcRoot and SysRoot default to "/", "/proc" and "/sys". Tests
	// point them at fixture trees.
	Root, ProcRoot, SysRoot string
	// Exec runs read-only programs (systemctl is-active, timedatectl show,
	// ...). Defaults to &ExecRunner{}.
	Exec CommandRunner
	// Privileged may be nil (helper not installed or disabled).
	Privileged Privileged
	// Updates is the last pending-updates report (may be nil) for
	// PKG-001/PKG-002.
	Updates *agentv1.UpdatesReport
	// AgentVersion and LatestAgentVersion feed AGT-001; an empty latest
	// version yields NA.
	AgentVersion, LatestAgentVersion string
	// RequiredServices lists units that must be active (SVC-001); an entry
	// may name alternatives separated by "|". nil means
	// DefaultRequiredServices(); an empty non-nil slice disables SVC-001.
	RequiredServices []string
	// ListenAllowlist holds allowed non-loopback listeners for NET-001 as
	// "proto:port" or "proto:lo-hi" (proto tcp or udp, covering IPv4 and
	// IPv6). nil means DefaultListenAllowlist().
	ListenAllowlist []string
	// CertDirs are scanned for TLS certificates (CRT-001). nil means
	// DefaultCertDirs().
	CertDirs []string
	// Now defaults to time.Now.
	Now func() time.Time

	// Adjtimex, when set, is used first by TIME-001 (typically
	// unix.Adjtimex). It is opt-in because the adjtimex syscall belongs to
	// systemd's @clock filter group, which SystemCallFilter=@system-service
	// does not allow; without it TIME-001 asks timedatectl/chronyc.
	Adjtimex func(*unix.Timex) (int, error)
	// CheckTimeout bounds each check (default DefaultCheckTimeout).
	CheckTimeout time.Duration
}

// DefaultRequiredServices is the SVC-001 default: some time sync daemon.
func DefaultRequiredServices() []string {
	return []string{"chronyd.service|chrony.service|systemd-timesyncd.service"}
}

// DefaultListenAllowlist is the NET-001 default: SSH only.
func DefaultListenAllowlist() []string { return []string{"tcp:22"} }

// DefaultCertDirs are the CRT-001 default directories. CA bundles
// (/etc/ssl/certs, /etc/pki/ca-trust) are skipped even when listed.
func DefaultCertDirs() []string {
	return []string{
		"/etc/ssl", "/etc/pki/tls", "/etc/letsencrypt/live", "/etc/nginx", "/etc/apache2",
		"/etc/httpd", "/etc/haproxy", "/etc/postfix", "/etc/dovecot",
	}
}

func (e Env) withDefaults() Env {
	if e.Root == "" {
		e.Root = "/"
	}
	if e.ProcRoot == "" {
		e.ProcRoot = "/proc"
	}
	if e.SysRoot == "" {
		e.SysRoot = "/sys"
	}
	if e.Exec == nil {
		e.Exec = &ExecRunner{}
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.RequiredServices == nil {
		e.RequiredServices = DefaultRequiredServices()
	}
	if e.ListenAllowlist == nil {
		e.ListenAllowlist = DefaultListenAllowlist()
	}
	if e.CertDirs == nil {
		e.CertDirs = DefaultCertDirs()
	}
	if e.CheckTimeout <= 0 {
		e.CheckTimeout = DefaultCheckTimeout
	}
	return e
}

// Catalog returns all checks in stable order.
func Catalog() []Definition {
	out := make([]Definition, len(catalog))
	for i := range catalog {
		out[i] = catalog[i].Definition
	}
	return out
}

// Run executes the checks named by ids (all when empty; unknown ids are
// ignored) in catalog order. Each check is bounded by Env.CheckTimeout; a
// check that fails, panics or times out yields status ERROR for that check
// only.
func Run(ctx context.Context, env Env, ids []string) *agentv1.CheckReport {
	env = env.withDefaults()
	rs := newRunState(env)
	report := &agentv1.CheckReport{CollectedAtMs: rs.now.UnixMilli()}
	for i := range catalog {
		c := &catalog[i]
		if len(ids) > 0 && !slices.Contains(ids, c.ID) {
			continue
		}
		report.Results = append(report.Results, c.finalize(runOne(ctx, rs, c, env.CheckTimeout)))
	}
	return report
}

type checkFunc func(ctx context.Context, r *runState) result

type check struct {
	Definition
	run checkFunc
}

// runOne runs c in its own goroutine so that a check ignoring its context
// cannot stall the whole run. A check that outlives its timeout keeps
// running in the background until its own I/O ends; its late result is
// dropped.
func runOne(ctx context.Context, rs *runState, c *check, timeout time.Duration) result {
	if ctx.Err() != nil {
		return errResult("check run cancelled", nil)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				slog.Error("security check panicked", "check_id", c.ID, "panic", fmt.Sprint(p))
				done <- errResult("internal error: check panicked", nil)
			}
		}()
		done <- c.run(cctx, rs)
	}()
	select {
	case res := <-done:
		return res
	case <-cctx.Done():
		if ctx.Err() != nil {
			return errResult("check run cancelled", nil)
		}
		return errResult(fmt.Sprintf("check timed out after %s", timeout), nil)
	}
}

// runState is shared by the checks of one Run. Lazily computed values use
// sync.Once because a timed-out check may still be running while the next
// one starts.
type runState struct {
	env  Env
	now  time.Time
	priv Privileged // memoized; nil when env.Privileged is nil

	osOnce sync.Once
	osRel  osRelease
	osErr  error

	pwOnce sync.Once
	pw     []passwdEntry
	pwErr  error
}

func newRunState(env Env) *runState {
	rs := &runState{env: env, now: env.Now()}
	if env.Privileged != nil {
		rs.priv = &memoPrivileged{p: env.Privileged}
	}
	return rs
}

// --- results ---------------------------------------------------------------

type kv struct{ k, v string }

type result struct {
	status  agentv1.CheckStatus
	summary string
	kv      []kv
}

func newResult(st agentv1.CheckStatus, summary string, kvs []string) result {
	r := result{status: st, summary: summary}
	for i := 0; i+1 < len(kvs); i += 2 {
		r.kv = append(r.kv, kv{kvs[i], kvs[i+1]})
	}
	return r
}

func pass(summary string, kvs ...string) result {
	return newResult(agentv1.CheckStatus_CHECK_STATUS_PASS, summary, kvs)
}

func fail(summary string, kvs ...string) result {
	return newResult(agentv1.CheckStatus_CHECK_STATUS_FAIL, summary, kvs)
}

func warn(summary string, kvs ...string) result {
	return newResult(agentv1.CheckStatus_CHECK_STATUS_WARN, summary, kvs)
}

func na(summary string, kvs ...string) result {
	return newResult(agentv1.CheckStatus_CHECK_STATUS_NA, summary, kvs)
}

func errResult(summary string, err error, kvs ...string) result {
	if err != nil {
		summary += ": " + err.Error()
	}
	return newResult(agentv1.CheckStatus_CHECK_STATUS_ERROR, summary, kvs)
}

// with returns r with one more evidence entry (r itself is not modified).
func (r result) with(k, v string) result {
	r.kv = append(slices.Clip(r.kv), kv{k, v})
	return r
}

// secretPattern matches crypt(3) hash prefixes and PEM private keys. A value
// that matches is replaced wholesale: evidence must never carry such
// material, whatever a check (or a buggy helper) produced.
var secretPattern = regexp.MustCompile(`\$(1|2[abxy]?|5|6|7|y|gy|md5|sha1|argon2(id|i|d)?)\$|PRIVATE KEY`)

func redact(s string) string {
	if secretPattern.MatchString(s) {
		return "[redacted]"
	}
	return s
}

func (d *Definition) finalize(r result) *agentv1.CheckResult {
	st := r.status
	if _, ok := agentv1.CheckStatus_name[int32(st)]; !ok || st == agentv1.CheckStatus_CHECK_STATUS_UNSPECIFIED {
		st = agentv1.CheckStatus_CHECK_STATUS_ERROR
	}
	ev := make(map[string]string, min(len(r.kv), MaxEvidenceEntries))
	dropped := 0
	for _, e := range r.kv {
		k := validate.Text(e.k, MaxEvidenceKey)
		if k == "" {
			continue
		}
		if _, dup := ev[k]; !dup && len(ev) >= MaxEvidenceEntries-1 {
			dropped++
			continue
		}
		ev[k] = redact(validate.Text(e.v, MaxEvidenceValue))
	}
	if dropped > 0 {
		ev["evidence_truncated"] = fmt.Sprintf("%d more entries omitted", dropped)
	}
	return &agentv1.CheckResult{
		CheckId:  d.ID,
		Status:   st,
		Severity: d.Severity,
		Title:    validate.Text(d.Title, maxTitle),
		Summary:  redact(validate.Text(r.summary, maxSummary)),
		Evidence: ev,
	}
}

// joinCapped joins items with ", " into at most MaxEvidenceValue bytes and
// notes how many items did not fit.
func joinCapped(items []string) string {
	var b strings.Builder
	for i, it := range items {
		sep, more := "", ""
		if i > 0 {
			sep = ", "
		}
		if left := len(items) - i - 1; left > 0 {
			more = fmt.Sprintf(" (+%d more)", left)
		}
		// Room for the "(+k more)" suffix was reserved when the previous
		// item was written, so stopping here always fits.
		if b.Len()+len(sep)+len(it)+len(more) > MaxEvidenceValue {
			fmt.Fprintf(&b, " (+%d more)", len(items)-i)
			return strings.TrimSpace(b.String())
		}
		b.WriteString(sep)
		b.WriteString(it)
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

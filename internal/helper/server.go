// Package helper implements stellwerk-agent-helper, the small root process
// that performs privileged work for the unprivileged agent core
// (ARCHITECTURE.md §5.1).
//
// The helper trusts nothing it receives: it checks the peer uid, loads the
// local policy, host identity and pinned job keys itself, re-verifies every
// SignedJob (signature, host, time window, nonce), re-applies policy and its
// own rate limit, and writes a journald entry before executing anything.
// The RPC set is fixed (helper.proto); there is no generic command endpoint.
package helper

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/framing"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/journal"
	"github.com/nobrain-soft/libremanager/internal/common/version"
	"github.com/nobrain-soft/libremanager/internal/helper/pkgmgr"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

// CommandRunner executes external programs (see package runner).
type CommandRunner = runner.Runner

// JournalWriter writes the on-host audit trail (see package journal).
type JournalWriter = journal.Writer

// Default file locations.
const (
	DefaultHostIDPath = "/etc/stellwerk/host-id"
	DefaultJobKeysDir = "/etc/stellwerk/jobkeys.d"
	DefaultStateDir   = "/var/lib/stellwerk-agent-helper"
)

// Limits.
const (
	maxChunk         = 32 << 10
	maxJobOutput     = 4 << 20
	maxKeys          = 16
	maxReportUpdates = 5000
	defaultMaxConns  = 32
)

// Paths are the privileged files the helper reads (overridable for tests).
type Paths struct {
	Shadow    string // /etc/shadow
	Sudoers   string // /etc/sudoers
	Proc      string // /proc
	OSRelease string // /etc/os-release
}

// Config configures a Server. Zero values select production defaults.
type Config struct {
	PolicyPath string
	HostIDPath string
	JobKeysDir string
	StateDir   string
	// AllowedUID is the stellwerk-agent uid; root (0) is always allowed.
	AllowedUID int
	// TimeSynced reports clock synchronization. nil means "unknown", which
	// rejects jobs when the policy requires time sync.
	TimeSynced func() (bool, error)
	Now        func() time.Time
	Runner     CommandRunner
	// PkgManager nil = autodetect on first use.
	PkgManager pkgmgr.Manager
	Journal    JournalWriter
	Logger     *slog.Logger
	// Users resolves accounts for policy and shell spawning.
	Users policy.UserLookup
	// LoginShell returns the shell to start for a user (default: from
	// /etc/passwd, must be an absolute executable, not nologin/false).
	LoginShell func(u *user.User) (string, error)
	Version    string
	Paths      Paths
	// RequestTimeout bounds reading the request (default 10 s); WriteTimeout
	// bounds each response frame (default 30 s).
	RequestTimeout time.Duration
	WriteTimeout   time.Duration
	// MaxConns bounds concurrent connections (default 32).
	MaxConns int
	// SkipOwnerChecks disables the root-ownership checks of policy, host
	// id, job keys and state dir. FOR TESTS ONLY; main never sets it.
	SkipOwnerChecks bool
}

// Server is the helper RPC server.
type Server struct {
	cfg    Config
	log    *slog.Logger
	nonces *envelope.FileNonceStore

	mu      sync.Mutex
	limiter *policy.RateLimiter
	limit   int
	shells  int
	pm      pkgmgr.Manager
}

// NewServer validates cfg, applies defaults and opens the persistent nonce
// store in StateDir.
func NewServer(cfg Config) (*Server, error) {
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&cfg.PolicyPath, policy.DefaultPath)
	def(&cfg.HostIDPath, DefaultHostIDPath)
	def(&cfg.JobKeysDir, DefaultJobKeysDir)
	def(&cfg.StateDir, DefaultStateDir)
	def(&cfg.Version, version.Version)
	def(&cfg.Paths.Shadow, "/etc/shadow")
	def(&cfg.Paths.Sudoers, "/etc/sudoers")
	def(&cfg.Paths.Proc, "/proc")
	def(&cfg.Paths.OSRelease, "/etc/os-release")
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Runner == nil {
		cfg.Runner = &runner.Exec{}
	}
	if cfg.Journal == nil {
		cfg.Journal = journal.New("stellwerk-agent")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Users == nil {
		cfg.Users = policy.OSUsers{}
	}
	if cfg.LoginShell == nil {
		cfg.LoginShell = defaultLoginShell
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.AllowedUID < 0 {
		return nil, errors.New("helper: invalid AllowedUID")
	}
	st, err := os.Lstat(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("helper: state dir: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("helper: state dir %s is not a directory", cfg.StateDir)
	}
	if !cfg.SkipOwnerChecks {
		if err := policy.CheckRootOwned(st); err != nil || st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("helper: state dir %s must be root-owned with mode 0700", cfg.StateDir)
		}
	}
	nonces, err := envelope.OpenFileNonceStore(filepath.Join(cfg.StateDir, "nonces"), cfg.Now)
	if err != nil {
		return nil, fmt.Errorf("helper: %w", err)
	}
	return &Server{cfg: cfg, log: cfg.Logger, nonces: nonces, pm: cfg.PkgManager}, nil
}

// Close releases the nonce store. Call it after Serve returned.
func (s *Server) Close() error {
	return s.nonces.Close() //nolint:wrapcheck
}

// Serve accepts connections until ctx is done or ln is closed. Cancelling
// ctx also cancels running jobs (and kills open shells).
func (s *Server) Serve(ctx context.Context, ln *net.UnixListener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	sem := make(chan struct{}, s.cfg.MaxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("accept failed", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			s.log.Warn("too many concurrent connections, dropping one")
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handle(ctx, c)
		}()
	}
}

func (s *Server) handle(ctx context.Context, c *net.UnixConn) {
	conn := framing.NewConn(c)
	defer func() { _ = conn.Close() }()
	cred, err := framing.PeerCred(c)
	if err != nil {
		s.log.Warn("cannot read peer credentials", "err", err)
		return
	}
	if cred.Uid != 0 && int64(cred.Uid) != int64(s.cfg.AllowedUID) {
		s.log.Warn("rejected connection from unauthorized peer", "uid", cred.Uid, "pid", cred.Pid)
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := &responder{conn: conn, raw: c, timeout: s.cfg.WriteTimeout, cancel: cancel}

	_ = c.SetReadDeadline(time.Now().Add(s.cfg.RequestTimeout))
	var req helperv1.HelperRequest
	// Plain reads (not conn.Read/recvmsg): the helper never accepts file
	// descriptors from the core (the kernel discards SCM_RIGHTS), and a
	// failing read cannot hit framing.Conn's n<0 slicing bug.
	if err := framing.Read(c, &req); err != nil {
		s.log.Warn("invalid request", "uid", cred.Uid, "pid", cred.Pid, "err", err)
		w.fail("invalid request")
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	// The client sends nothing after the request. EOF (or anything else)
	// means it went away: cancel whatever we are doing for it.
	go func() {
		var b [1]byte
		_, _ = c.Read(b[:])
		cancel()
	}()

	switch r := req.GetCall().(type) {
	case *helperv1.HelperRequest_Ping:
		hostID, _ := s.hostID()
		_ = w.send(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_Pong{Pong: &helperv1.PingResponse{Version: s.cfg.Version, HostId: hostID}}})
	case *helperv1.HelperRequest_ListUpgrades:
		s.listUpgrades(ctx, w)
	case *helperv1.HelperRequest_ReadPrivileged:
		s.readPrivileged(ctx, w, r.ReadPrivileged.GetKind())
	case *helperv1.HelperRequest_ExecuteJob:
		s.executeJob(ctx, w, r.ExecuteJob.GetJob())
	default:
		w.fail("unknown request")
	}
}

// responder writes response frames. After the first failed write the
// connection is considered dead and the request's context is cancelled.
type responder struct {
	conn    *framing.Conn
	raw     *net.UnixConn
	timeout time.Duration
	cancel  context.CancelFunc
	mu      sync.Mutex
	broken  bool
}

func (r *responder) write(m *helperv1.HelperResponse, f *os.File) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken {
		return errors.New("helper: connection broken")
	}
	_ = r.raw.SetWriteDeadline(time.Now().Add(r.timeout))
	var err error
	if f != nil {
		err = r.conn.WriteWithFile(m, f)
	} else {
		err = r.conn.Write(m)
	}
	if err != nil && !errors.Is(err, framing.ErrFrameTooLarge) {
		r.broken = true
		r.cancel()
	}
	return err //nolint:wrapcheck
}

func (r *responder) send(m *helperv1.HelperResponse) error { return r.write(m, nil) }

func (r *responder) fail(msg string) {
	_ = r.send(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_Error{Error: &helperv1.HelperError{Message: msg}}})
}

func (r *responder) finish(f *agentv1.JobFinished) {
	_ = r.send(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_Finished{Finished: f}})
}

func (r *responder) output(stream agentv1.OutputStream, p []byte) {
	_ = r.send(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_Output{Output: &agentv1.JobOutput{Stream: stream, Data: p}}})
}

// --- trusted local state -------------------------------------------------

func (s *Server) policy() (*policy.Policy, error) {
	p, err := policy.Load(s.cfg.PolicyPath, !s.cfg.SkipOwnerChecks)
	if err != nil {
		return nil, fmt.Errorf("local policy unavailable: %w", err)
	}
	return p, nil
}

// readTrusted reads a small root-owned regular file without following a
// final symlink.
func (s *Server) readTrusted(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) //nolint:gosec // configured trust-anchor path
	if err != nil {
		return nil, fmt.Errorf("helper: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("helper: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("helper: %s: not a regular file or too large", path)
	}
	if !s.cfg.SkipOwnerChecks {
		if err := policy.CheckRootOwned(st); err != nil {
			return nil, fmt.Errorf("helper: %s: %w", path, err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, fmt.Errorf("helper: %w", err)
	}
	return data, nil
}

func (s *Server) hostID() (string, error) {
	data, err := s.readTrusted(s.cfg.HostIDPath, 128)
	if err != nil {
		return "", fmt.Errorf("host identity unavailable: %w", err)
	}
	id, err := ids.Canonical(strings.TrimSpace(string(data)))
	if err != nil {
		return "", fmt.Errorf("host identity invalid: %w", err)
	}
	return id, nil
}

// keyRing loads the pinned job-signing keys (*.pub, base64 Ed25519).
// Unreadable or malformed files are skipped (that can only narrow trust).
func (s *Server) keyRing() (envelope.KeyRing, error) {
	dir := s.cfg.JobKeysDir
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("job keys unavailable: %s is not a directory", dir)
	}
	if !s.cfg.SkipOwnerChecks {
		if err := policy.CheckRootOwned(st); err != nil {
			return nil, fmt.Errorf("job keys unavailable: %s: %w", dir, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("job keys unavailable: %w", err)
	}
	ring := envelope.KeyRing{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pub") || len(ring) >= maxKeys {
			continue
		}
		p := filepath.Join(dir, e.Name())
		data, err := s.readTrusted(p, 1024)
		if err != nil {
			s.log.Warn("skipping job key", "path", p, "err", err)
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err == nil {
			_, err = ring.Add(pub)
		}
		if err != nil {
			s.log.Warn("skipping malformed job key", "path", p)
		}
	}
	if len(ring) == 0 {
		return nil, errors.New("job keys unavailable: no valid key pinned")
	}
	return ring, nil
}

func (s *Server) pkgManager() (pkgmgr.Manager, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pm == nil {
		pm, err := pkgmgr.Detect(s.cfg.Runner, s.cfg.Paths.OSRelease)
		if err != nil {
			return nil, err //nolint:wrapcheck
		}
		s.pm = pm
	}
	return s.pm, nil
}

func (s *Server) listUpgrades(ctx context.Context, w *responder) {
	pol, err := s.policy()
	if err != nil {
		w.fail(err.Error())
		return
	}
	if !pol.Capabilities.Packages.List {
		w.fail(policy.ErrDenied.Error() + ": package listing disabled")
		return
	}
	pm, err := s.pkgManager()
	if err != nil {
		w.fail(err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	rep := &agentv1.UpdatesReport{CheckedAtMs: s.cfg.Now().UnixMilli(), Manager: pm.Name()}
	ups, err := pm.ListUpgrades(ctx)
	if err != nil {
		rep.Error = err.Error()
	}
	for i, u := range ups {
		if i >= maxReportUpdates {
			rep.Error = fmt.Sprintf("list truncated to %d updates", maxReportUpdates)
			break
		}
		rep.Updates = append(rep.Updates, &agentv1.PendingUpdate{
			Name: u.Name, CurrentVersion: u.CurrentVersion, CandidateVersion: u.CandidateVersion,
			Arch: u.Arch, Source: u.Source, IsSecurity: u.IsSecurity, Advisories: u.Advisories,
		})
	}
	req, reasons, err := pm.RebootRequired(ctx)
	rep.RebootRequired, rep.RebootReasons = req, reasons
	if err != nil && rep.Error == "" {
		rep.Error = err.Error()
	}
	if err := w.send(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_Upgrades{Upgrades: rep}}); errors.Is(err, framing.ErrFrameTooLarge) {
		w.fail("updates report too large")
	}
}

// Package runtime is the agent core main loop (ARCHITECTURE.md §5.1):
// outbound mTLS connection with jittered exponential backoff, Hello and
// heartbeats, metrics (buffered in the offline spool while disconnected),
// inventory, pending updates, process snapshots, signed jobs, and client
// certificate renewal.
package runtime

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/nobrain-soft/libremanager/internal/agent/jobs"
	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/agent/shell"
	"github.com/nobrain-soft/libremanager/internal/agent/state"
	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// MetricsSource produces one collection round.
type MetricsSource interface {
	// Batch collects samples; live batches are encoded against the current
	// stream dictionary, non-live ones are self-contained (for the spool).
	Batch(ctx context.Context, now time.Time, live bool) (*agentv1.MetricsBatch, error)
	// NewStream resets the live dictionary (once per Connect stream).
	NewStream()
}

// InventorySource provides facts and inventory.
type InventorySource interface {
	Facts(ctx context.Context) *agentv1.HostFacts
	CollectAll(ctx context.Context) (*agentv1.InventoryReport, error)
	Packages(ctx context.Context) (*agentv1.InventorySection, error)
	PackageDBFingerprint() string
}

// Spool buffers metrics while offline.
type Spool interface {
	Append(b *agentv1.MetricsBatch) error
	Drain(ctx context.Context, send func(*agentv1.MetricsBatch) error) error
	Len() int
}

// ProcessSource returns top processes.
type ProcessSource interface {
	Snapshot(ctx context.Context) (*agentv1.ProcessSnapshot, error)
}

// UpdatesSource lists pending updates (via the helper).
type UpdatesSource interface {
	ListUpgrades(ctx context.Context) (*agentv1.UpdatesReport, error)
}

// CheckSource runs security checks.
type CheckSource interface {
	Run(ctx context.Context, ids []string) *agentv1.CheckReport
}

// Config wires the runtime.
type Config struct {
	Policy    *policy.Policy
	Paths     state.Paths
	Identity  *state.Identity
	Roots     *x509.CertPool
	Version   string
	Metrics   MetricsSource
	Inventory InventorySource
	Spool     Spool
	Processes ProcessSource
	Updates   UpdatesSource
	Checks    CheckSource
	// HelperAvailable reports whether the helper answers (informational).
	HelperAvailable func(ctx context.Context) bool
	// Runner executes jobs; Emit and Local/Shell are wired by New.
	Runner *jobs.Runner
	// OnProbes is called when central sends a new probe configuration.
	OnProbes func([]*agentv1.Probe)
	Now      func() time.Time
	// Backoff bounds (defaults 1 s → 5 min).
	MinBackoff, MaxBackoff time.Duration
}

// Agent is the running core.
type Agent struct {
	cfg    Config
	hostID string

	mu       sync.Mutex
	settings *agentv1.AgentSettings
	sess     *session
	probes   []*agentv1.Probe

	// outbox buffers job events and reports while disconnected.
	outbox chan *agentv1.ConnectRequest

	lastUpdates *agentv1.UpdatesReport
	cc          *grpc.ClientConn
}

type session struct {
	send chan *agentv1.ConnectRequest
	ctx  context.Context
}

// New creates the agent.
func New(cfg Config) (*Agent, error) {
	if cfg.Policy == nil || cfg.Identity == nil || cfg.Roots == nil || cfg.Runner == nil {
		return nil, errors.New("runtime: incomplete config")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 5 * time.Minute
	}
	id, err := pki.HostIDFromCert(cfg.Identity.Leaf())
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, hostID: id, outbox: make(chan *agentv1.ConnectRequest, 4096), settings: &agentv1.AgentSettings{
		MetricsIntervalS: 15, InventoryIntervalS: 6 * 3600, ProcessesIntervalS: 60, UpdatesCheckIntervalS: 6 * 3600, ChecksIntervalS: 24 * 3600,
	}}
	cfg.Runner.Emit = func(e *agentv1.JobEvent) {
		a.enqueue(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_JobEvent{JobEvent: e}}, e.GetFinished() != nil)
	}
	cfg.Runner.Local = a
	cfg.Runner.Shell = a.relayShell
	return a, nil
}

// HostID returns the enrolled host id.
func (a *Agent) HostID() string { return a.hostID }

// enqueue buffers a message for the current or next session. Important
// messages (job results) block briefly rather than being dropped.
func (a *Agent) enqueue(m *agentv1.ConnectRequest, important bool) {
	if important {
		select {
		case a.outbox <- m:
		case <-time.After(5 * time.Second):
			slog.Error("outbox full, dropping job result")
		}
		return
	}
	select {
	case a.outbox <- m:
	default:
		slog.Warn("outbox full, dropping message")
	}
}

// Run connects and serves until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	host, _, err := net.SplitHostPort(a.cfg.Policy.Central)
	if err != nil {
		return fmt.Errorf("runtime: central: %w", err)
	}
	tlsCfg := pki.ClientTLSConfig(a.cfg.Roots, host, a.cfg.Identity.Get)
	a.cc, err = grpc.NewClient(a.cfg.Policy.Central,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8<<20), grpc.MaxCallSendMsgSize(8<<20)),
	)
	if err != nil {
		return fmt.Errorf("runtime: client: %w", err)
	}
	defer a.cc.Close()

	var wg sync.WaitGroup
	wg.Go(func() { a.metricsLoop(ctx) })
	backoff := a.cfg.MinBackoff
	for ctx.Err() == nil {
		start := a.cfg.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			break
		}
		if a.cfg.Now().Sub(start) > time.Minute {
			backoff = a.cfg.MinBackoff
		}
		// Full jitter avoids a thundering herd after a central restart.
		wait := time.Duration(rand.Int64N(int64(backoff))) + a.cfg.MinBackoff/2 //nolint:gosec // jitter, not security
		slog.Warn("disconnected from central", "err", err, "retry_in", wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
		backoff = min(backoff*2, a.cfg.MaxBackoff)
	}
	wg.Wait()
	return nil
}

func (a *Agent) currentSession() *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess
}

func (a *Agent) currentSettings() *agentv1.AgentSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (a *Agent) session(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := agentv1.NewGatewayServiceClient(a.cc)
	stream, err := client.Connect(sctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	helperOK := false
	if a.cfg.HelperAvailable != nil {
		helperOK = a.cfg.HelperAvailable(ctx)
	}
	var facts *agentv1.HostFacts
	if a.cfg.Inventory != nil {
		facts = a.cfg.Inventory.Facts(ctx)
	}
	if err := stream.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{
		AgentVersion: a.cfg.Version, Facts: facts, BootId: bootID(), AgentTimeMs: a.cfg.Now().UnixMilli(),
		Policy: a.cfg.Policy.Summary(), HelperAvailable: helperOK,
	}}}); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("welcome: %w", err)
	}
	w := first.GetWelcome()
	if w == nil || w.GetHostId() != a.hostID {
		return errors.New("unexpected welcome from central")
	}
	if skew := time.Duration(w.GetServerTimeMs()-a.cfg.Now().UnixMilli()) * time.Millisecond; skew > time.Minute || skew < -time.Minute {
		slog.Warn("clock skew to central", "skew", skew)
	}
	a.applySettings(w.GetSettings())
	slog.Info("connected to central", "central", a.cfg.Policy.Central, "host_id", a.hostID)

	s := &session{send: make(chan *agentv1.ConnectRequest, 256), ctx: sctx}
	if a.cfg.Metrics != nil {
		a.cfg.Metrics.NewStream()
	}
	a.mu.Lock()
	a.sess = s
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.sess == s {
			a.sess = nil
		}
		a.mu.Unlock()
	}()

	errc := make(chan error, 3)
	// Sender: the only goroutine calling stream.Send from here on.
	go func() {
		for {
			var m *agentv1.ConnectRequest
			select {
			case <-sctx.Done():
				errc <- sctx.Err()
				return
			case m = <-s.send:
			case m = <-a.outbox:
			}
			if err := stream.Send(m); err != nil {
				if m.GetJobEvent() != nil {
					a.enqueue(m, false) // retry on the next session
				}
				errc <- fmt.Errorf("send: %w", err)
				return
			}
		}
	}()
	// Receiver.
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				errc <- fmt.Errorf("recv: %w", err)
				return
			}
			switch p := m.GetPayload().(type) {
			case *agentv1.ConnectResponse_Job:
				a.cfg.Runner.Handle(ctx, p.Job)
			case *agentv1.ConnectResponse_CancelJob:
				a.cfg.Runner.Cancel(p.CancelJob.GetJobId())
			case *agentv1.ConnectResponse_Settings:
				a.applySettings(p.Settings)
			case *agentv1.ConnectResponse_HeartbeatAck:
			}
		}
	}()
	go a.sessionTasks(sctx, s, w.GetRenewBeforeS())

	return <-errc
}

func (a *Agent) applySettings(st *agentv1.AgentSettings) {
	if st == nil {
		return
	}
	clamp := func(v, lo, hi, def uint32) uint32 {
		if v == 0 {
			return def
		}
		return min(max(v, lo), hi)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.settings = &agentv1.AgentSettings{
		MetricsIntervalS:      clamp(st.GetMetricsIntervalS(), 10, 300, 15),
		InventoryIntervalS:    clamp(st.GetInventoryIntervalS(), 600, 7*86400, 6*3600),
		ProcessesIntervalS:    clamp(st.GetProcessesIntervalS(), 15, 3600, 60),
		UpdatesCheckIntervalS: clamp(st.GetUpdatesCheckIntervalS(), 900, 7*86400, 6*3600),
		ChecksIntervalS:       clamp(st.GetChecksIntervalS(), 3600, 7*86400, 24*3600),
	}
	if len(st.GetProbes()) > 0 {
		a.probes = st.GetProbes()
		if a.cfg.OnProbes != nil {
			a.cfg.OnProbes(a.probes)
		}
	}
}

func (s *session) push(m *agentv1.ConnectRequest) bool {
	select {
	case s.send <- m:
		return true
	case <-s.ctx.Done():
		return false
	case <-time.After(10 * time.Second):
		return false
	}
}

func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)/10+1)) //nolint:gosec // jitter
}

// sessionTasks runs per-connection periodic work.
func (a *Agent) sessionTasks(ctx context.Context, s *session, renewBeforeS int64) {
	// Replay the spool first (oldest first).
	if a.cfg.Spool != nil && a.cfg.Spool.Len() > 0 {
		err := a.cfg.Spool.Drain(ctx, func(b *agentv1.MetricsBatch) error {
			if !s.push(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Metrics{Metrics: b}}) {
				return errors.New("session closed")
			}
			return nil
		})
		if err != nil {
			slog.Warn("spool replay interrupted", "err", err)
		}
	}
	a.sendInventory(ctx, s, true)
	a.sendUpdates(ctx, s)
	a.sendChecks(ctx, s, nil)

	st := a.currentSettings()
	hb := time.NewTicker(30 * time.Second)
	proc := time.NewTicker(time.Duration(st.GetProcessesIntervalS()) * time.Second)
	inv := time.NewTicker(jitter(time.Duration(st.GetInventoryIntervalS()) * time.Second))
	pkgWatch := time.NewTicker(60 * time.Second)
	upd := time.NewTicker(jitter(time.Duration(st.GetUpdatesCheckIntervalS()) * time.Second))
	chk := time.NewTicker(jitter(time.Duration(st.GetChecksIntervalS()) * time.Second))
	renew := time.NewTicker(time.Hour)
	defer func() {
		for _, t := range []*time.Ticker{hb, proc, inv, pkgWatch, upd, chk, renew} {
			t.Stop()
		}
	}()
	a.maybeRenew(ctx, renewBeforeS)
	pkgFP := ""
	if a.cfg.Inventory != nil {
		pkgFP = a.cfg.Inventory.PackageDBFingerprint()
	}
	pkgChangedAt := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			n := uint32(0)
			if a.cfg.Spool != nil {
				n = uint32(a.cfg.Spool.Len()) //nolint:gosec // small
			}
			s.push(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{
				AgentTimeMs: a.cfg.Now().UnixMilli(), SpoolBatches: n, RunningJobs: uint32(a.cfg.Runner.Running()), //nolint:gosec // small
			}}})
		case <-proc.C:
			if a.cfg.Processes != nil {
				if snap, err := a.cfg.Processes.Snapshot(ctx); err == nil {
					s.push(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Processes{Processes: snap}})
				}
			}
		case <-inv.C:
			a.sendInventory(ctx, s, true)
		case <-pkgWatch.C:
			// Package DB changed: rescan packages + pending updates, debounced 60 s.
			if a.cfg.Inventory == nil {
				continue
			}
			if fp := a.cfg.Inventory.PackageDBFingerprint(); fp != pkgFP {
				pkgFP = fp
				pkgChangedAt = a.cfg.Now()
			} else if !pkgChangedAt.IsZero() && a.cfg.Now().Sub(pkgChangedAt) >= 60*time.Second {
				pkgChangedAt = time.Time{}
				a.sendInventory(ctx, s, false)
				a.sendUpdates(ctx, s)
			}
		case <-upd.C:
			a.sendUpdates(ctx, s)
		case <-chk.C:
			a.sendChecks(ctx, s, nil)
		case <-renew.C:
			a.maybeRenew(ctx, renewBeforeS)
		}
	}
}

func (a *Agent) sendInventory(ctx context.Context, s *session, full bool) {
	if a.cfg.Inventory == nil || !a.cfg.Policy.Capabilities.Inventory {
		return
	}
	var rep *agentv1.InventoryReport
	if full {
		r, err := a.cfg.Inventory.CollectAll(ctx)
		if err != nil {
			slog.Warn("inventory collection failed", "err", err)
			return
		}
		rep = r
	} else {
		sec, err := a.cfg.Inventory.Packages(ctx)
		if err != nil {
			return
		}
		rep = &agentv1.InventoryReport{CollectedAtMs: a.cfg.Now().UnixMilli(), Sections: []*agentv1.InventorySection{sec}}
	}
	s.push(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Inventory{Inventory: rep}})
}

func (a *Agent) sendUpdates(ctx context.Context, s *session) {
	if a.cfg.Updates == nil || !a.cfg.Policy.Capabilities.Packages.List {
		return
	}
	uctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	rep, err := a.cfg.Updates.ListUpgrades(uctx)
	if err != nil {
		rep = &agentv1.UpdatesReport{CheckedAtMs: a.cfg.Now().UnixMilli(), Error: err.Error()}
	}
	a.mu.Lock()
	a.lastUpdates = rep
	a.mu.Unlock()
	s.push(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Updates{Updates: rep}})
}

// LastUpdates returns the last pending-updates report (for checks).
func (a *Agent) LastUpdates() *agentv1.UpdatesReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastUpdates
}

func (a *Agent) sendChecks(ctx context.Context, s *session, ids []string) {
	if a.cfg.Checks == nil || !a.cfg.Policy.Capabilities.SecurityChecks {
		return
	}
	rep := a.cfg.Checks.Run(ctx, ids)
	if rep != nil {
		s.push(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Checks{Checks: rep}})
	}
}

// --- jobs.Local

// RunChecks implements jobs.Local.
func (a *Agent) RunChecks(ctx context.Context, ids []string) error {
	s := a.currentSession()
	if s == nil {
		return errors.New("not connected")
	}
	if a.cfg.Checks == nil {
		return errors.New("checks not available")
	}
	a.sendChecks(ctx, s, ids)
	return nil
}

// CollectInventory implements jobs.Local.
func (a *Agent) CollectInventory(ctx context.Context) error {
	s := a.currentSession()
	if s == nil {
		return errors.New("not connected")
	}
	a.sendInventory(ctx, s, true)
	a.sendUpdates(ctx, s)
	return nil
}

// SetProbes implements jobs.Local.
func (a *Agent) SetProbes(p []*agentv1.Probe) {
	a.mu.Lock()
	a.probes = p
	a.mu.Unlock()
	if a.cfg.OnProbes != nil {
		a.cfg.OnProbes(p)
	}
}

// Probes returns the configured probes.
func (a *Agent) Probes() []*agentv1.Probe {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.probes
}

func (a *Agent) relayShell(ctx context.Context, g *agentv1.ShellGrant, requestedBy string, master *os.File) error {
	open := func(ctx context.Context) (agentv1.GatewayService_ShellSessionClient, error) {
		return agentv1.NewGatewayServiceClient(a.cc).ShellSession(ctx)
	}
	return shell.Relay(ctx, open, g, requestedBy, master)
}

// --- metrics

func (a *Agent) metricsLoop(ctx context.Context) {
	if a.cfg.Metrics == nil || !a.cfg.Policy.Capabilities.Metrics {
		return
	}
	for {
		iv := time.Duration(a.currentSettings().GetMetricsIntervalS()) * time.Second
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		}
		now := a.cfg.Now()
		if s := a.currentSession(); s != nil {
			b, err := a.cfg.Metrics.Batch(ctx, now, true)
			if err != nil {
				continue
			}
			if s.push(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Metrics{Metrics: b}}) {
				continue
			}
		}
		if a.cfg.Spool == nil {
			continue
		}
		b, err := a.cfg.Metrics.Batch(ctx, now, false)
		if err != nil {
			continue
		}
		if err := a.cfg.Spool.Append(b); err != nil {
			slog.Warn("spool append failed", "err", err)
		}
	}
}

// --- certificate renewal (2/3 of lifetime, over the existing identity)

func (a *Agent) maybeRenew(ctx context.Context, renewBeforeS int64) {
	leaf := a.cfg.Identity.Leaf()
	if leaf == nil {
		return
	}
	total := leaf.NotAfter.Sub(leaf.NotBefore)
	left := leaf.NotAfter.Sub(a.cfg.Now())
	threshold := total / 3
	if renewBeforeS > 0 {
		threshold = max(threshold, time.Duration(renewBeforeS)*time.Second)
	}
	if left > threshold {
		return
	}
	if err := a.Renew(ctx); err != nil {
		slog.Error("certificate renewal failed", "err", err, "expires", leaf.NotAfter)
	}
}

// Renew obtains a new certificate with a freshly generated key.
func (a *Agent) Renew(ctx context.Context) error {
	key, err := pki.GenerateKey()
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key, a.hostID)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := agentv1.NewGatewayServiceClient(a.cc).Renew(rctx, &agentv1.RenewRequest{CsrDer: csr})
	if err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	tc, err := pki.TLSCertificate(resp.GetCertChainDer(), key)
	if err != nil {
		return err
	}
	if id, err := pki.HostIDFromCert(tc.Leaf); err != nil || id != a.hostID {
		return errors.New("renew: certificate identity changed")
	}
	if err := state.SaveIdentity(a.cfg.Paths, key, resp.GetCertChainDer()); err != nil {
		return err
	}
	a.cfg.Identity.Set(tc)
	slog.Info("client certificate renewed", "not_after", tc.Leaf.NotAfter)
	return nil
}

// Package gateway implements `stellwerk-server gateway` (ARCHITECTURE.md
// §5.2): the agent-facing mTLS gRPC endpoint on :8443, the agent registry,
// ingestion of metrics/inventory/job events, job dispatch, shell relays,
// certificate renewal and the revocation denylist.
//
// Every agent is treated as potentially compromised (CLAUDE.md rule 6):
// identity comes only from the client certificate, all input is validated
// and size-limited, and server-side labels are added to metrics.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/gateway/remotewrite"
	"github.com/nobrain-soft/libremanager/internal/server/store"
)

// Limits.
const (
	MaxRecvMsgBytes     = 8 << 20
	MaxOutputPerTarget  = 4 << 20
	MaxSeriesPerStream  = 20000
	MaxPointsPerBatch   = 50000
	HelloTimeout        = 15 * time.Second
	HostDownGrace       = 2 * time.Minute
	RenewBefore         = 10 * 24 * time.Hour // agents renew at 2/3 of 30 d
	ServerCertRenewLeft = 30 * 24 * time.Hour
)

// Config wires the gateway.
type Config struct {
	Store *store.Store
	Audit *audit.Logger
	// CA is the agent intermediate CA (with key) that issues agent and
	// gateway certificates.
	CA *pki.CA
	// Roots trusts the root CA (client cert verification).
	Roots *x509.CertPool
	// ServerNames / ServerIPs are the gateway certificate SANs.
	ServerNames []string
	ServerIPs   []net.IP
	Pepper      auth.Pepper
	// RemoteWrite may be nil (metrics are then discarded).
	RemoteWrite *remotewrite.Writer
	// Install serves /install/* (may be nil).
	Install http.Handler
	// AgentSettings returns centrally managed agent settings.
	AgentSettings func(ctx context.Context) *agentv1.AgentSettings
	Now           func() time.Time
}

// Gateway is the agent gateway.
type Gateway struct {
	agentv1.UnimplementedGatewayServiceServer

	cfg      Config
	registry *Registry
	deny     *Denylist
	shells   *shellBroker
	grpc     *grpc.Server

	certMu sync.RWMutex
	cert   *tls.Certificate

	enrollLimit *auth.KeyedLimiter
	renewLimit  *auth.KeyedLimiter

	downMu     sync.Mutex
	downTimers map[uuid.UUID]*time.Timer
}

var jsonOpts = protojson.MarshalOptions{UseProtoNames: true}

// New creates a gateway.
func New(cfg Config) (*Gateway, error) {
	if cfg.Store == nil || cfg.CA == nil || cfg.Roots == nil || cfg.Audit == nil {
		return nil, errors.New("gateway: incomplete config")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.AgentSettings == nil {
		cfg.AgentSettings = func(context.Context) *agentv1.AgentSettings { return DefaultAgentSettings() }
	}
	g := &Gateway{
		cfg:         cfg,
		registry:    NewRegistry(),
		deny:        NewDenylist(),
		shells:      newShellBroker(),
		enrollLimit: auth.NewKeyedLimiter(10, 5),
		renewLimit:  auth.NewKeyedLimiter(6, 2),
		downTimers:  map[uuid.UUID]*time.Timer{},
	}
	if err := g.renewServerCert(); err != nil {
		return nil, err
	}
	g.grpc = grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxRecvMsgBytes),
		grpc.MaxSendMsgSize(MaxRecvMsgBytes),
		grpc.ChainUnaryInterceptor(g.unaryAuth),
		grpc.ChainStreamInterceptor(g.streamAuth),
	)
	agentv1.RegisterGatewayServiceServer(g.grpc, g)
	return g, nil
}

// DefaultAgentSettings are used when nothing is configured.
func DefaultAgentSettings() *agentv1.AgentSettings {
	return &agentv1.AgentSettings{
		MetricsIntervalS:      15,
		InventoryIntervalS:    6 * 3600,
		ProcessesIntervalS:    60,
		UpdatesCheckIntervalS: 6 * 3600,
		ChecksIntervalS:       24 * 3600,
	}
}

func (g *Gateway) renewServerCert() error {
	key, err := pki.GenerateKey()
	if err != nil {
		return err
	}
	cert, err := g.cfg.CA.IssueServerCert(key.Public(), g.cfg.ServerNames, g.cfg.ServerIPs, pki.ServerCertValidity, g.cfg.Now())
	if err != nil {
		return fmt.Errorf("gateway: server cert: %w", err)
	}
	tc, err := pki.TLSCertificate(g.cfg.CA.ChainDER(cert), key)
	if err != nil {
		return err
	}
	g.certMu.Lock()
	g.cert = &tc
	g.certMu.Unlock()
	return nil
}

// TLSConfig returns the TLS 1.3 listener config. Client certificates are
// verified when presented; RPCs other than Enroll require one.
func (g *Gateway) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  g.cfg.Roots,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			g.certMu.RLock()
			defer g.certMu.RUnlock()
			return g.cert, nil
		},
	}
}

// Handler routes gRPC (HTTP/2 + application/grpc) to the gRPC server and
// everything else to the install handler.
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			g.grpc.ServeHTTP(w, r)
			return
		}
		if g.cfg.Install != nil && strings.HasPrefix(r.URL.Path, "/install/") {
			g.cfg.Install.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// Serve runs the TLS listener on ln until ctx is done.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           g.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	tlsLn := tls.NewListener(ln, g.TLSConfig())
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("gateway: serve: %w", err)
	}
	return nil
}

// RunBackground starts LISTEN loops, sweepers and timers. It blocks until
// ctx is done.
func (g *Gateway) RunBackground(ctx context.Context) {
	q := g.cfg.Store.Q
	if err := q.MarkAllDisconnected(ctx); err != nil {
		slog.ErrorContext(ctx, "mark disconnected", "err", err)
	}
	if err := g.reloadDenylist(ctx); err != nil {
		slog.ErrorContext(ctx, "load denylist", "err", err)
	}
	g.scheduleInitialHostDown(ctx)

	var wg sync.WaitGroup
	wg.Go(func() {
		g.cfg.Store.Listen(ctx, []string{store.ChanDispatch, store.ChanRevocations}, func(ch, payload string) {
			id, err := uuid.Parse(payload)
			if err != nil {
				return
			}
			switch ch {
			case store.ChanDispatch:
				go g.dispatchHost(ctx, id)
			case store.ChanRevocations:
				if err := g.reloadDenylist(ctx); err != nil {
					slog.ErrorContext(ctx, "reload denylist", "err", err)
				}
				g.registry.Disconnect(id, errors.New("certificate revoked"))
			}
		}, func() {
			// After (re)connect, catch up on anything missed.
			_ = g.reloadDenylist(ctx)
			for _, id := range g.registry.HostIDs() {
				go g.dispatchHost(ctx, id)
			}
		})
	})
	wg.Go(func() { g.sweeper(ctx) })
	wg.Go(func() { g.heartbeatFlusher(ctx) })
	if g.cfg.RemoteWrite != nil {
		wg.Go(func() { g.cfg.RemoteWrite.Run(ctx) })
	}
	wg.Wait()
}

func (g *Gateway) sweeper(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		q := g.cfg.Store.Q
		expired, err := q.ExpireQueuedTargets(ctx)
		if err != nil {
			slog.WarnContext(ctx, "expire targets", "err", err)
		}
		for _, e := range expired {
			g.finalizeJob(ctx, e.JobID)
		}
		// Jobs may legitimately run long (dist-upgrade); 3 h without a result
		// means the agent lost it.
		stale, err := q.TimeoutStaleTargets(ctx, 180)
		if err != nil {
			slog.WarnContext(ctx, "timeout targets", "err", err)
		}
		for _, s := range stale {
			g.finalizeJob(ctx, s.JobID)
		}
		for _, id := range g.registry.HostIDs() {
			g.dispatchHost(ctx, id)
		}
		g.certMu.RLock()
		left := g.cert.Leaf.NotAfter.Sub(g.cfg.Now())
		g.certMu.RUnlock()
		if left < ServerCertRenewLeft {
			if err := g.renewServerCert(); err != nil {
				slog.ErrorContext(ctx, "renew gateway certificate", "err", err)
			}
		}
	}
}

func (g *Gateway) heartbeatFlusher(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ids := g.registry.HostIDs()
		if len(ids) == 0 {
			continue
		}
		if err := g.cfg.Store.Q.TouchHosts(ctx, ids); err != nil {
			slog.WarnContext(ctx, "touch hosts", "err", err)
		}
	}
}

func (g *Gateway) reloadDenylist(ctx context.Context) error {
	serials, err := g.cfg.Store.Q.ListRevokedSerials(ctx)
	if err != nil {
		return fmt.Errorf("gateway: denylist: %w", err)
	}
	g.deny.Replace(serials)
	return nil
}

// Registry exposes the registry (tests, control service).
func (g *Gateway) Registry() *Registry { return g.registry }

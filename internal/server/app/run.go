package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/api"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/config"
	"github.com/nobrain-soft/libremanager/internal/server/gateway"
	"github.com/nobrain-soft/libremanager/internal/server/gateway/remotewrite"
	"github.com/nobrain-soft/libremanager/internal/server/install"
	"github.com/nobrain-soft/libremanager/internal/server/signer"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/webui"
)

var nowFn = time.Now

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // path from config
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", errMissing, path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// RunSigner runs the signer role.
func RunSigner(ctx context.Context, cfg *config.Config) error {
	key, err := secretbox.LoadKeyFile(cfg.SignerSecret(MasterKeyFile))
	if err != nil {
		return err
	}
	js, err := signer.LoadKeyFile(key, cfg.SignerSecret(JobKeyFile))
	if err != nil {
		return err
	}
	svc, err := signer.NewService(js, cfg.SignerLogPath())
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()
	return signer.Serve(ctx, svc, cfg.SignerSocket())
}

// RunGateway runs the gateway role.
func RunGateway(ctx context.Context, cfg *config.Config) error {
	key, err := secretbox.LoadKeyFile(cfg.GatewaySecret(MasterKeyFile))
	if err != nil {
		return err
	}
	ider, err := secretbox.OpenFile(key, IntermediatePurpos, cfg.GatewaySecret(IntermediateKey))
	if err != nil {
		return err
	}
	ikey, err := pki.ParsePrivateKey(ider)
	if err != nil {
		return err
	}
	icertPEM, err := os.ReadFile(cfg.GatewaySecret(IntermediateCert))
	if err != nil {
		return fmt.Errorf("%w: %w", errMissing, err)
	}
	icert, err := pki.ParseCertPEM(icertPEM)
	if err != nil {
		return err
	}
	if err := pki.KeyMatchesCert(ikey, icert); err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(cfg.GatewaySecret(RootCertFile))
	if err != nil {
		return fmt.Errorf("%w: %w", errMissing, err)
	}
	root, err := pki.ParseCertPEM(rootPEM)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	pepper, err := auth.LoadPepper(cfg.GatewaySecret(PepperFile))
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	names, ips := []string{}, []net.IP{}
	for _, san := range append([]string{cfg.AgentHost()}, cfg.GatewaySANs...) {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else if san != "" {
			names = append(names, san)
		}
	}
	params := install.Params{AgentEndpoint: cfg.AgentEndpoint, CAPEM: string(rootPEM), CAFingerprint: pki.Fingerprint(root)}
	gw, err := gateway.New(gateway.Config{
		Store: st, Audit: audit.New(st), CA: &pki.CA{Cert: icert, Key: ikey, Chain: []*x509.Certificate{root}}, Roots: pool,
		ServerNames: names, ServerIPs: ips, Pepper: pepper, RemoteWrite: remotewrite.New(cfg.VictoriaMetricsURL),
		Install:       install.Handler(func() (install.Params, error) { return params, nil }, cfg.PackagesDir()),
		AgentSettings: agentSettings(st),
	})
	if err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.GatewayListen)
	if err != nil {
		return fmt.Errorf("gateway: listen: %w", err)
	}
	slog.InfoContext(ctx, "gateway listening", "addr", cfg.GatewayListen, "sans", append(names, ipStrings(ips)...))
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Go(func() { gw.RunBackground(ctx) })
	wg.Go(func() { errc <- gw.ServeControl(ctx, cfg.ControlSocket()) })
	wg.Go(func() { errc <- gw.Serve(ctx, ln) })
	select {
	case err := <-errc:
		if err != nil && ctx.Err() == nil {
			return err
		}
	case <-ctx.Done():
	}
	wg.Wait()
	return nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func agentSettings(_ *store.Store) func(context.Context) *agentv1.AgentSettings {
	return func(context.Context) *agentv1.AgentSettings { return gateway.DefaultAgentSettings() }
}

// RunAPI runs the API role.
func RunAPI(ctx context.Context, cfg *config.Config) error {
	key, err := secretbox.LoadKeyFile(cfg.APISecret(MasterKeyFile))
	if err != nil {
		return err
	}
	pepper, err := auth.LoadPepper(cfg.APISecret(PepperFile))
	if err != nil {
		return err
	}
	webhookToken, err := readTrim(cfg.APISecret(WebhookTokenFile))
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(cfg.APISecret(RootCertFile))
	if err != nil {
		return fmt.Errorf("%w: %w", errMissing, err)
	}
	root, err := pki.ParseCertPEM(rootPEM)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	wa, err := auth.NewWebAuthn(cfg.PublicURL)
	if err != nil {
		return err
	}
	sc, scc, err := signer.Dial(cfg.SignerSocket())
	if err != nil {
		return err
	}
	defer scc.Close()
	gc, gcc, err := gateway.DialControl(cfg.ControlSocket())
	if err != nil {
		return err
	}
	defer gcc.Close()
	srv, err := api.New(api.Deps{
		Cfg: cfg, Store: st, Audit: audit.New(st), MasterKey: key, Pepper: pepper, WebhookToken: webhookToken,
		Signer: sc, Control: gc, WebAuthn: wa, CAPEM: string(rootPEM), CAFP: pki.Fingerprint(root), UI: webui.Handler(),
	})
	if err != nil {
		return err
	}
	hs := &http.Server{
		Addr: cfg.APIListen, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go srv.RunBackground(ctx)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	slog.InfoContext(ctx, "api listening", "addr", cfg.APIListen, "public_url", cfg.PublicURL)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("api: %w", err)
	}
	return nil
}

// RunAll runs signer, gateway and api in one process (small installs;
// documented as less isolated than separate containers).
func RunAll(ctx context.Context, cfg *config.Config) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	run := func(name string, fn func(context.Context, *config.Config) error) {
		wg.Go(func() {
			if err := fn(ctx, cfg); err != nil && ctx.Err() == nil {
				slog.ErrorContext(ctx, "role failed", "role", name, "err", err)
				cancel(fmt.Errorf("%s: %w", name, err))
			}
		})
	}
	run("signer", RunSigner)
	run("gateway", RunGateway)
	// Give the sockets a moment to appear (clients connect lazily anyway).
	time.Sleep(200 * time.Millisecond)
	run("api", RunAPI)
	wg.Wait()
	if c := context.Cause(ctx); c != nil && !errors.Is(c, context.Canceled) {
		return c
	}
	return nil
}

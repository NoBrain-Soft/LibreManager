// Command stellwerk-server is the central server. Roles:
//
//	init        create secrets, PKI, job key, run migrations, break-glass admin
//	migrate     apply database migrations
//	api         REST API + WebSocket + web UI (behind Caddy)
//	gateway     agent gateway (:8443, mTLS gRPC + /install)
//	signer      job signer (unix socket only, holds the job-signing key)
//	all         signer + gateway + api in one process (small installs)
//	version     print version
//
// Configuration comes from STELLWERK_* environment variables (see
// internal/server/config).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nobrain-soft/libremanager/internal/common/version"
	"github.com/nobrain-soft/libremanager/internal/server/app"
	"github.com/nobrain-soft/libremanager/internal/server/config"
	"github.com/nobrain-soft/libremanager/internal/server/store"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: stellwerk-server <init|migrate|api|gateway|signer|all|version> [flags]")
	os.Exit(2)
}

func setupLogging() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("STELLWERK_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewJSONHandler(os.Stderr, opts)
	if os.Getenv("STELLWERK_LOG_FORMAT") == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	role := os.Args[1]
	if role == "version" || role == "--version" {
		fmt.Println("stellwerk-server", version.String())
		return
	}
	setupLogging()
	fs := flag.NewFlagSet(role, flag.ExitOnError)
	admin := fs.String("admin-username", "admin", "break-glass admin username (init)")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.FromEnv()
	if err != nil {
		slog.Error("configuration", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch role {
	case "init":
		err = app.Init(ctx, cfg, app.InitOptions{AdminUsername: *admin, Out: os.Stdout})
	case "migrate":
		var st *store.Store
		st, err = store.Open(ctx, cfg.DatabaseURL)
		if err == nil {
			err = store.Migrate(ctx, st.Pool)
			st.Close()
		}
	case "api":
		err = app.RunAPI(ctx, cfg)
	case "gateway":
		err = app.RunGateway(ctx, cfg)
	case "signer":
		err = app.RunSigner(ctx, cfg)
	case "all":
		err = app.RunAll(ctx, cfg)
	default:
		usage()
	}
	if err != nil {
		slog.Error("exiting", "role", role, "err", err)
		stop()
		os.Exit(1) //nolint:gocritic // stop() was called explicitly
	}
}

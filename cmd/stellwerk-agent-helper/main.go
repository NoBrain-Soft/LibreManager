// Command stellwerk-agent-helper is the privileged (root) helper of the
// Stellwerk agent. It is started by systemd socket activation
// (stellwerk-agent-helper.socket, /run/stellwerk/helper.sock, mode 0660,
// group stellwerk-agent) and serves the fixed RPC set in
// proto/stellwerk/helper/v1 to the unprivileged agent core.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/common/journal"
	"github.com/nobrain-soft/libremanager/internal/common/version"
	"github.com/nobrain-soft/libremanager/internal/helper"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("stellwerk-agent-helper", flag.ContinueOnError)
	listen := fs.String("listen", "", "listen on this unix socket instead of using systemd socket activation (development)")
	group := fs.String("group", "", "with --listen: group owning the socket (e.g. stellwerk-agent)")
	showVersion := fs.Bool("version", false, "print version and exit")
	policyPath := fs.String("policy", policy.DefaultPath, "local policy file")
	hostIDPath := fs.String("host-id", helper.DefaultHostIDPath, "host identity file")
	jobKeysDir := fs.String("jobkeys", helper.DefaultJobKeysDir, "directory of pinned job-signing keys (*.pub)")
	stateDir := fs.String("state-dir", helper.DefaultStateDir, "helper state directory (root 0700)")
	agentUser := fs.String("agent-user", "stellwerk-agent", "account of the agent core allowed to connect (root is always allowed)")
	debug := fs.Bool("debug", false, "debug logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("stellwerk-agent-helper", version.String())
		return 0
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := serve(log, *listen, *group, *agentUser, helper.Config{
		PolicyPath: *policyPath,
		HostIDPath: *hostIDPath,
		JobKeysDir: *jobKeysDir,
		StateDir:   *stateDir,
		TimeSynced: timeSynced,
		Journal:    journal.New("stellwerk-agent"),
		Logger:     log,
	}); err != nil {
		log.Error("helper failed", "err", err)
		return 1
	}
	return 0
}

func serve(log *slog.Logger, listen, group, agentUser string, cfg helper.Config) error {
	u, err := user.Lookup(agentUser)
	if err != nil {
		return fmt.Errorf("agent user: %w", err)
	}
	cfg.AllowedUID, err = strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("agent user uid: %w", err)
	}
	var ln *net.UnixListener
	if listen != "" {
		ln, err = listenPath(listen, group)
	} else {
		ln, err = activated()
	}
	if err != nil {
		return err
	}
	srv, err := helper.NewServer(cfg)
	if err != nil {
		_ = ln.Close()
		return err //nolint:wrapcheck
	}
	defer func() { _ = srv.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Info("helper listening", "version", version.Version, "addr", ln.Addr().String(), "allowed_uid", cfg.AllowedUID)
	return srv.Serve(ctx, ln) //nolint:wrapcheck
}

// activated returns the listener passed by systemd (LISTEN_FDS, fd 3).
func activated() (*net.UnixListener, error) {
	pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID"))
	n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(k)
	}
	if pid != os.Getpid() || n != 1 {
		return nil, errors.New("not socket-activated (expected exactly one fd); use --listen for development")
	}
	unix.CloseOnExec(3)
	f := os.NewFile(3, "systemd-socket")
	defer func() { _ = f.Close() }()
	l, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("activation socket: %w", err)
	}
	ul, ok := l.(*net.UnixListener)
	if !ok {
		_ = l.Close()
		return nil, errors.New("activation socket is not a unix stream socket")
	}
	return ul, nil
}

// listenPath creates the socket with mode 0660 (no window with wider
// permissions) and optionally hands it to group.
func listenPath(path, group string) (*net.UnixListener, error) {
	if st, err := os.Lstat(path); err == nil && st.Mode().Type() == os.ModeSocket {
		_ = os.Remove(path)
	}
	old := unix.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if group != "" {
		g, err := user.LookupGroup(group)
		if err == nil {
			var gid int
			if gid, err = strconv.Atoi(g.Gid); err == nil {
				err = os.Chown(path, -1, gid)
			}
		}
		if err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("socket group: %w", err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // group stellwerk-agent must connect
		_ = ln.Close()
		return nil, fmt.Errorf("socket mode: %w", err)
	}
	return ln, nil
}

// timeSynced reports whether the kernel considers the clock synchronized
// (adjtimex state != TIME_ERROR). Read-only: Modes is zero.
func timeSynced() (bool, error) {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return false, fmt.Errorf("adjtimex: %w", err)
	}
	return state != unix.TIME_ERROR, nil
}

// Command stellwerk-agent is the unprivileged agent core.
//
//	run            connect to central and serve (systemd unit)
//	enroll         enroll with a one-time token (as root; token on stdin)
//	unenroll       remove the local identity
//	status         show identity, certificate and helper status
//	check-config   validate /etc/stellwerk/agent.yaml
//	bench          measure collection cost against the resource budget
//	version        print version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/collect"
	"github.com/nobrain-soft/libremanager/internal/agent/enroll"
	"github.com/nobrain-soft/libremanager/internal/agent/helperclient"
	"github.com/nobrain-soft/libremanager/internal/agent/inventory"
	"github.com/nobrain-soft/libremanager/internal/agent/jobs"
	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/agent/runtime"
	"github.com/nobrain-soft/libremanager/internal/agent/spool"
	"github.com/nobrain-soft/libremanager/internal/agent/state"
	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/journal"
	"github.com/nobrain-soft/libremanager/internal/common/timesync"
	"github.com/nobrain-soft/libremanager/internal/common/version"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: stellwerk-agent <run|enroll|unenroll|status|check-config|bench|version> [--config /etc/stellwerk/agent.yaml]")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", policy.DefaultPath, "local policy file")
	tokenStdin := fs.Bool("token-stdin", false, "read the enrollment token from stdin (enroll)")
	debug := fs.Bool("debug", false, "debug logging")
	benchDur := fs.Duration("duration", 2*time.Minute, "bench duration")
	benchIv := fs.Duration("interval", 15*time.Second, "bench collection interval")
	_ = fs.Parse(os.Args[2:])

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "version", "--version":
		fmt.Println("stellwerk-agent", version.String())
		return
	case "run":
		err = run(ctx, *cfgPath)
	case "enroll":
		err = doEnroll(ctx, *cfgPath, *tokenStdin)
	case "unenroll":
		err = unenroll(*cfgPath)
	case "status":
		err = status(ctx, *cfgPath)
	case "check-config":
		err = checkConfig(*cfgPath)
	case "bench":
		err = bench(ctx, *benchDur, *benchIv)
	default:
		usage()
	}
	if err != nil {
		slog.Error("command failed", "command", cmd, "err", err)
		stop()
		os.Exit(1) //nolint:gocritic // stop() was called explicitly
	}
}

func loadPolicy(path string) (*policy.Policy, error) {
	// The policy must be root-owned: the agent user must not be able to
	// widen its own permissions.
	return policy.Load(path, true)
}

func run(ctx context.Context, cfgPath string) error {
	pol, err := loadPolicy(cfgPath)
	if err != nil {
		return err
	}
	if pol.Central == "" {
		return errors.New("central is not configured in " + cfgPath)
	}
	paths := state.DefaultPaths(pol.StateDir, pol.CAFile)
	cert, err := state.LoadIdentity(paths)
	if err != nil {
		return err
	}
	keys, err := state.LoadJobKeys(paths)
	if err != nil {
		return err
	}
	_, roots, err := state.LoadPinnedRoot(paths, pol.CAFingerprint)
	if err != nil {
		return err
	}
	hostID, err := state.ReadHostID(paths)
	if err != nil {
		return err
	}
	nonces, err := envelope.OpenFileNonceStore(paths.NonceFile(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = nonces.Close() }()
	sp, err := spool.Open(paths.SpoolDir(), pol.Spool.MaxBytes, pol.Spool.MaxAge)
	if err != nil {
		return err
	}
	defer func() { _ = sp.Close() }()

	hc := &helperclient.Client{SocketPath: pol.HelperSocket}
	jr := journal.New("stellwerk-agent")
	defer func() { _ = jr.Close() }()
	helperUp := func(ctx context.Context) bool {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err := hc.Ping(pctx)
		return err == nil
	}
	inv := &inventory.Collector{Privileged: privilegedAdapter{hc}, AgentVersion: version.Version, Policy: pol.Summary(),
		HelperAvailable: helperUp(ctx)}
	collectors := collect.DefaultCollectors(collect.Options{})
	probes := collect.FindProbeCollector(collectors)
	runner := &jobs.Runner{
		Verifier: &envelope.Verifier{Keys: keys, HostID: hostID, Nonces: nonces},
		Policy:   &policy.Evaluator{P: pol}, Limiter: policy.NewRateLimiter(pol.Limits.MaxJobsPerMinute, nil),
		Helper: hc, Journal: jr,
		TimeSynced: func() (bool, error) { ok, _, err := timesync.Synchronized(); return ok, err },
	}
	agent, err := runtime.New(runtime.Config{
		Policy: pol, Paths: paths, Identity: state.NewIdentity(cert), Roots: roots, Version: version.Version,
		Metrics: &metricsAdapter{collectors: collectors, enc: collect.NewEncoder(10000)}, Inventory: inv, Spool: sp,
		Processes: processAdapter{collect.NewProcSampler("/proc")}, Updates: hc, Checks: newChecks(hc, pol),
		HelperAvailable: helperUp, Runner: runner,
		OnProbes: func(p []*agentv1.Probe) {
			if probes != nil {
				probes.SetProbes(p)
			}
		},
	})
	if err != nil {
		return err
	}
	if agent.HostID() != hostID {
		return errors.New("certificate identity does not match /etc/stellwerk/host-id")
	}
	slog.Info("stellwerk agent starting", "version", version.Version, "host_id", hostID, "central", pol.Central)
	_ = jr.Send(journal.PriInfo, "Stellwerk agent started", map[string]string{"STELLWERK_HOST_ID": hostID})
	return agent.Run(ctx)
}

func readToken(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, 512)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	tok := strings.TrimSpace(line)
	if tok == "" {
		return "", errors.New("no token on stdin")
	}
	return tok, nil
}

func doEnroll(ctx context.Context, cfgPath string, tokenStdin bool) error {
	if !tokenStdin {
		return errors.New("pass the token on stdin with --token-stdin (never as an argument)")
	}
	if os.Geteuid() != 0 {
		return errors.New("enroll must run as root (it writes root-owned trust anchors)")
	}
	pol, err := loadPolicy(cfgPath)
	if err != nil {
		return err
	}
	tok, err := readToken(os.Stdin)
	if err != nil {
		return err
	}
	paths := state.DefaultPaths(pol.StateDir, pol.CAFile)
	if _, err := state.LoadIdentity(paths); err == nil {
		return errors.New("already enrolled; run `stellwerk-agent unenroll` first")
	}
	inv := &inventory.Collector{AgentVersion: version.Version}
	res, err := enroll.Enroll(ctx, enroll.Options{
		Central: pol.Central, CAFingerprint: pol.CAFingerprint, Token: tok, Paths: paths, Facts: inv.Facts(ctx),
		Chown: chownToAgent,
	})
	if err != nil {
		return err
	}
	fmt.Printf("enrolled as host %s (job keys: %s)\n", res.HostID, strings.Join(res.KeyIDs, ", "))
	return nil
}

// chownToAgent gives the state directory to the stellwerk-agent user.
// Traversal is confined with os.Root so symlinks cannot redirect it.
func chownToAgent(dir string) error {
	u, err := user.Lookup("stellwerk-agent")
	if err != nil {
		slog.Warn("user stellwerk-agent not found; state stays root-owned (development install?)")
		return nil
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(root.FS(), ".", func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return root.Lchown(p, uid, gid)
	})
}

func unenroll(cfgPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("unenroll must run as root")
	}
	pol, err := loadPolicy(cfgPath)
	if err != nil {
		return err
	}
	paths := state.DefaultPaths(pol.StateDir, pol.CAFile)
	for _, p := range []string{filepath.Join(paths.StateDir, "agent.key"), filepath.Join(paths.StateDir, "agent.crt"), paths.HostIDFile} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	fmt.Println("local identity removed. Decommission the host in the Stellwerk UI to revoke its certificate.")
	return nil
}

func status(ctx context.Context, cfgPath string) error {
	pol, err := policy.Load(cfgPath, false)
	if err != nil {
		return err
	}
	paths := state.DefaultPaths(pol.StateDir, pol.CAFile)
	fmt.Printf("central:        %s\n", pol.Central)
	if id, err := state.ReadHostID(paths); err == nil {
		fmt.Printf("host id:        %s\n", id)
	} else {
		fmt.Printf("host id:        (not enrolled)\n")
	}
	if c, err := state.LoadIdentity(paths); err == nil {
		fmt.Printf("certificate:    valid until %s\n", c.Leaf.NotAfter.Format(time.RFC3339))
	} else {
		fmt.Printf("certificate:    %v\n", err)
	}
	hc := &helperclient.Client{SocketPath: pol.HelperSocket, Timeout: 5 * time.Second}
	if p, err := hc.Ping(ctx); err == nil {
		fmt.Printf("helper:         ok (version %s)\n", p.GetVersion())
	} else {
		fmt.Printf("helper:         unavailable (%v)\n", err)
	}
	if ok, off, err := timesync.Synchronized(); err == nil {
		fmt.Printf("time sync:      %v (offset %s)\n", ok, off)
	}
	return nil
}

func checkConfig(cfgPath string) error {
	pol, err := policy.Load(cfgPath, os.Geteuid() == 0)
	if err != nil {
		return err
	}
	s := pol.Summary()
	fmt.Printf("ok: central=%s metrics=%v inventory=%v checks=%v upgrade=%v install=%v remove=%v services=%v reboot=%v shell=%v root_shell=%v scripts=%v\n",
		pol.Central, s.GetMetrics(), s.GetInventory(), s.GetSecurityChecks(), s.GetPkgUpgrade(), s.GetPkgInstall(), s.GetPkgRemove(),
		s.GetServiceControl(), s.GetReboot(), s.GetShell(), s.GetShellAllowRoot(), s.GetExecScripts())
	return nil
}

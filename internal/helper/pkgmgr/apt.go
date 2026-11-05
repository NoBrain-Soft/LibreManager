package pkgmgr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Apt is the Debian/Ubuntu backend.
//
// "Upgrade all" is `apt-get upgrade --with-new-pkgs`, and the listing
// simulates exactly that command. Unlike dist-upgrade it never removes
// packages to resolve conflicts (unsafe for unattended fleet patching), but
// unlike plain upgrade it installs new dependencies, which is what kernel
// ABI bumps (new linux-image-* packages) need. Packages that would require
// removals stay "kept back" and are neither listed nor installed.
type Apt struct {
	Runner runner.Runner
	// RebootFile / RebootPkgsFile default to /var/run/reboot-required(.pkgs).
	RebootFile     string
	RebootPkgsFile string
}

func aptEnv() []string {
	return []string{"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "NEEDRESTART_MODE=l"}
}

func aptOpts(verb ...string) []string {
	return append([]string{
		"-y", "-q",
		"-o", "DPkg::Lock::Timeout=300",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
	}, verb...)
}

// Name implements Manager.
func (a *Apt) Name() string { return "apt" }

// Refresh implements Manager.
func (a *Apt) Refresh(ctx context.Context, out Output) (Result, error) {
	return run(ctx, a.Runner, out.cmd("apt-get", aptEnv(), "-q", "-o", "DPkg::Lock::Timeout=300", "update"))
}

// ListUpgrades implements Manager (simulation only, no lock, no refresh).
func (a *Apt) ListUpgrades(ctx context.Context) ([]Upgrade, error) {
	data, code, err := runner.Output(ctx, a.Runner, runner.Cmd{
		Name: "apt-get", Env: aptEnv(),
		Args: []string{"-s", "-q", "-o", "Debug::NoLocking=1", "upgrade", "--with-new-pkgs"},
	}, maxListOutput)
	if err != nil {
		return nil, fmt.Errorf("pkgmgr: apt-get -s: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("pkgmgr: apt-get -s exited with %d", code)
	}
	return ParseAptSimulate(data), nil
}

// Upgrade implements Manager.
func (a *Apt) Upgrade(ctx context.Context, spec UpgradeSpec, out Output) (Result, error) {
	switch spec.Scope {
	case agentv1.UpgradeScope_UPGRADE_SCOPE_ALL:
		return run(ctx, a.Runner, out.cmd("apt-get", aptEnv(), aptOpts("upgrade", "--with-new-pkgs")...))
	case agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY:
		ups, err := a.ListUpgrades(ctx)
		if err != nil {
			return Result{ExitCode: -1}, err
		}
		var names []string
		for _, u := range ups {
			// Newly pulled-in packages are installed as dependencies.
			if u.IsSecurity && u.CurrentVersion != "" {
				names = append(names, u.Name)
			}
		}
		if len(names) == 0 {
			info(out, "no security updates pending")
			return Result{}, nil
		}
		return a.installOnlyUpgrade(ctx, names, out)
	case agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED:
		return a.installOnlyUpgrade(ctx, spec.Packages, out)
	default:
		return Result{ExitCode: -1}, errors.New("pkgmgr: invalid upgrade scope")
	}
}

func (a *Apt) installOnlyUpgrade(ctx context.Context, names []string, out Output) (Result, error) {
	if err := ValidateNames(names); err != nil {
		return Result{ExitCode: -1}, err
	}
	args := append(aptOpts("install", "--only-upgrade", "--"), names...)
	return run(ctx, a.Runner, out.cmd("apt-get", aptEnv(), args...))
}

// Install implements Manager.
func (a *Apt) Install(ctx context.Context, names []string, out Output) (Result, error) {
	if err := ValidateNames(names); err != nil {
		return Result{ExitCode: -1}, err
	}
	return run(ctx, a.Runner, out.cmd("apt-get", aptEnv(), append(aptOpts("install", "--"), names...)...))
}

// Remove implements Manager.
func (a *Apt) Remove(ctx context.Context, names []string, out Output) (Result, error) {
	if err := ValidateNames(names); err != nil {
		return Result{ExitCode: -1}, err
	}
	return run(ctx, a.Runner, out.cmd("apt-get", aptEnv(), append(aptOpts("remove", "--"), names...)...))
}

// Hold implements Manager.
func (a *Apt) Hold(ctx context.Context, names []string, hold bool, out Output) (Result, error) {
	if err := ValidateNames(names); err != nil {
		return Result{ExitCode: -1}, err
	}
	verb := "unhold"
	if hold {
		verb = "hold"
	}
	return run(ctx, a.Runner, out.cmd("apt-mark", aptEnv(), append([]string{verb, "--"}, names...)...))
}

// RebootRequired implements Manager via /var/run/reboot-required(.pkgs).
func (a *Apt) RebootRequired(context.Context) (bool, []string, error) {
	flag, pkgs := a.RebootFile, a.RebootPkgsFile
	if flag == "" {
		flag = "/var/run/reboot-required"
	}
	if pkgs == "" {
		pkgs = flag + ".pkgs"
	}
	if _, err := os.Stat(flag); errors.Is(err, os.ErrNotExist) {
		return false, nil, nil
	} else if err != nil {
		return false, nil, fmt.Errorf("pkgmgr: %w", err)
	}
	var reasons []string
	if data, err := readCapped(pkgs, 1<<20); err == nil {
		seen := map[string]bool{}
		for _, l := range lines(data) {
			l = strings.TrimSpace(l)
			if policy.ValidPackageName(l) && !seen[l] && len(reasons) < maxReasons {
				seen[l] = true
				reasons = append(reasons, l)
			}
		}
	}
	return true, reasons, nil
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // fixed system path
	if err != nil {
		return nil, fmt.Errorf("pkgmgr: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("pkgmgr: %w", err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("pkgmgr: %s too large", path)
	}
	return data, nil
}

// ParseAptSimulate extracts upgrades from `apt-get -s` output. Relevant
// lines look like:
//
//	Inst libssl3 [3.0.11-1~deb12u1] (3.0.13-1~deb12u2 Debian-Security:12/stable-security [amd64])
//	Inst linux-image-6.8.0-50-generic (6.8.0-50.51 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
//	Inst libc6 [2.36-9+deb12u3] (2.36-9+deb12u4 Debian:12.5/stable [amd64]) [libc-bin:amd64 ]
//
// A package is a security update when any candidate origin is a
// "-security" suite or the Debian-Security archive. Malformed lines and
// invalid package names are skipped.
func ParseAptSimulate(data []byte) []Upgrade {
	var out []Upgrade
	for _, line := range lines(data) {
		rest, ok := strings.CutPrefix(line, "Inst ")
		if !ok || len(out) >= maxUpgrades {
			continue
		}
		name, rest, _ := strings.Cut(rest, " ")
		if !policy.ValidPackageName(name) {
			continue
		}
		u := Upgrade{Name: name}
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				continue
			}
			u.CurrentVersion = rest[1:end]
			rest = strings.TrimSpace(rest[end+1:])
		}
		if !strings.HasPrefix(rest, "(") {
			continue
		}
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			continue
		}
		inner := rest[1:end]
		if i := strings.LastIndex(inner, " ["); i >= 0 && strings.HasSuffix(inner, "]") {
			u.Arch = inner[i+2 : len(inner)-1]
			inner = inner[:i]
		}
		ver, origins, _ := strings.Cut(inner, " ")
		if ver == "" {
			continue
		}
		u.CandidateVersion = ver
		var srcs []string
		for o := range strings.SplitSeq(origins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				srcs = append(srcs, o)
				if strings.Contains(strings.ToLower(o), "-security") {
					u.IsSecurity = true
				}
			}
		}
		u.Source = strings.Join(srcs, ", ")
		out = append(out, u)
	}
	return out
}

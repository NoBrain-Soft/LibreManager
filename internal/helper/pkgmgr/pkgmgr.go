// Package pkgmgr implements the helper's package-manager backends
// (ARCHITECTURE.md §7.2): apt for Debian/Ubuntu and dnf for the RHEL family.
//
// Every operation is non-interactive, goes through runner.Runner (argument
// arrays, trusted binaries, no shell) and re-validates package names with
// policy.ValidPackageName even though the helper already checked them.
package pkgmgr

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Upgrade is one pending package update.
type Upgrade struct {
	Name             string
	Arch             string
	CurrentVersion   string // empty for packages newly pulled in by the upgrade
	CandidateVersion string
	Source           string // origin / repository
	IsSecurity       bool
	Advisories       []string
}

// UpgradeSpec selects what Upgrade installs.
type UpgradeSpec struct {
	Scope    agentv1.UpgradeScope
	Packages []string // only for UPGRADE_SCOPE_NAMED
}

// Output receives the streamed output of an operation; nil writers discard.
type Output struct {
	Stdout io.Writer
	Stderr io.Writer
}

// Result of a state-changing operation.
type Result struct {
	ExitCode int
}

// Manager is implemented by each backend. A non-zero exit of the package
// manager is reported in Result, not as an error; errors mean the operation
// could not be attempted (invalid input, binary missing, cancelled).
type Manager interface {
	Name() string
	Refresh(ctx context.Context, out Output) (Result, error)
	// ListUpgrades never refreshes package metadata.
	ListUpgrades(ctx context.Context) ([]Upgrade, error)
	Upgrade(ctx context.Context, spec UpgradeSpec, out Output) (Result, error)
	Install(ctx context.Context, names []string, out Output) (Result, error)
	Remove(ctx context.Context, names []string, out Output) (Result, error)
	Hold(ctx context.Context, names []string, hold bool, out Output) (Result, error)
	RebootRequired(ctx context.Context) (bool, []string, error)
}

// Limits for parsed data.
const (
	maxListOutput = 32 << 20
	maxUpgrades   = 20000
	maxLine       = 64 << 10
	maxReasons    = 100
)

// ErrInvalidPackage is returned for names that fail validation.
var ErrInvalidPackage = errors.New("pkgmgr: invalid package name")

// ValidateNames re-checks a package list (defense in depth).
func ValidateNames(names []string) error {
	if len(names) == 0 || len(names) > policy.MaxPackagesPerJob {
		return fmt.Errorf("%w: need 1..%d packages, got %d", ErrInvalidPackage, policy.MaxPackagesPerJob, len(names))
	}
	for _, n := range names {
		if !policy.ValidPackageName(n) {
			return fmt.Errorf("%w: %q", ErrInvalidPackage, n)
		}
	}
	return nil
}

// Detect picks the backend from os-release (ID, ID_LIKE) and binary
// presence. osRelease defaults to /etc/os-release.
func Detect(r runner.Runner, osRelease string) (Manager, error) {
	if osRelease == "" {
		osRelease = "/etc/os-release"
	}
	ids := []string{}
	if data, err := os.ReadFile(osRelease); err == nil { //nolint:gosec // fixed system path
		kv := ParseOSRelease(data)
		ids = append(ids, strings.ToLower(kv["ID"]))
		ids = append(ids, strings.Fields(strings.ToLower(kv["ID_LIKE"]))...)
	}
	isAny := func(names ...string) bool {
		return slices.ContainsFunc(ids, func(id string) bool { return slices.Contains(names, id) })
	}
	switch {
	case isAny("debian", "ubuntu") && r.Available("apt-get"):
		return &Apt{Runner: r}, nil
	case isAny("rhel", "fedora", "centos", "rocky", "almalinux") && r.Available("dnf"):
		return &Dnf{Runner: r}, nil
	case r.Available("apt-get"):
		return &Apt{Runner: r}, nil
	case r.Available("dnf"):
		return &Dnf{Runner: r}, nil
	}
	return nil, errors.New("pkgmgr: no supported package manager found")
}

// ParseOSRelease parses KEY=value lines (values optionally quoted).
func ParseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range lines(data) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
}

// lines splits data into lines, skipping lines longer than maxLine.
func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxLine)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func (o Output) cmd(name string, env []string, args ...string) runner.Cmd {
	return runner.Cmd{Name: name, Args: args, Env: env, Stdout: o.Stdout, Stderr: o.Stderr}
}

func run(ctx context.Context, r runner.Runner, c runner.Cmd) (Result, error) {
	code, err := r.Run(ctx, c)
	if err != nil {
		return Result{ExitCode: code}, fmt.Errorf("pkgmgr: %w", err)
	}
	return Result{ExitCode: code}, nil
}

func info(o Output, msg string) {
	if o.Stdout != nil {
		_, _ = io.WriteString(o.Stdout, msg+"\n")
	}
}

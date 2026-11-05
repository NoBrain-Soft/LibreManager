package pkgmgr

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Dnf is the RHEL/Rocky/Alma/Fedora backend. Listing runs with -C
// (cache only) so it never refreshes metadata; PkgRefresh (makecache)
// populates the cache.
type Dnf struct {
	Runner runner.Runner
	// KernelRelease returns the running kernel (uname -r); tests override it.
	KernelRelease func() string
}

// Name implements Manager.
func (d *Dnf) Name() string { return "dnf" }

func (d *Dnf) dnf(ctx context.Context, out Output, args ...string) (Result, error) {
	return run(ctx, d.Runner, out.cmd("dnf", nil, append([]string{"-y"}, args...)...))
}

// Refresh implements Manager.
func (d *Dnf) Refresh(ctx context.Context, out Output) (Result, error) {
	return d.dnf(ctx, out, "makecache")
}

// ListUpgrades implements Manager.
func (d *Dnf) ListUpgrades(ctx context.Context) ([]Upgrade, error) {
	data, code, err := runner.Output(ctx, d.Runner, runner.Cmd{Name: "dnf", Args: []string{"-q", "-C", "check-update"}}, maxListOutput)
	if err != nil {
		return nil, fmt.Errorf("pkgmgr: dnf check-update: %w", err)
	}
	switch code {
	case 0:
		return nil, nil
	case 100: // updates available
	default:
		return nil, fmt.Errorf("pkgmgr: dnf check-update exited with %d", code)
	}
	ups := ParseCheckUpdate(data)

	// Installed versions and security advisories are best effort.
	qf := "%{NAME}.%{ARCH} %|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\\n"
	if data, code, err := runner.Output(ctx, d.Runner, runner.Cmd{Name: "rpm", Args: []string{"-qa", "--qf", qf}}, maxListOutput); err == nil && code == 0 {
		cur := ParseRPMVersions(data)
		for i := range ups {
			ups[i].CurrentVersion = cur[ups[i].Name+"."+ups[i].Arch]
		}
	}
	args := []string{"-q", "-C", "updateinfo", "list", "--security", "--available"}
	if data, code, err := runner.Output(ctx, d.Runner, runner.Cmd{Name: "dnf", Args: args}, maxListOutput); err == nil && code == 0 {
		adv := ParseUpdateinfo(data)
		for i := range ups {
			if a := adv[ups[i].Name+"."+ups[i].Arch]; len(a) > 0 {
				ups[i].IsSecurity, ups[i].Advisories = true, a
			}
		}
	}
	return ups, nil
}

// Upgrade implements Manager.
func (d *Dnf) Upgrade(ctx context.Context, spec UpgradeSpec, out Output) (Result, error) {
	switch spec.Scope {
	case agentv1.UpgradeScope_UPGRADE_SCOPE_ALL:
		return d.dnf(ctx, out, "upgrade")
	case agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY:
		return d.dnf(ctx, out, "upgrade", "--security")
	case agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED:
		if err := ValidateNames(spec.Packages); err != nil {
			return Result{ExitCode: -1}, err
		}
		return d.dnf(ctx, out, append([]string{"upgrade", "--"}, spec.Packages...)...)
	default:
		return Result{ExitCode: -1}, errors.New("pkgmgr: invalid upgrade scope")
	}
}

// Install implements Manager.
func (d *Dnf) Install(ctx context.Context, names []string, out Output) (Result, error) {
	if err := ValidateNames(names); err != nil {
		return Result{ExitCode: -1}, err
	}
	return d.dnf(ctx, out, append([]string{"install", "--"}, names...)...)
}

// Remove implements Manager.
func (d *Dnf) Remove(ctx context.Context, names []string, out Output) (Result, error) {
	if err := ValidateNames(names); err != nil {
		return Result{ExitCode: -1}, err
	}
	return d.dnf(ctx, out, append([]string{"remove", "--"}, names...)...)
}

// Hold implements Manager (requires the versionlock plugin).
func (d *Dnf) Hold(ctx context.Context, names []string, hold bool, out Output) (Result, error) {
	if err := ValidateNames(names); err != nil {
		return Result{ExitCode: -1}, err
	}
	verb := "delete"
	if hold {
		verb = "add"
	}
	return d.dnf(ctx, out, append([]string{"versionlock", verb, "--"}, names...)...)
}

// RebootRequired implements Manager: `needs-restarting -r` when installed
// (exit 1 = reboot required), else running vs. newest installed kernel.
func (d *Dnf) RebootRequired(ctx context.Context) (bool, []string, error) {
	if d.Runner.Available("needs-restarting") {
		data, code, err := runner.Output(ctx, d.Runner, runner.Cmd{Name: "needs-restarting", Args: []string{"-r"}}, 1<<20)
		if err != nil {
			return false, nil, fmt.Errorf("pkgmgr: needs-restarting: %w", err)
		}
		switch code {
		case 0:
			return false, nil, nil
		case 1:
			return true, ParseNeedsRestarting(data), nil
		default:
			return false, nil, fmt.Errorf("pkgmgr: needs-restarting exited with %d", code)
		}
	}
	running := d.kernelRelease()
	for _, pkg := range []string{"kernel-core", "kernel"} {
		qf := "%{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\\n"
		data, code, err := runner.Output(ctx, d.Runner, runner.Cmd{Name: "rpm", Args: []string{"-q", "--qf", qf, "--", pkg}}, 1<<20)
		if err != nil {
			return false, nil, fmt.Errorf("pkgmgr: rpm -q: %w", err)
		}
		if code != 0 {
			continue
		}
		newest := NewestKernel(data)
		if newest == "" || running == "" {
			break
		}
		if newest != running {
			return true, []string{fmt.Sprintf("kernel %s installed, running %s", newest, running)}, nil
		}
		return false, nil, nil
	}
	return false, nil, errors.New("pkgmgr: cannot determine installed kernel")
}

func (d *Dnf) kernelRelease() string {
	if d.KernelRelease != nil {
		return d.KernelRelease()
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

func knownArch(a string) bool {
	switch a {
	case "x86_64", "aarch64", "noarch", "i686", "i386", "ppc64le", "s390x", "armv7hl", "riscv64", "src":
		return true
	}
	return false
}

// splitNameArch splits "openssl-libs.x86_64".
func splitNameArch(s string) (name, arch string, ok bool) {
	i := strings.LastIndexByte(s, '.')
	if i <= 0 || !knownArch(s[i+1:]) || !policy.ValidPackageName(s[:i]) {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ParseCheckUpdate parses `dnf -q check-update` output:
//
//	openssl-libs.x86_64     1:3.0.7-27.el9      baseos
//
// Long names wrap onto their own line; the "Obsoleting Packages" section
// ends the list.
func ParseCheckUpdate(data []byte) []Upgrade {
	var out []Upgrade
	pending := ""
	for _, line := range lines(data) {
		if strings.HasPrefix(line, "Obsoleting Packages") {
			break
		}
		f := strings.Fields(line)
		if len(f) == 1 && pending == "" && strings.Contains(f[0], ".") && !strings.HasPrefix(line, " ") {
			pending = f[0]
			continue
		}
		if pending != "" {
			if len(f) == 2 {
				f = []string{pending, f[0], f[1]}
			}
			pending = ""
		}
		if len(f) != 3 || len(out) >= maxUpgrades {
			continue
		}
		name, arch, ok := splitNameArch(f[0])
		if !ok {
			continue
		}
		out = append(out, Upgrade{Name: name, Arch: arch, CandidateVersion: f[1], Source: f[2]})
	}
	return out
}

// ParseRPMVersions parses "name.arch [epoch:]version-release" lines.
func ParseRPMVersions(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range lines(data) {
		f := strings.Fields(line)
		if len(f) != 2 || len(out) >= 4*maxUpgrades {
			continue
		}
		if _, _, ok := splitNameArch(f[0]); ok {
			out[f[0]] = f[1]
		}
	}
	return out
}

// ParseNEVRA splits "openssl-libs-1:3.0.7-27.el9.x86_64" into
// name, "[epoch:]version-release" and arch.
func ParseNEVRA(s string) (name, evr, arch string, ok bool) {
	i := strings.LastIndexByte(s, '.')
	if i <= 0 || !knownArch(s[i+1:]) {
		return "", "", "", false
	}
	nvr := s[:i]
	j := strings.LastIndexByte(nvr, '-')
	if j <= 0 {
		return "", "", "", false
	}
	k := strings.LastIndexByte(nvr[:j], '-')
	if k <= 0 || k+1 == j || j+1 == len(nvr) {
		return "", "", "", false
	}
	if !policy.ValidPackageName(nvr[:k]) {
		return "", "", "", false
	}
	return nvr[:k], nvr[k+1:], s[i+1:], true
}

// ParseUpdateinfo parses `dnf updateinfo list --security` (dnf4:
// "RHSA-2024:1234 Important/Sec. pkg-1.0-1.el9.x86_64"; dnf5 advisory
// list adds type/date columns) into name.arch -> advisory ids.
func ParseUpdateinfo(data []byte) map[string][]string {
	out := map[string][]string{}
	for _, line := range lines(data) {
		f := strings.Fields(line)
		if len(f) < 2 || !validAdvisory(f[0]) {
			continue
		}
		for _, field := range f[1:] {
			name, _, arch, ok := ParseNEVRA(field)
			if !ok {
				continue
			}
			k := name + "." + arch
			if !slices.Contains(out[k], f[0]) && len(out[k]) < 32 && len(out) < maxUpgrades {
				out[k] = append(out[k], f[0])
			}
			break
		}
	}
	return out
}

func validAdvisory(s string) bool {
	if len(s) < 3 || len(s) > 64 || s[0] < 'A' || s[0] > 'Z' || !strings.Contains(s, "-") {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && !strings.ContainsRune("-:._", c) {
			return false
		}
	}
	return true
}

// ParseNeedsRestarting extracts "  * name" lines of `needs-restarting -r`.
func ParseNeedsRestarting(data []byte) []string {
	var out []string
	for _, line := range lines(data) {
		if r, ok := strings.CutPrefix(strings.TrimSpace(line), "* "); ok && len(out) < maxReasons {
			if r = strings.TrimSpace(r); r != "" && len(r) <= 256 {
				out = append(out, r)
			}
		}
	}
	return out
}

// NewestKernel picks the most recently installed kernel from
// "<installtime> <version-release.arch>" lines.
func NewestKernel(data []byte) string {
	best, bestT := "", int64(-1)
	for _, line := range lines(data) {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		t, err := strconv.ParseInt(f[0], 10, 64)
		if err == nil && t > bestT {
			best, bestT = f[1], t
		}
	}
	return best
}

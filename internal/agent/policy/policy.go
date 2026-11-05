// Package policy loads and evaluates the agent's local policy
// (/etc/stellwerk/agent.yaml, ARCHITECTURE.md §5.1).
//
// The policy is owned by the host administrator and cannot be changed
// remotely. Both the agent core and the root helper load it independently
// and evaluate every SignedJob against it, so central (or a compromised
// core) can never widen what is allowed on a host.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// DefaultPath is the location of the local policy.
const DefaultPath = "/etc/stellwerk/agent.yaml"

// maxPolicyBytes bounds the policy file size.
const maxPolicyBytes = 64 << 10

// ErrDenied is wrapped by every policy rejection.
var ErrDenied = errors.New("policy: denied")

// Policy is the parsed agent.yaml.
type Policy struct {
	// Central gateway address host:port.
	Central string `yaml:"central"`
	// SHA-256 fingerprint of the pinned root CA ("AB:CD:..." or hex).
	CAFingerprint string `yaml:"ca_fingerprint_sha256"`
	// CAFile is the pinned root CA PEM (default /etc/stellwerk/ca.pem).
	CAFile string `yaml:"ca_file"`
	// StateDir defaults to /var/lib/stellwerk-agent.
	StateDir string `yaml:"state_dir"`
	// HelperSocket defaults to /run/stellwerk/helper.sock.
	HelperSocket string `yaml:"helper_socket"`
	// RequireTimeSync rejects jobs while the clock is not synchronized.
	RequireTimeSync *bool `yaml:"require_time_sync"`

	Capabilities Capabilities `yaml:"capabilities"`
	Limits       Limits       `yaml:"limits"`
	Spool        Spool        `yaml:"spool"`
}

// Capabilities lists what central may ask this host to do.
type Capabilities struct {
	Metrics        bool     `yaml:"metrics"`
	Inventory      bool     `yaml:"inventory"`
	SecurityChecks bool     `yaml:"security_checks"`
	Packages       Packages `yaml:"packages"`
	Services       Services `yaml:"services"`
	Reboot         bool     `yaml:"reboot"`
	Shell          Shell    `yaml:"shell"`
	ExecScripts    bool     `yaml:"exec_scripts"`
	FileRead       FileRead `yaml:"file_read"`
	SelfUpdate     bool     `yaml:"self_update"`
}

// Packages controls package management.
type Packages struct {
	List    bool  `yaml:"list"`
	Refresh *bool `yaml:"refresh"`
	Upgrade bool  `yaml:"upgrade"`
	Install bool  `yaml:"install"`
	Remove  bool  `yaml:"remove"`
}

// Services controls systemd unit actions. Deny wins over allow.
type Services struct {
	Control bool     `yaml:"control"`
	Allow   []string `yaml:"allow"`
	Deny    []string `yaml:"deny"`
}

// Shell controls interactive shells.
type Shell struct {
	Enabled   bool `yaml:"enabled"`
	AllowRoot bool `yaml:"allow_root"`
	// AllowedUsers: "name" for a user, "%group" for members of a local group,
	// "*" for any non-root account with a login shell.
	AllowedUsers []string `yaml:"allowed_users"`
}

// FileRead controls reading files. Deny wins over allow; "**" matches any
// number of path segments.
type FileRead struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// Limits are local rate/concurrency limits.
type Limits struct {
	MaxJobsPerMinute    int           `yaml:"max_jobs_per_minute"`
	MaxConcurrentShells int           `yaml:"max_concurrent_shells"`
	MaxShellDuration    time.Duration `yaml:"max_shell_duration"`
	MaxFileReadBytes    uint64        `yaml:"max_file_read_bytes"`
}

// Spool bounds the offline metrics buffer.
type Spool struct {
	MaxBytes int64         `yaml:"max_bytes"`
	MaxAge   time.Duration `yaml:"max_age"`
}

// Defaults applied to unset fields.
const (
	DefaultCAFile           = "/etc/stellwerk/ca.pem"
	DefaultStateDir         = "/var/lib/stellwerk-agent"
	DefaultHelperSocket     = "/run/stellwerk/helper.sock"
	DefaultJobsPerMinute    = 30
	DefaultConcurrentShells = 3
	DefaultShellDuration    = 4 * time.Hour
	DefaultFileReadBytes    = 1 << 20
	DefaultSpoolBytes       = 50 << 20
	DefaultSpoolAge         = 24 * time.Hour
)

// Parse parses and validates policy YAML. Unknown keys are an error so that
// typos never silently fall back to a default.
func Parse(data []byte) (*Policy, error) {
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy: file larger than %d bytes", maxPolicyBytes)
	}
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	p.applyDefaults()
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Load reads the policy from path. If requireRootOwned is set (helper), the
// file must be owned by root and not writable by group/others.
func Load(p string, requireRootOwned bool) (*Policy, error) {
	p = filepath.Clean(p)
	st, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if requireRootOwned {
		if err := CheckRootOwned(st); err != nil {
			return nil, fmt.Errorf("policy: %s: %w", p, err)
		}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Parse(data)
}

// CheckRootOwned verifies a file is root-owned and not group/world writable.
func CheckRootOwned(st os.FileInfo) error {
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("insecure permissions %v", st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
		return fmt.Errorf("not owned by root (uid %d)", sys.Uid)
	}
	return nil
}

func (p *Policy) applyDefaults() {
	if p.CAFile == "" {
		p.CAFile = DefaultCAFile
	}
	if p.StateDir == "" {
		p.StateDir = DefaultStateDir
	}
	if p.HelperSocket == "" {
		p.HelperSocket = DefaultHelperSocket
	}
	if p.Limits.MaxJobsPerMinute == 0 {
		p.Limits.MaxJobsPerMinute = DefaultJobsPerMinute
	}
	if p.Limits.MaxConcurrentShells == 0 {
		p.Limits.MaxConcurrentShells = DefaultConcurrentShells
	}
	if p.Limits.MaxShellDuration == 0 {
		p.Limits.MaxShellDuration = DefaultShellDuration
	}
	if p.Limits.MaxFileReadBytes == 0 {
		p.Limits.MaxFileReadBytes = DefaultFileReadBytes
	}
	if p.Spool.MaxBytes == 0 {
		p.Spool.MaxBytes = DefaultSpoolBytes
	}
	if p.Spool.MaxAge == 0 {
		p.Spool.MaxAge = DefaultSpoolAge
	}
}

func (p *Policy) validate() error {
	if p.Central != "" && !strings.Contains(p.Central, ":") {
		return errors.New("policy: central must be host:port")
	}
	for _, pat := range slices.Concat(p.Capabilities.Services.Allow, p.Capabilities.Services.Deny) {
		if _, err := path.Match(pat, "x"); err != nil {
			return fmt.Errorf("policy: invalid service pattern %q", pat)
		}
	}
	for _, pat := range slices.Concat(p.Capabilities.FileRead.Allow, p.Capabilities.FileRead.Deny) {
		if !strings.HasPrefix(pat, "/") {
			return fmt.Errorf("policy: file_read pattern %q must be absolute", pat)
		}
		if _, err := path.Match(strings.ReplaceAll(pat, "**", "*"), "/x"); err != nil {
			return fmt.Errorf("policy: invalid file_read pattern %q", pat)
		}
	}
	for _, u := range p.Capabilities.Shell.AllowedUsers {
		name := strings.TrimPrefix(u, "%")
		if u != "*" && !validAccountName.MatchString(name) {
			return fmt.Errorf("policy: invalid shell user/group %q", u)
		}
	}
	if p.Limits.MaxJobsPerMinute < 0 || p.Limits.MaxConcurrentShells < 0 {
		return errors.New("policy: limits must be positive")
	}
	return nil
}

// TimeSyncRequired reports whether jobs need a synchronized clock (default true).
func (p *Policy) TimeSyncRequired() bool {
	return p.RequireTimeSync == nil || *p.RequireTimeSync
}

// RefreshAllowed reports whether package list refresh is allowed (defaults to
// packages.list).
func (p *Policy) RefreshAllowed() bool {
	if p.Capabilities.Packages.Refresh != nil {
		return *p.Capabilities.Packages.Refresh
	}
	return p.Capabilities.Packages.List
}

// Summary returns the informational summary reported to central.
func (p *Policy) Summary() *agentv1.PolicySummary {
	c := p.Capabilities
	return &agentv1.PolicySummary{
		Metrics:           c.Metrics,
		Inventory:         c.Inventory,
		SecurityChecks:    c.SecurityChecks,
		PkgUpgrade:        c.Packages.Upgrade,
		PkgInstall:        c.Packages.Install,
		PkgRemove:         c.Packages.Remove,
		ServiceControl:    c.Services.Control,
		Reboot:            c.Reboot,
		Shell:             c.Shell.Enabled,
		ShellAllowRoot:    c.Shell.AllowRoot,
		ShellAllowedUsers: c.Shell.AllowedUsers,
		ExecScripts:       c.ExecScripts,
		SelfUpdate:        c.SelfUpdate,
	}
}

// Input validation shared by core and helper.
var (
	// Debian/RPM package names (+ optional arch suffix). No leading '-' so a
	// name can never be parsed as an option.
	validPackageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~:-]{0,127}$`)
	validUnitName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\\-]{0,250}\.(service|socket|timer|target|path|mount)$`)
	validAccountName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
)

// ValidPackageName reports whether name is an acceptable package name.
func ValidPackageName(name string) bool { return validPackageName.MatchString(name) }

// ValidUnitName reports whether name is an acceptable systemd unit name.
func ValidUnitName(name string) bool { return validUnitName.MatchString(name) }

// ValidAccountName reports whether name is an acceptable unix account name.
func ValidAccountName(name string) bool { return validAccountName.MatchString(name) }

// MaxPackagesPerJob bounds package lists in a single job.
const MaxPackagesPerJob = 500

func deny(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, args...))
}

// UserLookup resolves accounts (overridable for tests).
type UserLookup interface {
	Lookup(name string) (*user.User, error)
	GroupIDs(u *user.User) ([]string, error)
	LookupGroup(name string) (*user.Group, error)
	HasLoginShell(u *user.User) bool
}

// OSUsers implements UserLookup with os/user and /etc/passwd.
type OSUsers struct{}

// Lookup implements UserLookup.
func (OSUsers) Lookup(name string) (*user.User, error) { return user.Lookup(name) } //nolint:wrapcheck

// GroupIDs implements UserLookup.
func (OSUsers) GroupIDs(u *user.User) ([]string, error) { return u.GroupIds() } //nolint:wrapcheck

// LookupGroup implements UserLookup.
func (OSUsers) LookupGroup(name string) (*user.Group, error) { return user.LookupGroup(name) } //nolint:wrapcheck

// HasLoginShell reports whether the account's shell is not nologin/false.
func (OSUsers) HasLoginShell(u *user.User) bool {
	sh := LoginShell(u.Username)
	return sh != "" && !strings.HasSuffix(sh, "/nologin") && !strings.HasSuffix(sh, "/false")
}

// LoginShell returns the account's shell from /etc/passwd ("" if unknown).
func LoginShell(name string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == name {
			return f[6]
		}
	}
	return ""
}

// Evaluator applies the policy to verified jobs.
type Evaluator struct {
	P     *Policy
	Users UserLookup
}

// Check returns nil if the job's action is allowed by local policy.
func (e *Evaluator) Check(job *agentv1.Job) error {
	c := e.P.Capabilities
	switch a := job.GetAction().(type) {
	case *agentv1.Job_PkgRefresh:
		if !e.P.RefreshAllowed() {
			return deny("package refresh disabled")
		}
	case *agentv1.Job_PkgUpgrade:
		if !c.Packages.Upgrade {
			return deny("package upgrade disabled")
		}
		switch a.PkgUpgrade.GetScope() {
		case agentv1.UpgradeScope_UPGRADE_SCOPE_ALL, agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY:
			if len(a.PkgUpgrade.GetPackages()) != 0 {
				return deny("package list only allowed with named scope")
			}
		case agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED:
			if err := checkPackages(a.PkgUpgrade.GetPackages()); err != nil {
				return err
			}
		default:
			return deny("invalid upgrade scope")
		}
	case *agentv1.Job_PkgInstall:
		if !c.Packages.Install {
			return deny("package install disabled")
		}
		return checkPackages(a.PkgInstall.GetPackages())
	case *agentv1.Job_PkgRemove:
		if !c.Packages.Remove {
			return deny("package remove disabled")
		}
		return checkPackages(a.PkgRemove.GetPackages())
	case *agentv1.Job_Service:
		return e.checkService(a.Service)
	case *agentv1.Job_Reboot:
		if !c.Reboot {
			return deny("reboot disabled")
		}
		if a.Reboot.GetDelayS() > 3600 || len(a.Reboot.GetMessage()) > 256 {
			return deny("invalid reboot parameters")
		}
	case *agentv1.Job_Shell:
		return e.checkShell(a.Shell)
	case *agentv1.Job_RunCheck:
		if !c.SecurityChecks {
			return deny("security checks disabled")
		}
		if len(a.RunCheck.GetCheckIds()) > 200 {
			return deny("too many checks")
		}
	case *agentv1.Job_Script:
		if !c.ExecScripts {
			return deny("script execution disabled")
		}
	case *agentv1.Job_AgentUpdate:
		if !c.SelfUpdate {
			return deny("self update disabled")
		}
	case *agentv1.Job_FileRead:
		return e.CheckFileRead(a.FileRead.GetPath())
	case *agentv1.Job_ProbeConfig:
		if !c.Metrics {
			return deny("metrics disabled")
		}
		if len(a.ProbeConfig.GetProbes()) > 100 {
			return deny("too many probes")
		}
	case *agentv1.Job_CollectInventory:
		if !c.Inventory {
			return deny("inventory disabled")
		}
	default:
		return deny("unknown action")
	}
	return nil
}

func checkPackages(pkgs []string) error {
	if len(pkgs) == 0 {
		return deny("empty package list")
	}
	if len(pkgs) > MaxPackagesPerJob {
		return deny("too many packages")
	}
	for _, p := range pkgs {
		if !ValidPackageName(p) {
			return deny("invalid package name %q", p)
		}
	}
	return nil
}

func (e *Evaluator) checkService(s *agentv1.ServiceAction) error {
	sc := e.P.Capabilities.Services
	if !sc.Control {
		return deny("service control disabled")
	}
	unit := s.GetUnit()
	if !ValidUnitName(unit) {
		return deny("invalid unit name %q", unit)
	}
	if s.GetOp() == agentv1.ServiceOp_SERVICE_OP_UNSPECIFIED || agentv1.ServiceOp_name[int32(s.GetOp())] == "" {
		return deny("invalid service operation")
	}
	// The agent's own units are never controllable remotely.
	if strings.HasPrefix(unit, "stellwerk-agent") {
		return deny("unit %q is protected", unit)
	}
	for _, pat := range sc.Deny {
		if ok, _ := path.Match(pat, unit); ok {
			return deny("unit %q denied by policy", unit)
		}
	}
	for _, pat := range sc.Allow {
		if ok, _ := path.Match(pat, unit); ok {
			return nil
		}
	}
	return deny("unit %q not in allow list", unit)
}

func (e *Evaluator) users() UserLookup {
	if e.Users != nil {
		return e.Users
	}
	return OSUsers{}
}

func (e *Evaluator) checkShell(g *agentv1.ShellGrant) error {
	sh := e.P.Capabilities.Shell
	if !sh.Enabled {
		return deny("shell disabled")
	}
	name := g.GetUnixUser()
	if !ValidAccountName(name) {
		return deny("invalid unix user %q", name)
	}
	if g.GetMaxDurationS() == 0 || time.Duration(g.GetMaxDurationS())*time.Second > e.P.Limits.MaxShellDuration {
		return deny("shell duration exceeds local limit")
	}
	if g.GetCols() > 1000 || g.GetRows() > 1000 {
		return deny("invalid terminal size")
	}
	users := e.users()
	u, err := users.Lookup(name)
	if err != nil {
		return deny("unknown unix user %q", name)
	}
	if u.Uid == "0" {
		if !sh.AllowRoot {
			return deny("root shell not allowed")
		}
		return nil
	}
	for _, entry := range sh.AllowedUsers {
		switch {
		case entry == "*":
			if users.HasLoginShell(u) {
				return nil
			}
		case strings.HasPrefix(entry, "%"):
			grp, err := users.LookupGroup(entry[1:])
			if err != nil {
				continue
			}
			gids, err := users.GroupIDs(u)
			if err != nil {
				continue
			}
			if slices.Contains(gids, grp.Gid) {
				return nil
			}
		case entry == name:
			return nil
		}
	}
	return deny("unix user %q not allowed for shell", name)
}

// CheckFileRead checks an absolute, already-cleaned path against file_read
// rules. Callers must resolve symlinks first and open without following.
func (e *Evaluator) CheckFileRead(p string) error {
	fr := e.P.Capabilities.FileRead
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return deny("invalid path")
	}
	for _, pat := range fr.Deny {
		if MatchPath(pat, p) {
			return deny("path %q denied by policy", p)
		}
	}
	for _, pat := range fr.Allow {
		if MatchPath(pat, p) {
			return nil
		}
	}
	return deny("path %q not in allow list", p)
}

// MatchPath matches an absolute path against a pattern where "*" matches
// within one segment and "**" matches zero or more whole segments.
func MatchPath(pattern, p string) bool {
	return matchSegs(strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(p, "/"), "/"))
}

func matchSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			for i := 0; i <= len(segs); i++ {
				if matchSegs(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, err := path.Match(pat[0], segs[0]); err != nil || !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

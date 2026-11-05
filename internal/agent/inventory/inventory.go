// Package inventory collects the host inventory (ARCHITECTURE.md §5.1
// "Inventory (MVP)") as InventorySection messages: OS, hardware, network,
// packages, services, listening ports, accounts, scheduled tasks,
// containers, SSH host keys, local TLS certificates and agent info.
//
// Everything is read unprivileged from files (dpkg status, /proc, /sys,
// /etc) or with fixed argv commands (rpm, systemctl). Data that needs root
// (sudoers, socket owners of other users' processes) comes from an optional
// PrivilegedReader backed by the helper.
//
// Every section is bounded in entry count, string length and encoded size
// (see limits.go), so a pathological host cannot produce a report anywhere
// near the 4 MiB gRPC message limit. All strings are sanitized to valid
// UTF-8 because one invalid string would make the whole message unmarshalable.
package inventory

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	"github.com/nobrain-soft/libremanager/internal/common/version"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// CommandRunner runs programs with argument vectors (never a shell).
type CommandRunner = osutil.CommandRunner

// PrivilegedReader provides data only root can read. It is implemented by
// the helper client; a nil PrivilegedReader is allowed.
type PrivilegedReader interface {
	// SudoRules returns a summary of effective sudo rules, one per entry
	// (e.g. "%sudo ALL=(ALL:ALL) ALL").
	SudoRules(ctx context.Context) ([]string, error)
	// SocketOwners maps socket inode numbers (decimal strings, as in the
	// inode column of /proc/net/tcp) to their owning process in netstat
	// "PID/name" notation (e.g. "812/sshd"); a bare name is also accepted.
	SocketOwners(ctx context.Context) (map[string]string, error)
}

// DefaultCertDirs are scanned for local TLS certificates. The system CA
// bundle (/etc/ssl/certs, ca-bundle files) is never reported.
var DefaultCertDirs = []string{
	"/etc/letsencrypt/live",
	"/etc/pki/tls/certs",
	"/etc/pki/nginx",
	"/etc/nginx/ssl",
	"/etc/nginx/certs",
	"/etc/apache2/ssl",
	"/etc/httpd/ssl",
	"/etc/haproxy/certs",
	"/etc/ssl/local",
}

// Collector gathers inventory. The zero value collects from the running
// host; tests point the roots at fixtures.
type Collector struct {
	// Root is the host filesystem root (default "/").
	Root string
	// ProcRoot defaults to Root + "/proc".
	ProcRoot string
	// Exec runs rpm and systemctl (default osutil.ExecRunner).
	Exec CommandRunner
	// Privileged is optional.
	Privileged PrivilegedReader
	// AgentVersion defaults to version.Version.
	AgentVersion string
	// Policy is reported in AgentInfo (informational only).
	Policy          *agentv1.PolicySummary
	HelperAvailable bool
	// CertDirs defaults to DefaultCertDirs (paths below Root).
	CertDirs []string

	// SysRoot defaults to Root + "/sys".
	SysRoot string
	// Statfs overrides statfs(2) (tests).
	Statfs osutil.StatfsFunc
	// Uname returns the kernel release and machine (default uname(2)).
	Uname func() (release, machine string, err error)
	// InterfaceAddrs returns addresses (CIDR notation) per interface name
	// (default net.Interfaces).
	InterfaceAddrs func() (map[string][]string, error)
	// ContainerSockets overrides the Docker/Podman API sockets to query.
	ContainerSockets []ContainerSocket
	// Now overrides time.Now (tests).
	Now func() time.Time
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

func (c *Collector) root() string {
	if c.Root == "" {
		return "/"
	}
	return c.Root
}

// path joins elem below Root.
func (c *Collector) path(elem ...string) string {
	return filepath.Join(append([]string{c.root()}, elem...)...)
}

func (c *Collector) proc(elem ...string) string {
	root := c.ProcRoot
	if root == "" {
		root = c.path("proc")
	}
	return filepath.Join(append([]string{root}, elem...)...)
}

func (c *Collector) sys(elem ...string) string {
	root := c.SysRoot
	if root == "" {
		root = c.path("sys")
	}
	return filepath.Join(append([]string{root}, elem...)...)
}

func (c *Collector) exec() CommandRunner {
	if c.Exec != nil {
		return c.Exec
	}
	return osutil.ExecRunner{Timeout: 60 * time.Second, MaxOutput: 32 << 20}
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Collector) log() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *Collector) agentVersion() string {
	if c.AgentVersion != "" {
		return osutil.Clean(c.AgentVersion, maxShort)
	}
	return osutil.Clean(version.Version, maxShort)
}

// Facts returns the identity facts sent with Enroll and Hello.
func (c *Collector) Facts(_ context.Context) *agentv1.HostFacts {
	osr := c.osRelease()
	release, machine := c.uname()
	host := c.hostname()
	return &agentv1.HostFacts{
		Hostname:     host,
		Fqdn:         c.fqdn(host),
		OsFamily:     osFamily(osr),
		OsId:         osr.ID,
		OsVersion:    osr.VersionID,
		Kernel:       release,
		Arch:         machine,
		AgentVersion: c.agentVersion(),
		MachineId:    c.machineID(),
	}
}

type sectionFunc struct {
	name string
	fn   func(context.Context) (*agentv1.InventorySection, error)
}

func (c *Collector) sections() []sectionFunc {
	return []sectionFunc{
		{"os", c.OS},
		{"hardware", c.Hardware},
		{"network", c.Network},
		{"packages", c.Packages},
		{"services", c.Services},
		{"ports", c.Ports},
		{"users", c.Users},
		{"scheduled", c.ScheduledTasks},
		{"containers", c.Containers},
		{"ssh_host_keys", c.SSHHostKeys},
		{"certificates", c.Certificates},
		{"agent", c.Agent},
	}
}

// CollectAll collects every section. Sections that fail are logged and
// left out (for example packages on a host with neither dpkg nor rpm); the
// error is non-nil only when ctx ends, in which case the partial report is
// returned as well.
func (c *Collector) CollectAll(ctx context.Context) (*agentv1.InventoryReport, error) {
	report := &agentv1.InventoryReport{CollectedAtMs: c.now().UnixMilli()}
	for _, s := range c.sections() {
		if err := ctx.Err(); err != nil {
			return report, fmt.Errorf("inventory: %w", err)
		}
		sec, err := s.fn(ctx)
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				c.log().Debug("inventory section not available", "section", s.name, "error", err)
			} else {
				c.log().Warn("inventory section failed", "section", s.name, "error", err)
			}
			continue
		}
		report.Sections = append(report.Sections, sec)
	}
	return report, nil
}

// ErrUnsupported marks a section that does not apply to this host.
var ErrUnsupported = errors.New("inventory: not supported on this host")

// newSection wraps data in an InventorySection with its hash: SHA-256 over
// the deterministic protobuf encoding of the data message.
func newSection(data proto.Message) (*agentv1.InventorySection, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("inventory: marshal section: %w", err)
	}
	if len(b) > maxSectionBytes {
		return nil, fmt.Errorf("inventory: section exceeds %d bytes", maxSectionBytes)
	}
	sum := sha256.Sum256(b)
	s := &agentv1.InventorySection{Hash: sum[:]}
	switch d := data.(type) {
	case *agentv1.OsInfo:
		s.Data = &agentv1.InventorySection_Os{Os: d}
	case *agentv1.Hardware:
		s.Data = &agentv1.InventorySection_Hardware{Hardware: d}
	case *agentv1.NetworkInfo:
		s.Data = &agentv1.InventorySection_Network{Network: d}
	case *agentv1.PackageList:
		s.Data = &agentv1.InventorySection_Packages{Packages: d}
	case *agentv1.ServiceList:
		s.Data = &agentv1.InventorySection_Services{Services: d}
	case *agentv1.ListeningPorts:
		s.Data = &agentv1.InventorySection_Ports{Ports: d}
	case *agentv1.UserAccounts:
		s.Data = &agentv1.InventorySection_Users{Users: d}
	case *agentv1.ScheduledTasks:
		s.Data = &agentv1.InventorySection_Scheduled{Scheduled: d}
	case *agentv1.Containers:
		s.Data = &agentv1.InventorySection_Containers{Containers: d}
	case *agentv1.SshHostKeys:
		s.Data = &agentv1.InventorySection_SshHostKeys{SshHostKeys: d}
	case *agentv1.Certificates:
		s.Data = &agentv1.InventorySection_Certificates{Certificates: d}
	case *agentv1.AgentInfo:
		s.Data = &agentv1.InventorySection_Agent{Agent: d}
	default:
		return nil, fmt.Errorf("inventory: unknown section type %T", data)
	}
	return s, nil
}

// SectionData returns the payload message of a section (nil if unset).
func SectionData(s *agentv1.InventorySection) proto.Message {
	switch d := s.GetData().(type) {
	case *agentv1.InventorySection_Os:
		return d.Os
	case *agentv1.InventorySection_Hardware:
		return d.Hardware
	case *agentv1.InventorySection_Network:
		return d.Network
	case *agentv1.InventorySection_Packages:
		return d.Packages
	case *agentv1.InventorySection_Services:
		return d.Services
	case *agentv1.InventorySection_Ports:
		return d.Ports
	case *agentv1.InventorySection_Users:
		return d.Users
	case *agentv1.InventorySection_Scheduled:
		return d.Scheduled
	case *agentv1.InventorySection_Containers:
		return d.Containers
	case *agentv1.InventorySection_SshHostKeys:
		return d.SshHostKeys
	case *agentv1.InventorySection_Certificates:
		return d.Certificates
	case *agentv1.InventorySection_Agent:
		return d.Agent
	}
	return nil
}

// Agent returns the AgentInfo section.
func (c *Collector) Agent(_ context.Context) (*agentv1.InventorySection, error) {
	info := &agentv1.AgentInfo{
		Version:         c.agentVersion(),
		Commit:          osutil.Clean(version.Commit, maxShort),
		HelperAvailable: c.HelperAvailable,
	}
	if c.Policy != nil {
		p := proto.CloneOf(c.Policy)
		p.ShellAllowedUsers = cleanList(p.GetShellAllowedUsers(), 64, maxShort)
		info.Policy = p
	}
	return newSection(info)
}

// cleanList sanitizes and bounds a list of strings.
func cleanList(in []string, maxItems, maxLen int) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(in), maxItems))
	for _, s := range in {
		if len(out) >= maxItems {
			break
		}
		if s = osutil.Clean(s, maxLen); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// capBySize truncates items so their encoded size stays within budget.
func capBySize[T proto.Message](items []T, budget int) ([]T, bool) {
	total := 0
	for i, it := range items {
		// field tag + length prefix + message
		total += proto.Size(it) + 4
		if total > budget {
			return items[:i], true
		}
	}
	return items, false
}

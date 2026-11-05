package inventory

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// osRelease holds the os-release(5) fields we use (already sanitized).
type osRelease struct {
	ID         string
	IDLike     []string
	VersionID  string
	PrettyName string
}

// parseOSRelease parses os-release content (shell-style KEY=value with
// optional quoting).
func parseOSRelease(data []byte) osRelease {
	var r osRelease
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = unquoteShell(v)
		switch k {
		case "ID":
			r.ID = strings.ToLower(osutil.Clean(v, maxShort))
		case "ID_LIKE":
			r.IDLike = cleanList(strings.Fields(strings.ToLower(v)), 8, maxShort)
		case "VERSION_ID":
			r.VersionID = osutil.Clean(v, maxShort)
		case "PRETTY_NAME":
			r.PrettyName = osutil.Clean(v, maxName)
		}
	}
	return r
}

// unquoteShell removes one level of double or single quotes and handles
// the backslash escapes allowed by os-release(5).
func unquoteShell(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
		var b strings.Builder
		for i := 0; i < len(v); i++ {
			if v[i] == '\\' && i+1 < len(v) && strings.IndexByte("\"\\$`", v[i+1]) >= 0 {
				i++
			}
			b.WriteByte(v[i])
		}
		return b.String()
	}
	return v
}

func (c *Collector) osRelease() osRelease {
	for _, p := range []string{c.path("etc", "os-release"), c.path("usr", "lib", "os-release")} {
		if data, err := osutil.ReadFileLimit(p, maxSmallFile); err == nil {
			return parseOSRelease(data)
		}
	}
	return osRelease{}
}

// osFamily maps os-release ID/ID_LIKE to the package family.
func osFamily(r osRelease) string {
	ids := append([]string{r.ID}, r.IDLike...)
	has := func(names ...string) bool {
		for _, n := range names {
			if slices.Contains(ids, n) {
				return true
			}
		}
		return false
	}
	switch {
	case has("debian", "ubuntu"):
		return "debian"
	case has("rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn"):
		return "rhel"
	case has("suse", "opensuse", "sles"):
		return "suse"
	case has("alpine"):
		return "alpine"
	case has("arch"):
		return "arch"
	}
	return ""
}

// OS returns the OsInfo section.
func (c *Collector) OS(_ context.Context) (*agentv1.InventorySection, error) {
	osr := c.osRelease()
	release, machine := c.uname()
	host := c.hostname()
	info := &agentv1.OsInfo{
		Id:             osr.ID,
		IdLike:         osr.IDLike,
		Family:         osFamily(osr),
		VersionId:      osr.VersionID,
		PrettyName:     osr.PrettyName,
		Kernel:         release,
		Arch:           machine,
		Hostname:       host,
		Fqdn:           c.fqdn(host),
		Virtualization: c.virtualization(),
		BootTimeUnix:   c.bootTime(),
		MachineId:      c.machineID(),
		Timezone:       c.timezone(),
	}
	return newSection(info)
}

var goarchToMachine = map[string]string{
	"amd64": "x86_64", "arm64": "aarch64", "386": "i686", "arm": "armv7l",
	"ppc64le": "ppc64le", "s390x": "s390x", "riscv64": "riscv64",
}

// uname returns the kernel release and machine architecture.
func (c *Collector) uname() (string, string) {
	release, _ := osutil.ReadString(c.proc("sys", "kernel", "osrelease"), 256)
	var machine string
	if c.Uname != nil {
		if r, m, err := c.Uname(); err == nil {
			if release == "" {
				release = r
			}
			machine = m
		}
	} else {
		var u unix.Utsname
		if err := unix.Uname(&u); err == nil {
			if release == "" {
				release = unix.ByteSliceToString(u.Release[:])
			}
			machine = unix.ByteSliceToString(u.Machine[:])
		}
	}
	if machine == "" {
		machine = goarchToMachine[runtime.GOARCH]
	}
	return osutil.Clean(release, maxShort), osutil.Clean(machine, maxShort)
}

func (c *Collector) hostname() string {
	if h, err := osutil.ReadString(c.proc("sys", "kernel", "hostname"), 256); err == nil && h != "" {
		return osutil.Clean(h, maxName)
	}
	if h, err := osutil.ReadString(c.path("etc", "hostname"), 256); err == nil && h != "" {
		return osutil.Clean(h, maxName)
	}
	h, _ := os.Hostname()
	return osutil.Clean(h, maxName)
}

// fqdn derives the fully qualified name like `hostname -f` would from
// /etc/hosts, without DNS lookups.
func (c *Collector) fqdn(host string) string {
	if strings.Contains(host, ".") || host == "" {
		return host
	}
	data, err := osutil.ReadFileLimit(c.path("etc", "hosts"), maxConfigFile)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) < 2 || !slices.Contains(f[1:], host) {
			continue
		}
		for _, name := range f[1:] {
			if strings.HasPrefix(name, host+".") {
				return osutil.Clean(name, maxName)
			}
		}
		if strings.Contains(f[1], ".") {
			return osutil.Clean(f[1], maxName)
		}
	}
	return ""
}

var machineIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (c *Collector) machineID() string {
	for _, p := range []string{c.path("etc", "machine-id"), c.path("var", "lib", "dbus", "machine-id")} {
		if id, err := osutil.ReadString(p, 128); err == nil && machineIDRe.MatchString(id) {
			return id
		}
	}
	return ""
}

func (c *Collector) bootTime() int64 {
	data, err := osutil.ReadFileLimit(c.proc("stat"), 4<<20)
	if err != nil {
		return 0
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

func (c *Collector) timezone() string {
	if tz, err := osutil.ReadString(c.path("etc", "timezone"), 256); err == nil && tz != "" {
		return osutil.Clean(tz, maxShort)
	}
	if target, err := os.Readlink(c.path("etc", "localtime")); err == nil {
		if _, tz, ok := strings.Cut(target, "zoneinfo/"); ok {
			tz = strings.TrimPrefix(strings.TrimPrefix(tz, "posix/"), "right/")
			return osutil.Clean(tz, maxShort)
		}
	}
	return ""
}

// dmiVendors maps DMI string prefixes to systemd-detect-virt names, in
// systemd's order.
var dmiVendors = []struct{ prefix, virt string }{
	{"KVM", "kvm"}, {"OpenStack", "kvm"}, {"KubeVirt", "kvm"},
	{"Amazon EC2", "amazon"}, {"QEMU", "qemu"},
	{"VMware", "vmware"}, {"VMW", "vmware"},
	{"innotek GmbH", "oracle"}, {"VirtualBox", "oracle"}, {"Oracle Corporation", "oracle"},
	{"Xen", "xen"}, {"Bochs", "bochs"}, {"Parallels", "parallels"},
	{"BHYVE", "bhyve"}, {"Hyper-V", "microsoft"},
	{"Apple Virtualization", "apple"}, {"Google Compute Engine", "google"},
}

// virtualization approximates systemd-detect-virt: containers first, then
// DMI vendor strings, the Xen hypervisor node and the cpuinfo hypervisor
// flag. Returns "none" on bare metal.
func (c *Collector) virtualization() string {
	if v, err := osutil.ReadString(c.path("run", "systemd", "container"), 64); err == nil && v != "" {
		return osutil.Clean(v, maxShort)
	}
	if _, err := os.Stat(c.path("run", ".containerenv")); err == nil {
		return "podman"
	}
	if _, err := os.Stat(c.path(".dockerenv")); err == nil {
		return "docker"
	}
	if rel, _ := osutil.ReadString(c.proc("sys", "kernel", "osrelease"), 256); strings.Contains(strings.ToLower(rel), "microsoft") {
		return "wsl"
	}
	dmi := func(name string) string {
		s, _ := osutil.ReadString(c.sys("class", "dmi", "id", name), 256)
		return s
	}
	vendor, product := dmi("sys_vendor"), dmi("product_name")
	if vendor == "Microsoft Corporation" && product == "Virtual Machine" {
		return "microsoft"
	}
	for _, field := range []string{product, vendor, dmi("board_vendor"), dmi("bios_vendor"), dmi("product_version")} {
		for _, d := range dmiVendors {
			if field != "" && strings.HasPrefix(field, d.prefix) {
				return d.virt
			}
		}
	}
	if t, err := osutil.ReadString(c.sys("hypervisor", "type"), 64); err == nil && t == "xen" {
		return "xen"
	}
	if cpuHasFlag(c.cpuinfo(), "hypervisor") {
		return "vm-other"
	}
	return "none"
}

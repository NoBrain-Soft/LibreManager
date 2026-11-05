package inventory

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeRunner struct {
	mu      sync.Mutex
	outputs map[string]fakeResult
	calls   []string
}

type fakeResult struct {
	out string
	err error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	r, ok := f.outputs[key]
	if !ok {
		return nil, fmt.Errorf("fake: unexpected command %q: %w", key, osutil.ErrNotFound)
	}
	return []byte(r.out), r.err
}

const (
	cmdListUnits  = "systemctl list-units --type=service --all --plain --no-legend --no-pager --full"
	cmdUnitFiles  = "systemctl list-unit-files --type=service --plain --no-legend --no-pager --full"
	cmdListTimers = "systemctl list-timers --all --plain --no-legend --no-pager --full"
)

var debianSystemctl = map[string]fakeResult{
	cmdListUnits: {out: `ssh.service      loaded active   running OpenBSD Secure Shell server
cron.service     loaded active   running Regular background program processing daemon
● ghost.service  not-found inactive dead  ghost.service
nginx.service    loaded failed   failed  A high performance web server
`},
	cmdUnitFiles: {out: `ssh.service       enabled  enabled
cron.service      enabled  enabled
nginx.service     enabled  enabled
apache2.service   disabled enabled
getty@.service    enabled  enabled
`},
	cmdListTimers: {out: `Thu 2026-11-05 18:00:00 UTC 39min left Thu 2026-11-05 06:00:00 UTC 11h ago apt-daily.timer      apt-daily.service
n/a                         n/a       n/a                         n/a     certbot.timer        certbot.service
-                           -         -                           -       bogus                bogus
`},
	"systemctl show --property=Id,TimersCalendar,TimersMonotonic -- apt-daily.timer certbot.timer": {out: `Id=apt-daily.timer
TimersCalendar={ OnCalendar=*-*-* 06,18:00:00 ; next_elapse=Thu 2026-11-05 18:00:00 UTC }
TimersMonotonic=

Id=certbot.timer
TimersCalendar={ OnCalendar=*-*-* 00,12:00:00 ; next_elapse=n/a }
TimersMonotonic={ OnBootSec=15min ; next_elapse=n/a } { OnUnitActiveSec=1d ; next_elapse=n/a }
`},
}

func debianCollector(t *testing.T) *Collector {
	t.Helper()
	return &Collector{
		Root:         "testdata/debian",
		Exec:         &fakeRunner{outputs: debianSystemctl},
		AgentVersion: "v1.2.3",
		Uname:        func() (string, string, error) { return "ignored", "x86_64", nil },
		InterfaceAddrs: func() (map[string][]string, error) {
			return map[string][]string{"eth0": {"10.0.2.15/24", "fe80::5054:ff:fe12:3456/64"}, "lo": {"127.0.0.1/8", "::1/128"}}, nil
		},
		Statfs: func(string) (osutil.FSStats, error) {
			return osutil.FSStats{Type: 0xEF53, BlockSize: 4096, Blocks: 1000}, nil
		},
		ContainerSockets: []ContainerSocket{},
		CertDirs:         []string{},
		Now:              func() time.Time { return time.UnixMilli(1_800_000_000_000) },
		Logger:           discard,
	}
}

func section[T proto.Message](t *testing.T, s *agentv1.InventorySection, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	d, ok := SectionData(s).(T)
	if !ok {
		t.Fatalf("section data is %T", SectionData(s))
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); string(sum[:]) != string(s.GetHash()) {
		t.Fatal("section hash does not match its data")
	}
	return d
}

func TestFacts(t *testing.T) {
	f := debianCollector(t).Facts(context.Background())
	want := &agentv1.HostFacts{
		Hostname: "web01", Fqdn: "web01.example.internal", OsFamily: "debian", OsId: "ubuntu",
		OsVersion: "24.04", Kernel: "6.8.0-45-generic", Arch: "x86_64", AgentVersion: "v1.2.3",
		MachineId: "4c4c4544004d3510804bc4c04f4e4d32",
	}
	if !proto.Equal(f, want) {
		t.Fatalf("facts = %v\nwant    %v", f, want)
	}
}

func TestOS(t *testing.T) {
	tests := []struct {
		name string
		c    *Collector
		want *agentv1.OsInfo
	}{
		{"ubuntu on qemu", debianCollector(t), &agentv1.OsInfo{
			Id: "ubuntu", IdLike: []string{"debian"}, Family: "debian", VersionId: "24.04",
			PrettyName: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-45-generic", Arch: "x86_64",
			Hostname: "web01", Fqdn: "web01.example.internal", Virtualization: "qemu",
			BootTimeUnix: 1762300000, MachineId: "4c4c4544004d3510804bc4c04f4e4d32", Timezone: "Europe/Berlin",
		}},
		{"rocky on vmware", &Collector{Root: "testdata/rhel", Uname: func() (string, string, error) { return "x", "aarch64", nil }, Logger: discard}, &agentv1.OsInfo{
			Id: "rocky", IdLike: []string{"rhel", "centos", "fedora"}, Family: "rhel", VersionId: "9.4",
			PrettyName: "Rocky Linux 9.4 (Blue Onyx)", Kernel: "5.14.0-427.13.1.el9_4.x86_64", Arch: "aarch64",
			Hostname: "db01.example.internal", Fqdn: "db01.example.internal", Virtualization: "vmware",
			MachineId: "0123456789abcdef0123456789abcdef", Timezone: "America/New_York",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.c.OS(context.Background())
			got := section[*agentv1.OsInfo](t, s, err)
			if tt.c.Root == "testdata/rhel" {
				h, _ := os.Hostname()
				if got.GetHostname() != "db01.example.internal" && got.GetHostname() != h {
					t.Fatalf("hostname = %q", got.GetHostname())
				}
			}
			if !proto.Equal(got, tt.want) {
				t.Fatalf("os = %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		in   string
		want osRelease
	}{
		{`ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"`, osRelease{ID: "debian", VersionID: "12", PrettyName: "Debian GNU/Linux 12 (bookworm)"}},
		{`# comment
ID='opensuse-leap'
ID_LIKE="suse opensuse"
PRETTY_NAME="Say \"hi\" \$x \\ ok"`, osRelease{ID: "opensuse-leap", IDLike: []string{"suse", "opensuse"}, PrettyName: `Say "hi" $x \ ok`}},
		{"ID=Ubuntu\nVERSION_ID=\"\xff\"\nGARBAGE\n", osRelease{ID: "ubuntu", VersionID: "�"}},
	}
	for i, tt := range tests {
		got := parseOSRelease([]byte(tt.in))
		if fmt.Sprint(got) != fmt.Sprint(tt.want) {
			t.Errorf("%d: got %+v, want %+v", i, got, tt.want)
		}
	}
}

func TestOSFamily(t *testing.T) {
	tests := []struct {
		id     string
		idLike []string
		want   string
	}{
		{"debian", nil, "debian"},
		{"ubuntu", []string{"debian"}, "debian"},
		{"linuxmint", []string{"ubuntu", "debian"}, "debian"},
		{"rhel", []string{"fedora"}, "rhel"},
		{"almalinux", []string{"rhel", "centos", "fedora"}, "rhel"},
		{"fedora", nil, "rhel"},
		{"amzn", []string{"centos", "rhel", "fedora"}, "rhel"},
		{"ol", nil, "rhel"},
		{"sles", nil, "suse"},
		{"alpine", nil, "alpine"},
		{"nixos", nil, ""},
	}
	for _, tt := range tests {
		if got := osFamily(osRelease{ID: tt.id, IDLike: tt.idLike}); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.id, got, tt.want)
		}
	}
}

// writeTree creates files below a new temp root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestVirtualization(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"systemd container", map[string]string{"run/systemd/container": "lxc\n", "sys/class/dmi/id/sys_vendor": "QEMU"}, "lxc"},
		{"podman", map[string]string{"run/.containerenv": ""}, "podman"},
		{"docker", map[string]string{".dockerenv": ""}, "docker"},
		{"wsl", map[string]string{"proc/sys/kernel/osrelease": "5.15.153.1-microsoft-standard-WSL2"}, "wsl"},
		{"kvm", map[string]string{"sys/class/dmi/id/sys_vendor": "Red Hat", "sys/class/dmi/id/product_name": "KVM"}, "kvm"},
		{"amazon", map[string]string{"sys/class/dmi/id/sys_vendor": "Amazon EC2"}, "amazon"},
		{"hyper-v", map[string]string{"sys/class/dmi/id/sys_vendor": "Microsoft Corporation", "sys/class/dmi/id/product_name": "Virtual Machine"}, "microsoft"},
		{"virtualbox board", map[string]string{"sys/class/dmi/id/board_vendor": "Oracle Corporation"}, "oracle"},
		{"google", map[string]string{"sys/class/dmi/id/product_name": "Google Compute Engine"}, "google"},
		{"xen pv", map[string]string{"sys/hypervisor/type": "xen\n"}, "xen"},
		{"unknown hypervisor", map[string]string{"proc/cpuinfo": "processor : 0\nflags : fpu hypervisor\n"}, "vm-other"},
		{"bare metal", map[string]string{"sys/class/dmi/id/sys_vendor": "Dell Inc.", "proc/cpuinfo": "processor : 0\nflags : fpu\n"}, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collector{Root: writeTree(t, tt.files), Logger: discard}
			if got := c.virtualization(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHardware(t *testing.T) {
	s, err := debianCollector(t).Hardware(context.Background())
	hw := section[*agentv1.Hardware](t, s, err)
	if hw.GetCpuModel() != "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz" || hw.GetCpuCores() != 2 || hw.GetCpuThreads() != 4 {
		t.Errorf("cpu = %q %d/%d", hw.GetCpuModel(), hw.GetCpuCores(), hw.GetCpuThreads())
	}
	if hw.GetMemoryBytes() != 8000000*1024 || hw.GetSwapBytes() != 1048576*1024 {
		t.Errorf("memory %d swap %d", hw.GetMemoryBytes(), hw.GetSwapBytes())
	}
	if hw.GetVendor() != "QEMU" || hw.GetProduct() != "Standard PC (Q35 + ICH9, 2009)" {
		t.Errorf("dmi %q %q", hw.GetVendor(), hw.GetProduct())
	}
	var devs []string
	for _, d := range hw.GetBlockDevices() {
		devs = append(devs, fmt.Sprintf("%s:%s:%d:%v:%s", d.GetName(), d.GetType(), d.GetSizeBytes(), d.GetRotational(), d.GetModel()))
	}
	want := []string{
		"dm-0:lvm:52224000000:false:vg0-root",
		"nvme0n1:disk:512110190592:false:Samsung SSD 980 PRO 1TB",
		"vda:disk:53687091200:true:",
		"vda1:part:1073741824:true:",
		"vda2:part:52612300800:true:",
	}
	if strings.Join(devs, "\n") != strings.Join(want, "\n") {
		t.Errorf("block devices:\n%s\nwant\n%s", strings.Join(devs, "\n"), strings.Join(want, "\n"))
	}
	var fss []string
	for _, f := range hw.GetFilesystems() {
		fss = append(fss, fmt.Sprintf("%s:%s:%s:%d", f.GetMountpoint(), f.GetDevice(), f.GetFstype(), f.GetSizeBytes()))
	}
	if strings.Join(fss, ",") != "/:/dev/mapper/vg0-root:ext4:4096000,/boot:/dev/vda1:ext4:4096000,/run:tmpfs:tmpfs:4096000" {
		t.Errorf("filesystems %v", fss)
	}
}

func TestParseCPUInfo(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		model      string
		cores, thr int
	}{
		{"arm neoverse", "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: 0xd0c\n\nprocessor\t: 1\nCPU implementer\t: 0x41\nCPU part\t: 0xd0c\n", "ARM Neoverse-N1", 2, 2},
		{"ampere", "processor : 0\nCPU implementer : 0xc0\nCPU part : 0xac3\n", "Ampere 0xac3", 1, 1},
		{"raspberry pi", "processor : 0\nCPU implementer : 0x41\nCPU part : 0xd08\nModel : Raspberry Pi 4 Model B Rev 1.4\n", "ARM Cortex-A72", 1, 1},
		{"two sockets", "processor : 0\nmodel name : X\nphysical id : 0\ncore id : 0\n\nprocessor : 1\nmodel name : X\nphysical id : 1\ncore id : 0\n", "X", 2, 2},
		{"empty", "", "", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCPUInfo([]byte(tt.in))
			if got.model != tt.model || got.cores != tt.cores || got.threads != tt.thr {
				t.Fatalf("got %q %d/%d", got.model, got.cores, got.threads)
			}
		})
	}
}

func TestNetwork(t *testing.T) {
	s, err := debianCollector(t).Network(context.Background())
	n := section[*agentv1.NetworkInfo](t, s, err)
	var ifs []string
	for _, i := range n.GetInterfaces() {
		ifs = append(ifs, fmt.Sprintf("%s %s %d %v %v", i.GetName(), i.GetMac(), i.GetMtu(), i.GetUp(), i.GetAddresses()))
	}
	wantIfs := []string{
		"docker0 02:42:ac:11:00:01 1500 false []",
		"eth0 52:54:00:12:34:56 1500 true [10.0.2.15/24 fe80::5054:ff:fe12:3456/64]",
		"lo 00:00:00:00:00:00 65536 true [127.0.0.1/8 ::1/128]",
	}
	if strings.Join(ifs, "\n") != strings.Join(wantIfs, "\n") {
		t.Errorf("interfaces:\n%s", strings.Join(ifs, "\n"))
	}
	var routes []string
	for _, r := range n.GetRoutes() {
		routes = append(routes, fmt.Sprintf("%s via %q dev %s metric %d", r.GetDestination(), r.GetGateway(), r.GetInterface(), r.GetMetric()))
	}
	wantRoutes := []string{
		`0.0.0.0/0 via "10.0.2.1" dev eth0 metric 100`,
		`10.0.2.0/24 via "" dev eth0 metric 100`,
		`172.17.0.0/16 via "" dev docker0 metric 0`,
		`fe80::/64 via "" dev eth0 metric 256`,
		`::/0 via "fe80::1" dev eth0 metric 1024`,
	}
	if strings.Join(routes, "\n") != strings.Join(wantRoutes, "\n") {
		t.Errorf("routes:\n%s", strings.Join(routes, "\n"))
	}
	if fmt.Sprint(n.GetDnsServers()) != "[10.0.0.2 10.0.0.3]" || fmt.Sprint(n.GetDnsSearch()) != "[example.internal corp.example]" {
		t.Errorf("dns %v search %v", n.GetDnsServers(), n.GetDnsSearch())
	}
}

func TestPackagesDpkg(t *testing.T) {
	s, err := debianCollector(t).Packages(context.Background())
	pl := section[*agentv1.PackageList](t, s, err)
	if pl.GetManager() != "dpkg" {
		t.Fatalf("manager %q", pl.GetManager())
	}
	var got []string
	for _, p := range pl.GetPackages() {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%s", p.GetName(), p.GetVersion(), p.GetArch(), p.GetSourceName(), p.GetPurl()))
	}
	want := []string{
		"bsdutils|1:2.39.3-9ubuntu6.1|amd64|util-linux|pkg:deb/ubuntu/bsdutils@1:2.39.3-9ubuntu6.1?arch=amd64&distro=ubuntu-24.04&upstream=util-linux%402.39.3-9ubuntu6.1",
		"halfconf|0.1|all||pkg:deb/ubuntu/halfconf@0.1?arch=all&distro=ubuntu-24.04",
		"libc6|2.39-0ubuntu8.3|amd64|glibc|pkg:deb/ubuntu/libc6@2.39-0ubuntu8.3?arch=amd64&distro=ubuntu-24.04&upstream=glibc",
		"libc6|2.39-0ubuntu8.3|i386|glibc|pkg:deb/ubuntu/libc6@2.39-0ubuntu8.3?arch=i386&distro=ubuntu-24.04&upstream=glibc",
		"libssl3t64|3.0.13-0ubuntu3.4|amd64|openssl|pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04&upstream=openssl",
		"libstdc++6|14.2.0-4ubuntu2~24.04|amd64|gcc-14|pkg:deb/ubuntu/libstdc%2B%2B6@14.2.0-4ubuntu2~24.04?arch=amd64&distro=ubuntu-24.04&upstream=gcc-14",
		"openssl|3.0.13-0ubuntu3.4|amd64||pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("packages:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

const rhelRPMOutput = "openssl\x1f1\x1f3.0.7\x1f27.el9\x1fx86_64\x1fopenssl-3.0.7-27.el9.src.rpm\x1e" +
	"openssl-libs\x1f1\x1f3.0.7\x1f27.el9\x1fx86_64\x1fopenssl-3.0.7-27.el9.src.rpm\x1e" +
	"bash\x1f(none)\x1f5.1.8\x1f9.el9\x1fx86_64\x1fbash-5.1.8-9.el9.src.rpm\x1e" +
	"tzdata\x1f(none)\x1f2024a\x1f1.el9\x1fnoarch\x1ftzdata-2024a-1.el9.src.rpm\x1e" +
	"gpg-pubkey\x1f(none)\x1f350d275d\x1f6279464b\x1f(none)\x1f(none)\x1e" +
	"broken\x1fonly-three\x1ffields\x1e" +
	"\n"

func rhelCollector(t *testing.T, out string, err error) *Collector {
	t.Helper()
	root := "testdata/rhel"
	return &Collector{
		Root:   root,
		Exec:   &fakeRunner{outputs: map[string]fakeResult{"rpm --root " + root + " -qa --qf " + rpmQueryFormat: {out: out, err: err}}},
		Logger: discard,
	}
}

func TestPackagesRPM(t *testing.T) {
	s, err := rhelCollector(t, rhelRPMOutput, nil).Packages(context.Background())
	pl := section[*agentv1.PackageList](t, s, err)
	var got []string
	for _, p := range pl.GetPackages() {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%s", p.GetName(), p.GetVersion(), p.GetArch(), p.GetSourceName(), p.GetPurl()))
	}
	want := []string{
		"bash|5.1.8-9.el9|x86_64||pkg:rpm/rocky/bash@5.1.8-9.el9?arch=x86_64&distro=rocky-9.4&upstream=bash-5.1.8-9.el9.src.rpm",
		"openssl|1:3.0.7-27.el9|x86_64||pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=x86_64&distro=rocky-9.4&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm",
		"openssl-libs|1:3.0.7-27.el9|x86_64|openssl|pkg:rpm/rocky/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rocky-9.4&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm",
		"tzdata|2024a-1.el9|noarch||pkg:rpm/rocky/tzdata@2024a-1.el9?arch=noarch&distro=rocky-9.4&upstream=tzdata-2024a-1.el9.src.rpm",
	}
	if pl.GetManager() != "rpm" || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("packages (%s):\n%s", pl.GetManager(), strings.Join(got, "\n"))
	}
	t.Run("rpm failure", func(t *testing.T) {
		if _, err := rhelCollector(t, "", errors.New("rpmdb locked")).Packages(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("empty output", func(t *testing.T) {
		if _, err := rhelCollector(t, "", nil).Packages(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestPackagesUnsupported(t *testing.T) {
	c := &Collector{Root: t.TempDir(), Logger: discard}
	if _, err := c.Packages(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if fp := c.PackageDBFingerprint(); fp != "" {
		t.Fatalf("fingerprint %q", fp)
	}
}

func TestRPMSourceName(t *testing.T) {
	tests := map[string]string{
		"openssl-3.0.7-27.el9.src.rpm":        "openssl",
		"python3.11-pip-22.3.1-4.el9.src.rpm": "python3.11-pip",
		"kernel-5.14.0-427.el9.nosrc.rpm":     "kernel",
		"weird.src.rpm":                       "",
		"no-suffix-1-2":                       "",
		"":                                    "",
		"-1-2.src.rpm":                        "",
	}
	for in, want := range tests {
		if got := rpmSourceName(in); got != want {
			t.Errorf("rpmSourceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPURLEscaping(t *testing.T) {
	tests := []struct {
		in, path, qual string
	}{
		{"libstdc++6", "libstdc%2B%2B6", "libstdc%2B%2B6"},
		{"1:2.3~rc1-4", "1:2.3~rc1-4", "1%3A2.3~rc1-4"},
		{"a b/c?d#e@f&g=h%", "a%20b%2Fc%3Fd%23e%40f%26g%3Dh%25", "a%20b%2Fc%3Fd%23e%40f%26g%3Dh%25"},
		{"ü", "%C3%BC", "%C3%BC"},
	}
	for _, tt := range tests {
		if got := purlEscape(tt.in); got != tt.path {
			t.Errorf("purlEscape(%q) = %q, want %q", tt.in, got, tt.path)
		}
		if got := purlEscapeQualifier(tt.in); got != tt.qual {
			t.Errorf("purlEscapeQualifier(%q) = %q, want %q", tt.in, got, tt.qual)
		}
	}
	// Debian sid has no VERSION_ID; derivatives use their own distro id.
	p := pkgInfo{name: "x", version: "1", arch: "amd64"}
	if got := debPURL(p, osRelease{ID: "debian"}); got != "pkg:deb/debian/x@1?arch=amd64&distro=debian" {
		t.Errorf("sid purl %q", got)
	}
	if got := debPURL(p, osRelease{ID: "linuxmint", IDLike: []string{"ubuntu", "debian"}, VersionID: "22"}); got != "pkg:deb/ubuntu/x@1?arch=amd64&distro=linuxmint-22" {
		t.Errorf("mint purl %q", got)
	}
	if got := rpmPURL(pkgInfo{name: "x", version: "1", release: "2.el9"}, osRelease{ID: "rhel", VersionID: "9.4"}); got != "pkg:rpm/redhat/x@1-2.el9?distro=rhel-9.4" {
		t.Errorf("rhel purl %q", got)
	}
}

func TestPackageDBFingerprint(t *testing.T) {
	root := writeTree(t, map[string]string{"var/lib/dpkg/status": "Package: a\n"})
	c := &Collector{Root: root}
	fp1 := c.PackageDBFingerprint()
	if fp1 == "" || !strings.Contains(fp1, "var/lib/dpkg/status") {
		t.Fatalf("fingerprint %q", fp1)
	}
	if c.PackageDBFingerprint() != fp1 {
		t.Fatal("fingerprint not stable")
	}
	p := filepath.Join(root, "var/lib/dpkg/status")
	if err := os.WriteFile(p, []byte("Package: a\nVersion: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c.PackageDBFingerprint() == fp1 {
		t.Fatal("fingerprint did not change after size change")
	}
	fp2 := c.PackageDBFingerprint()
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	if c.PackageDBFingerprint() == fp2 {
		t.Fatal("fingerprint did not change after mtime change")
	}
	// The sqlite WAL counts for rpm.
	rpmRoot := writeTree(t, map[string]string{"var/lib/rpm/rpmdb.sqlite": "x"})
	rc := &Collector{Root: rpmRoot}
	before := rc.PackageDBFingerprint()
	if err := os.WriteFile(filepath.Join(rpmRoot, "var/lib/rpm/rpmdb.sqlite-wal"), []byte("w"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc.PackageDBFingerprint() == before {
		t.Fatal("WAL change not detected")
	}
}

func FuzzParseDpkgStatus(f *testing.F) {
	seed, _ := os.ReadFile("testdata/debian/var/lib/dpkg/status")
	f.Add(seed)
	f.Add([]byte("Package: a\nStatus: install ok installed\nVersion: 1\nSource: b (2)\n\n"))
	f.Add([]byte("Package:\xff\nStatus: install ok installed\nVersion: \x00\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs, _ := parseDpkgStatus(strings.NewReader(string(data)), 100)
		if len(pkgs) > 100 {
			t.Fatalf("limit exceeded: %d", len(pkgs))
		}
		list := &agentv1.PackageList{Manager: "dpkg"}
		for _, p := range pkgs {
			if p.name == "" || p.version == "" {
				t.Fatalf("package without name/version: %+v", p)
			}
			list.Packages = append(list.Packages, toProtoPackage("dpkg", p, osRelease{ID: "debian", VersionID: "12"}))
		}
		if _, err := proto.Marshal(list); err != nil {
			t.Fatalf("package list does not marshal: %v", err)
		}
	})
}

func FuzzParseRPMQuery(f *testing.F) {
	f.Add([]byte(rhelRPMOutput))
	f.Add([]byte("a\x1f\x1f1\x1f1\x1f\x1f\x1e\x1e\x1f"))
	f.Add([]byte("\xff\x1f(none)\x1f\xfe\x1f1\x1fx\x1f\xfd.src.rpm\x1e"))
	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs := parseRPMQuery(data, 100)
		if len(pkgs) > 100 {
			t.Fatalf("limit exceeded: %d", len(pkgs))
		}
		list := &agentv1.PackageList{Manager: "rpm"}
		for _, p := range pkgs {
			if p.name == "" || p.version == "" || p.name == "gpg-pubkey" {
				t.Fatalf("unexpected package %+v", p)
			}
			list.Packages = append(list.Packages, toProtoPackage("rpm", p, osRelease{ID: "rocky", VersionID: "9.4"}))
		}
		if _, err := proto.Marshal(list); err != nil {
			t.Fatalf("package list does not marshal: %v", err)
		}
	})
}

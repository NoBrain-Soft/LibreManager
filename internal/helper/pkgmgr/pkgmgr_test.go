package pkgmgr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Captured from Debian 12 (bookworm) with a stale point release.
const aptDebian = `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
      Keep also in mind that locking is deactivated,
      so don't depend on the relevance to the real current situation!
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  base-files libc-bin libc6 libssl3 openssl tzdata
6 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst base-files [12.4+deb12u4] (12.4+deb12u5 Debian:12.5/stable [amd64])
Conf base-files (12.4+deb12u5 Debian:12.5/stable [amd64])
Inst libc6 [2.36-9+deb12u3] (2.36-9+deb12u4 Debian:12.5/stable [amd64]) [libc-bin:amd64 ]
Inst libc-bin [2.36-9+deb12u3] (2.36-9+deb12u4 Debian:12.5/stable [amd64])
Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian:12.5/stable, Debian-Security:12/stable-security [amd64])
Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian:12.5/stable, Debian-Security:12/stable-security [amd64])
Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12.11/stable-updates [all])
Conf libc6 (2.36-9+deb12u4 Debian:12.5/stable [amd64])
`

// Captured from Ubuntu 24.04 (noble), incl. a new kernel ABI package.
const aptUbuntu = `Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following NEW packages will be installed:
  linux-image-6.8.0-50-generic linux-modules-6.8.0-50-generic
The following packages will be upgraded:
  linux-image-generic libexpat1 libc6:i386
Inst linux-modules-6.8.0-50-generic (6.8.0-50.51 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-image-6.8.0-50-generic (6.8.0-50.51 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-image-generic [6.8.0-49.49] (6.8.0-50.50 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst libexpat1 [2.6.1-2build1] (2.6.1-2ubuntu0.1 Ubuntu:24.04/noble-updates [amd64])
Inst libc6:i386 [2.39-0ubuntu8.2] (2.39-0ubuntu8.3 Ubuntu:24.04/noble-updates [i386])
Inst --evil [1] (2 Ubuntu:24.04/noble-security [amd64])
Inst broken-line [1.0]
Inst noparen [1.0] 2.0 x
`

func TestParseAptSimulate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Upgrade
	}{
		{"debian", aptDebian, []Upgrade{
			{Name: "base-files", Arch: "amd64", CurrentVersion: "12.4+deb12u4", CandidateVersion: "12.4+deb12u5", Source: "Debian:12.5/stable"},
			{Name: "libc6", Arch: "amd64", CurrentVersion: "2.36-9+deb12u3", CandidateVersion: "2.36-9+deb12u4", Source: "Debian:12.5/stable"},
			{Name: "libc-bin", Arch: "amd64", CurrentVersion: "2.36-9+deb12u3", CandidateVersion: "2.36-9+deb12u4", Source: "Debian:12.5/stable"},
			{Name: "libssl3", Arch: "amd64", CurrentVersion: "3.0.11-1~deb12u1", CandidateVersion: "3.0.11-1~deb12u2", Source: "Debian:12.5/stable, Debian-Security:12/stable-security", IsSecurity: true},
			{Name: "openssl", Arch: "amd64", CurrentVersion: "3.0.11-1~deb12u1", CandidateVersion: "3.0.11-1~deb12u2", Source: "Debian:12.5/stable, Debian-Security:12/stable-security", IsSecurity: true},
			{Name: "tzdata", Arch: "all", CurrentVersion: "2024a-0+deb12u1", CandidateVersion: "2025b-0+deb12u1", Source: "Debian:12.11/stable-updates"},
		}},
		{"ubuntu", aptUbuntu, []Upgrade{
			{Name: "linux-modules-6.8.0-50-generic", Arch: "amd64", CandidateVersion: "6.8.0-50.51", Source: "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security", IsSecurity: true},
			{Name: "linux-image-6.8.0-50-generic", Arch: "amd64", CandidateVersion: "6.8.0-50.51", Source: "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security", IsSecurity: true},
			{Name: "linux-image-generic", Arch: "amd64", CurrentVersion: "6.8.0-49.49", CandidateVersion: "6.8.0-50.50", Source: "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security", IsSecurity: true},
			{Name: "libexpat1", Arch: "amd64", CurrentVersion: "2.6.1-2build1", CandidateVersion: "2.6.1-2ubuntu0.1", Source: "Ubuntu:24.04/noble-updates"},
			{Name: "libc6:i386", Arch: "i386", CurrentVersion: "2.39-0ubuntu8.2", CandidateVersion: "2.39-0ubuntu8.3", Source: "Ubuntu:24.04/noble-updates"},
		}},
		{"nothing", "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", nil},
		{"empty", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseAptSimulate([]byte(tc.in))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

const dnfCheckUpdate = `
NetworkManager.x86_64                 1:1.46.0-19.el9_4                 baseos
kernel.x86_64                         5.14.0-427.22.1.el9_4             baseos
kernel-core.x86_64                    5.14.0-427.22.1.el9_4             baseos
openssl-libs.x86_64                   1:3.0.7-27.el9                    baseos
subscription-manager-rhsm-certificates.noarch
                                      20220623-1.el9                    baseos
tzdata.noarch                         2024a-1.el9                       appstream
gpg-pubkey.(none)                     1-1                               @System
Obsoleting Packages
grub2-tools.x86_64                    1:2.06-80.el9                     baseos
    grub2-tools.x86_64                1:2.06-77.el9                     @baseos
`

const dnfUpdateinfo = `RLSA-2024:3501 Important/Sec. kernel-5.14.0-427.22.1.el9_4.x86_64
RLSA-2024:3501 Important/Sec. kernel-core-5.14.0-427.22.1.el9_4.x86_64
RLSA-2024:2447 Moderate/Sec.  openssl-libs-1:3.0.7-27.el9.x86_64
RLSA-2024:9999 Low/Sec.       openssl-libs-1:3.0.7-27.el9.x86_64
garbage line here
`

const dnf5Advisory = `Name           Type     Severity  Package                                   Issued
FEDORA-2024-1a2b3c4d5e security Important kernel-6.11.5-300.fc41.x86_64 2024-10-29 01:23:45
`

func TestParseCheckUpdate(t *testing.T) {
	got := ParseCheckUpdate([]byte(dnfCheckUpdate))
	want := []Upgrade{
		{Name: "NetworkManager", Arch: "x86_64", CandidateVersion: "1:1.46.0-19.el9_4", Source: "baseos"},
		{Name: "kernel", Arch: "x86_64", CandidateVersion: "5.14.0-427.22.1.el9_4", Source: "baseos"},
		{Name: "kernel-core", Arch: "x86_64", CandidateVersion: "5.14.0-427.22.1.el9_4", Source: "baseos"},
		{Name: "openssl-libs", Arch: "x86_64", CandidateVersion: "1:3.0.7-27.el9", Source: "baseos"},
		{Name: "subscription-manager-rhsm-certificates", Arch: "noarch", CandidateVersion: "20220623-1.el9", Source: "baseos"},
		{Name: "tzdata", Arch: "noarch", CandidateVersion: "2024a-1.el9", Source: "appstream"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseUpdateinfo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string][]string
	}{
		{"dnf4", dnfUpdateinfo, map[string][]string{
			"kernel.x86_64":       {"RLSA-2024:3501"},
			"kernel-core.x86_64":  {"RLSA-2024:3501"},
			"openssl-libs.x86_64": {"RLSA-2024:2447", "RLSA-2024:9999"},
		}},
		{"dnf5", dnf5Advisory, map[string][]string{"kernel.x86_64": {"FEDORA-2024-1a2b3c4d5e"}}},
		{"empty", "", map[string][]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseUpdateinfo([]byte(tc.in)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestParseNEVRA(t *testing.T) {
	tests := []struct {
		in             string
		name, evr, arc string
		ok             bool
	}{
		{"openssl-libs-1:3.0.7-27.el9.x86_64", "openssl-libs", "1:3.0.7-27.el9", "x86_64", true},
		{"kernel-5.14.0-427.22.1.el9_4.x86_64", "kernel", "5.14.0-427.22.1.el9_4", "x86_64", true},
		{"tzdata-2024a-1.el9.noarch", "tzdata", "2024a-1.el9", "noarch", true},
		{"foo-1.0-1.el9.weird", "", "", "", false},
		{"foo.x86_64", "", "", "", false},
		{"-1.0-1.x86_64", "", "", "", false},
		{"foo--1.x86_64", "", "", "", false},
		{"foo-1.0-.x86_64", "", "", "", false},
	}
	for _, tc := range tests {
		n, e, a, ok := ParseNEVRA(tc.in)
		if n != tc.name || e != tc.evr || a != tc.arc || ok != tc.ok {
			t.Errorf("ParseNEVRA(%q) = %q %q %q %v", tc.in, n, e, a, ok)
		}
	}
}

func TestParseNeedsRestartingAndKernel(t *testing.T) {
	nr := "Core libraries or services have been updated since boot-up:\n  * kernel\n  * systemd\n\nReboot is required to fully utilize these updates.\nMore information: https://access.redhat.com/solutions/27943\n"
	if got := ParseNeedsRestarting([]byte(nr)); !reflect.DeepEqual(got, []string{"kernel", "systemd"}) {
		t.Fatalf("got %v", got)
	}
	k := "1714000000 5.14.0-362.24.1.el9_3.x86_64\n1718000000 5.14.0-427.22.1.el9_4.x86_64\n1716000000 5.14.0-427.13.1.el9_4.x86_64\nbad\n"
	if got := NewestKernel([]byte(k)); got != "5.14.0-427.22.1.el9_4.x86_64" {
		t.Fatalf("newest %q", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	kv := ParseOSRelease([]byte("NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n# comment\nVERSION_ID='9.4'\n"))
	if kv["ID"] != "rocky" || kv["ID_LIKE"] != "rhel centos fedora" || kv["VERSION_ID"] != "9.4" || kv["NAME"] != "Rocky Linux" {
		t.Fatalf("%v", kv)
	}
}

// fakeRunner records invocations and returns scripted results keyed by
// "name arg0 arg1 ..." prefixes.
type fakeRunner struct {
	calls     []runner.Cmd
	available map[string]bool
	results   map[string]fakeResult
}

type fakeResult struct {
	out  string
	code int
}

func (f *fakeRunner) Available(name string) bool { return f.available[name] }

func (f *fakeRunner) Run(_ context.Context, c runner.Cmd) (int, error) {
	f.calls = append(f.calls, c)
	key := strings.Join(append([]string{c.Name}, c.Args...), " ")
	best := ""
	for k := range f.results {
		if strings.HasPrefix(key, k) && len(k) > len(best) {
			best = k
		}
	}
	r := f.results[best]
	if c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, r.out)
	}
	return r.code, nil
}

func (f *fakeRunner) argv(i int) string {
	return strings.Join(append([]string{f.calls[i].Name}, f.calls[i].Args...), " ")
}

func TestAptCommands(t *testing.T) {
	ctx := context.Background()
	opts := "-y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef"
	tests := []struct {
		name string
		do   func(a *Apt, o Output) (Result, error)
		want []string
	}{
		{"refresh", func(a *Apt, o Output) (Result, error) { return a.Refresh(ctx, o) }, []string{"apt-get -q -o DPkg::Lock::Timeout=300 update"}},
		{"all", func(a *Apt, o Output) (Result, error) {
			return a.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}, o)
		}, []string{"apt-get " + opts + " upgrade --with-new-pkgs"}},
		{"security", func(a *Apt, o Output) (Result, error) {
			return a.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}, o)
		}, []string{
			"apt-get -s -q -o Debug::NoLocking=1 upgrade --with-new-pkgs",
			"apt-get " + opts + " install --only-upgrade -- libssl3 openssl",
		}},
		{"named", func(a *Apt, o Output) (Result, error) {
			return a.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: []string{"nginx"}}, o)
		}, []string{"apt-get " + opts + " install --only-upgrade -- nginx"}},
		{"install", func(a *Apt, o Output) (Result, error) { return a.Install(ctx, []string{"htop", "jq"}, o) }, []string{"apt-get " + opts + " install -- htop jq"}},
		{"remove", func(a *Apt, o Output) (Result, error) { return a.Remove(ctx, []string{"telnet"}, o) }, []string{"apt-get " + opts + " remove -- telnet"}},
		{"hold", func(a *Apt, o Output) (Result, error) { return a.Hold(ctx, []string{"linux-image-generic"}, true, o) }, []string{"apt-mark hold -- linux-image-generic"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{results: map[string]fakeResult{"apt-get -s": {out: aptDebian}}}
			a := &Apt{Runner: fr}
			var buf bytes.Buffer
			if _, err := tc.do(a, Output{Stdout: &buf}); err != nil {
				t.Fatal(err)
			}
			if len(fr.calls) != len(tc.want) {
				t.Fatalf("calls %d, want %d", len(fr.calls), len(tc.want))
			}
			for i, w := range tc.want {
				if got := fr.argv(i); got != w {
					t.Errorf("call %d:\n got %s\nwant %s", i, got, w)
				}
				if !strings.Contains(strings.Join(fr.calls[i].Env, " "), "DEBIAN_FRONTEND=noninteractive") {
					t.Errorf("call %d: missing DEBIAN_FRONTEND", i)
				}
			}
		})
	}
}

func TestDnfCommands(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		do   func(d *Dnf, o Output) (Result, error)
		want string
	}{
		{"refresh", func(d *Dnf, o Output) (Result, error) { return d.Refresh(ctx, o) }, "dnf -y makecache"},
		{"all", func(d *Dnf, o Output) (Result, error) {
			return d.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}, o)
		}, "dnf -y upgrade"},
		{"security", func(d *Dnf, o Output) (Result, error) {
			return d.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}, o)
		}, "dnf -y upgrade --security"},
		{"named", func(d *Dnf, o Output) (Result, error) {
			return d.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: []string{"nginx", "openssl-libs"}}, o)
		}, "dnf -y upgrade -- nginx openssl-libs"},
		{"install", func(d *Dnf, o Output) (Result, error) { return d.Install(ctx, []string{"htop"}, o) }, "dnf -y install -- htop"},
		{"remove", func(d *Dnf, o Output) (Result, error) { return d.Remove(ctx, []string{"telnet"}, o) }, "dnf -y remove -- telnet"},
		{"unhold", func(d *Dnf, o Output) (Result, error) { return d.Hold(ctx, []string{"kernel"}, false, o) }, "dnf -y versionlock delete -- kernel"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{}
			if _, err := tc.do(&Dnf{Runner: fr}, Output{}); err != nil {
				t.Fatal(err)
			}
			if len(fr.calls) != 1 || fr.argv(0) != tc.want {
				t.Fatalf("calls %v, want %s", fr.calls, tc.want)
			}
		})
	}
}

func TestInvalidNamesNeverReachRunner(t *testing.T) {
	ctx := context.Background()
	bad := [][]string{nil, {"-oAPT::Update::Pre-Invoke::=id"}, {"ok", "--allow-unauthenticated"}, {"a b"}, {"x;id"}, make([]string, policy.MaxPackagesPerJob+1)}
	for _, names := range bad {
		fr := &fakeRunner{}
		a, d := &Apt{Runner: fr}, &Dnf{Runner: fr}
		ops := []func() (Result, error){
			func() (Result, error) { return a.Install(ctx, names, Output{}) },
			func() (Result, error) { return a.Remove(ctx, names, Output{}) },
			func() (Result, error) { return a.Hold(ctx, names, true, Output{}) },
			func() (Result, error) {
				return a.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: names}, Output{})
			},
			func() (Result, error) { return d.Install(ctx, names, Output{}) },
			func() (Result, error) { return d.Remove(ctx, names, Output{}) },
			func() (Result, error) {
				return d.Upgrade(ctx, UpgradeSpec{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: names}, Output{})
			},
		}
		for i, op := range ops {
			if _, err := op(); !errors.Is(err, ErrInvalidPackage) {
				t.Errorf("names %q op %d: err = %v", names, i, err)
			}
		}
		if len(fr.calls) != 0 {
			t.Errorf("names %q reached the runner: %v", names, fr.calls)
		}
	}
	if _, err := (&Apt{Runner: &fakeRunner{}}).Upgrade(ctx, UpgradeSpec{}, Output{}); err == nil {
		t.Error("unspecified scope accepted")
	}
}

func TestDnfListUpgrades(t *testing.T) {
	fr := &fakeRunner{results: map[string]fakeResult{
		"dnf -q -C check-update":       {out: dnfCheckUpdate, code: 100},
		"rpm -qa":                      {out: "openssl-libs.x86_64 1:3.0.7-25.el9\nkernel.x86_64 5.14.0-427.13.1.el9_4\n"},
		"dnf -q -C updateinfo list":    {out: dnfUpdateinfo},
		"dnf -q -C check-update --bad": {code: 1},
	}}
	ups, err := (&Dnf{Runner: fr}).ListUpgrades(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Upgrade{}
	for _, u := range ups {
		byName[u.Name] = u
	}
	if u := byName["openssl-libs"]; !u.IsSecurity || u.CurrentVersion != "1:3.0.7-25.el9" || len(u.Advisories) != 2 {
		t.Fatalf("openssl-libs %+v", u)
	}
	if u := byName["tzdata"]; u.IsSecurity {
		t.Fatalf("tzdata %+v", u)
	}

	fr.results["dnf -q -C check-update"] = fakeResult{code: 0}
	if ups, err := (&Dnf{Runner: fr}).ListUpgrades(context.Background()); err != nil || len(ups) != 0 {
		t.Fatalf("no updates: %v %v", ups, err)
	}
	fr.results["dnf -q -C check-update"] = fakeResult{code: 1}
	if _, err := (&Dnf{Runner: fr}).ListUpgrades(context.Background()); err == nil {
		t.Fatal("expected error for exit 1")
	}
}

func TestRebootRequired(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	flag := filepath.Join(dir, "reboot-required")
	a := &Apt{RebootFile: flag}
	if req, _, err := a.RebootRequired(ctx); err != nil || req {
		t.Fatalf("absent flag: %v %v", req, err)
	}
	if err := os.WriteFile(flag, []byte("*** System restart required ***\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flag+".pkgs", []byte("linux-image-6.8.0-50-generic\nlibc6\nlibc6\n$(id)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	req, reasons, err := a.RebootRequired(ctx)
	if err != nil || !req || !reflect.DeepEqual(reasons, []string{"linux-image-6.8.0-50-generic", "libc6"}) {
		t.Fatalf("got %v %v %v", req, reasons, err)
	}

	// dnf via needs-restarting.
	fr := &fakeRunner{available: map[string]bool{"needs-restarting": true}, results: map[string]fakeResult{
		"needs-restarting -r": {out: "Core libraries or services have been updated since boot-up:\n  * kernel\n", code: 1},
	}}
	if req, reasons, err := (&Dnf{Runner: fr}).RebootRequired(ctx); err != nil || !req || len(reasons) != 1 {
		t.Fatalf("needs-restarting: %v %v %v", req, reasons, err)
	}
	// dnf via kernel comparison.
	fr = &fakeRunner{results: map[string]fakeResult{
		"rpm -q --qf": {out: "1714000000 5.14.0-362.24.1.el9_3.x86_64\n1718000000 5.14.0-427.22.1.el9_4.x86_64\n"},
	}}
	d := &Dnf{Runner: fr, KernelRelease: func() string { return "5.14.0-362.24.1.el9_3.x86_64" }}
	if req, reasons, err := d.RebootRequired(ctx); err != nil || !req || len(reasons) != 1 {
		t.Fatalf("kernel compare: %v %v %v", req, reasons, err)
	}
	if got := fr.argv(0); got != `rpm -q --qf %{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\n -- kernel-core` {
		t.Fatalf("argv %s", got)
	}
	d.KernelRelease = func() string { return "5.14.0-427.22.1.el9_4.x86_64" }
	if req, _, err := d.RebootRequired(ctx); err != nil || req {
		t.Fatalf("same kernel: %v %v", req, err)
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "os-release")
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	both := &fakeRunner{available: map[string]bool{"apt-get": true, "dnf": true}}
	tests := []struct {
		osr  string
		r    *fakeRunner
		want string
	}{
		{"ID=debian\n", both, "apt"},
		{"ID=ubuntu\nID_LIKE=debian\n", both, "apt"},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", both, "dnf"},
		{"ID=almalinux\n", both, "dnf"},
		{"ID=weird\n", &fakeRunner{available: map[string]bool{"dnf": true}}, "dnf"},
		{"ID=weird\n", &fakeRunner{}, ""},
	}
	for _, tc := range tests {
		m, err := Detect(tc.r, write(tc.osr))
		got := ""
		if err == nil {
			got = m.Name()
		}
		if got != tc.want {
			t.Errorf("%q: got %q (%v), want %q", tc.osr, got, err, tc.want)
		}
	}
}

func FuzzParseAptSimulate(f *testing.F) {
	f.Add(aptDebian)
	f.Add(aptUbuntu)
	f.Add("Inst a [")
	f.Add("Inst a (")
	f.Add("Inst a [1] (2 [x])")
	f.Fuzz(func(t *testing.T, s string) {
		for _, u := range ParseAptSimulate([]byte(s)) {
			if !policy.ValidPackageName(u.Name) || u.CandidateVersion == "" {
				t.Fatalf("invalid entry %+v", u)
			}
		}
	})
}

func FuzzParseDnf(f *testing.F) {
	f.Add(dnfCheckUpdate)
	f.Add(dnfUpdateinfo)
	f.Add(dnf5Advisory)
	f.Add("a.x86_64\n  1 2\n")
	f.Fuzz(func(t *testing.T, s string) {
		for _, u := range ParseCheckUpdate([]byte(s)) {
			if !policy.ValidPackageName(u.Name) || !knownArch(u.Arch) {
				t.Fatalf("invalid entry %+v", u)
			}
		}
		for k, adv := range ParseUpdateinfo([]byte(s)) {
			if _, _, ok := splitNameArch(k); !ok || len(adv) == 0 {
				t.Fatalf("invalid key %q", k)
			}
		}
		ParseRPMVersions([]byte(s))
		ParseNeedsRestarting([]byte(s))
		NewestKernel([]byte(s))
		ParseNEVRA(s)
		ParseOSRelease([]byte(s))
	})
}

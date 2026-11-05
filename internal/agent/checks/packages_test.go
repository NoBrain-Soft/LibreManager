package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func updates(checkedAgo time.Duration, ups ...*agentv1.PendingUpdate) *agentv1.UpdatesReport {
	return &agentv1.UpdatesReport{CheckedAtMs: t0.Add(-checkedAgo).UnixMilli(), Manager: "apt", Updates: ups}
}

func TestSecurityUpdates(t *testing.T) {
	sec := func(name string, adv ...string) *agentv1.PendingUpdate {
		return &agentv1.PendingUpdate{Name: name, IsSecurity: true, Advisories: adv}
	}
	plain := &agentv1.PendingUpdate{Name: "vim"}
	tests := []struct {
		name string
		u    *agentv1.UpdatesReport
		want agentv1.CheckStatus
	}{
		{"no report", nil, NA},
		{"report error", &agentv1.UpdatesReport{Error: "apt: could not get lock"}, ERROR},
		{"clean", updates(time.Hour, plain), PASS},
		{"security pending", updates(time.Hour, plain, sec("openssl", "DSA-5678-1"), sec("libc6", "DSA-5679-1", "DSA-5678-1"), sec("openssl")), FAIL},
		{"stale clean", updates(10 * 24 * time.Hour), WARN},
		{"never checked", &agentv1.UpdatesReport{Manager: "dnf"}, WARN},
		{"stale but security pending", updates(30*24*time.Hour, sec("bash")), FAIL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: t.TempDir(), Updates: tc.u}, "PKG-001")
			expectStatus(t, r, tc.want)
			if tc.name == "security pending" {
				expectEvidence(t, r, "security_updates", "2")
				expectEvidence(t, r, "total_updates", "4")
				expectEvidence(t, r, "packages", "libc6, openssl")
				expectEvidence(t, r, "advisories", "DSA-5678-1, DSA-5679-1")
			}
		})
	}
}

func kernelTree(t *testing.T, base string, running string, installed ...string) (root, proc string) {
	t.Helper()
	root = copyTree(t, td(t, base))
	files := map[string]string{}
	for _, k := range installed {
		files["lib/modules/"+k+"/modules.builtin"] = "kernel/fs/ext4/ext4.ko\n"
	}
	addFiles(t, root, files)
	proc = writeTree(t, map[string]string{"sys/kernel/osrelease": running + "\n"})
	return root, proc
}

func TestRebootRequired(t *testing.T) {
	t.Run("updates report", func(t *testing.T) {
		u := updates(time.Hour)
		u.RebootRequired, u.RebootReasons = true, []string{"kernel 6.1.0-28-amd64 installed"}
		r := runCheck(t, Env{Root: td(t, "root/rhel"), ProcRoot: t.TempDir(), Updates: u}, "PKG-002")
		expectStatus(t, r, WARN)
		expectEvidence(t, r, "reasons", "kernel 6.1.0-28-amd64 installed")
	})
	t.Run("debian reboot-required file", func(t *testing.T) {
		root := copyTree(t, td(t, "root/debian"))
		addFiles(t, root, map[string]string{
			"run/reboot-required":      "*** System restart required ***\n",
			"run/reboot-required.pkgs": "linux-image-6.1.0-28-amd64\nlibc6\n",
		})
		r := runCheck(t, Env{Root: root, ProcRoot: t.TempDir()}, "PKG-002")
		expectStatus(t, r, WARN)
		expectEvidence(t, r, "reasons", "package libc6, package linux-image-6.1.0-28-amd64")
	})
	t.Run("debian clean", func(t *testing.T) {
		expectStatus(t, runCheck(t, Env{Root: td(t, "root/debian"), ProcRoot: t.TempDir()}, "PKG-002"), PASS)
	})
	t.Run("rhel without data", func(t *testing.T) {
		expectStatus(t, runCheck(t, Env{Root: td(t, "root/rhel"), ProcRoot: t.TempDir()}, "PKG-002"), NA)
	})
	t.Run("report with error is not trusted", func(t *testing.T) {
		u := &agentv1.UpdatesReport{Error: "dnf failed", RebootRequired: false}
		expectStatus(t, runCheck(t, Env{Root: td(t, "root/rhel"), ProcRoot: t.TempDir(), Updates: u}, "PKG-002"), NA)
	})
	t.Run("newer kernel installed", func(t *testing.T) {
		root, proc := kernelTree(t, "root/rhel", "5.14.0-427.13.1.el9_4.x86_64",
			"5.14.0-427.13.1.el9_4.x86_64", "5.14.0-503.11.1.el9_5.x86_64", "5.14.0-362.8.1.el9_3.x86_64")
		r := runCheck(t, Env{Root: root, ProcRoot: proc}, "PKG-002")
		expectStatus(t, r, WARN)
		expectEvidence(t, r, "reasons", "kernel 5.14.0-503.11.1.el9_5.x86_64 installed, running 5.14.0-427.13.1.el9_4.x86_64")
	})
	t.Run("running newest kernel", func(t *testing.T) {
		root, proc := kernelTree(t, "root/rhel", "5.14.0-503.11.1.el9_5.x86_64",
			"5.14.0-427.13.1.el9_4.x86_64", "5.14.0-503.11.1.el9_5.x86_64")
		expectStatus(t, runCheck(t, Env{Root: root, ProcRoot: proc}, "PKG-002"), PASS)
	})
	t.Run("other flavour is not newer", func(t *testing.T) {
		root, proc := kernelTree(t, "root/debian", "6.1.0-27-amd64", "6.1.0-27-amd64", "6.1.0-28-cloud-amd64")
		expectStatus(t, runCheck(t, Env{Root: root, ProcRoot: proc}, "PKG-002"), PASS)
	})
	t.Run("container: running kernel not installed", func(t *testing.T) {
		root, proc := kernelTree(t, "root/rhel", "6.8.0-45-generic", "5.14.0-503.11.1.el9_5.x86_64")
		expectStatus(t, runCheck(t, Env{Root: root, ProcRoot: proc}, "PKG-002"), NA)
	})
	t.Run("leftover module dirs are ignored", func(t *testing.T) {
		root, proc := kernelTree(t, "root/debian", "6.1.0-27-amd64", "6.1.0-27-amd64")
		addFiles(t, root, map[string]string{"lib/modules/6.1.0-29-amd64/updates/dkms/x.ko": ""})
		expectStatus(t, runCheck(t, Env{Root: root, ProcRoot: proc}, "PKG-002"), PASS)
	})
}

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"6.1.0-28-amd64", "6.1.0-27-amd64", 1},
		{"6.1.0-9-amd64", "6.1.0-10-amd64", -1},
		{"5.14.0-503.11.1.el9_5.x86_64", "5.14.0-427.13.1.el9_4.x86_64", 1},
		{"6.8.0-45-generic", "6.8.0-45-generic", 0},
		{"1.010", "1.10", 0},
		{"1.2", "1.2.1", -1},
		{"", "1", -1},
	} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if versionShape("6.1.0-27-amd64") != versionShape("6.1.0-28-amd64") || versionShape("6.1.0-27-amd64") == versionShape("6.1.0-27-cloud-amd64") {
		t.Fatal("versionShape")
	}
}

func TestAutoUpdatesDebian(t *testing.T) {
	enabled := map[string]cmdResp{"systemctl is-enabled -- apt-daily-upgrade.timer": {out: "enabled\n"}}
	disabled := map[string]cmdResp{"systemctl is-enabled -- apt-daily-upgrade.timer": {out: "disabled\n", code: 1}}
	tests := []struct {
		name  string
		files map[string]string // added to / overriding the debian fixture
		rm    []string
		exec  map[string]cmdResp
		want  agentv1.CheckStatus
	}{
		{"configured", nil, nil, enabled, PASS},
		{"timer state unknown", nil, nil, nil, PASS},
		{"timer disabled", nil, nil, disabled, FAIL},
		{"timer masked", nil, nil, map[string]cmdResp{"systemctl is-enabled -- apt-daily-upgrade.timer": {out: "masked\n", code: 1}}, FAIL},
		{"not installed", nil, []string{"usr/bin/unattended-upgrade"}, enabled, FAIL},
		{"periodic unset", nil, []string{"etc/apt/apt.conf.d/20auto-upgrades"}, enabled, FAIL},
		{"periodic zero later", map[string]string{"etc/apt/apt.conf.d/99local": `APT::Periodic::Unattended-Upgrade "0";`}, nil, enabled, FAIL},
		{"apt.conf overrides parts", map[string]string{"etc/apt/apt.conf": `APT::Periodic::Unattended-Upgrade "0";`}, nil, enabled, FAIL},
		{"nested syntax", map[string]string{"etc/apt/apt.conf.d/20auto-upgrades": "APT {\n  Periodic {\n    Unattended-Upgrade \"1\";\n  };\n};\n"}, nil, enabled, PASS},
		{"ignored editor backup", map[string]string{"etc/apt/apt.conf.d/20auto-upgrades~": `APT::Periodic::Unattended-Upgrade "0";`}, nil, enabled, PASS},
		{"always", map[string]string{"etc/apt/apt.conf.d/20auto-upgrades": `APT::Periodic::Unattended-Upgrade "always";`}, nil, enabled, PASS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := copyTree(t, td(t, "root/debian"))
			addFiles(t, root, tc.files)
			for _, p := range tc.rm {
				if err := os.Remove(filepath.Join(root, p)); err != nil {
					t.Fatal(err)
				}
			}
			r := runCheck(t, Env{Root: root, Exec: newExec(tc.exec)}, "PKG-003")
			expectStatus(t, r, tc.want)
		})
	}
}

func TestAutoUpdatesRHEL(t *testing.T) {
	timers := func(install, auto string) map[string]cmdResp {
		return map[string]cmdResp{
			"systemctl is-enabled -- dnf-automatic-install.timer": {out: install},
			"systemctl is-enabled -- dnf-automatic.timer":         {out: auto},
			"systemctl is-enabled -- dnf5-automatic.timer":        {code: 1},
		}
	}
	noApply := "[commands]\napply_updates = no\nupgrade_type = default\n"
	tests := []struct {
		name string
		conf *string
		rm   []string
		exec map[string]cmdResp
		want agentv1.CheckStatus
	}{
		{"timer + apply", nil, nil, timers("disabled", "enabled"), PASS},
		{"install timer", &noApply, nil, timers("enabled", "disabled"), PASS},
		{"download only", &noApply, nil, timers("disabled", "enabled"), WARN},
		{"no timer", nil, nil, timers("disabled", "disabled"), FAIL},
		{"not installed", nil, []string{"etc/dnf/automatic.conf", "usr/bin/dnf-automatic"}, timers("enabled", "enabled"), FAIL},
		{"systemctl unavailable", nil, nil, nil, ERROR},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := copyTree(t, td(t, "root/rhel"))
			if tc.conf != nil {
				addFiles(t, root, map[string]string{"etc/dnf/automatic.conf": *tc.conf})
			}
			for _, p := range tc.rm {
				if err := os.Remove(filepath.Join(root, p)); err != nil {
					t.Fatal(err)
				}
			}
			r := runCheck(t, Env{Root: root, Exec: newExec(tc.exec)}, "PKG-003")
			expectStatus(t, r, tc.want)
			if tc.name == "timer + apply" {
				expectEvidence(t, r, "upgrade_type", "security")
				expectEvidence(t, r, "apply_updates", "true")
			}
		})
	}
}

func TestAutoUpdatesOtherOS(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/os-release": "ID=alpine\n"})
	expectStatus(t, runCheck(t, Env{Root: root}, "PKG-003"), NA)
	expectStatus(t, runCheck(t, Env{Root: t.TempDir()}, "PKG-003"), NA)
}

func TestParseAptConf(t *testing.T) {
	conf := `
// comment "with quotes"
APT::Periodic::Update-Package-Lists "1";
APT { Periodic { Unattended-Upgrade "2"; Download-Upgradeable-Packages "1"; }; };
/* block
   APT::Periodic::Unattended-Upgrade "9"; */
# APT::Periodic::Unattended-Upgrade "8";
#include "/etc/apt/other.conf";
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern { "origin=Debian"; "o=x"; };
"Quoted::Key" "v";
Dpkg::Options { "--force-confdef"; };
Bare::Word value;
`
	got := map[string]string{}
	parseAptConf([]byte(conf), func(k, v string) { got[k] = v })
	want := map[string]string{
		"APT::Periodic::Update-Package-Lists":          "1",
		"APT::Periodic::Unattended-Upgrade":            "2",
		"APT::Periodic::Download-Upgradeable-Packages": "1",
		"Quoted::Key": "v",
		"Bare::Word":  "value",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for k := range got {
		if strings.Contains(k, "Origins-Pattern") || strings.Contains(k, "Dpkg") || strings.Contains(k, "include") {
			t.Errorf("unexpected key %q", k)
		}
	}
	// Unterminated constructs end parsing without panicking.
	for _, s := range []string{`A "unterminated`, "/* open", "A {", "}}}", `"a" "b"`, "#include"} {
		parseAptConf([]byte(s), func(string, string) {})
	}
}

func TestPeriodicEnabled(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "7": true, "always": true, "12h": true, "1d": true, "0": false, "": false, "no": false, "-1": false, "0d": false} {
		if periodicEnabled(v) != want {
			t.Errorf("%q: %v", v, !want)
		}
	}
}

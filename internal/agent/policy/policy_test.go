package policy

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

const sample = `
central: "stellwerk.example.internal:8443"
ca_fingerprint_sha256: "AB:CD"
capabilities:
  metrics: true
  inventory: true
  security_checks: true
  packages: { list: true, upgrade: true, install: false, remove: false }
  services: { control: true, allow: ["nginx.service", "*.service"], deny: ["sshd.service"] }
  reboot: true
  shell: { enabled: true, allow_root: false, allowed_users: ["ops", "%sudo-ops"] }
  exec_scripts: false
  file_read: { allow: ["/etc/**", "/var/log/**"], deny: ["/etc/shadow", "/etc/ssl/private/**"] }
  self_update: true
limits:
  max_jobs_per_minute: 30
  max_concurrent_shells: 3
`

type fakeUsers struct{}

func (fakeUsers) Lookup(name string) (*user.User, error) {
	switch name {
	case "root":
		return &user.User{Uid: "0", Gid: "0", Username: "root"}, nil
	case "ops":
		return &user.User{Uid: "1000", Gid: "1000", Username: "ops"}, nil
	case "alice":
		return &user.User{Uid: "1001", Gid: "1001", Username: "alice"}, nil
	case "bob":
		return &user.User{Uid: "1002", Gid: "1002", Username: "bob"}, nil
	case "daemon":
		return &user.User{Uid: "2", Gid: "2", Username: "daemon"}, nil
	}
	return nil, user.UnknownUserError(name)
}

func (fakeUsers) GroupIDs(u *user.User) ([]string, error) {
	if u.Username == "alice" {
		return []string{"1001", "5000"}, nil
	}
	return []string{u.Gid}, nil
}

func (fakeUsers) LookupGroup(name string) (*user.Group, error) {
	if name == "sudo-ops" {
		return &user.Group{Gid: "5000", Name: name}, nil
	}
	return nil, user.UnknownGroupError(name)
}

func (fakeUsers) HasLoginShell(u *user.User) bool { return u.Username != "daemon" }

func eval(t *testing.T, y string) *Evaluator {
	t.Helper()
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return &Evaluator{P: p, Users: fakeUsers{}}
}

func job(a any) *agentv1.Job {
	j := &agentv1.Job{}
	switch v := a.(type) {
	case *agentv1.PkgRefresh:
		j.Action = &agentv1.Job_PkgRefresh{PkgRefresh: v}
	case *agentv1.PkgUpgrade:
		j.Action = &agentv1.Job_PkgUpgrade{PkgUpgrade: v}
	case *agentv1.PkgInstall:
		j.Action = &agentv1.Job_PkgInstall{PkgInstall: v}
	case *agentv1.PkgRemove:
		j.Action = &agentv1.Job_PkgRemove{PkgRemove: v}
	case *agentv1.ServiceAction:
		j.Action = &agentv1.Job_Service{Service: v}
	case *agentv1.Reboot:
		j.Action = &agentv1.Job_Reboot{Reboot: v}
	case *agentv1.ShellGrant:
		j.Action = &agentv1.Job_Shell{Shell: v}
	case *agentv1.RunScript:
		j.Action = &agentv1.Job_Script{Script: v}
	case *agentv1.FileRead:
		j.Action = &agentv1.Job_FileRead{FileRead: v}
	}
	return j
}

func shell(u string) *agentv1.ShellGrant {
	return &agentv1.ShellGrant{UnixUser: u, Cols: 80, Rows: 24, MaxDurationS: 3600}
}

func TestEvaluator(t *testing.T) {
	e := eval(t, sample)
	cases := []struct {
		name  string
		job   *agentv1.Job
		allow bool
	}{
		{"refresh", job(&agentv1.PkgRefresh{}), true},
		{"upgrade all", job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}), true},
		{"upgrade security", job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}), true},
		{"upgrade named", job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: []string{"openssl", "libc6:amd64"}}), true},
		{"upgrade unspecified scope", job(&agentv1.PkgUpgrade{}), false},
		{"upgrade named empty", job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED}), false},
		{"upgrade all with names", job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL, Packages: []string{"x"}}), false},
		{"upgrade option injection", job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: []string{"-oAPT::Get::Something=1"}}), false},
		{"upgrade shell metachar", job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: []string{"x;rm -rf /"}}), false},
		{"install denied", job(&agentv1.PkgInstall{Packages: []string{"nmap"}}), false},
		{"remove denied", job(&agentv1.PkgRemove{Packages: []string{"nmap"}}), false},
		{"restart nginx", job(&agentv1.ServiceAction{Unit: "nginx.service", Op: agentv1.ServiceOp_SERVICE_OP_RESTART}), true},
		{"restart sshd denied", job(&agentv1.ServiceAction{Unit: "sshd.service", Op: agentv1.ServiceOp_SERVICE_OP_RESTART}), false},
		{"own unit protected", job(&agentv1.ServiceAction{Unit: "stellwerk-agent.service", Op: agentv1.ServiceOp_SERVICE_OP_STOP}), false},
		{"timer not allowed", job(&agentv1.ServiceAction{Unit: "apt-daily.timer", Op: agentv1.ServiceOp_SERVICE_OP_STOP}), false},
		{"invalid unit", job(&agentv1.ServiceAction{Unit: "../x.service", Op: agentv1.ServiceOp_SERVICE_OP_STOP}), false},
		{"unit option injection", job(&agentv1.ServiceAction{Unit: "--now.service", Op: agentv1.ServiceOp_SERVICE_OP_STOP}), false},
		{"unspecified op", job(&agentv1.ServiceAction{Unit: "nginx.service"}), false},
		{"bogus op", job(&agentv1.ServiceAction{Unit: "nginx.service", Op: 99}), false},
		{"reboot", job(&agentv1.Reboot{DelayS: 60}), true},
		{"reboot delay too long", job(&agentv1.Reboot{DelayS: 7200}), false},
		{"shell ops", job(shell("ops")), true},
		{"shell via group", job(shell("alice")), true},
		{"shell not allowed user", job(shell("bob")), false},
		{"shell root denied", job(shell("root")), false},
		{"shell unknown user", job(shell("nobody2")), false},
		{"shell invalid user", job(shell("Robert'); DROP")), false},
		{"shell too long", job(&agentv1.ShellGrant{UnixUser: "ops", MaxDurationS: 5 * 3600}), false},
		{"shell zero duration", job(&agentv1.ShellGrant{UnixUser: "ops"}), false},
		{"script disabled", job(&agentv1.RunScript{}), false},
		{"read nginx conf", job(&agentv1.FileRead{Path: "/etc/nginx/nginx.conf"}), true},
		{"read shadow denied", job(&agentv1.FileRead{Path: "/etc/shadow"}), false},
		{"read ssl private denied", job(&agentv1.FileRead{Path: "/etc/ssl/private/key.pem"}), false},
		{"read outside allow", job(&agentv1.FileRead{Path: "/root/.ssh/id_rsa"}), false},
		{"read traversal", job(&agentv1.FileRead{Path: "/etc/../root/.bashrc"}), false},
		{"read relative", job(&agentv1.FileRead{Path: "etc/passwd"}), false},
		{"no action", &agentv1.Job{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := e.Check(tc.job)
			if tc.allow && err != nil {
				t.Fatalf("denied: %v", err)
			}
			if !tc.allow && !errors.Is(err, ErrDenied) {
				t.Fatalf("err = %v, want ErrDenied", err)
			}
		})
	}
}

func TestShellRootAndWildcard(t *testing.T) {
	y := strings.Replace(sample, `allow_root: false, allowed_users: ["ops", "%sudo-ops"]`, `allow_root: true, allowed_users: ["*"]`, 1)
	e := eval(t, y)
	for _, u := range []string{"root", "bob", "alice"} {
		if err := e.Check(job(shell(u))); err != nil {
			t.Errorf("%s denied: %v", u, err)
		}
	}
	if err := e.Check(job(shell("daemon"))); !errors.Is(err, ErrDenied) {
		t.Errorf("nologin account allowed: %v", err)
	}
}

func TestParseStrict(t *testing.T) {
	for name, y := range map[string]string{
		"unknown key":     "capabilitiez: {}\n",
		"bad central":     "central: nohost\n",
		"relative glob":   "capabilities: { file_read: { allow: [\"etc/**\"] } }\n",
		"bad shell user":  "capabilities: { shell: { allowed_users: [\"Bad User\"] } }\n",
		"bad svc pattern": "capabilities: { services: { allow: [\"[\"] } }\n",
		"oversize":        strings.Repeat("#", maxPolicyBytes+1),
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDefaultsDenyEverything(t *testing.T) {
	e := eval(t, "central: \"c:8443\"\n")
	for _, j := range []*agentv1.Job{
		job(&agentv1.PkgRefresh{}),
		job(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}),
		job(&agentv1.Reboot{}),
		job(shell("ops")),
		job(&agentv1.FileRead{Path: "/etc/hosts"}),
	} {
		if err := e.Check(j); !errors.Is(err, ErrDenied) {
			t.Errorf("empty policy allowed %T", j.GetAction())
		}
	}
	if e.P.Limits.MaxJobsPerMinute != DefaultJobsPerMinute || e.P.StateDir != DefaultStateDir {
		t.Error("defaults not applied")
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{"/etc/**", "/etc/nginx/nginx.conf", true},
		{"/etc/**", "/etc", true},
		{"/etc/*", "/etc/nginx/nginx.conf", false},
		{"/var/log/*.log", "/var/log/syslog.log", true},
		{"/var/**/*.log", "/var/log/nginx/a.log", true},
		{"/etc/shadow", "/etc/shadow-", false},
		{"/etc/ssl/private/**", "/etc/ssl/private", true},
	}
	for _, tc := range cases {
		if got := MatchPath(tc.pat, tc.p); got != tc.want {
			t.Errorf("MatchPath(%q, %q) = %v", tc.pat, tc.p, got)
		}
	}
}

func TestLoadRequiresRootOwnership(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(sample), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, true); err == nil {
		t.Fatal("world-writable policy accepted")
	}
	if _, err := Load(p, false); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	r := NewRateLimiter(2, func() time.Time { return now })
	first, second := r.Allow(), r.Allow()
	if !first || !second {
		t.Fatal("within limit denied")
	}
	if r.Allow() {
		t.Fatal("over limit allowed")
	}
	now = now.Add(61 * time.Second)
	if !r.Allow() {
		t.Fatal("window did not slide")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		e := &Evaluator{P: p, Users: fakeUsers{}}
		_ = e.Check(job(&agentv1.FileRead{Path: "/etc/passwd"}))
		_ = e.Check(job(&agentv1.ServiceAction{Unit: "a.service", Op: agentv1.ServiceOp_SERVICE_OP_START}))
	})
}

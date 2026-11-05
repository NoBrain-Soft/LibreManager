package checks

import (
	"errors"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

const timeUnits = "systemctl is-active -- chronyd.service chrony.service systemd-timesyncd.service"

func TestRequiredServices(t *testing.T) {
	debian := td(t, "root/debian")
	tests := []struct {
		name     string
		root     string
		required []string
		exec     map[string]cmdResp
		want     agentv1.CheckStatus
	}{
		{"default, chrony active", debian, nil, map[string]cmdResp{timeUnits: {out: "inactive\nactive\ninactive\n"}}, PASS},
		{"default, none active", debian, nil, map[string]cmdResp{timeUnits: {out: "inactive\ninactive\nfailed\n", code: 3}}, FAIL},
		{"custom", debian, []string{"auditd", "falcon-sensor.service|cbagentd.service"}, map[string]cmdResp{
			"systemctl is-active -- auditd.service falcon-sensor.service cbagentd.service": {out: "active\ninactive\nactive\n"}}, PASS},
		{"custom, one missing", debian, []string{"auditd", "falcon-sensor.service|cbagentd.service"}, map[string]cmdResp{
			"systemctl is-active -- auditd.service falcon-sensor.service cbagentd.service": {out: "active\ninactive\ninactive\n", code: 3}}, FAIL},
		{"invalid names never reach argv", debian, []string{"--now", "a;b", "auditd"}, map[string]cmdResp{
			"systemctl is-active -- auditd.service": {out: "active\n"}}, FAIL},
		{"only invalid names", debian, []string{"-x", "../../etc"}, nil, ERROR},
		{"explicitly empty", debian, []string{}, nil, NA},
		{"no systemd", t.TempDir(), nil, nil, NA},
		{"systemctl error", debian, nil, map[string]cmdResp{timeUnits: {err: errors.New("timeout")}}, ERROR},
		{"systemctl missing", debian, nil, nil, ERROR},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ex := newExec(tc.exec)
			r := runCheck(t, Env{Root: tc.root, RequiredServices: tc.required, Exec: ex}, "SVC-001")
			expectStatus(t, r, tc.want)
			for _, argv := range ex.allCalls() {
				if !slices.Equal(argv[:3], []string{"systemctl", "is-active", "--"}) {
					t.Fatalf("argv %v", argv)
				}
				for _, a := range argv[3:] {
					if a[0] == '-' || !slices.Contains([]string{"auditd.service", "falcon-sensor.service", "cbagentd.service", "chronyd.service", "chrony.service", "systemd-timesyncd.service"}, a) {
						t.Fatalf("unexpected unit argument %q", a)
					}
				}
			}
			if tc.name == "invalid names never reach argv" {
				expectEvidence(t, r, "invalid_unit_names", "--now, a;b")
			}
		})
	}
}

const failedCmd = "systemctl list-units --state=failed --no-legend --plain --no-pager"

func TestFailedUnits(t *testing.T) {
	debian := td(t, "root/debian")
	tests := []struct {
		name string
		root string
		exec map[string]cmdResp
		want agentv1.CheckStatus
	}{
		{"none", debian, map[string]cmdResp{failedCmd: {out: ""}}, PASS},
		{"two failed", debian, map[string]cmdResp{failedCmd: {out: "backup.service loaded failed failed Nightly backup\n● logrotate.timer loaded failed failed Daily rotation\n"}}, FAIL},
		{"garbage lines ignored", debian, map[string]cmdResp{failedCmd: {out: "0 loaded units listed.\n"}}, PASS},
		{"exit code", debian, map[string]cmdResp{failedCmd: {code: 1}}, ERROR},
		{"missing systemctl", debian, nil, ERROR},
		{"no systemd", t.TempDir(), nil, NA},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: tc.root, Exec: newExec(tc.exec)}, "SVC-002")
			expectStatus(t, r, tc.want)
			if tc.want == FAIL {
				expectEvidence(t, r, "units", "backup.service, logrotate.timer")
				expectEvidence(t, r, "count", "2")
			}
		})
	}
}

const timedatectl = "timedatectl show -p NTP -p NTPSynchronized"

func TestTimeSync(t *testing.T) {
	adj := func(state int, status int32, err error) func(*unix.Timex) (int, error) {
		return func(tx *unix.Timex) (int, error) {
			if tx.Modes != 0 {
				t.Fatal("adjtimex called with modes set")
			}
			tx.Status = status
			return state, err
		}
	}
	tests := []struct {
		name   string
		root   string
		adj    func(*unix.Timex) (int, error)
		exec   map[string]cmdResp
		want   agentv1.CheckStatus
		source string
	}{
		{"adjtimex synced", "", adj(unix.TIME_OK, 0, nil), nil, PASS, "adjtimex"},
		{"adjtimex error state", "", adj(unix.TIME_ERROR, unix.STA_UNSYNC, nil), nil, FAIL, "adjtimex"},
		{"adjtimex unsync flag", "", adj(unix.TIME_OK, unix.STA_UNSYNC, nil), nil, FAIL, "adjtimex"},
		{"adjtimex blocked falls back", "", adj(0, 0, unix.EPERM), map[string]cmdResp{timedatectl: {out: "NTP=yes\nNTPSynchronized=yes\n"}}, PASS, "timedatectl"},
		{"timedatectl yes", "", nil, map[string]cmdResp{timedatectl: {out: "NTP=yes\nNTPSynchronized=yes\n"}}, PASS, "timedatectl"},
		{"timedatectl no", "", nil, map[string]cmdResp{timedatectl: {out: "NTP=no\nNTPSynchronized=no\n"}}, FAIL, "timedatectl"},
		{"chrony normal", "", nil, map[string]cmdResp{
			timedatectl:           {code: 1},
			"chronyc -n tracking": {out: "Reference ID    : C0A80001 (192.168.0.1)\nStratum         : 3\nLeap status     : Normal\n"}}, PASS, "chronyc"},
		{"chrony unsynchronised", "", nil, map[string]cmdResp{
			"chronyc -n tracking": {out: "Reference ID    : 00000000 ()\nLeap status     : Not synchronised\n"}}, FAIL, "chronyc"},
		{"timesyncd flag file", "timesync", nil, map[string]cmdResp{"chronyc -n tracking": {out: "506 Cannot talk to daemon\n", code: 1}}, PASS, "/run/systemd/timesync/synchronized"},
		{"undeterminable", "", nil, nil, ERROR, ""},
	}
	timesync := writeTree(t, map[string]string{"run/systemd/timesync/synchronized": ""})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.root == "timesync" {
				root = timesync
			}
			r := runCheck(t, Env{Root: root, Adjtimex: tc.adj, Exec: newExec(tc.exec)}, "TIME-001")
			expectStatus(t, r, tc.want)
			if tc.source != "" {
				expectEvidence(t, r, "source", tc.source)
			}
		})
	}
}

const logUnits = "systemctl is-active -- auditd.service rsyslog.service syslog-ng.service"

func TestLogging(t *testing.T) {
	tests := []struct {
		name  string
		base  string
		files map[string]string
		exec  map[string]cmdResp
		want  agentv1.CheckStatus
	}{
		{"debian auto + journal dir + auditd", "root/debian", nil, map[string]cmdResp{logUnits: {out: "active\ninactive\ninactive\n"}}, PASS},
		{"no auditd", "root/debian", nil, map[string]cmdResp{logUnits: {out: "inactive\ninactive\ninactive\n", code: 3}}, WARN},
		{"auditd unknown", "root/debian", nil, nil, WARN},
		{"rhel volatile, no syslog", "root/rhel", nil, map[string]cmdResp{logUnits: {out: "active\ninactive\ninactive\n"}}, FAIL},
		{"rhel volatile + rsyslog", "root/rhel", nil, map[string]cmdResp{logUnits: {out: "active\nactive\ninactive\n"}}, PASS},
		{"drop-in overrides to volatile", "root/debian", map[string]string{
			"usr/lib/systemd/journald.conf.d/10-persist.conf": "[Journal]\nStorage=persistent\n",
			"etc/systemd/journald.conf.d/50-volatile.conf":    "[Journal]\nStorage=volatile\n",
		}, map[string]cmdResp{logUnits: {out: "active\ninactive\ninactive\n"}}, FAIL},
		{"/etc drop-in masks /usr/lib drop-in of the same name", "root/rhel", map[string]string{
			"usr/lib/systemd/journald.conf.d/50-x.conf": "[Journal]\nStorage=volatile\n",
			"etc/systemd/journald.conf.d/50-x.conf":     "[Journal]\nStorage=persistent\n",
		}, map[string]cmdResp{logUnits: {out: "active\ninactive\ninactive\n"}}, PASS},
		{"other section ignored", "root/rhel", map[string]string{
			"etc/systemd/journald.conf.d/x.conf": "[Other]\nStorage=persistent\n",
		}, map[string]cmdResp{logUnits: {out: "active\ninactive\ninactive\n"}}, FAIL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := copyTree(t, td(t, tc.base))
			addFiles(t, root, tc.files)
			expectStatus(t, runCheck(t, Env{Root: root, Exec: newExec(tc.exec)}, "LOG-001"), tc.want)
		})
	}
}

package checks

import (
	"testing"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func TestMAC(t *testing.T) {
	debian, rhel := td(t, "root/debian"), td(t, "root/rhel")
	apparmorActive := map[string]cmdResp{"systemctl is-active -- apparmor.service": {out: "active\n"}}
	tests := []struct {
		name string
		root string
		sys  string
		exec map[string]cmdResp
		want agentv1.CheckStatus
		ev   map[string]string
	}{
		{"rhel enforcing", rhel, "sys/selinux-enforcing", nil, PASS, map[string]string{"selinux": "enforcing", "os_family": "rhel"}},
		{"rhel permissive", rhel, "sys/selinux-permissive", nil, FAIL, map[string]string{"selinux": "permissive"}},
		{"rhel disabled", rhel, "sys/none", nil, FAIL, map[string]string{"selinux": "disabled"}},
		{"rhel expects selinux, not apparmor", rhel, "sys/apparmor", nil, FAIL, nil},
		{"debian apparmor", debian, "sys/apparmor", nil, PASS, map[string]string{"apparmor_profiles": "3", "apparmor_enforcing": "2"}},
		{"debian complain only", debian, "sys/apparmor-complain", nil, WARN, nil},
		{"debian no profiles", debian, "sys/apparmor-noprofiles", nil, FAIL, nil},
		{"debian profiles unreadable, service active", debian, "sys/apparmor-unprivileged", apparmorActive, PASS, map[string]string{"apparmor_source": "apparmor.service"}},
		{"debian profiles unreadable, unknown", debian, "sys/apparmor-unprivileged", nil, WARN, nil},
		{"debian apparmor off", debian, "sys/apparmor-off", nil, FAIL, map[string]string{"apparmor_enabled": "false"}},
		{"debian selinux enforcing", debian, "sys/selinux-enforcing", nil, PASS, nil},
		{"debian selinux permissive, no apparmor", debian, "sys/selinux-permissive", nil, FAIL, nil},
		{"unknown os, nothing", t.TempDir(), "sys/none", nil, FAIL, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCheck(t, Env{Root: tc.root, SysRoot: td(t, tc.sys), Exec: newExec(tc.exec)}, "MAC-001")
			expectStatus(t, r, tc.want)
			for k, v := range tc.ev {
				expectEvidence(t, r, k, v)
			}
		})
	}
}

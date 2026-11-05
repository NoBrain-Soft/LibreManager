package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type selinuxState int

const (
	selinuxDisabled selinuxState = iota
	selinuxPermissive
	selinuxEnforcing
)

func (r *runState) selinux() selinuxState {
	v, err := readTrim(r.sysPath("fs/selinux/enforce"))
	switch {
	case err != nil:
		return selinuxDisabled
	case v == "1":
		return selinuxEnforcing
	}
	return selinuxPermissive
}

// apparmor returns whether AppArmor is enabled and how many profiles are
// loaded (-1: unknown). The profile list is root-only, so unprivileged
// agents fall back to the policy directory, then to apparmor.service.
func (r *runState) apparmor(ctx context.Context) (enabled bool, profiles, enforcing int, source string) {
	v, err := readTrim(r.sysPath("module/apparmor/parameters/enabled"))
	if err != nil || !strings.EqualFold(v, "Y") {
		return false, 0, 0, ""
	}
	if data, err := readCapped(r.sysPath("kernel/security/apparmor/profiles"), 4<<20); err == nil {
		for _, l := range nonEmptyLines(data) {
			profiles++
			if strings.HasSuffix(l, "(enforce)") {
				enforcing++
			}
		}
		return true, profiles, enforcing, "profiles"
	}
	if entries, err := os.ReadDir(r.sysPath("kernel/security/apparmor/policy/profiles")); err == nil {
		return true, len(entries), -1, "policy/profiles"
	}
	if r.systemdBooted() {
		if st, err := r.systemctlActive(ctx, "apparmor.service"); err == nil && st["apparmor.service"] == "active" {
			return true, -1, -1, "apparmor.service"
		}
	}
	return true, -1, -1, ""
}

func checkMAC(ctx context.Context, r *runState) result {
	family := r.osFamily()
	se := r.selinux()
	aaOn, profiles, enforcing, source := r.apparmor(ctx)
	seName := [...]string{"disabled", "permissive", "enforcing"}[se]
	kvs := []string{"os_family", family, "selinux", seName, "apparmor_enabled", fmt.Sprint(aaOn)}
	if aaOn {
		kvs = append(kvs, "apparmor_profiles", fmt.Sprint(profiles), "apparmor_source", source)
		if enforcing >= 0 {
			kvs = append(kvs, "apparmor_enforcing", fmt.Sprint(enforcing))
		}
	}
	if se == selinuxEnforcing {
		return pass("SELinux is enforcing", kvs...)
	}
	if family == "rhel" {
		if se == selinuxPermissive {
			return fail("SELinux is in permissive mode", kvs...)
		}
		return fail("SELinux is disabled", kvs...)
	}
	switch {
	case !aaOn && se == selinuxPermissive:
		return fail("SELinux is in permissive mode and AppArmor is not enabled", kvs...)
	case !aaOn:
		return fail("neither SELinux nor AppArmor is enabled", kvs...)
	case profiles == 0:
		return fail("AppArmor is enabled but no profiles are loaded", kvs...)
	case profiles > 0 && enforcing == 0:
		return warn("AppArmor profiles are loaded in complain mode only", kvs...)
	case profiles < 0 && source == "":
		return warn("AppArmor is enabled but loaded profiles cannot be verified", kvs...)
	}
	return pass("AppArmor is enabled with loaded profiles", kvs...)
}

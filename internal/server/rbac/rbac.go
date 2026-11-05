// Package rbac evaluates permissions × scopes (ARCHITECTURE.md §6.4):
// a role binding is either global or scoped to a host group subtree.
package rbac

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// Permissions.
const (
	HostView       = "host.view"
	HostManage     = "host.manage"
	EnrollManage   = "enroll.manage"
	PkgRefresh     = "pkg.refresh"
	PkgUpgrade     = "pkg.upgrade"
	PkgInstall     = "pkg.install"
	ServiceControl = "service.control"
	HostReboot     = "host.reboot"
	ShellOpen      = "shell.open"
	ShellRoot      = "shell.root"
	JobView        = "job.view"
	JobCancel      = "job.cancel"
	AuditView      = "audit.view"
	ShellReview    = "shell.review"
	SecurityView   = "security.view"
	SecurityManage = "security.manage"
	AlertsView     = "alerts.view"
	AlertsManage   = "alerts.manage"
	AdminUsers     = "admin.users"
	AdminSettings  = "admin.settings"
	AdminGroups    = "admin.groups"
)

// All lists every permission (for validation and UI).
var All = []string{
	HostView, HostManage, EnrollManage, PkgRefresh, PkgUpgrade, PkgInstall, ServiceControl, HostReboot,
	ShellOpen, ShellRoot, JobView, JobCancel, AuditView, ShellReview, SecurityView, SecurityManage,
	AlertsView, AlertsManage, AdminUsers, AdminSettings, AdminGroups,
}

// Binding is one role binding resolved to permissions.
type Binding struct {
	Permissions []string
	// GroupID nil = global.
	GroupID *uuid.UUID
}

// Principal is an authenticated user with resolved bindings.
type Principal struct {
	UserID   uuid.UUID
	Username string
	Bindings []Binding
}

// Load resolves the user's bindings.
func Load(ctx context.Context, q *db.Queries, userID uuid.UUID, username string) (*Principal, error) {
	rows, err := q.ListUserBindings(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("rbac: bindings: %w", err)
	}
	p := &Principal{UserID: userID, Username: username}
	for _, r := range rows {
		p.Bindings = append(p.Bindings, Binding{Permissions: r.Permissions, GroupID: r.HostGroupID})
	}
	return p, nil
}

// Matches reports whether granted covers perm ("*" or "prefix.*").
func Matches(granted, perm string) bool {
	if granted == "*" || granted == perm {
		return true
	}
	if p, ok := strings.CutSuffix(granted, ".*"); ok {
		return strings.HasPrefix(perm, p+".")
	}
	return false
}

func has(perms []string, perm string) bool {
	return slices.ContainsFunc(perms, func(g string) bool { return Matches(g, perm) })
}

// HasGlobal reports whether a global binding grants perm.
func (p *Principal) HasGlobal(perm string) bool {
	for _, b := range p.Bindings {
		if b.GroupID == nil && has(b.Permissions, perm) {
			return true
		}
	}
	return false
}

// HasAnywhere reports whether perm is granted globally or in any group.
func (p *Principal) HasAnywhere(perm string) bool {
	for _, b := range p.Bindings {
		if has(b.Permissions, perm) {
			return true
		}
	}
	return false
}

// groupsWith returns group ids whose scoped bindings grant perm.
func (p *Principal) groupsWith(perm string) []uuid.UUID {
	var out []uuid.UUID
	for _, b := range p.Bindings {
		if b.GroupID != nil && has(b.Permissions, perm) {
			out = append(out, *b.GroupID)
		}
	}
	return out
}

// CanOnHost reports whether perm is granted for hostID (globally or via a
// binding on one of the host's groups or their ancestors).
func (p *Principal) CanOnHost(ctx context.Context, q *db.Queries, perm string, hostID uuid.UUID) (bool, error) {
	if p.HasGlobal(perm) {
		return true, nil
	}
	scoped := p.groupsWith(perm)
	if len(scoped) == 0 {
		return false, nil
	}
	hostGroups, err := q.HostGroupIDsWithAncestors(ctx, hostID)
	if err != nil {
		return false, fmt.Errorf("rbac: host groups: %w", err)
	}
	for _, g := range hostGroups {
		if slices.Contains(scoped, g) {
			return true, nil
		}
	}
	return false, nil
}

// HostFilter describes which hosts a principal may see for perm.
type HostFilter struct {
	All   bool
	Hosts map[uuid.UUID]bool
}

// Allows reports whether id passes the filter.
func (f HostFilter) Allows(id uuid.UUID) bool { return f.All || f.Hosts[id] }

// HostsWith computes the visible host set for perm.
func (p *Principal) HostsWith(ctx context.Context, q *db.Queries, perm string) (HostFilter, error) {
	if p.HasGlobal(perm) {
		return HostFilter{All: true}, nil
	}
	f := HostFilter{Hosts: map[uuid.UUID]bool{}}
	var groups []uuid.UUID
	for _, g := range p.groupsWith(perm) {
		sub, err := q.GroupSubtree(ctx, g)
		if err != nil {
			return f, fmt.Errorf("rbac: subtree: %w", err)
		}
		groups = append(groups, sub...)
	}
	if len(groups) == 0 {
		return f, nil
	}
	ids, err := q.HostsInGroups(ctx, groups)
	if err != nil {
		return f, fmt.Errorf("rbac: hosts: %w", err)
	}
	for _, id := range ids {
		f.Hosts[id] = true
	}
	return f, nil
}

// GlobalPermissions lists permissions granted globally (expanded).
func (p *Principal) GlobalPermissions() []string {
	var out []string
	for _, perm := range All {
		if p.HasGlobal(perm) {
			out = append(out, perm)
		}
	}
	if p.HasGlobal("*") {
		out = append(out, "*")
	}
	return out
}

// Scoped is a permission granted on one group.
type Scoped struct {
	Permission string
	GroupID    uuid.UUID
}

// ScopedPermissions lists group-scoped grants (expanded).
func (p *Principal) ScopedPermissions() []Scoped {
	var out []Scoped
	for _, b := range p.Bindings {
		if b.GroupID == nil {
			continue
		}
		for _, perm := range All {
			if has(b.Permissions, perm) {
				out = append(out, Scoped{Permission: perm, GroupID: *b.GroupID})
			}
		}
	}
	return out
}

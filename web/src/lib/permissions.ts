// Permission evaluation for UI gating. The server always re-checks; this only
// decides what to show or enable.
//
// Sources: SessionInfo.permissions (global role bindings) and
// SessionInfo.scoped_permissions (bindings on a host group, which apply to
// that group's whole subtree, ARCHITECTURE.md §6.4).

export const PERMISSIONS = [
  'host.view',
  'host.manage',
  'enroll.manage',
  'pkg.refresh',
  'pkg.upgrade',
  'pkg.install',
  'service.control',
  'host.reboot',
  'shell.open',
  'shell.root',
  'job.view',
  'job.cancel',
  'audit.view',
  'shell.review',
  'security.view',
  'security.manage',
  'alerts.view',
  'alerts.manage',
  'admin.users',
  'admin.settings',
  'admin.groups',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

export interface PermissionSource {
  permissions: readonly string[];
  scoped_permissions?: readonly { permission: string; host_group_id: string }[] | null;
}

export interface GroupNode {
  id: string;
  parent_id?: string | null;
}

export interface Scope {
  /** Direct host groups of the object (e.g. Host.groups[].id). */
  groupIds?: readonly string[];
  /** All known groups, used to walk up to ancestors. Optional. */
  groups?: readonly GroupNode[];
}

/** Does a granted permission string cover the wanted one? Supports "*" and "prefix.*". */
export function grants(granted: string, wanted: string): boolean {
  if (granted === '*' || granted === wanted) return true;
  if (granted.endsWith('.*')) {
    const prefix = granted.slice(0, -1); // keep the dot
    return wanted.startsWith(prefix);
  }
  return false;
}

export function hasGlobal(src: PermissionSource | null | undefined, perm: Permission): boolean {
  if (!src) return false;
  return src.permissions.some((p) => grants(p, perm));
}

/** The given groups plus all their ancestors (cycle-safe). */
export function withAncestors(groupIds: readonly string[], groups: readonly GroupNode[] = []): Set<string> {
  const parent = new Map<string, string | null | undefined>();
  for (const g of groups) parent.set(g.id, g.parent_id);
  const out = new Set<string>();
  for (const start of groupIds) {
    let cur: string | null | undefined = start;
    let guard = 0;
    while (cur && !out.has(cur) && guard++ < 256) {
      out.add(cur);
      cur = parent.get(cur);
    }
  }
  return out;
}

/**
 * Is `perm` granted globally, or via a scoped binding on one of the scope's
 * groups or their ancestors?
 */
export function can(src: PermissionSource | null | undefined, perm: Permission, scope?: Scope): boolean {
  if (!src) return false;
  if (hasGlobal(src, perm)) return true;
  if (!scope?.groupIds || scope.groupIds.length === 0) return false;
  const scoped = src.scoped_permissions ?? [];
  if (scoped.length === 0) return false;
  const effective = withAncestors(scope.groupIds, scope.groups);
  return scoped.some((sp) => grants(sp.permission, perm) && effective.has(sp.host_group_id));
}

/** Granted globally or on at least one group (for nav items, "New job" buttons, …). */
export function canAnywhere(src: PermissionSource | null | undefined, perm: Permission): boolean {
  if (!src) return false;
  if (hasGlobal(src, perm)) return true;
  return (src.scoped_permissions ?? []).some((sp) => grants(sp.permission, perm));
}

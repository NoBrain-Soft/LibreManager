import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { groupsQuery } from '@/api/queries';
import { sessionQuery } from '@/api/session';
import type { Host, SessionInfo } from '@/api/types';
import { type Permission, can, canAnywhere } from '@/lib/permissions';

export interface Permissions {
  session: SessionInfo | null;
  /** Global grant, or scoped grant on one of `groupIds` (incl. ancestors). */
  can: (perm: Permission, groupIds?: readonly string[]) => boolean;
  /** Granted globally or on at least one group. */
  canAnywhere: (perm: Permission) => boolean;
  /** Shorthand for a host's groups. */
  canOnHost: (perm: Permission, host: Pick<Host, 'groups'> | null | undefined) => boolean;
}

export function usePermissions(): Permissions {
  const { data: session = null } = useQuery(sessionQuery);
  const needsTree = !!session && session.state === 'active' && (session.scoped_permissions?.length ?? 0) > 0;
  // The group tree is only needed to apply scoped bindings to child groups.
  const { data: groups } = useQuery({ ...groupsQuery, enabled: needsTree, retry: false });

  return useMemo<Permissions>(() => {
    const scope = (groupIds: readonly string[]) => ({ groupIds, ...(groups ? { groups } : {}) });
    return {
      session,
      can: (perm, groupIds) => can(session, perm, groupIds ? scope(groupIds) : undefined),
      canAnywhere: (perm) => canAnywhere(session, perm),
      canOnHost: (perm, host) => can(session, perm, scope(host?.groups.map((g) => g.id) ?? [])),
    };
  }, [session, groups]);
}

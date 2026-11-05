// Best-effort preview of the shell identity the server will use for a host.
// Host groups may override the fleet defaults (unset = inherit from the
// parent group, then from Settings.shell). The server is authoritative; the
// UI only uses this to decide whether to ask for a unix account.

import type { GroupShellSettings, HostGroup, ShellIdentityMode, ShellSettings } from '@/api/types';

export interface EffectiveShell {
  mode: ShellIdentityMode | null;
  sharedAccount: string | null;
  allowRoot: boolean | null;
  /** Several direct groups resolve to different settings. */
  ambiguous: boolean;
}

type Field = keyof GroupShellSettings;

function resolveField<F extends Field>(
  groupId: string,
  byId: ReadonlyMap<string, Pick<HostGroup, 'id' | 'parent_id' | 'shell'>>,
  field: F,
): GroupShellSettings[F] | undefined {
  let cur: string | null | undefined = groupId;
  const seen = new Set<string>();
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    const g = byId.get(cur);
    if (!g) return undefined;
    const v = g.shell?.[field];
    if (v !== undefined && v !== null && v !== '') return v;
    cur = g.parent_id;
  }
  return undefined;
}

export function effectiveShell(
  hostGroupIds: readonly string[],
  groups: readonly Pick<HostGroup, 'id' | 'parent_id' | 'shell'>[] | undefined,
  defaults: ShellSettings | undefined,
): EffectiveShell {
  const byId = new Map((groups ?? []).map((g) => [g.id, g]));
  const pick = <F extends Field>(field: F, fallback: GroupShellSettings[F] | undefined) => {
    const values = new Set<string>();
    let resolvedAll = true;
    let result: GroupShellSettings[F] | undefined;
    for (const id of hostGroupIds) {
      const v = groups ? resolveField(id, byId, field) : undefined;
      if (v === undefined) {
        resolvedAll = false;
        continue;
      }
      values.add(String(v));
      result = v;
    }
    // Groups without an override fall back to the default.
    if (!resolvedAll || hostGroupIds.length === 0) {
      if (fallback !== undefined) values.add(String(fallback));
      result ??= fallback;
    }
    if (values.size > 1) return { value: undefined, ambiguous: true };
    // Without the group tree, an inherited default cannot be trusted either.
    if (!groups && hostGroupIds.length > 0) return { value: undefined, ambiguous: false };
    return { value: result, ambiguous: false };
  };

  const mode = pick('identity', defaults?.default_identity);
  const shared = pick('shared_account', defaults?.shared_account);
  const root = pick('allow_root', defaults?.allow_root);
  return {
    mode: mode.value ?? null,
    sharedAccount: shared.value ?? null,
    allowRoot: root.value ?? null,
    ambiguous: mode.ambiguous || shared.ambiguous || root.ambiguous,
  };
}

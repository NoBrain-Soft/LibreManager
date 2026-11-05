import { describe, expect, it } from 'vitest';
import type { ShellSettings } from '@/api/types';
import { effectiveShell } from './identity';

const defaults: ShellSettings = {
  default_identity: 'shared',
  shared_account: 'ops',
  allow_root: false,
  max_duration_minutes: 240,
  idle_timeout_minutes: 15,
};

const groups = [
  { id: 'root', parent_id: null, shell: {} },
  { id: 'prod', parent_id: 'root', shell: { identity: 'per_user' as const } },
  { id: 'prod-db', parent_id: 'prod', shell: { allow_root: true } },
  { id: 'lab', parent_id: 'root', shell: { identity: 'choose' as const, shared_account: 'lab' } },
];

describe('effectiveShell', () => {
  it('uses fleet defaults for hosts without groups', () => {
    expect(effectiveShell([], groups, defaults)).toEqual({ mode: 'shared', sharedAccount: 'ops', allowRoot: false, ambiguous: false });
  });

  it('inherits overrides from parent groups', () => {
    expect(effectiveShell(['prod-db'], groups, defaults)).toEqual({
      mode: 'per_user',
      sharedAccount: 'ops',
      allowRoot: true,
      ambiguous: false,
    });
  });

  it('falls back to defaults for unset fields', () => {
    expect(effectiveShell(['root'], groups, defaults)).toMatchObject({ mode: 'shared', allowRoot: false });
  });

  it('flags conflicting groups as ambiguous', () => {
    const r = effectiveShell(['prod', 'lab'], groups, defaults);
    expect(r.ambiguous).toBe(true);
    expect(r.mode).toBeNull();
  });

  it('is unknown when neither groups nor settings are readable', () => {
    expect(effectiveShell(['prod'], undefined, undefined)).toEqual({ mode: null, sharedAccount: null, allowRoot: null, ambiguous: false });
    expect(effectiveShell(['prod'], undefined, defaults).mode).toBeNull();
  });

  it('uses group values even without settings access', () => {
    expect(effectiveShell(['lab'], groups, undefined)).toMatchObject({ mode: 'choose', sharedAccount: 'lab' });
  });
});

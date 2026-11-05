import { describe, expect, it } from 'vitest';
import { can, canAnywhere, grants, hasGlobal, withAncestors, type PermissionSource } from './permissions';

const G = {
  root: '00000000-0000-0000-0000-000000000001',
  prod: '00000000-0000-0000-0000-000000000002',
  prodWeb: '00000000-0000-0000-0000-000000000003',
  dev: '00000000-0000-0000-0000-000000000004',
};

const groups = [
  { id: G.root, parent_id: null },
  { id: G.prod, parent_id: G.root },
  { id: G.prodWeb, parent_id: G.prod },
  { id: G.dev, parent_id: G.root },
];

describe('grants', () => {
  it.each([
    ['*', 'shell.open', true],
    ['shell.open', 'shell.open', true],
    ['shell.*', 'shell.root', true],
    ['admin.*', 'admin.users', true],
    ['admin.*', 'audit.view', false],
    ['shell.open', 'shell.root', false],
    ['shell', 'shell.open', false],
    ['', 'host.view', false],
  ])('%s grants %s: %s', (granted, wanted, expected) => {
    expect(grants(granted, wanted)).toBe(expected);
  });
});

describe('global permissions', () => {
  it('allows listed permissions and the wildcard', () => {
    const viewer: PermissionSource = { permissions: ['host.view', 'job.view'] };
    expect(hasGlobal(viewer, 'host.view')).toBe(true);
    expect(hasGlobal(viewer, 'shell.open')).toBe(false);
    expect(hasGlobal({ permissions: ['*'] }, 'admin.settings')).toBe(true);
  });

  it('denies without a session', () => {
    expect(can(null, 'host.view')).toBe(false);
    expect(canAnywhere(undefined, 'host.view')).toBe(false);
  });
});

describe('scoped permissions', () => {
  const operator: PermissionSource = {
    permissions: ['host.view'],
    scoped_permissions: [
      { permission: 'shell.open', host_group_id: G.prod },
      { permission: 'pkg.*', host_group_id: G.dev },
    ],
  };

  it('applies to hosts directly in the group', () => {
    expect(can(operator, 'shell.open', { groupIds: [G.prod], groups })).toBe(true);
  });

  it('applies to the group subtree (child groups)', () => {
    expect(can(operator, 'shell.open', { groupIds: [G.prodWeb], groups })).toBe(true);
  });

  it('does not apply to sibling or parent groups', () => {
    expect(can(operator, 'shell.open', { groupIds: [G.dev], groups })).toBe(false);
    expect(can(operator, 'shell.open', { groupIds: [G.root], groups })).toBe(false);
  });

  it('without the group tree only direct membership matches', () => {
    expect(can(operator, 'shell.open', { groupIds: [G.prodWeb] })).toBe(false);
    expect(can(operator, 'shell.open', { groupIds: [G.prod] })).toBe(true);
  });

  it('supports wildcard scoped permissions', () => {
    expect(can(operator, 'pkg.upgrade', { groupIds: [G.dev], groups })).toBe(true);
    expect(can(operator, 'pkg.upgrade', { groupIds: [G.prod], groups })).toBe(false);
  });

  it('is denied for hosts without groups', () => {
    expect(can(operator, 'shell.open', { groupIds: [], groups })).toBe(false);
    expect(can(operator, 'shell.open')).toBe(false);
  });

  it('host in several groups: any match grants', () => {
    expect(can(operator, 'shell.open', { groupIds: [G.dev, G.prodWeb], groups })).toBe(true);
  });

  it('canAnywhere sees scoped grants', () => {
    expect(canAnywhere(operator, 'shell.open')).toBe(true);
    expect(canAnywhere(operator, 'pkg.install')).toBe(true);
    expect(canAnywhere(operator, 'admin.users')).toBe(false);
  });
});

describe('withAncestors', () => {
  it('walks up and survives cycles', () => {
    expect(withAncestors([G.prodWeb], groups)).toEqual(new Set([G.prodWeb, G.prod, G.root]));
    const cyclic = [
      { id: 'a', parent_id: 'b' },
      { id: 'b', parent_id: 'a' },
    ];
    expect(withAncestors(['a'], cyclic)).toEqual(new Set(['a', 'b']));
  });
});

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { CornerDownRightIcon, FolderTreeIcon, PencilIcon, PlusIcon, Trash2Icon } from 'lucide-react';
import { useId, useMemo, useState } from 'react';
import { api } from '@/api/client';
import { qk } from '@/api/keys';
import { groupsQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { GroupShellSettings, HostGroup, HostGroupInput, ShellIdentityMode } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { Callout, EmptyState, ErrorState, ForbiddenState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input, NativeSelect, Textarea } from '@/components/ui/input';
import { Field } from '@/components/ui/label';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { notifyError, notifySuccess } from '@/lib/notify';
import { UNIX_USER_RE } from '../shell/protocol';

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;

interface TreeRow {
  group: HostGroup;
  depth: number;
}

/** Depth-first order by name; orphans (missing parent) are treated as roots. */
function buildTree(groups: readonly HostGroup[]): TreeRow[] {
  const ids = new Set(groups.map((g) => g.id));
  const children = new Map<string | null, HostGroup[]>();
  for (const g of groups) {
    const parent = g.parent_id && ids.has(g.parent_id) ? g.parent_id : null;
    children.set(parent, [...(children.get(parent) ?? []), g]);
  }
  const out: TreeRow[] = [];
  const seen = new Set<string>();
  const walk = (parent: string | null, depth: number) => {
    for (const g of [...(children.get(parent) ?? [])].sort((a, b) => a.name.localeCompare(b.name))) {
      if (seen.has(g.id)) continue;
      seen.add(g.id);
      out.push({ group: g, depth });
      walk(g.id, depth + 1);
    }
  };
  walk(null, 0);
  // Anything left is part of a cycle; show it flat rather than hide it.
  for (const g of groups) if (!seen.has(g.id)) out.push({ group: g, depth: 0 });
  return out;
}

function descendants(groups: readonly HostGroup[], id: string): Set<string> {
  const out = new Set<string>([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const g of groups) {
      if (g.parent_id && out.has(g.parent_id) && !out.has(g.id)) {
        out.add(g.id);
        grew = true;
      }
    }
  }
  return out;
}

function ShellOverrides({ shell }: { shell: GroupShellSettings | undefined }) {
  const parts: string[] = [];
  if (shell?.identity) parts.push(`identity: ${shell.identity.replace('_', '-')}`);
  if (shell?.shared_account) parts.push(`account: ${shell.shared_account}`);
  if (shell?.allow_root !== undefined && shell.allow_root !== null) parts.push(shell.allow_root ? 'root allowed' : 'root denied');
  if (parts.length === 0) return <span className="text-xs text-muted-foreground">inherits</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {parts.map((p) => (
        <Badge key={p} variant="outline" className="font-mono">
          {p}
        </Badge>
      ))}
    </div>
  );
}

type Dlg = { kind: 'edit'; group: HostGroup | null; parentId: string | null } | { kind: 'delete'; group: HostGroup } | null;

export function GroupsPage() {
  const perms = usePermissions();
  const q = useQuery(groupsQuery);
  const qc = useQueryClient();
  const [dlg, setDlg] = useState<Dlg>(null);
  const rows = useMemo(() => buildTree(q.data ?? []), [q.data]);

  if (!perms.canAnywhere('admin.groups')) {
    return (
      <Page>
        <PageHeader title="Host groups" />
        <Card>
          <ForbiddenState />
        </Card>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader
        title="Host groups"
        description="Groups scope role bindings (a binding covers the group and its subtree) and can override shell settings."
        actions={
          <Button onClick={() => setDlg({ kind: 'edit', group: null, parentId: null })}>
            <PlusIcon /> New group
          </Button>
        }
      />
      <Card>
        {q.isPending ? (
          <TableSkeleton rows={5} cols={4} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={FolderTreeIcon}
            title="No host groups yet"
            description="Create groups such as “production” or “web” and assign hosts to them."
          />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Name</TH>
                <TH>Description</TH>
                <TH className="text-right">Hosts</TH>
                <TH>Shell overrides</TH>
                <TH className="w-28">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {rows.map(({ group: g, depth }) => (
                <TR key={g.id}>
                  <TD>
                    <span className="flex items-center gap-1.5" style={{ paddingLeft: `${depth * 1.25}rem` }}>
                      {depth > 0 && <CornerDownRightIcon className="size-3.5 text-muted-foreground" aria-hidden />}
                      <Link to="/hosts" search={{ group: g.id }} className="font-medium hover:text-primary hover:underline">
                        {g.name}
                      </Link>
                    </span>
                  </TD>
                  <TD className="max-w-96 truncate text-muted-foreground">{g.description || '–'}</TD>
                  <TD className="text-right">{g.host_count}</TD>
                  <TD>
                    <ShellOverrides shell={g.shell} />
                  </TD>
                  <TD>
                    <div className="flex justify-end gap-0.5">
                      <Button variant="ghost" size="icon-sm" aria-label={`Add child group to ${g.name}`} title="Add child group" onClick={() => setDlg({ kind: 'edit', group: null, parentId: g.id })}>
                        <PlusIcon />
                      </Button>
                      <Button variant="ghost" size="icon-sm" aria-label={`Edit ${g.name}`} title="Edit" onClick={() => setDlg({ kind: 'edit', group: g, parentId: g.parent_id ?? null })}>
                        <PencilIcon />
                      </Button>
                      <Button variant="ghost" size="icon-sm" aria-label={`Delete ${g.name}`} title="Delete" onClick={() => setDlg({ kind: 'delete', group: g })}>
                        <Trash2Icon />
                      </Button>
                    </div>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      {dlg?.kind === 'edit' && (
        <GroupDialog group={dlg.group} parentId={dlg.parentId} groups={q.data ?? []} onClose={() => setDlg(null)} />
      )}
      <ConfirmDialog
        open={dlg?.kind === 'delete'}
        onOpenChange={(o) => !o && setDlg(null)}
        title={dlg?.kind === 'delete' ? `Delete group ${dlg.group.name}?` : ''}
        description="Hosts stay enrolled but lose this membership; role bindings scoped to the group stop applying."
        confirmLabel="Delete group"
        destructive
        onConfirm={async () => {
          if (dlg?.kind !== 'delete') return;
          await request(() => api.DELETE('/host-groups/{groupId}', { params: { path: { groupId: dlg.group.id } } }));
          void qc.invalidateQueries({ queryKey: qk.groups });
          void qc.invalidateQueries({ queryKey: qk.hostsRoot });
          notifySuccess('Group deleted');
        }}
      >
        {dlg?.kind === 'delete' && dlg.group.host_count > 0 && (
          <Callout tone="warning">This group contains {dlg.group.host_count} host(s).</Callout>
        )}
      </ConfirmDialog>
    </Page>
  );
}

type Tri = 'inherit' | 'yes' | 'no';

function GroupDialog({
  group,
  parentId,
  groups,
  onClose,
}: {
  group: HostGroup | null;
  parentId: string | null;
  groups: readonly HostGroup[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(group?.name ?? '');
  const [parent, setParent] = useState<string>(parentId ?? '');
  const [description, setDescription] = useState(group?.description ?? '');
  const [identity, setIdentity] = useState<ShellIdentityMode | ''>(group?.shell.identity ?? '');
  const [account, setAccount] = useState(group?.shell.shared_account ?? '');
  const [root, setRoot] = useState<Tri>(group?.shell.allow_root === undefined || group.shell.allow_root === null ? 'inherit' : group.shell.allow_root ? 'yes' : 'no');
  const [error, setError] = useState<string | null>(null);
  const ids = { n: useId(), p: useId(), d: useId(), i: useId(), a: useId(), r: useId() };
  const excluded = useMemo(() => (group ? descendants(groups, group.id) : new Set<string>()), [group, groups]);

  const save = useMutation({
    mutationFn: (body: HostGroupInput) =>
      group
        ? request(() => api.PATCH('/host-groups/{groupId}', { params: { path: { groupId: group.id } }, body }))
        : request(() => api.POST('/host-groups', { body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.groups });
      void qc.invalidateQueries({ queryKey: qk.hostsRoot });
      notifySuccess(group ? 'Group updated' : 'Group created');
      onClose();
    },
    onError: (e) => notifyError(e, 'Could not save group'),
  });

  const submit = () => {
    if (!NAME_RE.test(name)) return setError('Name: letters, digits, space, ".", "_" and "-" (max 64).');
    if (account && !UNIX_USER_RE.test(account)) return setError('Shared account must be a valid unix user name.');
    if (description.length > 512) return setError('Description is limited to 512 characters.');
    setError(null);
    const shell: GroupShellSettings = {
      ...(identity ? { identity } : {}),
      ...(account ? { shared_account: account } : {}),
      ...(root !== 'inherit' ? { allow_root: root === 'yes' } : {}),
    };
    save.mutate({ name, parent_id: parent || null, description, shell });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="lg">
        <form
          className="contents"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <DialogHeader>
            <DialogTitle>{group ? `Edit ${group.name}` : 'New host group'}</DialogTitle>
            <DialogDescription>Unset shell options inherit from the parent group, then from the fleet defaults in Settings.</DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Name" htmlFor={ids.n}>
                <Input id={ids.n} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required autoFocus />
              </Field>
              <Field label="Parent group" htmlFor={ids.p}>
                <NativeSelect id={ids.p} value={parent} onChange={(e) => setParent(e.target.value)}>
                  <option value="">None (top level)</option>
                  {groups
                    .filter((g) => !excluded.has(g.id))
                    .map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                </NativeSelect>
              </Field>
            </div>
            <Field label="Description" htmlFor={ids.d}>
              <Textarea id={ids.d} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={512} rows={2} />
            </Field>
            <fieldset className="grid gap-3 rounded-md border p-3">
              <legend className="px-1 text-xs font-medium text-muted-foreground">Shell overrides</legend>
              <div className="grid gap-3 sm:grid-cols-3">
                <Field label="Identity" htmlFor={ids.i}>
                  <NativeSelect id={ids.i} value={identity} onChange={(e) => setIdentity(e.target.value as ShellIdentityMode | '')}>
                    <option value="">Inherit</option>
                    <option value="shared">Shared account</option>
                    <option value="per_user">Per user</option>
                    <option value="choose">User chooses</option>
                  </NativeSelect>
                </Field>
                <Field label="Shared account" htmlFor={ids.a} hint="Used when identity is shared">
                  <Input
                    id={ids.a}
                    value={account}
                    onChange={(e) => setAccount(e.target.value.toLowerCase())}
                    placeholder="inherit"
                    maxLength={32}
                    className="font-mono"
                    spellCheck={false}
                  />
                </Field>
                <Field label="Root shells" htmlFor={ids.r} hint="Host policy must also allow it">
                  <NativeSelect id={ids.r} value={root} onChange={(e) => setRoot(e.target.value as Tri)}>
                    <option value="inherit">Inherit</option>
                    <option value="no">Deny</option>
                    <option value="yes">Allow</option>
                  </NativeSelect>
                </Field>
              </div>
              {root === 'yes' && (
                <Callout tone="warning" title="Root shells">
                  Users with shell.root on this group can request root sessions. Prefer personal accounts with sudo.
                </Callout>
              )}
            </fieldset>
            {error && <Callout tone="critical">{error}</Callout>}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={onClose} disabled={save.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? 'Saving…' : group ? 'Save' : 'Create group'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

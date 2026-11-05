import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  BanIcon,
  CircleCheckIcon,
  EllipsisIcon,
  KeyRoundIcon,
  PencilIcon,
  PlusIcon,
  ShieldIcon,
  ShieldOffIcon,
  Trash2Icon,
  UsersIcon,
} from 'lucide-react';
import { useId, useMemo, useState } from 'react';
import { api } from '@/api/client';
import { qk } from '@/api/keys';
import { groupsQuery, roleBindingsQuery, rolesQuery, usersQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { RoleBindingInput, User, UserUpdate } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { SearchInput } from '@/components/common/SearchInput';
import { Callout, EmptyState, ErrorState, ForbiddenState, LoadingState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Field, Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/misc';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { notifyError, notifySuccess } from '@/lib/notify';
import { RoleBindingsEditor } from './RoleBindingsEditor';
import { SecretOnceDialog } from './SecretOnceDialog';

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

type Dlg =
  | { kind: 'create' }
  | { kind: 'edit'; user: User }
  | { kind: 'roles'; user: User }
  | { kind: 'reset-password'; user: User }
  | { kind: 'reset-mfa'; user: User }
  | { kind: 'delete'; user: User }
  | { kind: 'otp'; user: User; password: string; created: boolean }
  | null;

export function UsersPage() {
  const perms = usePermissions();
  const q = useQuery(usersQuery);
  const qc = useQueryClient();
  const [filter, setFilter] = useState('');
  const [dlg, setDlg] = useState<Dlg>(null);
  const me = perms.session?.user.id;

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return [...(q.data ?? [])]
      .filter((u) => !needle || [u.username, u.display_name, u.email].some((s) => s.toLowerCase().includes(needle)))
      .sort((a, b) => a.username.localeCompare(b.username));
  }, [q.data, filter]);

  const invalidate = () => void qc.invalidateQueries({ queryKey: qk.users });
  const toggleDisabled = useMutation({
    mutationFn: (u: User) =>
      request(() => api.PATCH('/users/{userId}', { params: { path: { userId: u.id } }, body: { disabled: !u.disabled } })),
    onSuccess: (u) => {
      invalidate();
      notifySuccess(u.disabled ? `${u.username} disabled` : `${u.username} enabled`);
    },
    onError: (e) => notifyError(e, 'Could not update user'),
  });

  if (!perms.canAnywhere('admin.users')) {
    return (
      <Page>
        <PageHeader title="Users" />
        <Card>
          <ForbiddenState />
        </Card>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader
        title="Users"
        description="Local accounts. Every user must use a second factor unless MFA is explicitly not required."
        actions={
          <Button onClick={() => setDlg({ kind: 'create' })}>
            <PlusIcon /> New user
          </Button>
        }
      />
      <div className="mb-3">
        <SearchInput value={filter} onChange={setFilter} placeholder="Filter users…" />
      </div>
      <Card>
        {q.isPending ? (
          <TableSkeleton rows={5} cols={6} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState icon={UsersIcon} title="No users found" />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>User</TH>
                <TH>Email</TH>
                <TH>MFA</TH>
                <TH>Status</TH>
                <TH>Last login</TH>
                <TH>Created</TH>
                <TH className="w-12">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((u) => (
                <TR key={u.id}>
                  <TD>
                    <div className="font-medium">
                      {u.display_name || u.username}
                      {u.id === me && <span className="ml-1.5 text-xs font-normal text-muted-foreground">(you)</span>}
                    </div>
                    <div className="font-mono text-xs text-muted-foreground">{u.username}</div>
                  </TD>
                  <TD className="text-muted-foreground">{u.email || '–'}</TD>
                  <TD>
                    {u.mfa_enrolled ? (
                      <Badge variant="good">
                        <ShieldIcon aria-hidden /> enrolled
                      </Badge>
                    ) : u.mfa_required ? (
                      <Badge variant="warning">
                        <ShieldOffIcon aria-hidden /> pending
                      </Badge>
                    ) : (
                      <Badge variant="neutral">not required</Badge>
                    )}
                  </TD>
                  <TD>
                    {u.disabled ? (
                      <Badge variant="neutral">
                        <BanIcon aria-hidden /> disabled
                      </Badge>
                    ) : (
                      <Badge variant="good">
                        <CircleCheckIcon aria-hidden /> active
                      </Badge>
                    )}
                  </TD>
                  <TD>
                    <RelativeTime value={u.last_login_at} fallback="never" />
                  </TD>
                  <TD>
                    <RelativeTime value={u.created_at} />
                  </TD>
                  <TD>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${u.username}`}>
                          <EllipsisIcon />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onSelect={() => setDlg({ kind: 'edit', user: u })}>
                          <PencilIcon /> Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => setDlg({ kind: 'roles', user: u })}>
                          <ShieldIcon /> Roles
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onSelect={() => setDlg({ kind: 'reset-password', user: u })}>
                          <KeyRoundIcon /> Reset password
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => setDlg({ kind: 'reset-mfa', user: u })}>
                          <ShieldOffIcon /> Reset MFA
                        </DropdownMenuItem>
                        <DropdownMenuItem disabled={u.id === me} onSelect={() => toggleDisabled.mutate(u)}>
                          <BanIcon /> {u.disabled ? 'Enable' : 'Disable'}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem destructive disabled={u.id === me} onSelect={() => setDlg({ kind: 'delete', user: u })}>
                          <Trash2Icon /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      {dlg?.kind === 'create' && (
        <CreateUserDialog
          onClose={() => setDlg(null)}
          onCreated={(user, password) => {
            invalidate();
            setDlg({ kind: 'otp', user, password, created: true });
          }}
        />
      )}
      {dlg?.kind === 'edit' && <EditUserDialog user={dlg.user} isSelf={dlg.user.id === me} onClose={() => setDlg(null)} />}
      {dlg?.kind === 'roles' && <RolesDialog user={dlg.user} onClose={() => setDlg(null)} />}
      {dlg?.kind === 'otp' && (
        <SecretOnceDialog
          open
          onClose={() => setDlg(null)}
          title={dlg.created ? `User ${dlg.user.username} created` : `Password reset for ${dlg.user.username}`}
          description="The user must change this one-time password at first sign-in and then enroll a second factor."
          secrets={[{ label: 'One-time password', value: dlg.password }]}
        />
      )}
      <ConfirmDialog
        open={dlg?.kind === 'reset-password'}
        onOpenChange={(o) => !o && setDlg(null)}
        title={dlg?.kind === 'reset-password' ? `Reset password of ${dlg.user.username}?` : ''}
        description="A new one-time password is generated; existing sessions of the user are ended."
        confirmLabel="Reset password"
        onConfirm={async () => {
          if (dlg?.kind !== 'reset-password') return;
          const user = dlg.user;
          const res = await request(() => api.POST('/users/{userId}/reset-password', { params: { path: { userId: user.id } } }));
          invalidate();
          // Open the one-time password dialog after the confirm dialog closes.
          setTimeout(() => setDlg({ kind: 'otp', user, password: res.one_time_password, created: false }), 0);
        }}
      />
      <ConfirmDialog
        open={dlg?.kind === 'reset-mfa'}
        onOpenChange={(o) => !o && setDlg(null)}
        title={dlg?.kind === 'reset-mfa' ? `Reset MFA of ${dlg.user.username}?` : ''}
        description="All security keys and the authenticator app are removed. The user must enroll a new factor at next sign-in."
        confirmLabel="Reset MFA"
        destructive
        onConfirm={async () => {
          if (dlg?.kind !== 'reset-mfa') return;
          await request(() => api.POST('/users/{userId}/reset-mfa', { params: { path: { userId: dlg.user.id } } }));
          invalidate();
          notifySuccess('MFA reset');
        }}
      />
      <ConfirmDialog
        open={dlg?.kind === 'delete'}
        onOpenChange={(o) => !o && setDlg(null)}
        title={dlg?.kind === 'delete' ? `Delete ${dlg.user.username}?` : ''}
        description="The account and its role bindings are removed. Audit entries are kept. Consider disabling instead."
        confirmLabel="Delete user"
        destructive
        typeToConfirm={dlg?.kind === 'delete' ? dlg.user.username : undefined}
        onConfirm={async () => {
          if (dlg?.kind !== 'delete') return;
          await request(() => api.DELETE('/users/{userId}', { params: { path: { userId: dlg.user.id } } }));
          invalidate();
          notifySuccess('User deleted');
        }}
      />
    </Page>
  );
}

function CreateUserDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (u: User, password: string) => void }) {
  const roles = useQuery(rolesQuery);
  const groups = useQuery({ ...groupsQuery, retry: false });
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [mfaRequired, setMfaRequired] = useState(true);
  const [bindings, setBindings] = useState<RoleBindingInput[]>([]);
  const [error, setError] = useState<string | null>(null);
  const ids = { u: useId(), d: useId(), e: useId(), m: useId() };
  const create = useMutation({
    mutationFn: () =>
      request(() =>
        api.POST('/users', {
          body: {
            username,
            mfa_required: mfaRequired,
            ...(displayName.trim() ? { display_name: displayName.trim() } : {}),
            ...(email.trim() ? { email: email.trim() } : {}),
            ...(bindings.length ? { role_bindings: bindings } : {}),
          },
        }),
      ),
    onSuccess: (res) => onCreated(res.user, res.one_time_password),
    onError: (e) => notifyError(e, 'Could not create user'),
  });
  const usernameError = username && !USERNAME_RE.test(username) ? 'Lowercase letters, digits, ".", "_" and "-"; must start with a letter or digit.' : null;

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="lg">
        <form
          className="contents"
          onSubmit={(e) => {
            e.preventDefault();
            if (!username || usernameError) {
              setError('Enter a valid username.');
              return;
            }
            setError(null);
            create.mutate();
          }}
        >
          <DialogHeader>
            <DialogTitle>New user</DialogTitle>
            <DialogDescription>A one-time password is generated and shown once after creation.</DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Username" htmlFor={ids.u} error={usernameError}>
                <Input
                  id={ids.u}
                  value={username}
                  onChange={(e) => setUsername(e.target.value.toLowerCase())}
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={64}
                  required
                  autoFocus
                  className="font-mono"
                />
              </Field>
              <Field label="Display name" htmlFor={ids.d}>
                <Input id={ids.d} value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={128} />
              </Field>
              <Field label="Email" htmlFor={ids.e} hint="Used for notifications only.">
                <Input id={ids.e} type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={255} />
              </Field>
              <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
                <Label htmlFor={ids.m}>Require MFA</Label>
                <Switch id={ids.m} checked={mfaRequired} onCheckedChange={setMfaRequired} />
              </div>
            </div>
            {!mfaRequired && (
              <Callout tone="warning" title="MFA disabled for this user">
                Only do this for test accounts. Global MFA policy in Settings may still require it.
              </Callout>
            )}
            <div className="grid gap-1.5">
              <Label>Roles</Label>
              {roles.isPending ? (
                <LoadingState className="py-3" />
              ) : roles.isError ? (
                <ErrorState error={roles.error} compact />
              ) : (
                <RoleBindingsEditor value={bindings} onChange={setBindings} roles={roles.data} groups={groups.data ?? []} />
              )}
            </div>
            {error && <Callout tone="critical">{error}</Callout>}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={onClose} disabled={create.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? 'Creating…' : 'Create user'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditUserDialog({ user, isSelf, onClose }: { user: User; isSelf: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [displayName, setDisplayName] = useState(user.display_name);
  const [email, setEmail] = useState(user.email);
  const [mfaRequired, setMfaRequired] = useState(user.mfa_required);
  const [disabled, setDisabled] = useState(user.disabled);
  const ids = { d: useId(), e: useId(), m: useId(), x: useId() };
  const save = useMutation({
    mutationFn: (body: UserUpdate) => request(() => api.PATCH('/users/{userId}', { params: { path: { userId: user.id } }, body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.users });
      notifySuccess('User updated');
      onClose();
    },
    onError: (e) => notifyError(e, 'Could not update user'),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="md">
        <form
          className="contents"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate({ display_name: displayName.trim(), email: email.trim(), mfa_required: mfaRequired, disabled });
          }}
        >
          <DialogHeader>
            <DialogTitle>Edit {user.username}</DialogTitle>
          </DialogHeader>
          <DialogBody className="grid gap-3">
            <Field label="Display name" htmlFor={ids.d}>
              <Input id={ids.d} value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={128} />
            </Field>
            <Field label="Email" htmlFor={ids.e}>
              <Input id={ids.e} type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={255} />
            </Field>
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <Label htmlFor={ids.m}>Require MFA</Label>
              <Switch id={ids.m} checked={mfaRequired} onCheckedChange={setMfaRequired} />
            </div>
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <div>
                <Label htmlFor={ids.x}>Account disabled</Label>
                {isSelf && <p className="text-xs text-muted-foreground">You cannot disable your own account.</p>}
              </div>
              <Switch id={ids.x} checked={disabled} onCheckedChange={setDisabled} disabled={isSelf} />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={onClose} disabled={save.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? 'Saving…' : 'Save'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RolesDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const qc = useQueryClient();
  const current = useQuery(roleBindingsQuery(user.id));
  const roles = useQuery(rolesQuery);
  const groups = useQuery({ ...groupsQuery, retry: false });
  const [draft, setDraft] = useState<RoleBindingInput[] | null>(null);
  const value =
    draft ?? (current.data ?? []).map((b) => ({ role_id: b.role_id, host_group_id: b.host_group_id ?? null }));
  const save = useMutation({
    mutationFn: (body: RoleBindingInput[]) =>
      request(() => api.PUT('/users/{userId}/role-bindings', { params: { path: { userId: user.id } }, body })),
    onSuccess: (res) => {
      qc.setQueryData(qk.roleBindings(user.id), res);
      void qc.invalidateQueries({ queryKey: qk.session });
      notifySuccess('Roles updated');
      onClose();
    },
    onError: (e) => notifyError(e, 'Could not save roles'),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Roles of {user.username}</DialogTitle>
          <DialogDescription>
            A role on a host group applies to that group and all its child groups. Global roles apply to every host.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {current.isPending || roles.isPending ? (
            <LoadingState />
          ) : current.isError || roles.isError ? (
            <ErrorState error={current.error ?? roles.error} compact />
          ) : (
            <RoleBindingsEditor value={value} onChange={setDraft} roles={roles.data} groups={groups.data ?? []} disabled={save.isPending} />
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={save.isPending}>
            Cancel
          </Button>
          <Button onClick={() => save.mutate(value)} disabled={save.isPending || draft === null}>
            {save.isPending ? 'Saving…' : 'Save roles'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

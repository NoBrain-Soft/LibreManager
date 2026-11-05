import { useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRoundIcon, PlusIcon, SmartphoneIcon, Trash2Icon } from 'lucide-react';
import { useId, useState } from 'react';
import { api } from '@/api/client';
import { errorMessage } from '@/api/errors';
import { qk } from '@/api/keys';
import { webauthnCredentialsQuery } from '@/api/queries';
import { request } from '@/api/request';
import { refreshSession, sessionQuery } from '@/api/session';
import type { WebauthnCredential } from '@/api/types';
import { SecurityKeyRegister, TotpEnroll } from '@/auth/MfaEnroll';
import { Badge } from '@/components/ui/badge';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { Callout, EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Field } from '@/components/ui/label';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { notifySuccess } from '@/lib/notify';

const MIN_PASSWORD = 12;

export function AccountPage() {
  const { data: session } = useQuery(sessionQuery);
  if (!session) return null;
  const u = session.user;
  return (
    <Page className="mx-0 max-w-4xl">
      <PageHeader title="Account & security" description="Your profile, password and second factors." />
      <div className="grid gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[9rem_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="text-muted-foreground">Username</dt>
              <dd className="font-mono">{u.username}</dd>
              <dt className="text-muted-foreground">Display name</dt>
              <dd>{u.display_name || '–'}</dd>
              <dt className="text-muted-foreground">Email</dt>
              <dd>{u.email || '–'}</dd>
              <dt className="text-muted-foreground">Session expires</dt>
              <dd>
                <RelativeTime value={session.expires_at} />
              </dd>
              <dt className="text-muted-foreground">Permissions</dt>
              <dd className="flex flex-wrap gap-1">
                {session.permissions.length === 0 && (session.scoped_permissions?.length ?? 0) === 0 && (
                  <span className="text-muted-foreground">none</span>
                )}
                {session.permissions.map((p) => (
                  <Badge key={p} variant="outline" className="font-mono">
                    {p}
                  </Badge>
                ))}
                {(session.scoped_permissions?.length ?? 0) > 0 && (
                  <Badge variant="secondary">+{session.scoped_permissions?.length} scoped to host groups</Badge>
                )}
              </dd>
            </dl>
          </CardContent>
        </Card>
        <PasswordCard />
        <SecurityKeysCard />
        <TotpCard enabled={session.mfa.totp} keyCount={session.mfa.webauthn} mfaRequired={u.mfa_required} />
      </div>
    </Page>
  );
}

function PasswordCard() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ids = { c: useId(), n: useId(), k: useId(), u: useId() };
  const { data: session } = useQuery(sessionQuery);

  const problem =
    next && next.length < MIN_PASSWORD
      ? `At least ${MIN_PASSWORD} characters.`
      : next && next === current
        ? 'Must differ from the current password.'
        : confirm && confirm !== next
          ? 'The passwords do not match.'
          : null;
  const ready = !!current && next.length >= MIN_PASSWORD && next === confirm && next !== current;

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      await request(() => api.POST('/auth/password', { body: { current_password: current, new_password: next } }));
      setCurrent('');
      setNext('');
      setConfirm('');
      await refreshSession();
      notifySuccess('Password changed');
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Password</CardTitle>
          <CardDescription>Use a long passphrase; it is stored with Argon2id.</CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        <form
          className="grid max-w-md gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <input type="text" id={ids.u} autoComplete="username" value={session?.user.username ?? ''} readOnly hidden />
          <Field label="Current password" htmlFor={ids.c}>
            <Input id={ids.c} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" maxLength={1024} />
          </Field>
          <Field label="New password" htmlFor={ids.n} hint={`At least ${MIN_PASSWORD} characters`}>
            <Input id={ids.n} type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" maxLength={1024} />
          </Field>
          <Field label="Repeat new password" htmlFor={ids.k} error={problem}>
            <Input
              id={ids.k}
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              maxLength={1024}
              aria-invalid={!!problem}
            />
          </Field>
          {error && <Callout tone="critical">{error}</Callout>}
          <Button type="submit" className="w-fit" disabled={!ready || busy}>
            {busy ? 'Saving…' : 'Change password'}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function SecurityKeysCard() {
  const q = useQuery(webauthnCredentialsQuery);
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<WebauthnCredential | null>(null);

  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: qk.webauthnCredentials });
    await refreshSession();
  };

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle className="flex items-center gap-2">
            <KeyRoundIcon className="size-4" /> Security keys
          </CardTitle>
          <CardDescription>FIDO2/WebAuthn keys are the recommended second factor and are required for step-up on most hosts.</CardDescription>
        </div>
        <Button size="sm" onClick={() => setAdding(true)}>
          <PlusIcon /> Add key
        </Button>
      </CardHeader>
      {q.isPending ? (
        <TableSkeleton rows={2} cols={3} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
      ) : q.data.length === 0 ? (
        <EmptyState icon={KeyRoundIcon} title="No security keys registered" className="py-6" />
      ) : (
        <Table>
          <THead>
            <TR className="hover:bg-transparent">
              <TH>Name</TH>
              <TH>Added</TH>
              <TH>Last used</TH>
              <TH className="w-12">
                <span className="sr-only">Actions</span>
              </TH>
            </TR>
          </THead>
          <TBody>
            {q.data.map((c) => (
              <TR key={c.id}>
                <TD className="font-medium">{c.name}</TD>
                <TD>
                  <RelativeTime value={c.created_at} />
                </TD>
                <TD>
                  <RelativeTime value={c.last_used_at} fallback="never" />
                </TD>
                <TD>
                  <Button variant="ghost" size="icon-sm" onClick={() => setRemoving(c)} aria-label={`Remove ${c.name}`}>
                    <Trash2Icon />
                  </Button>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      <Dialog open={adding} onOpenChange={setAdding}>
        {adding && (
          <DialogContent size="sm">
            <DialogHeader>
              <DialogTitle>Add a security key</DialogTitle>
              <DialogDescription>Insert or tap your key when the browser asks for it.</DialogDescription>
            </DialogHeader>
            <DialogBody>
              <SecurityKeyRegister
                onDone={async () => {
                  setAdding(false);
                  await refresh();
                  notifySuccess('Security key registered');
                }}
              />
            </DialogBody>
          </DialogContent>
        )}
      </Dialog>
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={`Remove “${removing?.name ?? ''}”?`}
        description="You can no longer sign in with this key. The server refuses to remove your last factor if MFA is required."
        confirmLabel="Remove key"
        destructive
        onConfirm={async () => {
          if (!removing) return;
          await request(() =>
            api.DELETE('/auth/webauthn/credentials/{credentialId}', { params: { path: { credentialId: removing.id } } }),
          );
          await refresh();
          notifySuccess('Security key removed');
        }}
      />
    </Card>
  );
}

function TotpCard({ enabled, keyCount, mfaRequired }: { enabled: boolean; keyCount: number; mfaRequired: boolean }) {
  const [enrolling, setEnrolling] = useState(false);
  const [disabling, setDisabling] = useState(false);
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle className="flex items-center gap-2">
            <SmartphoneIcon className="size-4" /> Authenticator app
          </CardTitle>
          <CardDescription>Time-based one-time codes (TOTP) as a fallback factor, if allowed by the administrator.</CardDescription>
        </div>
        {enabled ? (
          <Button size="sm" variant="outline" onClick={() => setDisabling(true)}>
            Disable
          </Button>
        ) : (
          <Button size="sm" onClick={() => setEnrolling(true)}>
            Set up
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {enabled ? <Badge variant="good">enabled</Badge> : <Badge variant="neutral">not set up</Badge>}
      </CardContent>
      <Dialog open={enrolling} onOpenChange={setEnrolling}>
        {enrolling && (
          <DialogContent size="md">
            <DialogHeader>
              <DialogTitle>Set up an authenticator app</DialogTitle>
            </DialogHeader>
            <DialogBody>
              <TotpEnroll
                onDone={async () => {
                  setEnrolling(false);
                  await refreshSession();
                  notifySuccess('Authenticator app enabled');
                }}
              />
            </DialogBody>
          </DialogContent>
        )}
      </Dialog>
      <ConfirmDialog
        open={disabling}
        onOpenChange={setDisabling}
        title="Disable the authenticator app?"
        description={
          keyCount === 0 && mfaRequired
            ? 'You have no security key. The server will refuse this unless another factor remains.'
            : 'Codes from your app will no longer be accepted.'
        }
        confirmLabel="Disable"
        destructive
        onConfirm={async () => {
          await request(() => api.DELETE('/auth/totp'));
          await refreshSession();
          notifySuccess('Authenticator app disabled');
        }}
      />
    </Card>
  );
}

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BanIcon, KeyRoundIcon, PlusIcon } from 'lucide-react';
import { useId, useMemo, useState } from 'react';
import { api } from '@/api/client';
import { qk } from '@/api/keys';
import { enrollmentTokensQuery, groupsQuery, systemInfoQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { EnrollmentToken, EnrollmentTokenCreate, EnrollmentTokenCreated } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { CopyButton } from '@/components/common/CopyButton';
import { KeyValueEditor } from '@/components/common/KeyValueEditor';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { Callout, EmptyState, ErrorState, ForbiddenState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input, NativeSelect } from '@/components/ui/input';
import { Field, Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/misc';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { parseDate } from '@/lib/format';
import { fromKVs, type KV } from '@/lib/kv';
import { useNow } from '@/lib/now';
import { notifyError, notifySuccess } from '@/lib/notify';
import { SecretOnceDialog } from './SecretOnceDialog';

type TokenState = 'active' | 'revoked' | 'expired' | 'used';

function tokenState(t: EnrollmentToken, now: number): TokenState {
  if (t.revoked_at) return 'revoked';
  if ((parseDate(t.expires_at)?.getTime() ?? 0) <= now) return 'expired';
  if (t.uses >= t.max_uses) return 'used';
  return 'active';
}

const STATE_BADGE: Record<TokenState, { label: string; variant: 'good' | 'neutral' | 'warning' }> = {
  active: { label: 'active', variant: 'good' },
  revoked: { label: 'revoked', variant: 'neutral' },
  expired: { label: 'expired', variant: 'neutral' },
  used: { label: 'used up', variant: 'neutral' },
};

export function EnrollmentPage() {
  const perms = usePermissions();
  const tokens = useQuery(enrollmentTokensQuery);
  const groups = useQuery({ ...groupsQuery, retry: false });
  const info = useQuery(systemInfoQuery);
  const qc = useQueryClient();
  const now = useNow();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null);
  const [revoke, setRevoke] = useState<EnrollmentToken | null>(null);
  const [showInactive, setShowInactive] = useState(false);
  const groupName = useMemo(() => new Map((groups.data ?? []).map((g) => [g.id, g.name])), [groups.data]);

  const rows = useMemo(
    () =>
      [...(tokens.data ?? [])]
        .filter((t) => showInactive || tokenState(t, now) === 'active')
        .sort((a, b) => (parseDate(b.created_at)?.getTime() ?? 0) - (parseDate(a.created_at)?.getTime() ?? 0)),
    [tokens.data, showInactive, now],
  );

  if (!perms.canAnywhere('enroll.manage')) {
    return (
      <Page>
        <PageHeader title="Enrollment" />
        <Card>
          <ForbiddenState />
        </Card>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader
        title="Enrollment"
        description="Tokens let new servers enroll their agent. Prefer single-use tokens with a short lifetime."
        actions={
          <Button onClick={() => setCreating(true)}>
            <PlusIcon /> New token
          </Button>
        }
      />

      {info.data && (
        <Card className="mb-4">
          <CardContent className="grid gap-x-6 gap-y-2 py-3 text-sm sm:grid-cols-[auto_1fr]">
            <span className="text-muted-foreground">Agent endpoint</span>
            <span className="flex items-center gap-1.5 font-mono text-xs">
              {info.data.agent_endpoint}
              <CopyButton text={info.data.agent_endpoint} size="icon-sm" variant="ghost" label="Copy agent endpoint" />
            </span>
            <span className="text-muted-foreground">Root CA fingerprint (SHA-256)</span>
            <span className="flex min-w-0 items-center gap-1.5 font-mono text-xs">
              <span className="break-all">{info.data.ca_fingerprint}</span>
              <CopyButton text={info.data.ca_fingerprint} size="icon-sm" variant="ghost" label="Copy CA fingerprint" />
            </span>
            <span className="text-muted-foreground">Server version</span>
            <span className="font-mono text-xs">{info.data.version}</span>
          </CardContent>
        </Card>
      )}

      <div className="mb-2 flex items-center justify-end">
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={showInactive} onCheckedChange={(v) => setShowInactive(v === true)} /> Show expired, used and revoked
        </label>
      </div>
      <Card>
        {tokens.isPending ? (
          <TableSkeleton rows={4} cols={6} />
        ) : tokens.isError ? (
          <ErrorState error={tokens.error} onRetry={() => void tokens.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={KeyRoundIcon}
            title={tokens.data.length ? 'No active tokens' : 'No enrollment tokens yet'}
            description="Create a token to get an install command for a new server."
          />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Description</TH>
                <TH>Group</TH>
                <TH>Labels</TH>
                <TH>Uses</TH>
                <TH>Expires</TH>
                <TH>State</TH>
                <TH>Created</TH>
                <TH className="w-12">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((t) => {
                const st = tokenState(t, now);
                const labels = Object.entries(t.labels);
                return (
                  <TR key={t.id}>
                    <TD className="max-w-64 truncate font-medium">{t.description || <span className="text-muted-foreground">–</span>}</TD>
                    <TD className="text-muted-foreground">{t.host_group_id ? (groupName.get(t.host_group_id) ?? 'unknown') : '–'}</TD>
                    <TD className="max-w-56">
                      <div className="flex flex-wrap gap-1">
                        {labels.slice(0, 3).map(([k, v]) => (
                          <Badge key={k} variant="outline" className="font-mono">
                            {k}={v}
                          </Badge>
                        ))}
                        {labels.length > 3 && <Badge variant="outline">+{labels.length - 3}</Badge>}
                      </div>
                    </TD>
                    <TD className="tabular">
                      {t.uses} / {t.max_uses}
                    </TD>
                    <TD>
                      <RelativeTime value={t.expires_at} />
                    </TD>
                    <TD>
                      <Badge variant={STATE_BADGE[st].variant}>{STATE_BADGE[st].label}</Badge>
                    </TD>
                    <TD className="text-xs text-muted-foreground">
                      <RelativeTime value={t.created_at} />
                      {t.created_by && <div>by {t.created_by}</div>}
                    </TD>
                    <TD>
                      {st === 'active' && (
                        <Button variant="ghost" size="icon-sm" onClick={() => setRevoke(t)} aria-label="Revoke token" title="Revoke">
                          <BanIcon />
                        </Button>
                      )}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>

      {creating && (
        <CreateTokenDialog
          onClose={() => setCreating(false)}
          onCreated={(res) => {
            setCreating(false);
            setCreated(res);
          }}
        />
      )}
      {created && (
        <SecretOnceDialog
          open
          onClose={() => setCreated(null)}
          title="Enrollment token created"
          description="Run the install command as root on the new server. The token is read from stdin so it does not appear in the process list."
          secrets={[
            { label: 'Install command', value: created.install_command },
            { label: 'Token secret', value: created.secret },
          ]}
        >
          <p className="text-xs text-muted-foreground">
            Valid for {created.token.max_uses === 1 ? 'one enrollment' : `${created.token.max_uses} enrollments`}, expires{' '}
            <RelativeTime value={created.token.expires_at} />. Verify the CA fingerprint on the server matches the one shown on this page.
          </p>
        </SecretOnceDialog>
      )}
      <ConfirmDialog
        open={revoke !== null}
        onOpenChange={(o) => !o && setRevoke(null)}
        title="Revoke this token?"
        description="Servers can no longer enroll with it. Already enrolled hosts are not affected."
        confirmLabel="Revoke"
        destructive
        onConfirm={async () => {
          if (!revoke) return;
          await request(() => api.DELETE('/enrollment-tokens/{tokenId}', { params: { path: { tokenId: revoke.id } } }));
          void qc.invalidateQueries({ queryKey: qk.enrollmentTokens });
          notifySuccess('Token revoked');
        }}
      />
    </Page>
  );
}

function CreateTokenDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (r: EnrollmentTokenCreated) => void }) {
  const qc = useQueryClient();
  const groups = useQuery({ ...groupsQuery, retry: false });
  const [description, setDescription] = useState('');
  const [groupId, setGroupId] = useState('');
  const [labels, setLabels] = useState<KV[]>([]);
  const [maxUses, setMaxUses] = useState('1');
  const [ttl, setTtl] = useState('24');
  const [error, setError] = useState<string | null>(null);
  const ids = { d: useId(), g: useId(), m: useId(), t: useId() };

  const create = useMutation({
    mutationFn: (body: EnrollmentTokenCreate) =>
      request(() => api.POST('/enrollment-tokens', { body })),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: qk.enrollmentTokens });
      onCreated(res);
    },
    onError: (e) => notifyError(e, 'Could not create token'),
  });

  const submit = () => {
    const uses = Number(maxUses);
    const hours = Number(ttl);
    if (!Number.isInteger(uses) || uses < 1 || uses > 1000) return setError('Max uses must be 1–1000.');
    if (!Number.isInteger(hours) || hours < 1 || hours > 720) return setError('Lifetime must be 1–720 hours.');
    const kv = fromKVs(labels, 32);
    if (kv.error) return setError(kv.error);
    setError(null);
    create.mutate({
      max_uses: uses,
      ttl_hours: hours,
      ...(description.trim() ? { description: description.trim() } : {}),
      ...(groupId ? { host_group_id: groupId } : {}),
      ...(Object.keys(kv.record).length ? { labels: kv.record } : {}),
    });
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
            <DialogTitle>New enrollment token</DialogTitle>
            <DialogDescription>Hosts enrolled with this token join the group and get the labels below.</DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4">
            <Field label="Description" htmlFor={ids.d} hint="e.g. “web-03 rollout” – shown in the token list">
              <Input id={ids.d} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={256} autoFocus />
            </Field>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Host group" htmlFor={ids.g}>
                <NativeSelect id={ids.g} value={groupId} onChange={(e) => setGroupId(e.target.value)} disabled={groups.isError}>
                  <option value="">No group</option>
                  {(groups.data ?? []).map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </NativeSelect>
              </Field>
              <Field label="Max uses" htmlFor={ids.m}>
                <Input id={ids.m} type="number" min={1} max={1000} value={maxUses} onChange={(e) => setMaxUses(e.target.value)} />
              </Field>
              <Field label="Lifetime (hours)" htmlFor={ids.t}>
                <Input id={ids.t} type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(e.target.value)} />
              </Field>
            </div>
            <div className="grid gap-1.5">
              <Label>Labels</Label>
              <KeyValueEditor rows={labels} onChange={setLabels} />
            </div>
            {Number(maxUses) > 10 && (
              <Callout tone="warning" title="Multi-use token">
                Anyone with this token can enroll up to {maxUses} hosts until it expires. Keep the lifetime short.
              </Callout>
            )}
            {error && <Callout tone="critical">{error}</Callout>}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={onClose} disabled={create.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? 'Creating…' : 'Create token'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

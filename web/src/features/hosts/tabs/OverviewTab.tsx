import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { PencilIcon, PowerOffIcon, Trash2Icon } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { api } from '@/api/client';
import { qk } from '@/api/keys';
import { groupsQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { Host, HostUpdate } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { ConnectionBadge } from '@/components/common/badges';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { KeyValueEditor } from '@/components/common/KeyValueEditor';
import { MultiSelect } from '@/components/common/MultiSelect';
import { RelativeTime } from '@/components/common/RelativeTime';
import { Callout } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/misc';
import { formatDateTime, parseDate } from '@/lib/format';
import { fromKVs, type KV, toKVs } from '@/lib/kv';
import { useNow } from '@/lib/now';
import { notifyError, notifySuccess } from '@/lib/notify';
import { osLabel, useCurrentHost } from '../hostUtils';
import { PolicySummaryView } from '../PolicySummary';

export function OverviewTab() {
  const { data: host } = useCurrentHost();
  if (!host) return null;
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <div className="grid content-start gap-4">
        <FactsCard host={host} />
        <LabelsCard host={host} />
      </div>
      <div className="grid content-start gap-4">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Local policy</CardTitle>
              <CardDescription>What this host allows, as reported by its agent. Enforced on the host itself.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <PolicySummaryView policy={host.policy} />
          </CardContent>
        </Card>
        <DangerZone host={host} />
      </div>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="contents">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children ?? '–'}</dd>
    </div>
  );
}

function FactsCard({ host }: { host: Host }) {
  const now = useNow();
  const certExpiry = parseDate(host.cert_not_after);
  const certDays = certExpiry ? (certExpiry.getTime() - now) / 86_400_000 : null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Facts</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-[9rem_1fr] gap-x-4 gap-y-2 text-sm">
          <Fact label="Hostname">{host.hostname}</Fact>
          <Fact label="FQDN">{host.fqdn || '–'}</Fact>
          <Fact label="Primary IP">{host.primary_ip ? <span className="font-mono">{host.primary_ip}</span> : '–'}</Fact>
          <Fact label="Connection">
            <ConnectionBadge connected={host.connected} status={host.status} />
          </Fact>
          <Fact label="Operating system">{osLabel(host)}</Fact>
          <Fact label="OS family">{host.os_family || '–'}</Fact>
          <Fact label="Kernel">{host.kernel ? <span className="font-mono text-xs">{host.kernel}</span> : '–'}</Fact>
          <Fact label="Architecture">{host.arch || '–'}</Fact>
          <Fact label="Agent version">{host.agent_version ? <span className="font-mono text-xs">{host.agent_version}</span> : '–'}</Fact>
          <Fact label="Enrolled">
            <RelativeTime value={host.enrolled_at} />
          </Fact>
          <Fact label="Last seen">
            <RelativeTime value={host.last_seen_at} fallback="never" />
          </Fact>
          <Fact label="Certificate expires">
            {certExpiry ? (
              <span className="inline-flex flex-wrap items-center gap-1.5">
                <span title={formatDateTime(certExpiry)}>{formatDateTime(certExpiry)}</span>
                {certDays !== null && certDays < 0 && <Badge variant="critical">expired</Badge>}
                {certDays !== null && certDays >= 0 && certDays < 14 && <Badge variant="warning">in {Math.ceil(certDays)} d</Badge>}
              </span>
            ) : (
              '–'
            )}
          </Fact>
          <Fact label="Host ID">
            <span className="font-mono text-xs">{host.id}</span>
          </Fact>
        </dl>
      </CardContent>
    </Card>
  );
}

function usePatchHost(host: Host) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: HostUpdate) =>
      request(() => api.PATCH('/hosts/{hostId}', { params: { path: { hostId: host.id } }, body })),
    onSuccess: (updated) => {
      qc.setQueryData(qk.host(host.id), updated);
      void qc.invalidateQueries({ queryKey: qk.hostsRoot });
    },
  });
}

function LabelsCard({ host }: { host: Host }) {
  const perms = usePermissions();
  const canManage = perms.canOnHost('host.manage', host);
  const [editing, setEditing] = useState(false);
  const [rows, setRows] = useState<KV[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const groups = useQuery({ ...groupsQuery, enabled: editing, retry: false });
  const patch = usePatchHost(host);

  const startEdit = () => {
    setRows(toKVs(host.labels));
    setGroupIds(host.groups.map((g) => g.id));
    setError(null);
    setEditing(true);
  };

  const save = () => {
    const { record, error: err } = fromKVs(rows);
    if (err) {
      setError(err);
      return;
    }
    const body: HostUpdate = { labels: record };
    if (groups.data) body.group_ids = groupIds;
    patch.mutate(body, {
      onSuccess: () => {
        setEditing(false);
        notifySuccess('Host updated');
      },
      onError: (e) => notifyError(e, 'Could not update host'),
    });
  };

  const labels = Object.entries(host.labels);
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Labels & groups</CardTitle>
          <CardDescription>Groups scope permissions and shell settings; labels are free-form metadata.</CardDescription>
        </div>
        {canManage && !editing && (
          <Button variant="outline" size="sm" onClick={startEdit}>
            <PencilIcon /> Edit
          </Button>
        )}
      </CardHeader>
      <CardContent className="grid gap-4">
        {!editing ? (
          <>
            <div>
              <div className="mb-1.5 text-xs font-medium text-muted-foreground">Groups</div>
              {host.groups.length === 0 ? (
                <span className="text-sm text-muted-foreground">Not in any group</span>
              ) : (
                <div className="flex flex-wrap gap-1">
                  {host.groups.map((g) => (
                    <Badge key={g.id} variant="secondary">
                      {g.name}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
            <div>
              <div className="mb-1.5 text-xs font-medium text-muted-foreground">Labels</div>
              {labels.length === 0 ? (
                <span className="text-sm text-muted-foreground">No labels</span>
              ) : (
                <div className="flex flex-wrap gap-1">
                  {labels.map(([k, v]) => (
                    <Badge key={k} variant="outline" className="font-mono">
                      {k}={v}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </>
        ) : (
          <>
            <div className="grid gap-1.5">
              <Label>Groups</Label>
              {groups.isError ? (
                <p className="text-xs text-muted-foreground">Groups cannot be loaded; only labels will be saved.</p>
              ) : (
                <MultiSelect
                  options={(groups.data ?? []).map((g) => ({ value: g.id, label: g.name }))}
                  value={groupIds}
                  onChange={setGroupIds}
                  placeholder={groups.isPending ? 'Loading…' : 'No groups'}
                />
              )}
            </div>
            <div className="grid gap-1.5">
              <Label>Labels</Label>
              <KeyValueEditor rows={rows} onChange={setRows} disabled={patch.isPending} />
            </div>
            {error && <Callout tone="critical">{error}</Callout>}
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setEditing(false)} disabled={patch.isPending}>
                Cancel
              </Button>
              <Button onClick={save} disabled={patch.isPending}>
                {patch.isPending ? 'Saving…' : 'Save'}
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function DangerZone({ host }: { host: Host }) {
  const perms = usePermissions();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const patch = usePatchHost(host);
  const [confirmDecom, setConfirmDecom] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  if (!perms.canOnHost('host.manage', host) || host.status === 'decommissioned') return null;

  const disabled = host.status === 'disabled';
  return (
    <Card className="border-critical/30">
      <CardHeader>
        <div>
          <CardTitle>Host lifecycle</CardTitle>
          <CardDescription>Disable to stop dispatching jobs; decommission to revoke the host permanently.</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="text-sm font-medium">Active</div>
            <p className="text-xs text-muted-foreground">
              {disabled ? 'The host is disabled: it stays enrolled but receives no jobs.' : 'The host receives jobs and shell sessions.'}
            </p>
          </div>
          <Switch
            checked={!disabled}
            disabled={patch.isPending}
            aria-label="Host active"
            onCheckedChange={(on) => {
              if (on)
                patch.mutate({ status: 'active' }, { onError: (e) => notifyError(e, 'Could not enable host') });
              else setConfirmDisable(true);
            }}
          />
        </div>
        <div className="flex items-center justify-between gap-4 border-t pt-4">
          <div>
            <div className="text-sm font-medium">Decommission</div>
            <p className="text-xs text-muted-foreground">Revokes all certificates. The agent can no longer connect; re-enrollment is required.</p>
          </div>
          <Button variant="destructive" size="sm" onClick={() => setConfirmDecom(true)}>
            <Trash2Icon /> Decommission
          </Button>
        </div>
      </CardContent>

      <ConfirmDialog
        open={confirmDisable}
        onOpenChange={setConfirmDisable}
        title={`Disable ${host.hostname}?`}
        description="Pending and new jobs will not be dispatched to this host until it is enabled again."
        confirmLabel="Disable host"
        destructive
        onConfirm={async () => {
          await patch.mutateAsync({ status: 'disabled' });
          notifySuccess('Host disabled');
        }}
      >
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <PowerOffIcon className="size-4" /> Monitoring data keeps flowing while the agent is connected.
        </div>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmDecom}
        onOpenChange={setConfirmDecom}
        title={`Decommission ${host.hostname}?`}
        description="All certificates of this host are revoked immediately. This cannot be undone."
        confirmLabel="Decommission host"
        destructive
        typeToConfirm={host.hostname}
        onConfirm={async () => {
          await request(() => api.DELETE('/hosts/{hostId}', { params: { path: { hostId: host.id } } }));
          void qc.invalidateQueries({ queryKey: qk.hostsRoot });
          void qc.invalidateQueries({ queryKey: qk.dashboard });
          qc.removeQueries({ queryKey: qk.host(host.id) });
          notifySuccess(`${host.hostname} decommissioned`);
          void navigate({ to: '/hosts' });
        }}
      />
    </Card>
  );
}

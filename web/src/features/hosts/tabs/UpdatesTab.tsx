import { useQuery } from '@tanstack/react-query';
import { ArrowUpCircleIcon, CircleCheckIcon, PowerIcon, RefreshCwIcon, RotateCwIcon, ShieldCheckIcon, TriangleAlertIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { hostUpdatesQuery } from '@/api/queries';
import { usePermissions } from '@/auth/usePermissions';
import { RelativeTime } from '@/components/common/RelativeTime';
import { SearchInput } from '@/components/common/SearchInput';
import { Callout, EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/misc';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { useSelection } from '@/lib/selection';
import { cn, pluralize } from '@/lib/utils';
import { type QuickAction, QuickJobDialog } from '../../jobs/QuickJobDialog';
import { policyFlag, useCurrentHost } from '../hostUtils';

export function UpdatesTab() {
  const { data: host } = useCurrentHost();
  const perms = usePermissions();
  const q = useQuery({ ...hostUpdatesQuery(host?.id ?? ''), enabled: !!host });
  const [filter, setFilter] = useState('');
  const [securityOnly, setSecurityOnly] = useState(false);
  const [action, setAction] = useState<QuickAction | null>(null);

  const rows = useMemo(() => {
    const all = [...(q.data?.updates ?? [])].sort(
      (a, b) => Number(b.is_security) - Number(a.is_security) || a.name.localeCompare(b.name),
    );
    const needle = filter.trim().toLowerCase();
    return all.filter((u) => (!securityOnly || u.is_security) && (!needle || u.name.toLowerCase().includes(needle)));
  }, [q.data, filter, securityOnly]);
  const keys = useMemo(() => rows.map((u) => `${u.name}|${u.arch ?? ''}`), [rows]);
  const sel = useSelection(keys);

  if (!host) return null;
  const canRefresh = perms.canOnHost('pkg.refresh', host);
  const canUpgrade = perms.canOnHost('pkg.upgrade', host) && policyFlag(host, 'pkg_upgrade') !== false;
  const canReboot = perms.canOnHost('host.reboot', host) && policyFlag(host, 'reboot') !== false;
  const data = q.data;
  const securityCount = data?.updates.filter((u) => u.is_security).length ?? 0;
  const selectedNames = [...new Set(rows.filter((u) => sel.selected.has(`${u.name}|${u.arch ?? ''}`)).map((u) => u.name))];
  const target = [{ id: host.id, hostname: host.hostname }];

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        {canRefresh && (
          <Button variant="outline" size="sm" onClick={() => setAction('refresh')} disabled={!host.connected}>
            <RefreshCwIcon /> Refresh lists
          </Button>
        )}
        {canUpgrade && (
          <>
            <Button size="sm" onClick={() => setAction('security')} disabled={!host.connected || securityCount === 0}>
              <ShieldCheckIcon /> Upgrade security ({securityCount})
            </Button>
            <Button variant="outline" size="sm" onClick={() => setAction('all')} disabled={!host.connected || !data?.updates.length}>
              <ArrowUpCircleIcon /> Upgrade all ({data?.updates.length ?? 0})
            </Button>
            <Button variant="outline" size="sm" onClick={() => setAction('named')} disabled={!host.connected || selectedNames.length === 0}>
              Upgrade selected ({selectedNames.length})
            </Button>
          </>
        )}
        {canUpgrade && policyFlag(host, 'pkg_upgrade') === false && (
          <span className="text-xs text-muted-foreground">Upgrades are disabled by the host's local policy.</span>
        )}
        <div className="flex-1" />
        {data && (
          <span className="text-xs text-muted-foreground">
            {data.manager && <span className="mr-2 font-mono">{data.manager}</span>}
            checked <RelativeTime value={data.checked_at} fallback="never" />
          </span>
        )}
      </div>

      {!host.connected && <Callout tone="warning" title="Host offline">Jobs will be dispatched when the agent reconnects (until they expire).</Callout>}

      {data?.reboot_required && (
        <Callout
          tone="warning"
          icon={RotateCwIcon}
          title="Reboot required"
          action={
            canReboot && (
              <Button variant="outline" size="sm" onClick={() => setAction('reboot')} disabled={!host.connected}>
                <PowerIcon /> Reboot
              </Button>
            )
          }
        >
          {data.reboot_reasons?.length ? data.reboot_reasons.join(', ') : 'Updated kernel or core libraries are not active yet.'}
        </Callout>
      )}
      {data?.error && (
        <Callout tone="critical" icon={TriangleAlertIcon} title="Package manager reported an error">
          <span className="font-mono">{data.error}</span>
        </Callout>
      )}

      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b px-3 py-2">
          <SearchInput value={filter} onChange={setFilter} placeholder="Filter updates…" />
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={securityOnly} onCheckedChange={(v) => setSecurityOnly(v === true)} /> Security only
          </label>
        </div>
        {q.isPending ? (
          <TableSkeleton rows={6} cols={5} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={CircleCheckIcon}
            title={data?.updates.length ? 'No matching updates' : 'Up to date'}
            description={data?.updates.length ? undefined : 'No pending updates were reported at the last check.'}
          />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                {canUpgrade && (
                  <TH>
                    <Checkbox checked={sel.headerState} onCheckedChange={sel.toggleAll} aria-label="Select all updates" />
                  </TH>
                )}
                <TH>Package</TH>
                <TH>Installed</TH>
                <TH>Candidate</TH>
                <TH>Source</TH>
                <TH>Advisories</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((u) => {
                const key = `${u.name}|${u.arch ?? ''}`;
                return (
                  <TR
                    key={key}
                    data-state={sel.selected.has(key) ? 'selected' : undefined}
                    className={cn(u.is_security && 'bg-critical/[0.04]')}
                  >
                    {canUpgrade && (
                      <TD>
                        <Checkbox
                          checked={sel.selected.has(key)}
                          onCheckedChange={(v) => sel.toggle(key, v === true)}
                          aria-label={`Select ${u.name}`}
                        />
                      </TD>
                    )}
                    <TD>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{u.name}</span>
                        {u.arch && <span className="text-xs text-muted-foreground">{u.arch}</span>}
                        {u.is_security && (
                          <Badge variant="critical">
                            <ShieldCheckIcon aria-hidden /> security
                          </Badge>
                        )}
                      </div>
                    </TD>
                    <TD className="font-mono text-xs text-muted-foreground">{u.current_version}</TD>
                    <TD className="font-mono text-xs">{u.candidate_version}</TD>
                    <TD className="max-w-60 truncate text-xs text-muted-foreground">{u.source || '–'}</TD>
                    <TD className="max-w-72">
                      <div className="flex flex-wrap gap-1">
                        {(u.advisories ?? []).slice(0, 4).map((a) => (
                          <Badge key={a} variant="outline" className="font-mono">
                            {a}
                          </Badge>
                        ))}
                        {(u.advisories?.length ?? 0) > 4 && <Badge variant="outline">+{(u.advisories?.length ?? 0) - 4}</Badge>}
                      </div>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
        {data && data.updates.length > 0 && (
          <div className="border-t px-3 py-2 text-xs text-muted-foreground">
            {pluralize(data.updates.length, 'update')}, {securityCount} security
          </div>
        )}
      </Card>

      <QuickJobDialog
        action={action}
        targets={target}
        packages={selectedNames}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={sel.clear}
      />
    </div>
  );
}

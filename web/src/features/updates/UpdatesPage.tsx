import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { ArrowUpCircleIcon, CircleCheckIcon, PowerIcon, RefreshCwIcon, RotateCwIcon, ShieldCheckIcon, XIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { fleetUpdatesQuery, hostsQuery } from '@/api/queries';
import type { HostUpdatesSummary } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { ConnectionBadge, RebootBadge } from '@/components/common/badges';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { SearchInput } from '@/components/common/SearchInput';
import { SortHeader } from '@/components/common/SortHeader';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { NativeSelect } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/misc';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatNumber, parseDate } from '@/lib/format';
import type { Permission } from '@/lib/permissions';
import { useSelection } from '@/lib/selection';
import { sortItems, useSort } from '@/lib/sort';
import { pluralize } from '@/lib/utils';
import { type QuickAction, QuickJobDialog } from '../jobs/QuickJobDialog';

type Filter = 'pending' | 'security' | 'reboot' | 'all';
type SortKey = 'hostname' | 'total' | 'security' | 'checked';

const PERM: Record<QuickAction, Permission> = {
  refresh: 'pkg.refresh',
  security: 'pkg.upgrade',
  all: 'pkg.upgrade',
  named: 'pkg.upgrade',
  reboot: 'host.reboot',
};

export function UpdatesPage() {
  const perms = usePermissions();
  const q = useQuery(fleetUpdatesQuery);
  // Host records carry the groups needed for scoped permission checks.
  const hosts = useQuery(hostsQuery({}));
  const [filter, setFilter] = useState<Filter>('pending');
  const [text, setText] = useState('');
  const [action, setAction] = useState<QuickAction | null>(null);
  const sort = useSort<SortKey>('security', 'desc');

  const all = useMemo(() => q.data ?? [], [q.data]);
  const totals = useMemo(
    () => ({
      hosts: all.filter((h) => h.total > 0).length,
      updates: all.reduce((n, h) => n + h.total, 0),
      security: all.reduce((n, h) => n + h.security, 0),
      reboot: all.filter((h) => h.reboot_required).length,
    }),
    [all],
  );
  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const list = all.filter((h) => {
      if (needle && !h.hostname.toLowerCase().includes(needle) && !(h.os_pretty_name ?? '').toLowerCase().includes(needle)) return false;
      if (filter === 'pending') return h.total > 0 || h.reboot_required;
      if (filter === 'security') return h.security > 0;
      if (filter === 'reboot') return h.reboot_required;
      return true;
    });
    const get = (h: HostUpdatesSummary) =>
      sort.key === 'hostname'
        ? h.hostname
        : sort.key === 'total'
          ? h.total
          : sort.key === 'security'
            ? h.security * 100000 + h.total
            : parseDate(h.checked_at)?.getTime();
    return sortItems(list, get, sort.dir);
  }, [all, filter, text, sort.key, sort.dir]);

  const ids = useMemo(() => rows.map((r) => r.host_id), [rows]);
  const sel = useSelection(ids);
  const hostById = useMemo(() => new Map((hosts.data ?? []).map((h) => [h.id, h])), [hosts.data]);
  const selected = rows.filter((r) => sel.selected.has(r.host_id));
  const allowed = (a: QuickAction) =>
    selected.filter((r) => perms.canOnHost(PERM[a], hostById.get(r.host_id) ?? { groups: [] })).map((r) => ({ id: r.host_id, hostname: r.hostname }));
  const targets = action ? allowed(action) : [];

  return (
    <Page>
      <PageHeader title="Updates" description="Pending package updates across the fleet." />
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Total label="Hosts with updates" value={totals.hosts} of={all.length} />
        <Total label="Pending updates" value={totals.updates} />
        <Total label="Security updates" value={totals.security} tone={totals.security > 0 ? 'critical' : undefined} />
        <Total label="Reboot required" value={totals.reboot} tone={totals.reboot > 0 ? 'warning' : undefined} />
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={text} onChange={setText} placeholder="Filter hosts…" />
        <NativeSelect aria-label="Show" className="w-48" value={filter} onChange={(e) => setFilter(e.target.value as Filter)}>
          <option value="pending">Hosts with pending work</option>
          <option value="security">Security updates</option>
          <option value="reboot">Reboot required</option>
          <option value="all">All hosts</option>
        </NativeSelect>
        <div className="flex-1" />
        {sel.selected.size > 0 && (
          <div className="flex flex-wrap items-center gap-2" role="region" aria-label="Bulk actions">
            <span className="text-sm font-medium">{pluralize(sel.selected.size, 'host')} selected</span>
            <Button size="sm" variant="outline" onClick={() => setAction('refresh')} disabled={allowed('refresh').length === 0}>
              <RefreshCwIcon /> Refresh
            </Button>
            <Button size="sm" onClick={() => setAction('security')} disabled={allowed('security').length === 0}>
              <ShieldCheckIcon /> Security upgrade
            </Button>
            <Button size="sm" variant="outline" onClick={() => setAction('all')} disabled={allowed('all').length === 0}>
              <ArrowUpCircleIcon /> Upgrade all
            </Button>
            <Button size="sm" variant="outline" onClick={() => setAction('reboot')} disabled={allowed('reboot').length === 0}>
              <PowerIcon /> Reboot
            </Button>
            <Button size="icon-sm" variant="ghost" onClick={sel.clear} aria-label="Clear selection">
              <XIcon />
            </Button>
          </div>
        )}
      </div>

      <Card>
        {q.isPending ? (
          <TableSkeleton rows={8} cols={6} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={CircleCheckIcon}
            title={filter === 'all' ? 'No hosts' : 'Nothing pending'}
            description={filter === 'all' ? undefined : 'No host matches this filter. Nice.'}
          />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>
                  <Checkbox checked={sel.headerState} onCheckedChange={sel.toggleAll} aria-label="Select all hosts" />
                </TH>
                <SortHeader sort={sort} k="hostname">Host</SortHeader>
                <TH>Connection</TH>
                <TH>OS</TH>
                <SortHeader sort={sort} k="total">Updates</SortHeader>
                <SortHeader sort={sort} k="security">Security</SortHeader>
                <TH>Reboot</TH>
                <SortHeader sort={sort} k="checked">Checked</SortHeader>
              </TR>
            </THead>
            <TBody>
              {rows.map((h) => (
                <TR key={h.host_id} data-state={sel.selected.has(h.host_id) ? 'selected' : undefined}>
                  <TD>
                    <Checkbox
                      checked={sel.selected.has(h.host_id)}
                      onCheckedChange={(v) => sel.toggle(h.host_id, v === true)}
                      aria-label={`Select ${h.hostname}`}
                    />
                  </TD>
                  <TD>
                    <Link
                      to="/hosts/$hostId/updates"
                      params={{ hostId: h.host_id }}
                      className="font-medium hover:text-primary hover:underline"
                    >
                      {h.hostname}
                    </Link>
                  </TD>
                  <TD>
                    <ConnectionBadge connected={h.connected} />
                  </TD>
                  <TD className="max-w-56 truncate text-muted-foreground">{h.os_pretty_name || '–'}</TD>
                  <TD className="tabular">{h.total > 0 ? formatNumber(h.total) : <span className="text-muted-foreground">0</span>}</TD>
                  <TD>
                    {h.security > 0 ? (
                      <Badge variant="critical">
                        <ShieldCheckIcon aria-hidden /> {h.security}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TD>
                  <TD>{h.reboot_required ? <RebootBadge /> : <span className="text-muted-foreground">–</span>}</TD>
                  <TD>
                    <RelativeTime value={h.checked_at} fallback="never" />
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      <QuickJobDialog
        action={action}
        targets={targets}
        excluded={selected.length - targets.length}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={sel.clear}
      />
    </Page>
  );
}

function Total({ label, value, of, tone }: { label: string; value: number; of?: number; tone?: 'critical' | 'warning' }) {
  const Icon = tone === 'warning' ? RotateCwIcon : tone === 'critical' ? ShieldCheckIcon : null;
  return (
    <Card className={tone === 'critical' ? 'border-l-[3px] border-l-critical p-3' : tone === 'warning' ? 'border-l-[3px] border-l-warning p-3' : 'p-3'}>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        {label}
        {Icon && <Icon className={tone === 'critical' ? 'size-4 text-critical' : 'size-4 text-text-warning'} aria-hidden />}
      </div>
      <div className="text-2xl font-semibold">
        {formatNumber(value)}
        {of !== undefined && <span className="ml-1 text-sm font-normal text-muted-foreground">/ {formatNumber(of)}</span>}
      </div>
    </Card>
  );
}

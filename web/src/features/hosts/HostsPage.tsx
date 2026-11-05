import { useQuery } from '@tanstack/react-query';
import { getRouteApi, Link } from '@tanstack/react-router';
import {
  ChevronDownIcon,
  PlusIcon,
  PowerIcon,
  RefreshCwIcon,
  ServerIcon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
  XIcon,
  ArrowUpCircleIcon,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import { groupsQuery, hostsQuery } from '@/api/queries';
import type { Host } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { ConnectionBadge } from '@/components/common/badges';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { SearchInput } from '@/components/common/SearchInput';
import { SortHeader } from '@/components/common/SortHeader';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { NativeSelect } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/misc';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { Tip } from '@/components/ui/tooltip';
import { parseDate } from '@/lib/format';
import type { Permission } from '@/lib/permissions';
import { useSelection } from '@/lib/selection';
import { sortItems, useSort } from '@/lib/sort';
import { cn, pluralize } from '@/lib/utils';
import type { HostsSearch } from '@/routes/search';
import { NewJobDialog } from '../jobs/NewJobDialog';
import { UpdatesCell } from './HostCells';
import { osLabel } from './hostUtils';
import { type QuickAction, QuickJobDialog } from '../jobs/QuickJobDialog';

const route = getRouteApi('/app/hosts');

type SortKey = 'hostname' | 'os' | 'agent' | 'updates' | 'last_seen' | 'status';

const ACTION_PERMISSION: Record<QuickAction, Permission> = {
  refresh: 'pkg.refresh',
  security: 'pkg.upgrade',
  all: 'pkg.upgrade',
  named: 'pkg.upgrade',
  reboot: 'host.reboot',
};

export function HostsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const perms = usePermissions();
  const groups = useQuery({ ...groupsQuery, retry: false });
  const hosts = useQuery(hostsQuery({ q: search.q, status: search.status, group_id: search.group }));
  const sort = useSort<SortKey>('hostname');
  const [action, setAction] = useState<QuickAction | null>(null);
  const [customOpen, setCustomOpen] = useState(false);

  const setSearch = (patch: Partial<HostsSearch>) =>
    void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });

  const rows = useMemo(() => {
    let list = hosts.data ?? [];
    if (!search.status) list = list.filter((h) => h.status !== 'decommissioned');
    if (search.conn) list = list.filter((h) => (search.conn === 'connected' ? h.connected : !h.connected));
    if (search.updates === 'any') list = list.filter((h) => (h.updates?.total ?? 0) > 0);
    if (search.updates === 'security') list = list.filter((h) => (h.updates?.security ?? 0) > 0);
    if (search.updates === 'reboot') list = list.filter((h) => h.updates?.reboot_required);
    const get = (h: Host) => {
      switch (sort.key) {
        case 'hostname':
          return h.hostname;
        case 'os':
          return osLabel(h);
        case 'agent':
          return h.agent_version;
        case 'updates':
          return (h.updates?.security ?? 0) * 100000 + (h.updates?.total ?? 0);
        case 'last_seen':
          return parseDate(h.last_seen_at)?.getTime();
        case 'status':
          return h.connected ? 1 : 0;
      }
    };
    return sortItems(list, get, sort.dir);
  }, [hosts.data, search.status, search.conn, search.updates, sort.key, sort.dir]);

  const ids = useMemo(() => rows.map((h) => h.id), [rows]);
  const sel = useSelection(ids);
  const selectedHosts = rows.filter((h) => sel.selected.has(h.id));

  const allowedFor = (a: QuickAction) => selectedHosts.filter((h) => perms.canOnHost(ACTION_PERMISSION[a], h));
  const actionTargets = action ? allowedFor(action) : [];

  const filtersActive = !!(search.q || search.status || search.group || search.conn || search.updates);
  const canAnyBulk = (['refresh', 'security', 'reboot'] as const).some((a) => perms.canAnywhere(ACTION_PERMISSION[a]));

  return (
    <Page>
      <PageHeader
        title="Hosts"
        description={hosts.data ? `${pluralize(rows.length, 'host')} shown` : 'Managed servers'}
        actions={
          perms.canAnywhere('enroll.manage') && (
            <Button asChild variant="outline">
              <Link to="/admin/enrollment">
                <PlusIcon /> Enroll host
              </Link>
            </Button>
          )
        }
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput
          value={search.q ?? ''}
          onChange={(q) => setSearch({ q: q || undefined })}
          placeholder="Search hostname or FQDN…"
          debounce={250}
        />
        <NativeSelect
          aria-label="Connection"
          className="w-36"
          value={search.conn ?? ''}
          onChange={(e) => setSearch({ conn: (e.target.value || undefined) as HostsSearch['conn'] })}
        >
          <option value="">Any connection</option>
          <option value="connected">Connected</option>
          <option value="offline">Offline</option>
        </NativeSelect>
        <NativeSelect
          aria-label="Status"
          className="w-40"
          value={search.status ?? ''}
          onChange={(e) => setSearch({ status: (e.target.value || undefined) as HostsSearch['status'] })}
        >
          <option value="">Active & disabled</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
          <option value="decommissioned">Decommissioned</option>
        </NativeSelect>
        {groups.data && groups.data.length > 0 && (
          <NativeSelect
            aria-label="Group"
            className="w-44"
            value={search.group ?? ''}
            onChange={(e) => setSearch({ group: e.target.value || undefined })}
          >
            <option value="">All groups</option>
            {groups.data.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </NativeSelect>
        )}
        <NativeSelect
          aria-label="Updates"
          className="w-44"
          value={search.updates ?? ''}
          onChange={(e) => setSearch({ updates: (e.target.value || undefined) as HostsSearch['updates'] })}
        >
          <option value="">Any update state</option>
          <option value="any">Updates pending</option>
          <option value="security">Security updates</option>
          <option value="reboot">Reboot required</option>
        </NativeSelect>
        {filtersActive && (
          <Button variant="ghost" size="sm" onClick={() => void navigate({ search: {}, replace: true })}>
            <XIcon /> Reset
          </Button>
        )}
      </div>

      {sel.selected.size > 0 && (
        <div
          className="sticky top-0 z-10 mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-primary/30 bg-card px-3 py-2 shadow-sm"
          role="region"
          aria-label="Bulk actions"
        >
          <span className="text-sm font-medium">{pluralize(sel.selected.size, 'host')} selected</span>
          <div className="flex-1" />
          {canAnyBulk ? (
            <>
              <BulkButton icon={RefreshCwIcon} label="Refresh lists" count={allowedFor('refresh').length} onClick={() => setAction('refresh')} />
              <BulkButton icon={ShieldCheckIcon} label="Security upgrade" count={allowedFor('security').length} onClick={() => setAction('security')} />
              <BulkButton icon={ArrowUpCircleIcon} label="Upgrade all" count={allowedFor('all').length} onClick={() => setAction('all')} />
              <BulkButton icon={PowerIcon} label="Reboot" count={allowedFor('reboot').length} onClick={() => setAction('reboot')} />
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" aria-label="More actions">
                    <SlidersHorizontalIcon /> More <ChevronDownIcon />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => setCustomOpen(true)}>Custom job…</DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={sel.clear}>Clear selection</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          ) : (
            <span className="text-xs text-muted-foreground">Your role has no bulk actions.</span>
          )}
          <Button variant="ghost" size="icon-sm" onClick={sel.clear} aria-label="Clear selection">
            <XIcon />
          </Button>
        </div>
      )}

      <Card className={cn(hosts.isFetching && hosts.isPlaceholderData && 'opacity-70')}>
        {hosts.isPending ? (
          <TableSkeleton rows={8} cols={6} />
        ) : hosts.isError ? (
          <ErrorState error={hosts.error} onRetry={() => void hosts.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={ServerIcon}
            title={filtersActive ? 'No hosts match the filters' : 'No hosts enrolled yet'}
            description={
              filtersActive
                ? 'Try a different search or reset the filters.'
                : 'Create an enrollment token and run the install command on a server.'
            }
            action={
              !filtersActive && perms.canAnywhere('enroll.manage') ? (
                <Button asChild size="sm">
                  <Link to="/admin/enrollment">Create enrollment token</Link>
                </Button>
              ) : undefined
            }
          />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>
                  <Checkbox checked={sel.headerState} onCheckedChange={sel.toggleAll} aria-label="Select all hosts" />
                </TH>
                <SortHeader sort={sort} k="hostname">Host</SortHeader>
                <SortHeader sort={sort} k="status">Connection</SortHeader>
                <SortHeader sort={sort} k="os">OS</SortHeader>
                <SortHeader sort={sort} k="agent" className="hidden xl:table-cell">Agent</SortHeader>
                <SortHeader sort={sort} k="updates">Updates</SortHeader>
                <TH className="hidden xl:table-cell">Groups</TH>
                <SortHeader sort={sort} k="last_seen">Last seen</SortHeader>
              </TR>
            </THead>
            <TBody>
              {rows.map((h) => (
                <TR key={h.id} data-state={sel.selected.has(h.id) ? 'selected' : undefined}>
                  <TD>
                    <Checkbox
                      checked={sel.selected.has(h.id)}
                      onCheckedChange={(v) => sel.toggle(h.id, v === true)}
                      aria-label={`Select ${h.hostname}`}
                    />
                  </TD>
                  <TD className="max-w-64">
                    <Link
                      to="/hosts/$hostId"
                      params={{ hostId: h.id }}
                      className="font-medium text-foreground hover:text-primary hover:underline"
                    >
                      {h.hostname}
                    </Link>
                    <div className="truncate text-xs text-muted-foreground">
                      {[h.fqdn && h.fqdn !== h.hostname ? h.fqdn : null, h.primary_ip].filter(Boolean).join(' · ') || ' '}
                    </div>
                  </TD>
                  <TD>
                    <ConnectionBadge connected={h.connected} status={h.status} />
                  </TD>
                  <TD className="max-w-56 truncate">{osLabel(h)}</TD>
                  <TD className="hidden font-mono text-xs text-muted-foreground xl:table-cell">{h.agent_version || '–'}</TD>
                  <TD>
                    <UpdatesCell host={h} />
                  </TD>
                  <TD className="hidden max-w-48 xl:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {h.groups.slice(0, 3).map((g) => (
                        <Badge key={g.id} variant="outline" className="max-w-32 truncate">
                          {g.name}
                        </Badge>
                      ))}
                      {h.groups.length > 3 && <Badge variant="outline">+{h.groups.length - 3}</Badge>}
                    </div>
                  </TD>
                  <TD>
                    <RelativeTime value={h.last_seen_at} fallback="never" />
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      <QuickJobDialog
        action={action}
        targets={actionTargets}
        excluded={selectedHosts.length - actionTargets.length}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={sel.clear}
      />
      <NewJobDialog open={customOpen} onOpenChange={setCustomOpen} preset={{ hostIds: selectedHosts.map((h) => h.id) }} />
    </Page>
  );
}

function BulkButton({
  icon: Icon,
  label,
  count,
  onClick,
}: {
  icon: typeof RefreshCwIcon;
  label: string;
  count: number;
  onClick: () => void;
}) {
  const btn = (
    <Button variant="outline" size="sm" onClick={onClick} disabled={count === 0}>
      <Icon /> {label}
    </Button>
  );
  return count === 0 ? (
    <Tip content="No permission on the selected hosts">
      <span tabIndex={0}>{btn}</span>
    </Tip>
  ) : (
    btn
  );
}

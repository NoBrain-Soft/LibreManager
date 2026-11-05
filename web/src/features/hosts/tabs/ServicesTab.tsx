import { useQuery } from '@tanstack/react-query';
import { CogIcon, EllipsisIcon, PlayIcon, RotateCwIcon, SquareIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { hostInventoryQuery } from '@/api/queries';
import { usePermissions } from '@/auth/usePermissions';
import { RelativeTime } from '@/components/common/RelativeTime';
import { SearchInput } from '@/components/common/SearchInput';
import { SortHeader } from '@/components/common/SortHeader';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
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
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import type { BadgeVariantProps } from '@/components/ui/variants';
import { sortItems, useSort } from '@/lib/sort';
import { asArray, field, str } from '@/lib/utils';
import type { ServiceOp } from '../../jobs/jobForm';
import { useCreateJob } from '../../jobs/useCreateJob';
import { policyFlag, useCurrentHost } from '../hostUtils';

interface Unit {
  name: string;
  description: string;
  load: string;
  active: string;
  sub: string;
  fileState: string;
}

function toUnits(data: unknown): Unit[] {
  return asArray(field(data, 'units'))
    .map((u) => ({
      name: str(field(u, 'name')),
      description: str(field(u, 'description')),
      load: str(field(u, 'load_state')),
      active: str(field(u, 'active_state')),
      sub: str(field(u, 'sub_state')),
      fileState: str(field(u, 'unit_file_state')),
    }))
    .filter((u) => u.name);
}

function activeVariant(state: string): NonNullable<BadgeVariantProps['variant']> {
  switch (state) {
    case 'active':
      return 'good';
    case 'failed':
      return 'critical';
    case 'activating':
    case 'deactivating':
    case 'reloading':
      return 'info';
    default:
      return 'neutral';
  }
}

const DESTRUCTIVE_OPS = new Set<ServiceOp>(['stop', 'disable', 'restart']);

export function ServicesTab() {
  const { data: host } = useCurrentHost();
  const perms = usePermissions();
  const inv = useQuery({ ...hostInventoryQuery(host?.id ?? ''), enabled: !!host });
  const [q, setQ] = useState('');
  const [state, setState] = useState<'all' | 'running' | 'failed' | 'inactive'>('all');
  const sort = useSort<'name' | 'active' | 'fileState'>('name');
  const [pending, setPending] = useState<{ unit: string; op: ServiceOp } | null>(null);
  const create = useCreateJob();

  const section = inv.data?.sections.services;
  const units = useMemo(() => toUnits(section?.data), [section]);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const filtered = units.filter((u) => {
      if (needle && !u.name.toLowerCase().includes(needle) && !u.description.toLowerCase().includes(needle)) return false;
      if (state === 'running') return u.active === 'active';
      if (state === 'failed') return u.active === 'failed';
      if (state === 'inactive') return u.active === 'inactive';
      return true;
    });
    return sortItems(filtered, (u) => (sort.key === 'active' ? `${u.active === 'failed' ? 0 : 1}${u.active}` : u[sort.key]), sort.dir);
  }, [units, q, state, sort.key, sort.dir]);

  if (!host) return null;
  const canControl = perms.canOnHost('service.control', host) && policyFlag(host, 'service_control') !== false;
  const failed = units.filter((u) => u.active === 'failed').length;

  const run = (unit: string, op: ServiceOp) =>
    create.mutateAsync({ type: 'service', params: { unit, op }, targets: { host_ids: [host.id] } });

  const request = (unit: string, op: ServiceOp) => {
    if (DESTRUCTIVE_OPS.has(op)) setPending({ unit, op });
    else void run(unit, op).catch(() => undefined);
  };

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
        <SearchInput value={q} onChange={setQ} placeholder="Filter units…" />
        <NativeSelect aria-label="State" className="w-36" value={state} onChange={(e) => setState(e.target.value as typeof state)}>
          <option value="all">All states</option>
          <option value="running">Active</option>
          <option value="failed">Failed{failed ? ` (${failed})` : ''}</option>
          <option value="inactive">Inactive</option>
        </NativeSelect>
        <div className="flex-1" />
        {section && (
          <span className="text-xs text-muted-foreground">
            {units.length} units · inventory <RelativeTime value={section.collected_at} />
          </span>
        )}
      </div>
      {!canControl && perms.canOnHost('service.control', host) && (
        <p className="border-b px-3 py-2 text-xs text-muted-foreground">Service control is disabled by this host's local policy.</p>
      )}
      {inv.isPending ? (
        <TableSkeleton rows={10} cols={5} />
      ) : inv.isError ? (
        <ErrorState error={inv.error} onRetry={() => void inv.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState icon={CogIcon} title={units.length ? 'No matching units' : 'No service inventory yet'} />
      ) : (
        <Table>
          <THead>
            <TR className="hover:bg-transparent">
              <SortHeader sort={sort} k="name">Unit</SortHeader>
              <SortHeader sort={sort} k="active">State</SortHeader>
              <SortHeader sort={sort} k="fileState">Enabled</SortHeader>
              <TH>Description</TH>
              {canControl && <TH className="w-12"><span className="sr-only">Actions</span></TH>}
            </TR>
          </THead>
          <TBody>
            {rows.slice(0, 1000).map((u) => (
              <TR key={u.name}>
                <TD className="font-mono text-xs">{u.name}</TD>
                <TD>
                  <span className="inline-flex items-center gap-1.5">
                    <Badge variant={activeVariant(u.active)}>{u.active || 'unknown'}</Badge>
                    {u.sub && <span className="text-xs text-muted-foreground">{u.sub}</span>}
                  </span>
                </TD>
                <TD className="text-xs text-muted-foreground">{u.fileState || '–'}</TD>
                <TD className="max-w-96 truncate text-muted-foreground" title={u.description}>
                  {u.description}
                </TD>
                {canControl && (
                  <TD>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${u.name}`} disabled={!host.connected}>
                          <EllipsisIcon />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onSelect={() => request(u.name, 'restart')}>
                          <RotateCwIcon /> Restart
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => request(u.name, 'reload')}>
                          <RotateCwIcon /> Reload
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => request(u.name, 'start')}>
                          <PlayIcon /> Start
                        </DropdownMenuItem>
                        <DropdownMenuItem destructive onSelect={() => request(u.name, 'stop')}>
                          <SquareIcon /> Stop
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onSelect={() => request(u.name, 'enable')}>Enable at boot</DropdownMenuItem>
                        <DropdownMenuItem destructive onSelect={() => request(u.name, 'disable')}>
                          Disable at boot
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TD>
                )}
              </TR>
            ))}
          </TBody>
        </Table>
      )}
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending ? `${pending.op[0]?.toUpperCase()}${pending.op.slice(1)} ${pending.unit}?` : ''}
        description={`This runs "systemctl ${pending?.op ?? ''} ${pending?.unit ?? ''}" on ${host.hostname} as a signed job.`}
        confirmLabel={pending ? `${pending.op[0]?.toUpperCase()}${pending.op.slice(1)}` : 'Confirm'}
        destructive={pending?.op === 'stop' || pending?.op === 'disable'}
        onConfirm={() => (pending ? run(pending.unit, pending.op) : undefined)}
      />
    </Card>
  );
}

import { useQuery } from '@tanstack/react-query';
import { ActivityIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { hostProcessesQuery } from '@/api/queries';
import { RelativeTime } from '@/components/common/RelativeTime';
import { SearchInput } from '@/components/common/SearchInput';
import { SortHeader } from '@/components/common/SortHeader';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, THead, TR } from '@/components/ui/table';
import { formatBytes, formatNumber } from '@/lib/format';
import { sortItems, useSort } from '@/lib/sort';
import { useHostId } from '../hostUtils';

export function ProcessesTab() {
  const hostId = useHostId();
  const q = useQuery(hostProcessesQuery(hostId));
  const [filter, setFilter] = useState('');
  const sort = useSort<'cpu' | 'rss' | 'pid' | 'name' | 'user'>('cpu', 'desc');

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const list = (q.data?.processes ?? []).filter(
      (p) => !needle || p.name.toLowerCase().includes(needle) || (p.cmdline ?? '').toLowerCase().includes(needle) || (p.user ?? '').toLowerCase().includes(needle),
    );
    return sortItems(
      list,
      (p) => {
        switch (sort.key) {
          case 'cpu':
            return p.cpu_percent;
          case 'rss':
            return p.rss_bytes;
          case 'pid':
            return p.pid;
          case 'name':
            return p.name;
          case 'user':
            return p.user;
        }
      },
      sort.dir,
    );
  }, [q.data, filter, sort.key, sort.dir]);

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-3 py-2">
        <SearchInput value={filter} onChange={setFilter} placeholder="Filter processes…" />
        {q.data && (
          <span className="text-xs text-muted-foreground">
            Top {q.data.processes.length}
            {q.data.total ? ` of ${formatNumber(q.data.total)} processes` : ''} · snapshot{' '}
            <RelativeTime value={q.data.collected_at} fallback="never" />
          </span>
        )}
      </div>
      {q.isPending ? (
        <TableSkeleton rows={10} cols={6} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState icon={ActivityIcon} title="No process snapshot" description="The agent sends the top processes every 60 seconds." />
      ) : (
        <Table>
          <THead>
            <TR className="hover:bg-transparent">
              <SortHeader sort={sort} k="pid">PID</SortHeader>
              <SortHeader sort={sort} k="name">Name</SortHeader>
              <SortHeader sort={sort} k="user">User</SortHeader>
              <SortHeader sort={sort} k="cpu" className="text-right">CPU</SortHeader>
              <SortHeader sort={sort} k="rss" className="text-right">Memory (RSS)</SortHeader>
              <TD className="h-8 text-xs font-medium text-muted-foreground">Command</TD>
            </TR>
          </THead>
          <TBody>
            {rows.map((p) => (
              <TR key={p.pid}>
                <TD className="font-mono text-xs text-muted-foreground">{p.pid}</TD>
                <TD className="font-medium">
                  {p.name}
                  {p.state && <span className="ml-1.5 text-xs text-muted-foreground">{p.state}</span>}
                </TD>
                <TD className="text-muted-foreground">{p.user || '–'}</TD>
                <TD className="text-right">{p.cpu_percent !== undefined ? `${p.cpu_percent.toFixed(1)} %` : '–'}</TD>
                <TD className="text-right">{formatBytes(p.rss_bytes)}</TD>
                <TD className="max-w-[28rem] truncate font-mono text-xs text-muted-foreground" title={p.cmdline}>
                  {p.cmdline || '–'}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </Card>
  );
}

import { useQuery } from '@tanstack/react-query';
import { PackageIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { hostPackagesQuery } from '@/api/queries';
import { SearchInput } from '@/components/common/SearchInput';
import { SortHeader } from '@/components/common/SortHeader';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, THead, TR } from '@/components/ui/table';
import { formatNumber } from '@/lib/format';
import { sortItems, useSort } from '@/lib/sort';
import { cn } from '@/lib/utils';
import { useHostId } from '../hostUtils';

const PAGE = 300;

export function PackagesTab() {
  const hostId = useHostId();
  const [q, setQ] = useState('');
  const [limit, setLimit] = useState(PAGE);
  const sort = useSort<'name' | 'version' | 'arch' | 'source'>('name');
  const pkgs = useQuery(hostPackagesQuery(hostId, q));

  const rows = useMemo(
    () => sortItems(pkgs.data ?? [], (p) => p[sort.key], sort.dir),
    [pkgs.data, sort.key, sort.dir],
  );

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-3 py-2">
        <SearchInput
          value={q}
          onChange={(v) => {
            setQ(v);
            setLimit(PAGE);
          }}
          debounce={300}
          placeholder="Search packages…"
        />
        <span className="text-xs text-muted-foreground">
          {pkgs.data ? `${formatNumber(pkgs.data.length)} packages${q ? ' matching' : ' installed'}` : ''}
        </span>
      </div>
      {pkgs.isPending ? (
        <TableSkeleton rows={10} cols={4} />
      ) : pkgs.isError ? (
        <ErrorState error={pkgs.error} onRetry={() => void pkgs.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState icon={PackageIcon} title={q ? 'No matching packages' : 'No package inventory yet'} />
      ) : (
        <div className={cn(pkgs.isFetching && pkgs.isPlaceholderData && 'opacity-60')}>
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <SortHeader sort={sort} k="name">Name</SortHeader>
                <SortHeader sort={sort} k="version">Version</SortHeader>
                <SortHeader sort={sort} k="arch">Arch</SortHeader>
                <SortHeader sort={sort} k="source">Source</SortHeader>
              </TR>
            </THead>
            <TBody>
              {rows.slice(0, limit).map((p) => (
                <TR key={`${p.name}/${p.arch}/${p.version}`}>
                  <TD className="font-medium">{p.name}</TD>
                  <TD className="font-mono text-xs">{p.version}</TD>
                  <TD className="text-muted-foreground">{p.arch}</TD>
                  <TD className="max-w-80 truncate text-muted-foreground" title={p.purl}>
                    {p.source || '–'}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
          {rows.length > limit && (
            <div className="border-t p-2 text-center">
              <Button variant="ghost" size="sm" onClick={() => setLimit((l) => l + PAGE)}>
                Show more ({formatNumber(rows.length - limit)} remaining)
              </Button>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

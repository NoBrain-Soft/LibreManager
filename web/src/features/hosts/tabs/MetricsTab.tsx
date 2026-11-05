import { useQuery, useQueryClient } from '@tanstack/react-query';
import { LineChartIcon, PauseIcon, PlayIcon, RefreshCwIcon } from 'lucide-react';
import { useState } from 'react';
import { qk } from '@/api/keys';
import { hostMetricsQuery, TIME_RANGES, type TimeRange } from '@/api/queries';
import type { MetricsPanel } from '@/api/types';
import { EmptyState, ErrorState } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/misc';
import { useNow } from '@/lib/now';
import { cn } from '@/lib/utils';
import { TimeSeriesChart } from '../../metrics/TimeSeriesChart';
import { useHostId } from '../hostUtils';

const PANELS: { panel: MetricsPanel; title: string; description: string }[] = [
  { panel: 'cpu', title: 'CPU', description: 'Utilization by mode' },
  { panel: 'load', title: 'Load average', description: '1, 5 and 15 minute load' },
  { panel: 'memory', title: 'Memory', description: 'Used, cached and available' },
  { panel: 'swap', title: 'Swap', description: 'Swap usage' },
  { panel: 'disk_usage', title: 'Disk usage', description: 'Per filesystem' },
  { panel: 'disk_io', title: 'Disk I/O', description: 'Throughput per device' },
  { panel: 'network', title: 'Network', description: 'Traffic per interface' },
  { panel: 'tcp', title: 'TCP', description: 'Connection states' },
  { panel: 'pressure', title: 'Pressure (PSI)', description: 'CPU, memory and I/O stall' },
];

export function MetricsTab() {
  const hostId = useHostId();
  const qc = useQueryClient();
  const [range, setRange] = useState<TimeRange>(TIME_RANGES[0] as TimeRange);
  const [live, setLive] = useState(true);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div role="radiogroup" aria-label="Time range" className="inline-flex rounded-md border bg-card p-0.5">
          {TIME_RANGES.map((r) => (
            <button
              key={r.key}
              type="button"
              role="radio"
              aria-checked={r.key === range.key}
              onClick={() => setRange(r)}
              className={cn(
                'rounded px-2.5 py-1 text-xs font-medium tabular',
                r.key === range.key ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
              )}
            >
              {r.label}
            </button>
          ))}
        </div>
        <Button variant="outline" size="sm" onClick={() => setLive((v) => !v)} aria-pressed={live}>
          {live ? <PauseIcon /> : <PlayIcon />} {live ? 'Auto-refresh 30 s' : 'Paused'}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void qc.invalidateQueries({ queryKey: [...qk.host(hostId), 'metrics'] })}
        >
          <RefreshCwIcon /> Refresh
        </Button>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {PANELS.map((p) => (
          <PanelCard key={p.panel} hostId={hostId} {...p} range={range} live={live} />
        ))}
      </div>
    </div>
  );
}

function PanelCard({
  hostId,
  panel,
  title,
  description,
  range,
  live,
}: {
  hostId: string;
  panel: MetricsPanel;
  title: string;
  description: string;
  range: TimeRange;
  live: boolean;
}) {
  const q = useQuery({ ...hostMetricsQuery(hostId, panel, range), refetchInterval: live ? 30_000 : false });
  const now = useNow();
  const end = Math.floor((q.dataUpdatedAt || now) / 1000);
  const hasPoints = (q.data?.series ?? []).some((s) => s.points.length > 0);

  return (
    <Card>
      <CardHeader className="py-2.5">
        <div>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className={cn('pt-3', q.isFetching && q.isPlaceholderData && 'opacity-60 transition-opacity')}>
        {q.isPending ? (
          <Skeleton className="h-[230px] w-full" />
        ) : q.isError && !q.data ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
        ) : !q.data || !hasPoints ? (
          <EmptyState icon={LineChartIcon} title="No data in this range" description="The agent may be offline or the collector disabled." className="py-12" />
        ) : (
          <TimeSeriesChart data={q.data} range={[end - range.seconds, end]} />
        )}
      </CardContent>
    </Card>
  );
}

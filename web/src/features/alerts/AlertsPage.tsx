import { useQuery } from '@tanstack/react-query';
import { getRouteApi, Link } from '@tanstack/react-router';
import { BellOffIcon } from 'lucide-react';
import { useMemo } from 'react';
import { alertsQuery } from '@/api/queries';
import { AlertStatusBadge, SeverityBadge } from '@/components/common/badges';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { durationBetween, formatElapsed, parseDate } from '@/lib/format';
import { useNow } from '@/lib/now';
import { severityRank } from '@/lib/status';
import { cn } from '@/lib/utils';

const route = getRouteApi('/app/alerts');

const HIDDEN_LABELS = new Set(['alertname', 'severity', 'host_id', 'hostname']);

export function AlertsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const status = search.status ?? 'firing';
  const q = useQuery(alertsQuery(status));
  const now = useNow();

  const rows = useMemo(
    () =>
      [...(q.data ?? [])].sort(
        (a, b) =>
          Number(b.status === 'firing') - Number(a.status === 'firing') ||
          severityRank(b.severity) - severityRank(a.severity) ||
          (parseDate(b.starts_at)?.getTime() ?? 0) - (parseDate(a.starts_at)?.getTime() ?? 0),
      ),
    [q.data],
  );

  return (
    <Page>
      <PageHeader title="Alerts" description="From vmalert/Alertmanager and built-in state alerts (e.g. host down)." />
      <div role="tablist" aria-label="Alert status" className="mb-3 inline-flex rounded-md border bg-card p-0.5">
        {(['firing', 'resolved', 'all'] as const).map((s) => (
          <button
            key={s}
            type="button"
            role="tab"
            aria-selected={status === s}
            onClick={() => void navigate({ search: { status: s }, replace: true })}
            className={cn(
              'rounded px-3 py-1 text-xs font-medium capitalize',
              status === s ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {s}
          </button>
        ))}
      </div>
      <Card className={cn(q.isFetching && q.isPlaceholderData && 'opacity-70')}>
        {q.isPending ? (
          <TableSkeleton rows={6} cols={6} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={BellOffIcon}
            title={status === 'firing' ? 'No alerts firing' : 'No alerts'}
            description={status === 'firing' ? 'Everything is quiet right now.' : undefined}
          />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Severity</TH>
                <TH>Alert</TH>
                <TH>Host</TH>
                <TH>Status</TH>
                <TH>Started</TH>
                <TH>Duration</TH>
                <TH>Labels</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((a) => {
                const labels = Object.entries(a.labels).filter(([k]) => !HIDDEN_LABELS.has(k));
                return (
                  <TR key={a.id}>
                    <TD>
                      <SeverityBadge severity={a.severity} />
                    </TD>
                    <TD className="max-w-[28rem]">
                      <div className="font-medium">{a.name}</div>
                      {a.summary && <div className="text-xs text-muted-foreground">{a.summary}</div>}
                    </TD>
                    <TD>
                      {a.host_id ? (
                        <Link to="/hosts/$hostId" params={{ hostId: a.host_id }} className="hover:text-primary hover:underline">
                          {a.hostname || 'host'}
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">{a.hostname || '–'}</span>
                      )}
                    </TD>
                    <TD>
                      <AlertStatusBadge status={a.status} />
                    </TD>
                    <TD>
                      <RelativeTime value={a.starts_at} />
                    </TD>
                    <TD className="text-muted-foreground">{formatElapsed(durationBetween(a.starts_at, a.ends_at, now))}</TD>
                    <TD className="max-w-80">
                      <div className="flex flex-wrap gap-1">
                        {labels.slice(0, 5).map(([k, v]) => (
                          <Badge key={k} variant="outline" className="max-w-56 truncate font-mono" title={`${k}=${v}`}>
                            {k}={v}
                          </Badge>
                        ))}
                        {labels.length > 5 && <Badge variant="outline">+{labels.length - 5}</Badge>}
                      </div>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>
    </Page>
  );
}

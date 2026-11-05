import { useQuery } from '@tanstack/react-query';
import { ChevronRightIcon, PlayIcon, ShieldCheckIcon } from 'lucide-react';
import { Fragment, useMemo, useState } from 'react';
import { hostChecksQuery } from '@/api/queries';
import type { CheckResult } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { CheckStatusBadge, SeverityBadge } from '@/components/common/badges';
import { RelativeTime } from '@/components/common/RelativeTime';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { NativeSelect } from '@/components/ui/input';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { severityRank } from '@/lib/status';
import { cn } from '@/lib/utils';
import { useCreateJob } from '../../jobs/useCreateJob';
import { useCurrentHost } from '../hostUtils';

const STATUS_RANK: Record<string, number> = { fail: 0, error: 1, warn: 2, pass: 3, na: 4 };

export function SecurityTab() {
  const { data: host } = useCurrentHost();
  const perms = usePermissions();
  const q = useQuery({ ...hostChecksQuery(host?.id ?? ''), enabled: !!host });
  const [status, setStatus] = useState<'problems' | 'all' | CheckResult['status']>('problems');
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const create = useCreateJob();

  const all = useMemo(() => q.data ?? [], [q.data]);
  const counts = useMemo(() => {
    const c = { pass: 0, fail: 0, warn: 0, na: 0, error: 0 };
    for (const r of all) if (r.status in c) c[r.status] += 1;
    return c;
  }, [all]);
  const rows = useMemo(
    () =>
      all
        .filter((r) => (status === 'all' ? true : status === 'problems' ? ['fail', 'warn', 'error'].includes(r.status) : r.status === status))
        .sort(
          (a, b) =>
            (STATUS_RANK[a.status] ?? 9) - (STATUS_RANK[b.status] ?? 9) ||
            severityRank(b.severity) - severityRank(a.severity) ||
            a.check_id.localeCompare(b.check_id),
        ),
    [all, status],
  );

  if (!host) return null;
  const applicable = counts.pass + counts.fail + counts.warn;
  const score = applicable > 0 ? Math.round((counts.pass / applicable) * 100) : null;
  const lastRun = all.map((r) => r.collected_at).filter(Boolean).sort().at(-1);

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="grid gap-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Stat label="Compliance" value={score === null ? '–' : `${score} %`} hint="passed / applicable" />
        <Stat label="Failed" value={counts.fail} tone={counts.fail > 0 ? 'critical' : undefined} />
        <Stat label="Warnings" value={counts.warn} tone={counts.warn > 0 ? 'warning' : undefined} />
        <Stat label="Passed" value={counts.pass} />
        <Stat label="Errors / N/A" value={`${counts.error} / ${counts.na}`} />
      </div>
      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
          <NativeSelect aria-label="Status filter" className="w-44" value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
            <option value="problems">Problems only</option>
            <option value="all">All checks</option>
            <option value="fail">Failed</option>
            <option value="warn">Warnings</option>
            <option value="pass">Passed</option>
            <option value="error">Errors</option>
            <option value="na">Not applicable</option>
          </NativeSelect>
          <div className="flex-1" />
          {lastRun && (
            <span className="text-xs text-muted-foreground">
              last run <RelativeTime value={lastRun} />
            </span>
          )}
          {perms.canOnHost('security.manage', host) && (
            <Button
              variant="outline"
              size="sm"
              disabled={!host.connected || create.isPending}
              onClick={() => create.mutate({ type: 'run_check', params: {}, targets: { host_ids: [host.id] } })}
            >
              <PlayIcon /> Run checks now
            </Button>
          )}
        </div>
        {q.isPending ? (
          <TableSkeleton rows={8} cols={4} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={ShieldCheckIcon}
            title={all.length === 0 ? 'No check results yet' : 'No problems found'}
            description={all.length === 0 ? 'Checks run daily on each host.' : 'All applicable checks passed.'}
          />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH className="w-8" />
                <TH>Check</TH>
                <TH>Status</TH>
                <TH>Severity</TH>
                <TH>Summary</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => {
                const expanded = open.has(r.check_id);
                const evidence = Object.entries(r.evidence ?? {});
                return (
                  <Fragment key={r.check_id}>
                    <TR className={cn(evidence.length > 0 && 'cursor-pointer')} onClick={() => evidence.length && toggle(r.check_id)}>
                      <TD>
                        {evidence.length > 0 && (
                          <button
                            type="button"
                            aria-expanded={expanded}
                            aria-label={`${expanded ? 'Hide' : 'Show'} evidence for ${r.check_id}`}
                            className="rounded p-0.5 hover:bg-accent"
                            onClick={(e) => {
                              e.stopPropagation();
                              toggle(r.check_id);
                            }}
                          >
                            <ChevronRightIcon className={cn('size-3.5 transition-transform', expanded && 'rotate-90')} />
                          </button>
                        )}
                      </TD>
                      <TD>
                        <div className="font-medium">{r.title}</div>
                        <div className="font-mono text-xs text-muted-foreground">{r.check_id}</div>
                      </TD>
                      <TD>
                        <CheckStatusBadge status={r.status} />
                      </TD>
                      <TD>
                        <SeverityBadge severity={r.severity} />
                      </TD>
                      <TD className="max-w-[32rem] text-muted-foreground">{r.summary || '–'}</TD>
                    </TR>
                    {expanded && (
                      <TR className="bg-muted/40 hover:bg-muted/40">
                        <TD />
                        <TD colSpan={4}>
                          <dl className="grid gap-x-4 gap-y-1 py-1 text-xs sm:grid-cols-[minmax(8rem,auto)_1fr]">
                            {evidence.map(([k, v]) => (
                              <div key={k} className="contents">
                                <dt className="text-muted-foreground">{k}</dt>
                                <dd className="whitespace-pre-wrap break-all font-mono">{v}</dd>
                              </div>
                            ))}
                          </dl>
                        </TD>
                      </TR>
                    )}
                  </Fragment>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}

function Stat({ label, value, hint, tone }: { label: string; value: string | number; hint?: string; tone?: 'critical' | 'warning' }) {
  return (
    <Card
      className={cn(
        'p-3',
        tone === 'critical' && 'border-l-[3px] border-l-critical',
        tone === 'warning' && 'border-l-[3px] border-l-warning',
      )}
    >
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
      {hint && <div className="text-[11px] text-muted-foreground">{hint}</div>}
    </Card>
  );
}

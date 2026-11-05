import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getRouteApi, Link } from '@tanstack/react-router';
import { BanIcon, ChevronLeftIcon, ServerIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { api } from '@/api/client';
import { useEventsStatus } from '@/api/events';
import { qk } from '@/api/keys';
import { jobQuery, jobTargetsQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { JobTarget } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { JobStatusBadge, TargetStatusBadge } from '@/components/common/badges';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { Page } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { EmptyState, ErrorState, LoadingState, TableSkeleton } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { durationBetween, formatElapsed, humanize } from '@/lib/format';
import { useNow } from '@/lib/now';
import { notifySuccess } from '@/lib/notify';
import { ACTIVE_TARGET_STATUSES, describeJob, jobTypeLabel } from '@/lib/status';
import { cn, str } from '@/lib/utils';
import { JobOutput } from './JobOutput';
import { JobProgress } from './JobsTable';

const route = getRouteApi('/app/jobs/$jobId');

const TARGET_ORDER: Record<string, number> = {
  running: 0,
  failed: 1,
  rejected: 2,
  timed_out: 3,
  dispatched: 4,
  queued: 5,
  expired: 6,
  canceled: 7,
  succeeded: 8,
};

export function JobDetailPage() {
  const { jobId } = route.useParams();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const perms = usePermissions();
  const qc = useQueryClient();
  const live = useEventsStatus() === 'open';
  const now = useNow();
  const [confirmCancel, setConfirmCancel] = useState(false);

  const job = useQuery({
    ...jobQuery(jobId),
    refetchInterval: (q) => (q.state.data?.status === 'running' ? (live ? 10_000 : 3000) : false),
  });
  const running = job.data?.status === 'running';
  const targets = useQuery({
    ...jobTargetsQuery(jobId),
    refetchInterval: (q) =>
      running || q.state.data?.some((t) => ACTIVE_TARGET_STATUSES.has(t.status)) ? (live ? 10_000 : 3000) : false,
  });

  const sorted = useMemo(
    () =>
      [...(targets.data ?? [])].sort(
        (a, b) => (TARGET_ORDER[a.status] ?? 9) - (TARGET_ORDER[b.status] ?? 9) || a.hostname.localeCompare(b.hostname),
      ),
    [targets.data],
  );
  const selected: JobTarget | undefined = sorted.find((t) => t.host_id === search.target) ?? sorted[0];

  if (job.isPending) return <LoadingState label="Loading job…" className="min-h-[40vh]" />;
  if (job.isError)
    return (
      <Page>
        <BackLink />
        <Card>
          <ErrorState error={job.error} onRetry={() => void job.refetch()} />
        </Card>
      </Page>
    );

  const j = job.data;
  const desc = describeJob(j.type, j.params);
  const params = Object.entries(j.params ?? {}).filter(([, v]) => v !== undefined && v !== null && !(Array.isArray(v) && v.length === 0));

  return (
    <Page>
      <BackLink />
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight">{jobTypeLabel(j.type)}</h1>
            <JobStatusBadge status={j.status} />
          </div>
          {desc && <p className="mt-0.5 text-sm text-muted-foreground">{desc}</p>}
          <div className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
            <span>by {j.requested_by}</span>
            <span>
              created <RelativeTime value={j.created_at} />
            </span>
            {j.finished_at && (
              <span>
                finished <RelativeTime value={j.finished_at} />
              </span>
            )}
            <span>duration {formatElapsed(durationBetween(j.created_at, j.finished_at, now))}</span>
            <span className="font-mono">{j.id}</span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-56">
            <JobProgress job={j} />
          </div>
          {running && perms.canAnywhere('job.cancel') && (
            <Button variant="outline" onClick={() => setConfirmCancel(true)}>
              <BanIcon /> Cancel
            </Button>
          )}
        </div>
      </div>

      {params.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-x-6 gap-y-1 rounded-md border bg-card px-3 py-2 text-xs">
          {params.map(([k, v]) => (
            <span key={k}>
              <span className="text-muted-foreground">{humanize(k)}:</span>{' '}
              <span className="font-mono">{Array.isArray(v) ? v.join(', ') : str(v)}</span>
            </span>
          ))}
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        <Card className="min-w-0">
          <CardHeader className="py-2.5">
            <CardTitle>Targets ({targets.data?.length ?? j.counts.total})</CardTitle>
          </CardHeader>
          {targets.isPending ? (
            <TableSkeleton rows={4} cols={3} />
          ) : targets.isError ? (
            <ErrorState error={targets.error} onRetry={() => void targets.refetch()} compact />
          ) : sorted.length === 0 ? (
            <EmptyState icon={ServerIcon} title="No targets" description="No host matched the job's targets." />
          ) : (
            <Table>
              <THead>
                <TR className="hover:bg-transparent">
                  <TH>Host</TH>
                  <TH>Status</TH>
                  <TH>Exit</TH>
                  <TH>Time</TH>
                </TR>
              </THead>
              <TBody>
                {sorted.map((t) => {
                  const isSel = selected?.host_id === t.host_id;
                  return (
                    <TR
                      key={t.host_id}
                      data-state={isSel ? 'selected' : undefined}
                      className={cn('cursor-pointer', isSel && 'bg-primary/6')}
                      onClick={() => void navigate({ search: { target: t.host_id }, replace: true })}
                    >
                      <TD className="max-w-44">
                        <button
                          type="button"
                          className="truncate text-left font-medium hover:text-primary"
                          aria-pressed={isSel}
                          onClick={(e) => {
                            e.stopPropagation();
                            void navigate({ search: { target: t.host_id }, replace: true });
                          }}
                        >
                          {t.hostname}
                        </button>
                        {t.message && (
                          <div className="truncate text-xs text-muted-foreground" title={t.message}>
                            {t.message}
                          </div>
                        )}
                      </TD>
                      <TD>
                        <TargetStatusBadge status={t.status} />
                      </TD>
                      <TD className={cn('font-mono text-xs', t.exit_code ? 'text-text-critical' : 'text-muted-foreground')}>
                        {t.exit_code ?? '–'}
                      </TD>
                      <TD className="text-xs text-muted-foreground">
                        {t.started_at ? formatElapsed(durationBetween(t.started_at, t.finished_at, now)) : '–'}
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </Card>

        <Card className="min-w-0 overflow-hidden">
          {selected ? (
            <>
              <CardHeader className="py-2.5">
                <div className="min-w-0">
                  <CardTitle className="flex items-center gap-2">
                    <Link to="/hosts/$hostId" params={{ hostId: selected.host_id }} className="hover:text-primary hover:underline">
                      {selected.hostname}
                    </Link>
                    <TargetStatusBadge status={selected.status} />
                  </CardTitle>
                  {selected.message && <p className="mt-0.5 text-xs text-muted-foreground">{selected.message}</p>}
                </div>
                <div className="text-right text-xs text-muted-foreground">
                  {selected.started_at && (
                    <div>
                      started <RelativeTime value={selected.started_at} />
                    </div>
                  )}
                  {selected.exit_code !== null && selected.exit_code !== undefined && <div>exit code {selected.exit_code}</div>}
                </div>
              </CardHeader>
              <JobOutput
                key={`${jobId}/${selected.host_id}`}
                jobId={jobId}
                hostId={selected.host_id}
                hostname={selected.hostname}
                active={ACTIVE_TARGET_STATUSES.has(selected.status)}
              />
            </>
          ) : (
            <EmptyState title="Select a target" description="Pick a host to see its output." />
          )}
        </Card>
      </div>

      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title="Cancel this job?"
        description="Queued targets are not started. Targets that are already running may finish their current step."
        confirmLabel="Cancel job"
        destructive
        onConfirm={async () => {
          await request(() => api.POST('/jobs/{jobId}/cancel', { params: { path: { jobId } } }));
          void qc.invalidateQueries({ queryKey: qk.job(jobId) });
          void qc.invalidateQueries({ queryKey: qk.jobsRoot });
          notifySuccess('Cancel requested');
        }}
      />
    </Page>
  );
}

function BackLink() {
  return (
    <Link to="/jobs" className="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
      <ChevronLeftIcon className="size-3.5" /> Jobs
    </Link>
  );
}

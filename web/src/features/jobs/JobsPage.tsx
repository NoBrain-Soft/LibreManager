import { useQuery } from '@tanstack/react-query';
import { ListChecksIcon, PlusIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useEventsStatus } from '@/api/events';
import { jobsQuery } from '@/api/queries';
import type { JobStatus } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { SearchInput } from '@/components/common/SearchInput';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { NativeSelect } from '@/components/ui/input';
import { describeJob, jobTypeLabel } from '@/lib/status';
import { cn } from '@/lib/utils';
import { JOB_PERMISSION, JOB_TYPES } from './jobForm';
import { JobsTable } from './JobsTable';
import { NewJobDialog } from './NewJobDialog';

export function JobsPage() {
  const perms = usePermissions();
  const live = useEventsStatus() === 'open';
  const [limit, setLimit] = useState(100);
  const [status, setStatus] = useState<JobStatus | ''>('');
  const [filter, setFilter] = useState('');
  const [open, setOpen] = useState(false);
  const q = useQuery({
    ...jobsQuery({ limit }),
    refetchInterval: (query) => (query.state.data?.some((j) => j.status === 'running') ? (live ? 15_000 : 4000) : 30_000),
  });

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return (q.data ?? []).filter(
      (j) =>
        (!status || j.status === status) &&
        (!needle ||
          jobTypeLabel(j.type).toLowerCase().includes(needle) ||
          describeJob(j.type, j.params).toLowerCase().includes(needle) ||
          j.requested_by.toLowerCase().includes(needle)),
    );
  }, [q.data, status, filter]);

  const canCreate = JOB_TYPES.some((t) => perms.canAnywhere(JOB_PERMISSION[t]));

  return (
    <Page>
      <PageHeader
        title="Jobs"
        description="Signed actions executed on hosts, newest first."
        actions={
          canCreate && (
            <Button onClick={() => setOpen(true)}>
              <PlusIcon /> New job
            </Button>
          )
        }
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={filter} onChange={setFilter} placeholder="Filter by type, package, user…" />
        <NativeSelect aria-label="Status" className="w-40" value={status} onChange={(e) => setStatus(e.target.value as JobStatus | '')}>
          <option value="">Any status</option>
          <option value="running">Running</option>
          <option value="succeeded">Succeeded</option>
          <option value="partial">Partial</option>
          <option value="failed">Failed</option>
          <option value="canceled">Canceled</option>
        </NativeSelect>
      </div>
      <Card className={cn(q.isFetching && q.isPlaceholderData && 'opacity-70')}>
        {q.isPending ? (
          <TableSkeleton rows={8} cols={6} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={ListChecksIcon}
            title={q.data.length ? 'No jobs match the filters' : 'No jobs yet'}
            description={q.data.length ? undefined : 'Start a job from a host, the updates view, or with “New job”.'}
          />
        ) : (
          <>
            <JobsTable jobs={rows} />
            {q.data.length >= limit && limit < 500 && (
              <div className="border-t p-2 text-center">
                <Button variant="ghost" size="sm" onClick={() => setLimit((l) => Math.min(500, l + 100))}>
                  Load older jobs
                </Button>
              </div>
            )}
          </>
        )}
      </Card>
      <NewJobDialog open={open} onOpenChange={setOpen} />
    </Page>
  );
}

import { useQuery } from '@tanstack/react-query';
import { ListChecksIcon, PlusIcon } from 'lucide-react';
import { useState } from 'react';
import { jobsQuery } from '@/api/queries';
import { usePermissions } from '@/auth/usePermissions';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { JobsTable } from '../../jobs/JobsTable';
import { NewJobDialog } from '../../jobs/NewJobDialog';
import { useHostId } from '../hostUtils';

export function JobsTab() {
  const hostId = useHostId();
  const perms = usePermissions();
  const [limit, setLimit] = useState(50);
  const [open, setOpen] = useState(false);
  const q = useQuery({
    ...jobsQuery({ host_id: hostId, limit }),
    refetchInterval: (query) => (query.state.data?.some((j) => j.status === 'running') ? 5000 : 30_000),
  });

  return (
    <Card>
      <div className="flex items-center justify-between border-b px-3 py-2">
        <span className="text-sm font-medium">Jobs on this host</span>
        <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
          <PlusIcon /> New job
        </Button>
      </div>
      {q.isPending ? (
        <TableSkeleton rows={5} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : q.data.length === 0 ? (
        <EmptyState icon={ListChecksIcon} title="No jobs for this host yet" />
      ) : (
        <>
          <JobsTable jobs={q.data} />
          {q.data.length >= limit && limit < 500 && (
            <div className="border-t p-2 text-center">
              <Button variant="ghost" size="sm" onClick={() => setLimit((l) => Math.min(500, l + 100))}>
                Load more
              </Button>
            </div>
          )}
        </>
      )}
      {perms.session && <NewJobDialog open={open} onOpenChange={setOpen} preset={{ hostIds: [hostId] }} />}
    </Card>
  );
}

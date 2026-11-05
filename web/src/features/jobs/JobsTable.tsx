import { Link } from '@tanstack/react-router';
import type { Job } from '@/api/types';
import { JobStatusBadge } from '@/components/common/badges';
import { RelativeTime } from '@/components/common/RelativeTime';
import { Progress } from '@/components/ui/misc';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { durationBetween, formatElapsed } from '@/lib/format';
import { useNow } from '@/lib/now';
import { describeJob, jobTypeLabel } from '@/lib/status';

export function JobProgress({ job }: { job: Job }) {
  const c = job.counts;
  const done = c.succeeded + c.failed;
  const other = Math.max(0, c.total - done - c.running - c.queued);
  return (
    <div className="grid min-w-32 gap-1">
      <Progress
        value={done + other}
        max={Math.max(1, c.total)}
        tone={c.failed > 0 ? 'warning' : job.status === 'succeeded' ? 'good' : 'primary'}
        label="Job progress"
      />
      <div className="flex gap-2 text-xs text-muted-foreground tabular">
        <span>
          {done}/{c.total} done
        </span>
        {c.running > 0 && <span>{c.running} running</span>}
        {c.failed > 0 && <span className="text-text-critical">{c.failed} failed</span>}
      </div>
    </div>
  );
}

export function JobsTable({ jobs, compact }: { jobs: readonly Job[]; compact?: boolean }) {
  const now = useNow();
  return (
    <Table>
      <THead>
        <TR className="hover:bg-transparent">
          <TH>Job</TH>
          <TH>Status</TH>
          <TH>Progress</TH>
          {!compact && <TH>Requested by</TH>}
          <TH>Created</TH>
          {!compact && <TH>Duration</TH>}
        </TR>
      </THead>
      <TBody>
        {jobs.map((job) => {
          const desc = describeJob(job.type, job.params);
          return (
            <TR key={job.id}>
              <TD className="max-w-80">
                <Link
                  to="/jobs/$jobId"
                  params={{ jobId: job.id }}
                  className="font-medium text-foreground hover:text-primary hover:underline"
                >
                  {jobTypeLabel(job.type)}
                </Link>
                {desc && <div className="truncate text-xs text-muted-foreground">{desc}</div>}
              </TD>
              <TD>
                <JobStatusBadge status={job.status} />
              </TD>
              <TD>
                <JobProgress job={job} />
              </TD>
              {!compact && <TD className="text-muted-foreground">{job.requested_by}</TD>}
              <TD>
                <RelativeTime value={job.created_at} />
              </TD>
              {!compact && (
                <TD className="text-muted-foreground">{formatElapsed(durationBetween(job.created_at, job.finished_at, now))}</TD>
              )}
            </TR>
          );
        })}
      </TBody>
    </Table>
  );
}

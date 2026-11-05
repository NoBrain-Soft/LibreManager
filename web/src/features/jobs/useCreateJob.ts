import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { api } from '@/api/client';
import { qk } from '@/api/keys';
import { request } from '@/api/request';
import type { Job, JobCreate } from '@/api/types';
import { notifyError } from '@/lib/notify';
import { jobTypeLabel } from '@/lib/status';
import { toast } from '@/lib/toast';
import { pluralize } from '@/lib/utils';

/** POST /jobs with step-up handling, cache updates and a "View job" toast. */
export function useCreateJob(opts: { navigateOnSuccess?: boolean } = {}) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return useMutation({
    mutationFn: (body: JobCreate): Promise<Job> => request(() => api.POST('/jobs', { body })),
    onSuccess: (job) => {
      qc.setQueryData(qk.job(job.id), job);
      void qc.invalidateQueries({ queryKey: qk.jobsRoot });
      void qc.invalidateQueries({ queryKey: qk.dashboard });
      const open = () => void navigate({ to: '/jobs/$jobId', params: { jobId: job.id } });
      toast({
        title: `${jobTypeLabel(job.type)} started`,
        description: `${pluralize(job.counts.total, 'target host')}`,
        variant: 'success',
        action: { label: 'View job', onClick: open },
      });
      if (opts.navigateOnSuccess) open();
    },
    onError: (e) => notifyError(e, 'Could not start the job'),
  });
}

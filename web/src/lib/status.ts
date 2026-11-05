import type { JobParams, JobType } from '@/api/types';

/** Target states that may still produce output or change. */
export const ACTIVE_TARGET_STATUSES: ReadonlySet<string> = new Set(['queued', 'dispatched', 'running']);

export const SEVERITY_RANK: Readonly<Record<string, number>> = {
  critical: 5,
  high: 4,
  serious: 4,
  warning: 3,
  medium: 3,
  low: 2,
  info: 1,
};

export function severityRank(s: string | undefined): number {
  return SEVERITY_RANK[(s ?? '').toLowerCase()] ?? 0;
}

export const JOB_TYPE_LABELS: Readonly<Record<JobType, string>> = {
  pkg_refresh: 'Refresh package lists',
  pkg_upgrade: 'Upgrade packages',
  pkg_install: 'Install packages',
  pkg_remove: 'Remove packages',
  service: 'Service action',
  reboot: 'Reboot',
  run_check: 'Run security checks',
  collect_inventory: 'Collect inventory',
};

export function jobTypeLabel(t: string): string {
  return JOB_TYPE_LABELS[t as JobType] ?? t;
}

/** One-line description of job params for lists. */
export function describeJob(type: string, params: JobParams | undefined): string {
  const p = params ?? {};
  switch (type) {
    case 'pkg_upgrade':
      if (p.scope === 'security') return 'Security updates only';
      if (p.scope === 'named') return listPreview(p.packages);
      return 'All available updates';
    case 'pkg_install':
    case 'pkg_remove':
      return listPreview(p.packages);
    case 'service':
      return [p.op, p.unit].filter(Boolean).join(' ');
    case 'reboot':
      return [p.delay_s ? `in ${p.delay_s}s` : 'now', p.message ? `“${p.message}”` : ''].filter(Boolean).join(' ');
    case 'run_check':
      return p.check_ids?.length ? listPreview(p.check_ids) : 'All checks';
    default:
      return '';
  }
}

function listPreview(items: readonly string[] | undefined, max = 3): string {
  if (!items || items.length === 0) return '';
  const head = items.slice(0, max).join(', ');
  return items.length > max ? `${head} +${items.length - max}` : head;
}

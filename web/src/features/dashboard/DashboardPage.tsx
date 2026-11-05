import { useQuery } from '@tanstack/react-query';
import { Link, type LinkProps } from '@tanstack/react-router';
import {
  BellIcon,
  CircleDotIcon,
  FileBadgeIcon,
  ListChecksIcon,
  type LucideIcon,
  PackageIcon,
  RotateCwIcon,
  ServerIcon,
  ShieldAlertIcon,
  UnplugIcon,
} from 'lucide-react';
import { dashboardQuery } from '@/api/queries';
import type { Dashboard } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Card, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/misc';
import { formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';
import { JobsTable } from '../jobs/JobsTable';

type Tone = 'neutral' | 'good' | 'warning' | 'serious' | 'critical';

interface TileSpec {
  label: string;
  value: (d: Dashboard) => number;
  icon: LucideIcon;
  /** Tone when value > 0. */
  tone: Tone;
  hint: (d: Dashboard, v: number) => string;
  link?: LinkProps;
}

const TILES: TileSpec[] = [
  {
    label: 'Hosts',
    value: (d) => d.hosts_total,
    icon: ServerIcon,
    tone: 'neutral',
    hint: (d) => `${formatNumber(d.hosts_connected)} connected`,
    link: { to: '/hosts' },
  },
  {
    label: 'Connected',
    value: (d) => d.hosts_connected,
    icon: CircleDotIcon,
    tone: 'good',
    hint: (d) => (d.hosts_total ? `${Math.round((d.hosts_connected / d.hosts_total) * 100)} % of fleet` : 'No hosts yet'),
    link: { to: '/hosts', search: { conn: 'connected' } },
  },
  {
    label: 'Offline',
    value: (d) => d.hosts_offline,
    icon: UnplugIcon,
    tone: 'serious',
    hint: (_d, v) => (v ? 'Not reporting' : 'All agents reporting'),
    link: { to: '/hosts', search: { conn: 'offline' } },
  },
  {
    label: 'Hosts with pending updates',
    value: (d) => d.updates_pending_hosts,
    icon: PackageIcon,
    tone: 'warning',
    hint: (_d, v) => (v ? 'Updates available' : 'Everything up to date'),
    link: { to: '/updates' },
  },
  {
    label: 'Security updates',
    value: (d) => d.security_updates,
    icon: ShieldAlertIcon,
    tone: 'critical',
    hint: (_d, v) => (v ? 'Pending across the fleet' : 'None pending'),
    link: { to: '/updates' },
  },
  {
    label: 'Reboot required',
    value: (d) => d.reboot_required,
    icon: RotateCwIcon,
    tone: 'warning',
    hint: (_d, v) => (v ? 'Hosts need a restart' : 'No reboots pending'),
    link: { to: '/hosts', search: { updates: 'reboot' } },
  },
  {
    label: 'Firing alerts',
    value: (d) => d.alerts_firing,
    icon: BellIcon,
    tone: 'critical',
    hint: (_d, v) => (v ? 'Need attention' : 'All quiet'),
    link: { to: '/alerts', search: { status: 'firing' } },
  },
  {
    label: 'Expiring certificates',
    value: (d) => d.expiring_certs,
    icon: FileBadgeIcon,
    tone: 'warning',
    hint: (_d, v) => (v ? 'Agent certs expire soon' : 'No expiring certs'),
    link: { to: '/hosts' },
  },
];

const toneIcon: Record<Tone, string> = {
  neutral: 'text-muted-foreground',
  good: 'text-good',
  warning: 'text-text-warning',
  serious: 'text-serious',
  critical: 'text-critical',
};

function Tile({ spec, data }: { spec: TileSpec; data: Dashboard }) {
  const v = spec.value(data);
  const Icon = spec.icon;
  const active = v > 0;
  const body = (
    <Card
      className={cn(
        'flex h-full flex-col gap-1 p-3.5 transition-colors',
        spec.link && 'hover:border-ring/50 hover:bg-accent/40',
        active && spec.tone !== 'neutral' && spec.tone !== 'good' && 'border-l-[3px]',
        active && spec.tone === 'critical' && 'border-l-critical',
        active && spec.tone === 'serious' && 'border-l-serious',
        active && spec.tone === 'warning' && 'border-l-warning',
      )}
    >
      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>{spec.label}</span>
        <Icon className={cn('size-4', active ? toneIcon[spec.tone] : 'text-muted-foreground/60')} aria-hidden />
      </div>
      <div className="text-2xl font-semibold leading-tight">{formatNumber(v)}</div>
      <div className="text-xs text-muted-foreground">{spec.hint(data, v)}</div>
    </Card>
  );
  return spec.link ? (
    <Link {...spec.link} className="block rounded-lg focus-visible:outline-2 focus-visible:outline-ring">
      {body}
    </Link>
  ) : (
    body
  );
}

export function DashboardPage() {
  const q = useQuery(dashboardQuery);
  const perms = usePermissions();
  const name = perms.session?.user.display_name || perms.session?.user.username;

  return (
    <Page>
      <PageHeader title="Dashboard" description={name ? `Fleet overview for ${name}` : 'Fleet overview'} />
      {q.isError && !q.data ? (
        <Card>
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        </Card>
      ) : (
        <>
          <section aria-label="Fleet status" className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {q.data
              ? TILES.map((t) => <Tile key={t.label} spec={t} data={q.data} />)
              : TILES.map((t) => <Skeleton key={t.label} className="h-[92px] rounded-lg" />)}
          </section>

          <Card className="mt-5">
            <CardHeader>
              <CardTitle>Recent jobs</CardTitle>
              {perms.canAnywhere('job.view') && (
                <Link to="/jobs" className="text-xs text-primary hover:underline">
                  All jobs
                </Link>
              )}
            </CardHeader>
            {!q.data ? (
              <TableSkeleton rows={4} />
            ) : (q.data.recent_jobs ?? []).length === 0 ? (
              <EmptyState icon={ListChecksIcon} title="No jobs yet" description="Jobs you start on hosts show up here." />
            ) : (
              <JobsTable jobs={q.data.recent_jobs ?? []} compact />
            )}
          </Card>
        </>
      )}
    </Page>
  );
}

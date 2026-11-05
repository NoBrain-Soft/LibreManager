import { useQuery } from '@tanstack/react-query';
import { getRouteApi, Link } from '@tanstack/react-router';
import { DatabaseIcon } from 'lucide-react';
import { hostInventoryQuery } from '@/api/queries';
import type { InventorySection } from '@/api/types';
import { RelativeTime } from '@/components/common/RelativeTime';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { humanize } from '@/lib/format';
import { asArray, cn, field, str } from '@/lib/utils';
import { useHostId } from '../hostUtils';
import { SectionView } from '../inventory/SectionView';

const route = getRouteApi('/app/hosts/$hostId/inventory');

const ORDER = ['os', 'hardware', 'network', 'services', 'ports', 'users', 'scheduled', 'containers', 'ssh_host_keys', 'certificates', 'agent', 'packages'];

const TITLES: Record<string, string> = {
  os: 'Operating system',
  hardware: 'Hardware',
  network: 'Network',
  services: 'Services',
  ports: 'Listening ports',
  users: 'Users & groups',
  scheduled: 'Scheduled tasks',
  containers: 'Containers',
  ssh_host_keys: 'SSH host keys',
  certificates: 'TLS certificates',
  agent: 'Agent',
  packages: 'Packages',
};

function sortSections(keys: string[]): string[] {
  return [...keys].sort((a, b) => {
    const ia = ORDER.indexOf(a);
    const ib = ORDER.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || a.localeCompare(b);
  });
}

export function InventoryTab() {
  const hostId = useHostId();
  const search = route.useSearch();
  const q = useQuery(hostInventoryQuery(hostId));

  if (q.isPending) return <Card><TableSkeleton rows={8} cols={3} /></Card>;
  if (q.isError) return <Card><ErrorState error={q.error} onRetry={() => void q.refetch()} /></Card>;

  const sections = q.data.sections;
  const keys = sortSections(Object.keys(sections));
  if (keys.length === 0) {
    return (
      <Card>
        <EmptyState icon={DatabaseIcon} title="No inventory yet" description="The agent sends a full inventory on start and every 6 hours." />
      </Card>
    );
  }
  const active = search.section && sections[search.section] ? search.section : (keys[0] as string);
  const section = sections[active] as InventorySection;

  return (
    <div className="grid gap-4 lg:grid-cols-[13rem_minmax(0,1fr)]">
      <nav aria-label="Inventory sections" className="flex gap-1 overflow-x-auto lg:flex-col">
        {keys.map((k) => (
          <Link
            key={k}
            from="/hosts/$hostId/inventory"
            search={{ section: k }}
            replace
            className={cn(
              'whitespace-nowrap rounded-md px-2.5 py-1.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground',
              k === active && 'bg-accent font-medium text-foreground',
            )}
            aria-current={k === active ? 'true' : undefined}
          >
            {TITLES[k] ?? humanize(k)}
          </Link>
        ))}
      </nav>
      <Card className="min-w-0">
        <CardHeader>
          <CardTitle>{TITLES[active] ?? humanize(active)}</CardTitle>
          <span className="text-xs text-muted-foreground">
            collected <RelativeTime value={section.collected_at} />
          </span>
        </CardHeader>
        <CardContent>
          {active === 'packages' ? (
            <p className="text-sm text-muted-foreground">
              {asArray(field(section.data, 'packages')).length} packages ({str(field(section.data, 'manager')) || 'unknown manager'}).{' '}
              <Link to="/hosts/$hostId/packages" params={{ hostId }} className="text-primary hover:underline">
                Open the Packages tab
              </Link>{' '}
              to search them.
            </p>
          ) : (
            <SectionView data={section.data} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

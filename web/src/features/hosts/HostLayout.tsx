import { useQuery } from '@tanstack/react-query';
import { Link, Outlet } from '@tanstack/react-router';
import { ChevronLeftIcon, RotateCwIcon, TerminalIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { hostQuery } from '@/api/queries';
import { usePermissions } from '@/auth/usePermissions';
import { ConnectionBadge, RebootBadge } from '@/components/common/badges';
import { Page } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { ErrorState, LoadingState } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { osLabel, policyFlag, useHostId } from './hostUtils';

type HostTabPath =
  | '/hosts/$hostId'
  | '/hosts/$hostId/metrics'
  | '/hosts/$hostId/inventory'
  | '/hosts/$hostId/packages'
  | '/hosts/$hostId/updates'
  | '/hosts/$hostId/services'
  | '/hosts/$hostId/processes'
  | '/hosts/$hostId/security'
  | '/hosts/$hostId/jobs'
  | '/hosts/$hostId/shell';

const tabClass =
  'relative -mb-px inline-flex h-9 items-center gap-1.5 whitespace-nowrap border-b-2 border-transparent px-3 text-sm text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring';
const activeTab = { className: '!border-primary !text-foreground font-medium', 'aria-current': 'page' as const };

export function HostLayout() {
  const hostId = useHostId();
  const host = useQuery(hostQuery(hostId));
  const perms = usePermissions();

  if (host.isPending) return <LoadingState label="Loading host…" className="min-h-[40vh]" />;
  if (host.isError)
    return (
      <Page>
        <BackLink />
        <Card>
          <ErrorState error={host.error} onRetry={() => void host.refetch()} />
        </Card>
      </Page>
    );

  const h = host.data;
  const shellAllowed = perms.canOnHost('shell.open', h) && policyFlag(h, 'shell') !== false;
  const updates = h.updates?.total ?? 0;
  const security = h.updates?.security ?? 0;

  const tab = (to: HostTabPath, label: ReactNode, exact = false) => ({ to, label, exact });
  const tabs = [
    tab('/hosts/$hostId', 'Overview', true),
    tab('/hosts/$hostId/metrics', 'Metrics'),
    tab('/hosts/$hostId/inventory', 'Inventory'),
    tab('/hosts/$hostId/packages', 'Packages'),
    tab(
      '/hosts/$hostId/updates',
      <>
        Updates
        {updates > 0 && (
          <Badge variant={security > 0 ? 'critical' : 'secondary'} className="px-1 leading-4">
            {updates}
          </Badge>
        )}
      </>,
    ),
    tab('/hosts/$hostId/services', 'Services'),
    tab('/hosts/$hostId/processes', 'Processes'),
    ...(perms.canOnHost('security.view', h) ? [tab('/hosts/$hostId/security', 'Security')] : []),
    ...(perms.canOnHost('job.view', h) ? [tab('/hosts/$hostId/jobs', 'Jobs')] : []),
    ...(shellAllowed ? [tab('/hosts/$hostId/shell', 'Shell')] : []),
  ];

  return (
    <Page className="pb-8">
      <BackLink />
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="truncate text-lg font-semibold tracking-tight">{h.hostname}</h1>
            <ConnectionBadge connected={h.connected} status={h.status} />
            {h.updates?.reboot_required && <RebootBadge />}
          </div>
          <div className="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
            {h.fqdn && h.fqdn !== h.hostname && <span>{h.fqdn}</span>}
            {h.primary_ip && <span className="font-mono">{h.primary_ip}</span>}
            <span>{osLabel(h)}</span>
            {h.agent_version && <span>agent {h.agent_version}</span>}
            <span>
              last seen <RelativeTime value={h.last_seen_at} fallback="never" />
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void host.refetch()} disabled={host.isFetching} aria-label="Reload host">
            <RotateCwIcon className={cn(host.isFetching && 'animate-spin')} />
          </Button>
          {shellAllowed && (
            <Button asChild size="sm" disabled={!h.connected}>
              <Link to="/hosts/$hostId/shell" params={{ hostId }}>
                <TerminalIcon /> Shell
              </Link>
            </Button>
          )}
        </div>
      </div>

      <nav aria-label="Host sections" className="mb-4 flex overflow-x-auto border-b scrollbar-thin">
        {tabs.map((t) => (
          <Link
            key={t.to}
            to={t.to}
            params={{ hostId }}
            activeOptions={{ exact: t.exact, includeSearch: false }}
            className={tabClass}
            activeProps={activeTab}
          >
            {t.label}
          </Link>
        ))}
      </nav>
      <Outlet />
    </Page>
  );
}

function BackLink() {
  return (
    <Link to="/hosts" className="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
      <ChevronLeftIcon className="size-3.5" /> Hosts
    </Link>
  );
}

import { keepPreviousData, queryOptions } from '@tanstack/react-query';
import { chooseStep } from '@/lib/format';
import { nowSeconds } from '@/lib/now';
import { api, call } from './client';
import { qk } from './keys';
import type { HostStatus, MetricsPanel } from './types';

function clean<T extends Record<string, unknown>>(q: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== null && v !== '') (out as Record<string, unknown>)[k] = v;
  }
  return out;
}

export const systemInfoQuery = queryOptions({
  queryKey: qk.systemInfo,
  queryFn: ({ signal }) => call(api.GET('/system/info', { signal })),
  staleTime: 5 * 60_000,
});

export const settingsQuery = queryOptions({
  queryKey: qk.settings,
  queryFn: ({ signal }) => call(api.GET('/settings', { signal })),
  staleTime: 60_000,
});

export const dashboardQuery = queryOptions({
  queryKey: qk.dashboard,
  queryFn: ({ signal }) => call(api.GET('/dashboard', { signal })),
  refetchInterval: 30_000,
});

export interface HostFilters {
  q?: string;
  status?: HostStatus;
  group_id?: string;
}

export const hostsQuery = (f: HostFilters = {}) =>
  queryOptions({
    queryKey: qk.hosts(f),
    queryFn: ({ signal }) => call(api.GET('/hosts', { params: { query: clean({ ...f }) }, signal })),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  });

export const hostQuery = (hostId: string) =>
  queryOptions({
    queryKey: qk.host(hostId),
    queryFn: ({ signal }) => call(api.GET('/hosts/{hostId}', { params: { path: { hostId } }, signal })),
    refetchInterval: 60_000,
  });

export const hostInventoryQuery = (hostId: string) =>
  queryOptions({
    queryKey: qk.hostInventory(hostId),
    queryFn: ({ signal }) => call(api.GET('/hosts/{hostId}/inventory', { params: { path: { hostId } }, signal })),
    staleTime: 60_000,
  });

export const hostPackagesQuery = (hostId: string, q: string) =>
  queryOptions({
    queryKey: qk.hostPackages(hostId, q),
    queryFn: ({ signal }) =>
      call(api.GET('/hosts/{hostId}/packages', { params: { path: { hostId }, query: clean({ q }) }, signal })),
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });

export const hostUpdatesQuery = (hostId: string) =>
  queryOptions({
    queryKey: qk.hostUpdates(hostId),
    queryFn: ({ signal }) => call(api.GET('/hosts/{hostId}/updates', { params: { path: { hostId } }, signal })),
  });

export const hostProcessesQuery = (hostId: string) =>
  queryOptions({
    queryKey: qk.hostProcesses(hostId),
    queryFn: ({ signal }) => call(api.GET('/hosts/{hostId}/processes', { params: { path: { hostId } }, signal })),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });

export const hostChecksQuery = (hostId: string) =>
  queryOptions({
    queryKey: qk.hostChecks(hostId),
    queryFn: ({ signal }) => call(api.GET('/hosts/{hostId}/checks', { params: { path: { hostId } }, signal })),
  });

export interface TimeRange {
  key: string;
  label: string;
  seconds: number;
}

export const TIME_RANGES: readonly TimeRange[] = [
  { key: '1h', label: '1 h', seconds: 3600 },
  { key: '6h', label: '6 h', seconds: 6 * 3600 },
  { key: '24h', label: '24 h', seconds: 24 * 3600 },
  { key: '7d', label: '7 d', seconds: 7 * 86400 },
  { key: '30d', label: '30 d', seconds: 30 * 86400 },
];

export const hostMetricsQuery = (hostId: string, panel: MetricsPanel, range: TimeRange) =>
  queryOptions({
    queryKey: qk.hostMetrics(hostId, panel, range.key),
    queryFn: ({ signal }) => {
      const end = nowSeconds();
      const start = end - range.seconds;
      const step = chooseStep(range.seconds);
      return call(
        api.GET('/hosts/{hostId}/metrics/{panel}', {
          params: { path: { hostId, panel }, query: { start, end, step } },
          signal,
        }),
      );
    },
    refetchInterval: 30_000,
    staleTime: 25_000,
    placeholderData: keepPreviousData,
  });

export const groupsQuery = queryOptions({
  queryKey: qk.groups,
  queryFn: ({ signal }) => call(api.GET('/host-groups', { signal })),
  staleTime: 60_000,
});

export const jobsQuery = (f: { host_id?: string; limit?: number } = {}) =>
  queryOptions({
    queryKey: qk.jobs(f),
    queryFn: ({ signal }) => call(api.GET('/jobs', { params: { query: clean({ ...f }) }, signal })),
    placeholderData: keepPreviousData,
  });

export const jobQuery = (jobId: string) =>
  queryOptions({
    queryKey: qk.job(jobId),
    queryFn: ({ signal }) => call(api.GET('/jobs/{jobId}', { params: { path: { jobId } }, signal })),
  });

export const jobTargetsQuery = (jobId: string) =>
  queryOptions({
    queryKey: qk.jobTargets(jobId),
    queryFn: ({ signal }) => call(api.GET('/jobs/{jobId}/targets', { params: { path: { jobId } }, signal })),
  });

export const fleetUpdatesQuery = queryOptions({
  queryKey: qk.updates,
  queryFn: ({ signal }) => call(api.GET('/updates', { signal })),
  refetchInterval: 60_000,
});

export const securitySummaryQuery = queryOptions({
  queryKey: qk.securitySummary,
  queryFn: ({ signal }) => call(api.GET('/security/summary', { signal })),
});

export const alertsQuery = (status: 'firing' | 'resolved' | 'all') =>
  queryOptions({
    queryKey: qk.alerts(status),
    queryFn: ({ signal }) =>
      call(api.GET('/alerts', { params: { query: status === 'all' ? {} : { status } }, signal })),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });

export const usersQuery = queryOptions({
  queryKey: qk.users,
  queryFn: ({ signal }) => call(api.GET('/users', { signal })),
});

export const roleBindingsQuery = (userId: string) =>
  queryOptions({
    queryKey: qk.roleBindings(userId),
    queryFn: ({ signal }) =>
      call(api.GET('/users/{userId}/role-bindings', { params: { path: { userId } }, signal })),
  });

export const rolesQuery = queryOptions({
  queryKey: qk.roles,
  queryFn: ({ signal }) => call(api.GET('/roles', { signal })),
  staleTime: 5 * 60_000,
});

export const enrollmentTokensQuery = queryOptions({
  queryKey: qk.enrollmentTokens,
  queryFn: ({ signal }) => call(api.GET('/enrollment-tokens', { signal })),
});

export const shellSessionsQuery = (hostId?: string) =>
  queryOptions({
    queryKey: qk.shellSessions(hostId),
    queryFn: ({ signal }) =>
      call(api.GET('/shell-sessions', { params: { query: clean({ host_id: hostId, limit: 200 }) }, signal })),
    refetchInterval: 30_000,
  });

export const webauthnCredentialsQuery = queryOptions({
  queryKey: qk.webauthnCredentials,
  queryFn: ({ signal }) => call(api.GET('/auth/webauthn/credentials', { signal })),
});

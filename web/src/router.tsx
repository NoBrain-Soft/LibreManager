import type { QueryClient } from '@tanstack/react-query';
import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  lazyRouteComponent,
  redirect,
} from '@tanstack/react-router';
import { sessionQuery } from '@/api/session';
import { AppShell } from '@/app/AppShell';
import { NotFound, RootLayout, RouteError } from '@/app/RootLayout';
import { LoginPage } from '@/auth/LoginPage';
import { LoadingState } from '@/components/common/states';
import {
  validateAlertsSearch,
  validateHostsSearch,
  validateInventorySearch,
  validateJobDetailSearch,
  validateLoginSearch,
  validateShellSessionsSearch,
} from '@/routes/search';

export interface RouterContext {
  queryClient: QueryClient;
}

const rootRoute = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
  notFoundComponent: NotFound,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  validateSearch: validateLoginSearch,
  component: LoginPage,
});

/** Pathless layout for everything behind authentication. */
const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'app',
  beforeLoad: async ({ context, location }) => {
    const session = await context.queryClient.ensureQueryData(sessionQuery);
    if (!session || session.state !== 'active') {
      // eslint-disable-next-line @typescript-eslint/only-throw-error -- TanStack Router redirect protocol
      throw redirect({ to: '/login', search: { redirect: location.href } });
    }
  },
  component: AppShell,
  errorComponent: RouteError,
});

const page = <T extends Record<string, unknown>>(loader: () => Promise<T>, name: keyof T & string) =>
  lazyRouteComponent(loader, name);

const indexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  beforeLoad: () => {
    // eslint-disable-next-line @typescript-eslint/only-throw-error -- TanStack Router redirect protocol
    throw redirect({ to: '/dashboard', replace: true });
  },
});

const dashboardRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'dashboard',
  component: page(() => import('@/features/dashboard/DashboardPage'), 'DashboardPage'),
});

const hostsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'hosts',
  validateSearch: validateHostsSearch,
  component: page(() => import('@/features/hosts/HostsPage'), 'HostsPage'),
});

const hostRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'hosts/$hostId',
  component: page(() => import('@/features/hosts/HostLayout'), 'HostLayout'),
});

const hostOverviewRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: '/',
  component: page(() => import('@/features/hosts/tabs/OverviewTab'), 'OverviewTab'),
});
const hostMetricsRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'metrics',
  component: page(() => import('@/features/hosts/tabs/MetricsTab'), 'MetricsTab'),
});
const hostInventoryRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'inventory',
  validateSearch: validateInventorySearch,
  component: page(() => import('@/features/hosts/tabs/InventoryTab'), 'InventoryTab'),
});
const hostPackagesRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'packages',
  component: page(() => import('@/features/hosts/tabs/PackagesTab'), 'PackagesTab'),
});
const hostUpdatesRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'updates',
  component: page(() => import('@/features/hosts/tabs/UpdatesTab'), 'UpdatesTab'),
});
const hostServicesRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'services',
  component: page(() => import('@/features/hosts/tabs/ServicesTab'), 'ServicesTab'),
});
const hostProcessesRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'processes',
  component: page(() => import('@/features/hosts/tabs/ProcessesTab'), 'ProcessesTab'),
});
const hostSecurityRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'security',
  component: page(() => import('@/features/hosts/tabs/SecurityTab'), 'SecurityTab'),
});
const hostJobsRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'jobs',
  component: page(() => import('@/features/hosts/tabs/JobsTab'), 'JobsTab'),
});
const hostShellRoute = createRoute({
  getParentRoute: () => hostRoute,
  path: 'shell',
  component: page(() => import('@/features/shell/ShellTab'), 'ShellTab'),
});

const jobsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'jobs',
  component: page(() => import('@/features/jobs/JobsPage'), 'JobsPage'),
});

const jobRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'jobs/$jobId',
  validateSearch: validateJobDetailSearch,
  component: page(() => import('@/features/jobs/JobDetailPage'), 'JobDetailPage'),
});

const updatesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'updates',
  component: page(() => import('@/features/updates/UpdatesPage'), 'UpdatesPage'),
});

const securityRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'security',
  component: page(() => import('@/features/security/SecurityPage'), 'SecurityPage'),
});

const alertsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'alerts',
  validateSearch: validateAlertsSearch,
  component: page(() => import('@/features/alerts/AlertsPage'), 'AlertsPage'),
});

const accountRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'account',
  component: page(() => import('@/features/account/AccountPage'), 'AccountPage'),
});

const adminUsersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'admin/users',
  component: page(() => import('@/features/admin/UsersPage'), 'UsersPage'),
});
const adminGroupsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'admin/groups',
  component: page(() => import('@/features/admin/GroupsPage'), 'GroupsPage'),
});
const adminEnrollmentRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'admin/enrollment',
  component: page(() => import('@/features/admin/EnrollmentPage'), 'EnrollmentPage'),
});
const adminAuditRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'admin/audit',
  component: page(() => import('@/features/admin/AuditPage'), 'AuditPage'),
});
const adminShellSessionsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'admin/shell-sessions',
  validateSearch: validateShellSessionsSearch,
  component: page(() => import('@/features/admin/ShellSessionsPage'), 'ShellSessionsPage'),
});
const adminSettingsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'admin/settings',
  component: page(() => import('@/features/admin/SettingsPage'), 'SettingsPage'),
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    indexRoute,
    dashboardRoute,
    hostsRoute,
    hostRoute.addChildren([
      hostOverviewRoute,
      hostMetricsRoute,
      hostInventoryRoute,
      hostPackagesRoute,
      hostUpdatesRoute,
      hostServicesRoute,
      hostProcessesRoute,
      hostSecurityRoute,
      hostJobsRoute,
      hostShellRoute,
    ]),
    jobsRoute,
    jobRoute,
    updatesRoute,
    securityRoute,
    alertsRoute,
    accountRoute,
    adminUsersRoute,
    adminGroupsRoute,
    adminEnrollmentRoute,
    adminAuditRoute,
    adminShellSessionsRoute,
    adminSettingsRoute,
  ]),
]);

export function buildRouter(queryClient: QueryClient) {
  return createRouter({
    routeTree,
    context: { queryClient },
    defaultPreload: 'intent',
    // Data freshness is handled by TanStack Query.
    defaultPreloadStaleTime: 0,
    defaultPendingComponent: () => <LoadingState />,
    defaultPendingMs: 150,
    scrollRestoration: true,
  });
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof buildRouter>;
  }
}

// Query keys. Prefix-based so invalidating ['host', id] refreshes every
// per-host query, ['jobs'] every job list, etc.

export const SESSION_KEY = ['session'] as const;

export const qk = {
  session: SESSION_KEY,
  systemInfo: ['system-info'] as const,
  settings: ['settings'] as const,
  dashboard: ['dashboard'] as const,

  hostsRoot: ['hosts'] as const,
  hosts: (filters: { q?: string; status?: string; group_id?: string }) => ['hosts', filters] as const,
  hostRoot: ['host'] as const,
  host: (id: string) => ['host', id] as const,
  hostInventory: (id: string) => ['host', id, 'inventory'] as const,
  hostPackages: (id: string, q: string) => ['host', id, 'packages', q] as const,
  hostUpdates: (id: string) => ['host', id, 'updates'] as const,
  hostProcesses: (id: string) => ['host', id, 'processes'] as const,
  hostChecks: (id: string) => ['host', id, 'checks'] as const,
  hostMetrics: (id: string, panel: string, range: string) => ['host', id, 'metrics', panel, range] as const,

  groups: ['host-groups'] as const,

  jobsRoot: ['jobs'] as const,
  jobs: (filters: { host_id?: string; limit?: number }) => ['jobs', filters] as const,
  jobRoot: ['job'] as const,
  job: (id: string) => ['job', id] as const,
  jobTargets: (id: string) => ['job', id, 'targets'] as const,

  updates: ['updates'] as const,
  securitySummary: ['security-summary'] as const,
  alertsRoot: ['alerts'] as const,
  alerts: (status: string) => ['alerts', status] as const,

  users: ['users'] as const,
  roleBindings: (userId: string) => ['users', userId, 'role-bindings'] as const,
  roles: ['roles'] as const,
  enrollmentTokens: ['enrollment-tokens'] as const,
  auditRoot: ['audit'] as const,
  audit: (filters: { actor?: string; action?: string }) => ['audit', filters] as const,
  shellSessionsRoot: ['shell-sessions'] as const,
  shellSessions: (hostId?: string) => ['shell-sessions', hostId ?? ''] as const,
  webauthnCredentials: ['webauthn-credentials'] as const,
};

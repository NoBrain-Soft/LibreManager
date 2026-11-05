import { queryOptions } from '@tanstack/react-query';
import { api, call } from './client';
import { hasCode } from './errors';
import { SESSION_KEY } from './keys';
import { queryClient } from './queryClient';
import type { SessionInfo } from './types';

/**
 * GET /auth/session. Resolves to null when there is no session, so the
 * login page can render without triggering the global "session ended"
 * redirect. The result (incl. csrf_token) stays in memory only.
 */
export const sessionQuery = queryOptions({
  queryKey: SESSION_KEY,
  queryFn: async ({ signal }): Promise<SessionInfo | null> => {
    try {
      return await call(api.GET('/auth/session', { signal }));
    } catch (e) {
      if (hasCode(e, 'unauthenticated')) return null;
      throw e;
    }
  },
  staleTime: 60_000,
  // Detect idle/absolute expiry and keep the CSRF token current.
  refetchInterval: 2 * 60_000,
  refetchOnWindowFocus: true,
});

/** Re-fetch the session now (after login steps, step-up, CSRF failures). */
export function refreshSession(): Promise<SessionInfo | null> {
  return queryClient.fetchQuery({ ...sessionQuery, staleTime: 0 });
}

/** Forget everything cached for the previous user. */
export function clearSessionData(): void {
  queryClient.cancelQueries().catch(() => undefined);
  queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== SESSION_KEY[0] });
  queryClient.setQueryData(SESSION_KEY, null);
}

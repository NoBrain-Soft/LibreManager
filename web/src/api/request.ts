import { withStepUp } from '@/auth/stepup';
import { call } from './client';
import { isApiError } from './errors';
import { refreshSession } from './session';

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/**
 * The contract has no dedicated CSRF error code; servers typically answer a
 * missing/stale token with 403 and a csrf-specific code or message.
 */
function isCsrfFailure(e: unknown): boolean {
  if (!isApiError(e) || e.status !== 403) return false;
  return /csrf/i.test(e.code) || /csrf/i.test(e.message);
}

/**
 * Run an API call that may need step-up auth (and, for state-changing
 * requests, a fresh CSRF token). `fn` must create a new request each time
 * because it may be retried.
 */
export function request<T>(fn: () => Promise<FetchResult<T>>): Promise<T> {
  return withStepUp(async () => {
    try {
      return await call(fn());
    } catch (e) {
      if (!isCsrfFailure(e)) throw e;
      await refreshSession();
      return await call(fn());
    }
  });
}

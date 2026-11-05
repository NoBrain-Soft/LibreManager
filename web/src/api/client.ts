import createClient, { type Client } from 'openapi-fetch';
import { createCsrfMiddleware } from './csrf';
import { ApiError } from './errors';
import { SESSION_KEY } from './keys';
import { queryClient } from './queryClient';
import type { paths } from './schema';
import type { SessionInfo } from './types';

export type ApiClient = Client<paths>;

export interface ApiClientOptions {
  baseUrl?: string;
  fetch?: (input: Request) => Promise<Response>;
  /** In-memory CSRF token source (never Web Storage). */
  getCsrfToken: () => string | null | undefined;
}

export const API_BASE = '/api/v1';

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const client = createClient<paths>({
    baseUrl: opts.baseUrl ?? API_BASE,
    // The session is an HttpOnly cookie; never send it cross-origin.
    credentials: 'same-origin',
    // Avoid HTTP caches holding API responses.
    cache: 'no-store',
    headers: { Accept: 'application/json' },
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(createCsrfMiddleware(opts.getCsrfToken));
  return client;
}

/**
 * The CSRF token lives in memory only: it is read from the cached
 * GET /auth/session result on every state-changing request, so a refreshed
 * session (login step, step-up, rotation) is picked up automatically.
 */
export function getCsrfToken(): string | null {
  return queryClient.getQueryData<SessionInfo | null>(SESSION_KEY)?.csrf_token ?? null;
}

export const api: ApiClient = createApiClient({ getCsrfToken });

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

function isAbort(e: unknown): boolean {
  return e instanceof DOMException ? e.name === 'AbortError' : e instanceof Error && e.name === 'AbortError';
}

/**
 * Await an openapi-fetch call and return its data, or throw ApiError for
 * non-2xx responses (parsing the `{error:{code,message}}` envelope),
 * network failures and unparsable bodies. Abort errors are re-thrown as-is
 * so TanStack Query can handle cancellation.
 */
export async function call<T>(promise: Promise<FetchResult<T>>): Promise<T> {
  let res: FetchResult<T>;
  try {
    res = await promise;
  } catch (e) {
    if (isAbort(e)) throw e;
    if (e instanceof SyntaxError) throw new ApiError(0, 'invalid_response', 'The server sent an unexpected response.');
    throw new ApiError(0, 'network', 'Cannot reach the Stellwerk server. Check your connection.');
  }
  if (!res.response.ok) throw ApiError.fromResponse(res.response.status, res.error);
  return res.data as T;
}

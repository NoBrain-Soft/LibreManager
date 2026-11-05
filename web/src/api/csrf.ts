import type { Middleware } from 'openapi-fetch';

export const CSRF_HEADER = 'X-CSRF-Token';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

export function isStateChanging(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

function sameOrigin(url: string): boolean {
  // In the browser only attach the token to our own origin. (Requests are
  // always relative to /api/v1, so this is defense in depth.)
  if (typeof location === 'undefined' || !location.origin || location.origin === 'null') return true;
  try {
    return new URL(url, location.href).origin === location.origin;
  } catch {
    return false;
  }
}

/**
 * openapi-fetch middleware that sends the session's CSRF token on every
 * state-changing request. The token is read on each request from an
 * in-memory source (the session query cache), never from Web Storage.
 */
export function createCsrfMiddleware(getToken: () => string | null | undefined): Middleware {
  return {
    onRequest({ request }) {
      if (!isStateChanging(request.method)) return undefined;
      if (!sameOrigin(request.url)) return undefined;
      const token = getToken();
      if (token) request.headers.set(CSRF_HEADER, token);
      return request;
    },
  };
}

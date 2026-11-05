import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApiClient } from './client';
import { CSRF_HEADER, createCsrfMiddleware, isStateChanging } from './csrf';
import { ApiError } from './errors';
import { call } from './client';

const BASE = 'http://stellwerk.test/api/v1';

function mockFetch(status = 200, body: unknown = {}) {
  const requests: Request[] = [];
  const fetch = vi.fn((req: Request) => {
    requests.push(req);
    const init = { status, headers: { 'Content-Type': 'application/json' } };
    return Promise.resolve(status === 204 ? new Response(null, { status }) : new Response(JSON.stringify(body), init));
  });
  return { fetch, requests };
}

async function runMiddleware(method: string, token: string | null, url = `${BASE}/hosts`) {
  const mw = createCsrfMiddleware(() => token);
  const request = new Request(url, { method });
  const out = await mw.onRequest!({
    request,
    schemaPath: '/hosts',
    params: {},
    id: 'x',
    options: {} as never,
  });
  return (out instanceof Request ? out : request).headers.get(CSRF_HEADER);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('isStateChanging', () => {
  it.each([
    ['GET', false],
    ['head', false],
    ['OPTIONS', false],
    ['POST', true],
    ['put', true],
    ['PATCH', true],
    ['DELETE', true],
  ])('%s -> %s', (m, expected) => {
    expect(isStateChanging(m)).toBe(expected);
  });
});

describe('CSRF middleware', () => {
  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('adds the token on %s', async (method) => {
    expect(await runMiddleware(method, 'tok-123')).toBe('tok-123');
  });

  it.each(['GET', 'HEAD'])('never sends the token on %s', async (method) => {
    expect(await runMiddleware(method, 'tok-123')).toBeNull();
  });

  it('sends nothing when no token is known yet (e.g. login)', async () => {
    expect(await runMiddleware('POST', null)).toBeNull();
  });

  it('does not attach the token to other origins', async () => {
    vi.stubGlobal('location', { origin: 'https://stellwerk.test', href: 'https://stellwerk.test/hosts' });
    expect(await runMiddleware('POST', 'tok', 'https://evil.example/api')).toBeNull();
    expect(await runMiddleware('POST', 'tok', 'https://stellwerk.test/api/v1/jobs')).toBe('tok');
  });
});

describe('API client integration', () => {
  it('sends same-origin credentials and reads the current token per request', async () => {
    const { fetch, requests } = mockFetch(201, { id: 'job' });
    let token = 'first';
    const client = createApiClient({ baseUrl: BASE, fetch, getCsrfToken: () => token });

    await client.POST('/jobs', { body: { type: 'pkg_refresh', targets: { host_ids: [] } } });
    token = 'rotated';
    await client.DELETE('/hosts/{hostId}', { params: { path: { hostId: 'h1' } } });
    await client.GET('/hosts');

    expect(requests).toHaveLength(3);
    expect(requests.map((r) => r.credentials)).toEqual(['same-origin', 'same-origin', 'same-origin']);
    expect(requests[0]!.headers.get(CSRF_HEADER)).toBe('first');
    expect(requests[1]!.headers.get(CSRF_HEADER)).toBe('rotated');
    expect(requests[2]!.headers.get(CSRF_HEADER)).toBeNull();
    expect(requests[0]!.headers.get('Content-Type')).toBe('application/json');
  });
});

describe('call()', () => {
  it('returns data on success and undefined on 204', async () => {
    const ok = mockFetch(200, [{ id: 'h1' }]);
    const client = createApiClient({ baseUrl: BASE, fetch: ok.fetch, getCsrfToken: () => null });
    await expect(call(client.GET('/hosts'))).resolves.toEqual([{ id: 'h1' }]);

    const empty = mockFetch(204);
    const client2 = createApiClient({ baseUrl: BASE, fetch: empty.fetch, getCsrfToken: () => 't' });
    await expect(call(client2.POST('/auth/logout'))).resolves.toBeUndefined();
  });

  it('parses the error envelope', async () => {
    const { fetch } = mockFetch(403, { error: { code: 'stepup_required', message: 'Confirm it is you' } });
    const client = createApiClient({ baseUrl: BASE, fetch, getCsrfToken: () => 't' });
    const err = await call(client.POST('/hosts/{hostId}/shell', { params: { path: { hostId: 'h' } }, body: { cols: 80, rows: 24 } })).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 403, code: 'stepup_required', message: 'Confirm it is you' });
  });

  it('maps non-JSON errors and network failures', async () => {
    const html = vi.fn(() => Promise.resolve(new Response('<html>Bad gateway</html>', { status: 502 })));
    const client = createApiClient({ baseUrl: BASE, fetch: html, getCsrfToken: () => null });
    await expect(call(client.GET('/hosts'))).rejects.toMatchObject({ status: 502, code: 'internal' });

    const down = vi.fn(() => Promise.reject(new TypeError('Failed to fetch')));
    const client2 = createApiClient({ baseUrl: BASE, fetch: down, getCsrfToken: () => null });
    await expect(call(client2.GET('/hosts'))).rejects.toMatchObject({ status: 0, code: 'network' });

    const unauth = mockFetch(401, {});
    const client3 = createApiClient({ baseUrl: BASE, fetch: unauth.fetch, getCsrfToken: () => null });
    await expect(call(client3.GET('/hosts'))).rejects.toMatchObject({ status: 401, code: 'unauthenticated' });
  });
});

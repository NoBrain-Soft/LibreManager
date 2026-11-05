// API error envelope handling: `{ "error": { "code": "...", "message": "..." } }`.

export type KnownErrorCode =
  | 'unauthenticated'
  | 'forbidden'
  | 'stepup_required'
  | 'not_found'
  | 'invalid'
  | 'conflict'
  | 'rate_limited'
  | 'internal'
  // client-side codes
  | 'network'
  | 'invalid_response';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }

  /** Build from an HTTP status and a (possibly non-JSON) error body. */
  static fromResponse(status: number, body: unknown): ApiError {
    const env = parseEnvelope(body);
    if (env) return new ApiError(status, env.code, env.message);
    const code = codeForStatus(status);
    return new ApiError(status, code, defaultMessage(code, status));
  }
}

/** Thrown when the user dismisses a step-up dialog. */
export class StepUpCancelledError extends Error {
  constructor() {
    super('Re-authentication was cancelled.');
    this.name = 'StepUpCancelledError';
  }
}

const MAX_MESSAGE = 500;

function parseEnvelope(body: unknown): { code: string; message: string } | null {
  if (typeof body !== 'object' || body === null) return null;
  const err = (body as { error?: unknown }).error;
  if (typeof err !== 'object' || err === null) return null;
  const { code, message } = err as { code?: unknown; message?: unknown };
  if (typeof code !== 'string' || code === '') return null;
  const msg = typeof message === 'string' && message !== '' ? message : defaultMessage(code, 0);
  return { code: code.slice(0, 64), message: msg.slice(0, MAX_MESSAGE) };
}

export function codeForStatus(status: number): KnownErrorCode {
  switch (status) {
    case 400:
    case 422:
      return 'invalid';
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 429:
      return 'rate_limited';
    default:
      return 'internal';
  }
}

function defaultMessage(code: string, status: number): string {
  switch (code) {
    case 'unauthenticated':
      return 'Your session has ended. Please sign in again.';
    case 'forbidden':
      return 'You do not have permission to do this.';
    case 'stepup_required':
      return 'Please confirm your identity to continue.';
    case 'not_found':
      return 'The requested item was not found.';
    case 'invalid':
      return 'The request was invalid.';
    case 'conflict':
      return 'The item was changed or already exists.';
    case 'rate_limited':
      return 'Too many requests. Please wait a moment and try again.';
    case 'network':
      return 'Cannot reach the Stellwerk server. Check your connection.';
    case 'invalid_response':
      return 'The server sent an unexpected response.';
    default:
      return status ? `The server reported an error (HTTP ${status}).` : 'Something went wrong.';
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

export function hasCode(e: unknown, code: KnownErrorCode): boolean {
  return isApiError(e) && e.code === code;
}

/** Friendly message for any thrown value, suitable for toasts and alerts. */
export function errorMessage(e: unknown): string {
  if (isApiError(e)) {
    if (e.code === 'forbidden') {
      return e.message && e.message !== defaultMessage('forbidden', 0)
        ? `Permission denied: ${e.message}`
        : 'You do not have permission to do this.';
    }
    return e.message || defaultMessage(e.code, e.status);
  }
  if (e instanceof StepUpCancelledError) return e.message;
  if (e instanceof Error && e.message) return e.message;
  return 'Something went wrong.';
}

/** Short title for error states. */
export function errorTitle(e: unknown): string {
  if (!isApiError(e)) return 'Something went wrong';
  switch (e.code) {
    case 'forbidden':
      return 'Access denied';
    case 'not_found':
      return 'Not found';
    case 'network':
      return 'Server unreachable';
    case 'rate_limited':
      return 'Slow down';
    default:
      return 'Request failed';
  }
}

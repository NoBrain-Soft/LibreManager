// Step-up authentication: when the API answers `stepup_required`, ask the
// user to re-authenticate (WebAuthn or TOTP) and retry the action once.
//
// The dialog itself lives in <StepUpProvider>, which registers a handler
// here. Concurrent requests that hit `stepup_required` share one dialog.

import { ApiError, hasCode } from '@/api/errors';

/** Resolves once the user verified; rejects with StepUpCancelledError otherwise. */
type Handler = () => Promise<void>;

let handler: Handler | null = null;
let pending: Promise<void> | null = null;

export function setStepUpHandler(h: Handler | null): void {
  handler = h;
}

export function requestStepUp(): Promise<void> {
  if (!handler) {
    return Promise.reject(new ApiError(403, 'stepup_required', 'Re-authentication is required.'));
  }
  pending ??= handler().finally(() => {
    pending = null;
  });
  return pending;
}

/** Run `fn`; on `stepup_required`, step up and retry (at most `retries` times). */
export async function withStepUp<T>(fn: () => Promise<T>, retries = 1): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (!hasCode(e, 'stepup_required') || retries <= 0) throw e;
    await requestStepUp();
    return withStepUp(fn, retries - 1);
  }
}

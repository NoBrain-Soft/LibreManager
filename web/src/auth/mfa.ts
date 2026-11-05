// MFA ceremonies shared by the login flow, the step-up dialog and the
// account page.

import { api, call } from '@/api/client';
import { request } from '@/api/request';
import { clearSessionData } from '@/api/session';
import type { LoginResult, TotpEnrollment } from '@/api/types';
import { createCredential, getAssertion } from '@/lib/webauthn';

/** WebAuthn assertion for login (pending_mfa) or step-up. */
export async function verifyWithSecurityKey(): Promise<LoginResult> {
  const options = await call(api.POST('/auth/mfa/webauthn/begin'));
  const credential = await getAssertion(options);
  return call(api.POST('/auth/mfa/webauthn/finish', { body: credential }));
}

/** TOTP code for login (pending_mfa) or step-up. */
export function verifyWithTotp(code: string): Promise<LoginResult> {
  return call(api.POST('/auth/mfa/totp', { body: { code } }));
}

/** Register a new security key (login enrollment or account page). */
export async function registerSecurityKey(name: string): Promise<LoginResult> {
  const options = await request(() => api.POST('/auth/webauthn/register/begin'));
  const credential = await createCredential(options);
  return request(() => api.POST('/auth/webauthn/register/finish', { body: { name, credential } }));
}

export function beginTotpEnrollment(): Promise<TotpEnrollment> {
  return request(() => api.POST('/auth/totp/enroll'));
}

export function confirmTotpEnrollment(code: string): Promise<LoginResult> {
  return request(() => api.POST('/auth/totp/confirm', { body: { code } }));
}

export async function logout(): Promise<void> {
  try {
    await call(api.POST('/auth/logout'));
  } catch {
    /* the session may already be gone; clear locally regardless */
  }
  clearSessionData();
}

export const TOTP_PATTERN = /^[0-9]{6}$/;

/** Keep digits only, max 6 (pasted codes often contain spaces). */
export function normalizeTotp(input: string): string {
  return input.replace(/\D/g, '').slice(0, 6);
}

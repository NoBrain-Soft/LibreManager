# 0009 — Local accounts as primary authentication (no IdP integration at first)

- Status: accepted
- Date: 2026-11-05
- Deviates from: ARCHITECTURE.md §6.4 (OIDC primary, local accounts break-glass only)

## Context
Owner decision for the first release: no identity-provider integration; users are managed as local accounts on the management server. The threat model still assumes phishing and stolen sessions (T2).

## Decision
- Local accounts are first-class: Argon2id (m = 64 MiB, t = 3, p = 4) passwords, minimum 12 characters, common-password and username checks, lockout after 5 failures for 15 minutes plus per-IP/per-user rate limits, timing-safe handling of unknown users.
- **MFA is required by default** (global setting and per-user flag): WebAuthn security keys preferred, TOTP (RFC 6238, replay-protected) allowed and can be disabled by policy.
- New users and password resets get a one-time password; first login forces a password change and MFA enrollment. When a user already has a factor, MFA is verified *before* a forced password change.
- Step-up (fresh MFA within 5 minutes) is required for medium/high-risk actions (package upgrades, service control, reboot, shell, user and settings administration, decommissioning).
- Sessions are server-side (PostgreSQL), 8 h absolute / 30 min idle, rotated on every login state transition; cookies `__Host-…; Secure; HttpOnly; SameSite=Strict`; CSRF token header and same-origin checks on state-changing requests.
- RBAC (built-in roles, scoped to host-group subtrees) applies to local accounts exactly as it would to SSO users.
- The schema keeps `users.external_id` and `auth_source` so OIDC can be added later without migration of existing accounts.

## Consequences
User lifecycle (joiners/leavers) is manual in the Admin UI. Adding OIDC later is an additive change (new login path + group-claim → role-binding mapping).

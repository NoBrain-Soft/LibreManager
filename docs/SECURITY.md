# Security

## Reporting
Report vulnerabilities privately to the maintainers (internal project). Do not open public issues for security problems.

## Design summary (details: ARCHITECTURE.md §6)

| Threat | Mitigation in the code |
|--------|------------------------|
| T1 Web/API compromise | Job-signing key only in the signer (no network, unix socket, own signature log, independent validation + rate limits). Agent core **and** root helper verify every envelope and enforce the host's root-owned local policy. |
| T2 Stolen credentials/session | Argon2id, lockout + rate limits, MFA required by default (WebAuthn/TOTP with replay protection), step-up for risky actions, server-side sessions (idle 30 min / absolute 8 h), `__Host-` SameSite=Strict HttpOnly cookies, CSRF header + same-origin checks, strict CSP. |
| T3 Rogue host | Identity only from the client certificate (SPIFFE URI SAN); server-side metric labels; size/rate limits on every message; job events accepted only for that host's own targets; shell streams bound to the granted host. |
| T4 MitM | TLS 1.3 only, mutual TLS, pinned root fingerprint, no `InsecureSkipVerify` anywhere (tests use `internal/pki/testpki`). |
| T5 Replay | Envelope binds host, job id, 16-byte nonce and validity window; persistent nonce caches in core and helper; signer caps TTL (10 min, shells 2 min). |
| T7 Enrollment abuse | Tokens are random 256-bit, stored only as peppered HMAC, single-use/short-TTL by default, scoped to a group; enrollment is rate limited per IP. |
| T8 Shell abuse | RBAC per group, step-up, configurable identity, root needs central + host consent, banner, journald entries on the host, encrypted recordings with SHA-256 in the DB, idle/max duration, kill switch. |
| T9 Audit tampering | SHA-256 hash chain verified in the UI, append-only trigger (deletion only via the retention job), journald entries on hosts for every job. |
| T10 Secret leakage | Keys sealed with XChaCha20-Poly1305 per role; root CA key can be moved offline; tokens/sessions stored as hashes; settings secrets write-only and sealed. |

## Hardening checklist for operators
- Move `/opt/stellwerk/secrets/ca/root.key.sealed` and `secrets/ca/master.key` offline after installation.
- Configure an age recipient (`/opt/stellwerk/backup.recipient`) so backups are encrypted.
- Keep host policies minimal (`packages.install/remove: false`, `shell.allow_root: false` unless needed).
- Review the audit log and run *Verify chain* periodically.
- Keep NTP working on all hosts: agents refuse signed jobs when the clock is not synchronized.

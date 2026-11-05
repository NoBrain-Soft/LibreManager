# 0004 — Job-signing key held by a separate signer process

- Status: accepted
- Date: 2026-11-05

## Context
Threat T1: an attacker who compromises the internet-facing API must not automatically gain root on every server.

## Decision
- Every action reaches an agent only as a `SignedJob`: Ed25519 over `"stellwerk-job-v1" || 0x00 || job`, bound to one `host_id`, a nonce and a validity window (default 10 min, shell grants 2 min).
- Only `stellwerk-server signer` holds the private key. It runs in its own container with **no network** and exposes a unix socket shared with the API. It validates schema, target counts and TTL itself, rate-limits per user and logs every signature to its own append-only log.
- The agent core **and** the root helper both verify signature, host, window, nonce (persistent caches) and local policy independently. There is no unsigned path.
- Phase 5 adds WebAuthn assertions over the job digest, verified by the signer, for high-risk actions.

## Consequences
A compromised API can still request signatures for actions its users could request, but it cannot exceed the signer's limits or any host's local policy, and every signature is logged outside the API's reach. Key rotation: announce a new key signed by the old one; agents keep ≤ 2 active keys (Phase 5).

# 0002 — gRPC over HTTP/2 with mutual TLS 1.3

- Status: accepted
- Date: 2026-11-05

## Context
Agent ↔ central needs strong per-host identity, multiplexing (control stream + shell streams), streaming, and typed contracts that can evolve without breaking old agents.

## Decision
- One long-lived bidirectional `Connect` stream per agent plus a dedicated `ShellSession` stream per interactive session (no head-of-line blocking).
- TLS 1.3 only, mutual TLS. Host identity is the SPIFFE URI SAN `spiffe://stellwerk/host/<uuid>` assigned by central at signing time; agent-supplied names are informational.
- The agent pins the root CA by SHA-256 fingerprint (`/etc/stellwerk/agent.yaml`). `InsecureSkipVerify` is forbidden, including tests (`internal/pki/testpki`).
- `Enroll` is the only RPC accepted without a client certificate. `/install/*` is served on the same port with server-auth TLS only.
- Contracts live in `proto/` (buf lint + breaking checks in CI).

## Consequences
The gateway serves gRPC via `grpc.Server.ServeHTTP` on a Go `http.Server` so gRPC and `/install` share :8443. Revocation is an in-memory serial denylist on the gateway (the only relying party); certificates live 30 days and are renewed at 2/3 of their lifetime over the existing identity.

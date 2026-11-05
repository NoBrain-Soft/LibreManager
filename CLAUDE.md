# CLAUDE.md — Stellwerk

Central Linux server management platform: Go server + Go agent (outbound mTLS gRPC) + React web panel.
**Read `docs/ARCHITECTURE.md` before any non-trivial change.** It is the source of truth; if you need to deviate, write an ADR in `docs/adr/NNNN-title.md` first and update the architecture doc.

## Current phase

> Update this line when a phase is finished.

**Phase 0 — Foundations** (see ARCHITECTURE.md §9). Work through the checklist at the bottom of this file in order.

## Tech stack (fixed — don't swap without an ADR)

- Go (latest stable), CGO disabled for agent + helper. Modules: `grpc-go`, `protobuf` (via `buf`), `pgx/v5`, `sqlc`, `goose`, `oapi-codegen`, `go-webauthn/webauthn`, `coreos/go-oidc`, `gopsutil` + `prometheus/procfs`, `zerolog` or `log/slog` (prefer `slog`), `anchore/grype` (vuln-worker only).
- PostgreSQL 17+, VictoriaMetrics single-node, vmalert, Alertmanager, Caddy. Grafana only as optional compose profile.
- Frontend: React + TypeScript (strict) + Vite, TanStack Query + Router, Tailwind + shadcn/ui, xterm.js, uPlot. API client generated from `api/openapi.yaml`.
- Packaging: nfpm (.deb/.rpm), GoReleaser, cosign/minisign signatures.

## Repository layout

See ARCHITECTURE.md §10. Binaries in `cmd/`, all logic in `internal/`. Agent code must never import `internal/server/...` and vice versa; shared code lives in `internal/common` and `internal/pki`.

## Non-negotiable security rules

1. **Managed servers open no inbound ports.** The agent only dials out to the gateway.
2. **TLS 1.3 only**, mTLS for all agent traffic, CA fingerprint pinned in the agent. Never add `InsecureSkipVerify`, not even in tests (use test CAs from `internal/pki/testpki`).
3. **Every action an agent executes must arrive as a `SignedJob`** and be verified by the agent core **and** again by the helper (signature, `host_id`, time window, nonce, local policy). No "unsigned fast path".
4. **The API process never holds the job-signing key.** Only the signer does, reachable via unix socket.
5. The helper (root) exposes a **fixed, typed RPC set** — no generic "run this command string" endpoint. Shell-outs use `exec.Command` with argument arrays, never `sh -c` with interpolated input.
6. Validate and size-limit all input from agents (treat every agent as potentially compromised). Labels/host identity come from the cert + DB, never from agent-supplied fields.
7. Secrets: never log them, never put them in URLs, store only hashes of tokens (enrollment, API), Argon2id for passwords.
8. Web: strict CSP, HttpOnly/Secure/SameSite=Strict cookies, CSRF protection on state-changing requests, no tokens in localStorage.
9. Every state-changing operation writes an audit log entry (hash-chained). Every job executed on a host is logged to the host's journald.
10. Pin container images by digest; no `latest` tags in `deploy/`.

## Resource budget (agent)

< 30 MB RSS, < 1 % CPU average at 15 s interval, static binary < 20 MB. A CI benchmark enforces this — don't add dependencies to the agent without checking binary size and memory (`make agent-bench`).

## Conventions

- Go: `golangci-lint` config in repo is law; errors wrapped with `%w`; `context.Context` first parameter; no global state except metrics registries; table-driven tests.
- IDs: UUIDv7. Times: UTC in storage, `timestamptz` in Postgres.
- Protobuf: `buf lint` + `buf breaking` against `main`; never reuse field numbers.
- REST: OpenAPI-first — change `api/openapi.yaml`, regenerate, then implement.
- DB: one goose migration per change, never edit an applied migration.
- Commits: Conventional Commits (`feat(agent): …`, `fix(gateway): …`, `sec: …`).
- Tests for every security-relevant path must include **negative cases** (expired, replayed, wrong host, wrong key, policy-denied, oversize).

## Commands (create these in Phase 0)

```bash
make dev            # start dev stack (postgres, victoriametrics, server all-in-one, web dev server)
make test           # go test ./... + web tests
make lint           # golangci-lint, buf lint, eslint
make gen            # buf generate, oapi-codegen, sqlc generate, TS client
make agent-bench    # agent RSS/CPU/binary-size budget check
make packages       # build .deb/.rpm via nfpm
make e2e            # VM-based end-to-end tests (Incus/Vagrant)
```

## Phase checklists

### Phase 0 — Foundations
- [ ] `go.mod`, directory skeleton per ARCHITECTURE.md §10, `README.md`
- [ ] `buf.yaml` + initial protos: `gateway.proto` (Enroll, Connect bidi, Renew, ShellSession), `job.proto` (SignedJob/Job per §6.3), `metrics.proto`, `inventory.proto`
- [ ] `api/openapi.yaml` skeleton (auth, hosts, enrollment-tokens, jobs, events WS)
- [ ] `internal/common/envelope`: sign/verify with domain separation + full negative test suite + fuzz test
- [ ] `internal/pki`: root/intermediate CA creation, CSR signing with SPIFFE URI SAN, test PKI helper
- [ ] Makefile targets above (stubs ok), `.golangci.yml`, CI workflow (lint, test, gosec, govulncheck, build)
- [ ] `deploy/dev/compose.yml` (postgres, victoriametrics), goose migrations for core tables (§5.7: users, hosts, host_groups, enrollment_tokens, agent_certs, audit_log)
- [ ] ADRs 0001–0008 from ARCHITECTURE.md §2 (agent vs SSH, gRPC/mTLS, VictoriaMetrics, signer separation, built-in CA, Go, React, Compose deployment)

### Phase 1 — MVP core (see ARCHITECTURE.md §9 for exit criteria)
- [ ] `server init` (migrations, CA, keys, break-glass admin)
- [ ] Gateway: mTLS listener, Enroll, Connect stream, registry, heartbeats, revocation denylist, cert renewal
- [ ] Agent: enroll, connect/backoff, collectors, spool, inventory
- [ ] Gateway → VictoriaMetrics remote-write with server-side labels
- [ ] API: local auth (Argon2id + WebAuthn/TOTP), sessions, hosts, enrollment tokens, metrics query proxy
- [ ] Web: login, host list, host detail (overview, charts, inventory), enrollment UI
- [ ] `deploy/install-central.sh`, `deploy/agent-install.sh.tmpl`, nfpm packaging + systemd units (hardened)
- [ ] `make agent-bench` passing budget

### Phase 2+ 
Follow ARCHITECTURE.md §9; add a checklist here when starting each phase.

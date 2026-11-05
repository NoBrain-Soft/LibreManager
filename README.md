# LibreManager — Stellwerk

Central Linux server management: monitoring, inventory, security checks, package updates and a recorded browser shell for a fleet of Debian/Ubuntu and RHEL-family servers — from one web panel, without opening any inbound port on the managed servers.

*Stellwerk* (German for "signal box") is the working name used in code and packages. The architecture is described in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); decisions are recorded in [`docs/adr/`](docs/adr/).

## How it works

```
Browser ──HTTPS──▶ Caddy ──▶ stellwerk-server api ──unix socket──▶ signer (job-signing key, no network)
                                   │        └─unix socket─▶ gateway (:8443, mTLS gRPC)
                                   ▼                              ▲
                     PostgreSQL · VictoriaMetrics · vmalert · Alertmanager
                                                                  │ outbound only, TLS 1.3, pinned CA
      managed server:  stellwerk-agent (unprivileged) ──▶ gateway │
                       └── stellwerk-agent-helper (root, fixed RPC set, re-verifies every job)
```

- **Agent** (`stellwerk-agent`, ~14 MB static, ~18 MB RSS): dials out to the gateway, streams metrics every 15 s (buffered on disk while offline), inventory (OS, hardware, network, packages with PURLs, services, ports, users, timers, certificates, SSH host keys), pending updates and security check results.
- **Every action is a signed job.** The API asks the separate signer for an Ed25519 envelope bound to one host, a nonce and a 10-minute window. The agent core *and* the root helper each verify the signature, host, window, nonce and the host's **local policy** (`/etc/stellwerk/agent.yaml`, which central cannot change). A compromised web tier cannot exceed what the signer signs and each host allows.
- **Web panel**: hosts, live charts, inventory, updates (security-only / all / named), service control, reboots, job history with live output, recorded shell (xterm.js, encrypted asciicast recordings), alerts, audit log (hash-chained, verifiable), users/roles/host groups, enrollment tokens.
- **Accounts**: local accounts with Argon2id passwords and mandatory MFA (WebAuthn security keys or TOTP), RBAC scoped by host-group subtree, step-up authentication for risky actions.

## Status

| Phase | Scope | State |
|-------|-------|-------|
| 0 | Repo, contracts (protobuf, OpenAPI), envelope + PKI, migrations, CI, ADRs | done |
| 1 | Init, gateway (enroll/connect/renew/revocation), agent (collectors, spool, inventory), remote-write, API with local auth, web UI, installers, packaging | done; smoke-tested with real binaries, VM validation pending |
| 2 | Signer, signed jobs, helper with apt/dnf/services/reboot, job framework, audit chain + syslog export | done |
| 3 | Remote shell (PTY via helper, dedicated stream, recordings), RBAC scopes, step-up | done (OIDC deferred, ADR-0009) |
| 4 | Security checks, alerting + notifications | checks + alerting done; Grype vulnerability worker open |
| 5–6 | Patch policies/rings, self-update, 4-eyes, scripts, HA, … | not started |

See the checklists in [`CLAUDE.md`](CLAUDE.md).

## Quick start (central node)

Requirements: Debian 12/13, Ubuntu 24.04 or RHEL/Alma/Rocky 9/10, 2 vCPU / 4 GB RAM / 50 GB disk, a DNS name, ports 443 (UI) and 8443 (agents).

```bash
make image   # or use a released image reference with digest
sudo deploy/install-central.sh --fqdn stellwerk.example.internal --image registry.example/stellwerk-server@sha256:<digest>
```

The installer prints the UI URL, the CA fingerprint and a **one-time password** for the break-glass `admin` account (password change and MFA enrollment are enforced at first login). Details: [`docs/runbooks/install-central.md`](docs/runbooks/install-central.md).

## Enrolling servers

1. `make packages` and copy `dist/stellwerk-agent*` to `/opt/stellwerk/data/packages/` on the central node.
2. In the UI: *Admin → Enrollment tokens → New*. Copy the command shown once and run it on the server. It pins the CA, verifies the script hash, installs the package, writes the local policy and enrolls with the token read from stdin.
3. Review `/etc/stellwerk/agent.yaml` on the host — it decides what central may do there (package install/remove and root shells are off by default).

## Development

```bash
make tools        # buf, protoc plugins, oapi-codegen, sqlc, golangci-lint
make dev          # PostgreSQL + VictoriaMetrics in containers, `server all` + Vite dev server
make test         # Go (race) + web tests; DB tests need STELLWERK_TEST_DATABASE_URL
make lint         # golangci-lint, buf lint, eslint, tsc
make gen          # regenerate protobuf, OpenAPI stubs, sqlc, TS client
make agent-bench  # agent budget: binary < 20 MB, RSS < 30 MB, CPU < 1 %
make packages     # .deb/.rpm via nfpm
```

Layout: binaries in `cmd/`, logic in `internal/` (`internal/agent`, `internal/helper`, `internal/server`, shared `internal/common` and `internal/pki`), contracts in `proto/` and `api/openapi.yaml`, deployment in `deploy/`, web panel in `web/`, cross-component tests in `test/`.

Database tests: `STELLWERK_TEST_DATABASE_URL=postgres://user:pw@127.0.0.1:5432/postgres?sslmode=disable go test ./...` (the user needs `CREATEDB`; each test gets its own database).

## Security

See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model summary, hardening and how to report issues.

## License

Internal use only for now; the project may be open-sourced later. All dependencies are OSI-licensed.

# 0008 — Docker/Podman Compose deployment

- Status: accepted
- Date: 2026-11-05

## Context
The fleet is ~10 servers (owner answer, 2026-11-05); HA is not needed now (Phase 6).

## Decision
`install-central.sh` generates `/opt/stellwerk` with a Compose project: Caddy, api, gateway, signer, PostgreSQL 17, VictoriaMetrics, vmalert, Alertmanager and an optional Grafana profile. All images are pinned by digest. Containers run as non-root with read-only root filesystems, no capabilities and `no-new-privileges`; each role mounts only its own secrets directory. `server all` runs every role in one process for very small or development installs (documented as less isolated).

## Consequences
Single-node central. Upgrades = new digests + migration on start; backups via the `stellwerk-backup` timer (pg_dump + secrets, encrypted with age when a recipient is configured).

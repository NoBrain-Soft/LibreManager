# 0001 — Own outbound agent instead of SSH push

- Status: accepted
- Date: 2026-11-05

## Context
Monitoring needs something resident on every host anyway (push-based metrics at 15 s, instant events). An SSH-push design (Ansible style) needs inbound port 22 from central, central custody of keys that can log in (often with sudo) everywhere, and jump hosts for NAT/DMZ segments.

## Decision
Every managed server runs `stellwerk-agent`, which only **dials out** to the central gateway (`:8443`). All management (jobs, shells) is routed through this connection. Managed servers open no inbound ports (CLAUDE.md rule 1). An agentless SSH mode stays a possible Phase 6 option.

## Consequences
- One-time agent install per host (one command with an enrollment token).
- Central never holds SSH credentials; compromise of central yields at most what the signer will sign *and* what each host's local policy allows (see 0004).
- Works through NAT and firewalls as long as hosts reach central:8443.

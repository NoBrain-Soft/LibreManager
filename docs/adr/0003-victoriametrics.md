# 0003 — VictoriaMetrics single-node for metrics

- Status: accepted
- Date: 2026-11-05

## Context
15 s resolution for ~10 hosts now (≥ 1,000 must be possible), 30 days raw retention, PromQL-compatible queries for the UI and optional Grafana, minimal RAM/disk on the central node.

## Decision
VictoriaMetrics single-node (Apache-2.0). The gateway writes via Prometheus remote-write and adds `host_id`, `hostname` and `groups` labels **server-side**; agent-supplied labels with those names are dropped. vmalert + Alertmanager evaluate the default rule pack. The UI never sends raw MetricsQL: it asks for named panels and the API builds queries with the host label injected.

## Consequences
Retention is configured on the VictoriaMetrics container (`-retentionPeriod`, default 30d). VictoriaMetrics is never exposed outside the compose network.

# 0010 — Notifications are delivered by Stellwerk, Alertmanager forwards to it

- Status: accepted
- Date: 2026-11-05
- Refines: ARCHITECTURE.md §3.2 / §7.3 (receivers in Alertmanager)

## Context
Owner decision: notification channels are e-mail and generic webhooks, both optional. Two alert sources exist: metric rules (vmalert → Alertmanager) and state alerts raised by the gateway (host down after 2 minutes without a connection). Configuring receivers in both Alertmanager and Stellwerk would split configuration and require regenerating `alertmanager.yml` from the UI.

## Decision
Alertmanager keeps grouping, deduplication, inhibition and silencing, and has a single receiver: the authenticated Stellwerk webhook (`/api/v1/alertmanager/webhook`, bearer token). Stellwerk stores all alerts and delivers notifications for every state change to the channels configured in *Settings → Notifications*:
- SMTP with verified TLS (mandatory STARTTLS when enabled, implicit TLS on 465),
- HTTPS webhooks with an optional HMAC-SHA256 signature (`X-Stellwerk-Timestamp`, `X-Stellwerk-Signature`) and a minimum severity.
Secrets (SMTP password, webhook secrets) are write-only in the API and sealed at rest.

## Consequences
One place to configure channels, consistent formatting for metric and state alerts, and a "send test" button. Teams/Slack/ITSM can be reached through their webhook endpoints.

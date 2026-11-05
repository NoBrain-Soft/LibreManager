# Runbook: enroll a server

1. UI → *Admin → Enrollment tokens → New*: pick a host group, labels, max uses and TTL.
2. Copy the command shown once (it contains the root CA, the install-script hash and the token).
3. On the server run the command as a user with sudo. The token is passed on stdin (never as an argument).
4. Check `/etc/stellwerk/agent.yaml` and adjust the local policy (e.g. allowed shell users, service allow/deny lists). Restart: `systemctl restart stellwerk-agent stellwerk-agent-helper`.
5. `stellwerk-agent status` shows identity, certificate validity, helper and time sync.

Unenroll: decommission the host in the UI (revokes its certificates), then on the host `stellwerk-agent unenroll && apt purge stellwerk-agent` (or `dnf remove`).

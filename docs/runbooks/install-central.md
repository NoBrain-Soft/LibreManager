# Runbook: install the central node

1. Prepare a VM (Debian 12/13, Ubuntu 24.04, RHEL/Alma/Rocky 9/10), 2 vCPU / 4 GB / 50 GB, DNS name, NTP.
2. Obtain the server image reference **with digest** (CI artifact or `make image` + push to your registry).
3. Run:
   ```bash
   sudo deploy/install-central.sh --fqdn stellwerk.example.internal \
        --image registry.example/stellwerk-server@sha256:<digest> \
        --tls internal            # or acme (--acme-email) or custom (--cert/--key)
   ```
   Optional: `--agent-endpoint gw.example.internal:8443` if agents use another name, `--admin-cidrs 10.0.0.0/8` to restrict 443.
4. Note the printed CA fingerprint and the one-time admin password.
5. Log in → set a new password → register a security key (or TOTP).
6. Settings: verify retention (metrics 30 d, audit ≥ 365 d, recordings 90 d), shell identity mode, notifications (SMTP and/or webhooks, "send test").
7. Copy agent packages: `make packages && scp dist/stellwerk-agent* central:/opt/stellwerk/data/packages/`.
8. Move the root CA key offline (see SECURITY.md).

Re-running the installer is safe: existing secrets, keys and data are kept.

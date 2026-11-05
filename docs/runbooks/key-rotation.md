# Runbook: keys and certificates

| Item | Rotation |
|------|----------|
| Agent client certificates (30 d) | Automatic: agents renew at 2/3 of the lifetime over mTLS. Revocation: decommission or disable the host. |
| Gateway server certificate (90 d) | Automatic on the gateway (renewed when < 30 d remain). |
| Agent intermediate CA (2 y) | Plan before expiry: issue a new intermediate with the offline root, restart the gateway; agents trust the root, so no host change is needed. |
| Root CA (10 y) | Requires re-pinning on all hosts (new `ca.pem` + fingerprint in `agent.yaml`). |
| Job-signing key | Phase 5: announcement signed by the old key. Until then: generate a new key with `server init` after moving the old sealed key away, then distribute the new public key to `/etc/stellwerk/jobkeys.d/` on all hosts (configuration management). |

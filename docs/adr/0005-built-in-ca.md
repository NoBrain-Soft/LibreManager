# 0005 — Built-in certificate authority

- Status: accepted
- Date: 2026-11-05

## Context
mTLS needs a CA. step-ca or Vault/OpenBao would be additional services to operate, back up and secure.

## Decision
`internal/pki` implements a root CA (ECDSA P-256, 10 y) and an online agent intermediate (2 y, path length 0) using Go's `crypto/x509`. `server init` creates them; the root key is sealed with its own master key and can be moved offline after the intermediate is issued. Agent keys are generated on the host and never leave it; CSR subject/SANs are ignored. The gateway's server certificate (90 d) is issued by the intermediate and renewed automatically.

## Consequences
Fewer moving parts; the lifecycle is fully under our control and tested. An HSM / OpenBao backend can be added behind the same interfaces later (Phase 6).

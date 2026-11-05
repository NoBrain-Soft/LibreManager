-- name: InsertAgentCert :exec
INSERT INTO agent_certs (serial, host_id, not_before, not_after) VALUES ($1, $2, $3, $4);

-- name: RevokeHostCerts :many
UPDATE agent_certs SET revoked_at = now(), revoke_reason = $2
WHERE host_id = $1 AND revoked_at IS NULL
RETURNING serial;

-- name: ListRevokedSerials :many
-- Revoked certificates that are not yet expired (older ones fail validity anyway).
SELECT serial FROM agent_certs WHERE revoked_at IS NOT NULL AND not_after > now() - interval '1 day';

-- name: GetAgentCert :one
SELECT * FROM agent_certs WHERE serial = $1;

-- name: CreateEnrollmentToken :one
INSERT INTO enrollment_tokens (id, token_hash, description, host_group_id, labels, max_uses, expires_at, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListEnrollmentTokens :many
SELECT t.*, coalesce(u.username, '')::text AS created_by_name
FROM enrollment_tokens t LEFT JOIN users u ON u.id = t.created_by
ORDER BY t.created_at DESC;

-- name: ConsumeEnrollmentToken :one
-- Atomically uses one slot of a valid token.
UPDATE enrollment_tokens SET uses = uses + 1
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() AND uses < max_uses
RETURNING *;

-- name: RevokeEnrollmentToken :execrows
UPDATE enrollment_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

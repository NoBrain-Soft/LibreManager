-- name: UpsertJobSigningKey :exec
INSERT INTO job_signing_keys (key_id, public_key) VALUES ($1, $2) ON CONFLICT (key_id) DO NOTHING;

-- name: ListActiveJobSigningKeys :many
SELECT * FROM job_signing_keys WHERE retired_at IS NULL ORDER BY created_at;

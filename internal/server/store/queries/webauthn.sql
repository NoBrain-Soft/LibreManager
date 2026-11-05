-- name: CreateWebauthnCredential :exec
INSERT INTO webauthn_credentials (id, user_id, credential_id, credential, name, sign_count)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListWebauthnCredentials :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at;

-- name: CountWebauthnCredentials :one
SELECT count(*) FROM webauthn_credentials WHERE user_id = $1;

-- name: UpdateWebauthnCredentialUse :exec
UPDATE webauthn_credentials SET credential = $3, sign_count = $4, last_used_at = now()
WHERE user_id = $1 AND credential_id = $2;

-- name: DeleteWebauthnCredential :execrows
DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2;

-- name: DeleteUserWebauthnCredentials :exec
DELETE FROM webauthn_credentials WHERE user_id = $1;

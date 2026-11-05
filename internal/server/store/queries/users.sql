-- name: CreateUser :one
INSERT INTO users (id, username, display_name, email, password_hash, password_change_required, mfa_required)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY username;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: UpdateUserProfile :one
UPDATE users SET
    display_name = coalesce(sqlc.narg('display_name'), display_name),
    email        = coalesce(sqlc.narg('email'), email),
    disabled     = coalesce(sqlc.narg('disabled'), disabled),
    mfa_required = coalesce(sqlc.narg('mfa_required'), mfa_required),
    updated_at   = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2, password_change_required = $3, failed_logins = 0, locked_until = NULL, updated_at = now()
WHERE id = $1;

-- name: RecordLoginFailure :one
UPDATE users SET
    failed_logins = failed_logins + 1,
    locked_until = CASE WHEN failed_logins + 1 >= sqlc.arg('max_failures')::int
                        THEN now() + make_interval(mins => sqlc.arg('lock_minutes')::int)
                        ELSE locked_until END,
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING failed_logins, locked_until;

-- name: RecordLoginSuccess :exec
UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now(), updated_at = now() WHERE id = $1;

-- name: SetTotpPending :exec
UPDATE users SET totp_pending_secret = $2, updated_at = now() WHERE id = $1;

-- name: ActivateTotp :exec
UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL, totp_last_step = $2, updated_at = now()
WHERE id = $1 AND totp_pending_secret IS NOT NULL;

-- name: SetTotpLastStep :execrows
-- Advances the replay counter only forwards (atomic compare).
UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2;

-- name: ClearTotp :exec
UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = 0, updated_at = now() WHERE id = $1;

-- name: CountAdmins :one
SELECT count(DISTINCT u.id) FROM users u
JOIN role_bindings rb ON rb.user_id = u.id
JOIN roles r ON r.id = rb.role_id
WHERE '*' = ANY (r.permissions) AND rb.host_group_id IS NULL AND NOT u.disabled;

-- name: CreateSession :exec
INSERT INTO sessions (id_hash, user_id, state, csrf_token, ip, user_agent, expires_at, mfa_at, stepup_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetSession :one
SELECT * FROM sessions WHERE id_hash = $1;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now() WHERE id_hash = $1;

-- name: SetSessionStepup :exec
UPDATE sessions SET stepup_at = now() WHERE id_hash = $1;

-- name: SetSessionWebauthn :exec
UPDATE sessions SET webauthn_session = $2 WHERE id_hash = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id_hash = $1;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteUserSessionsExcept :exec
DELETE FROM sessions WHERE user_id = $1 AND id_hash <> $2;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at < now() OR last_seen_at < now() - make_interval(mins => sqlc.arg('idle_minutes')::int);

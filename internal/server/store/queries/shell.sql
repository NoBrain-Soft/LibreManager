-- name: CreateShellSession :exec
INSERT INTO shell_sessions (id, host_id, user_id, username, unix_user, job_id) VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetShellSession :one
SELECT s.*, h.hostname FROM shell_sessions s JOIN hosts h ON h.id = s.host_id WHERE s.id = $1;

-- name: EndShellSession :exec
UPDATE shell_sessions SET ended_at = now(), end_reason = $2, recording_ref = $3, recording_sha256 = $4, bytes_in = $5, bytes_out = $6
WHERE id = $1 AND ended_at IS NULL;

-- name: ListShellSessions :many
SELECT s.*, h.hostname FROM shell_sessions s JOIN hosts h ON h.id = s.host_id
WHERE (sqlc.narg('host_id')::uuid IS NULL OR s.host_id = sqlc.narg('host_id'))
ORDER BY s.started_at DESC LIMIT sqlc.arg('lim');

-- name: ListOldRecordings :many
SELECT id, recording_ref FROM shell_sessions WHERE recording_ref <> '' AND started_at < now() - make_interval(days => sqlc.arg('days')::int);

-- name: ClearRecordingRef :exec
UPDATE shell_sessions SET recording_ref = '' WHERE id = $1;

-- name: CloseDanglingShellSessions :exec
UPDATE shell_sessions SET ended_at = now(), end_reason = 'server restart' WHERE ended_at IS NULL;

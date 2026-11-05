-- name: LockAudit :exec
SELECT pg_advisory_xact_lock(4242001);

-- name: LastAuditHash :one
SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1;

-- name: InsertAudit :one
INSERT INTO audit_log (ts, actor, actor_ip, action, target, details, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id;

-- name: ListAudit :many
SELECT * FROM audit_log
WHERE (sqlc.narg('before_id')::bigint IS NULL OR id < sqlc.narg('before_id'))
  AND (sqlc.narg('actor')::text IS NULL OR actor = sqlc.narg('actor'))
  AND (sqlc.narg('action')::text IS NULL OR action LIKE sqlc.narg('action') || '%')
ORDER BY id DESC LIMIT sqlc.arg('lim');

-- name: AuditRange :many
SELECT * FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2;

-- name: AuditAfter :many
SELECT * FROM audit_log WHERE id > $1 ORDER BY id LIMIT 500;

-- name: EnableAuditRetention :exec
SELECT set_config('stellwerk.audit_retention', 'on', true);

-- name: DeleteOldAudit :execrows
DELETE FROM audit_log WHERE ts < now() - make_interval(days => sqlc.arg('days')::int);

-- name: AuditBatchAfter :many
SELECT * FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2;

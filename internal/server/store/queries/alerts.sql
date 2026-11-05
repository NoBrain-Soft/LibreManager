-- name: UpsertAlert :one
INSERT INTO alerts (id, fingerprint, host_id, name, severity, status, summary, labels, annotations, starts_at, ends_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (fingerprint) DO UPDATE SET status = EXCLUDED.status, severity = EXCLUDED.severity, summary = EXCLUDED.summary,
    labels = EXCLUDED.labels, annotations = EXCLUDED.annotations, ends_at = EXCLUDED.ends_at, updated_at = now(),
    starts_at = CASE WHEN alerts.status = 'resolved' AND EXCLUDED.status = 'firing' THEN EXCLUDED.starts_at ELSE alerts.starts_at END,
    notified_at = CASE WHEN alerts.status <> EXCLUDED.status THEN NULL ELSE alerts.notified_at END
RETURNING *;

-- name: ListAlerts :many
SELECT a.*, coalesce(h.hostname, '')::text AS hostname FROM alerts a LEFT JOIN hosts h ON h.id = a.host_id
WHERE (sqlc.narg('status')::text IS NULL OR a.status = sqlc.narg('status'))
ORDER BY a.status = 'firing' DESC, a.starts_at DESC LIMIT 500;

-- name: MarkAlertNotified :exec
UPDATE alerts SET notified_at = now() WHERE id = $1;

-- name: CountFiringAlerts :one
SELECT count(*)::int FROM alerts WHERE status = 'firing';

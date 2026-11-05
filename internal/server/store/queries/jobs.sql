-- name: CreateJob :one
INSERT INTO jobs (id, type, params, requested_by, requested_by_name, approved_by)
VALUES ($1, $2, $3, $4, $5, coalesce(sqlc.narg('approved_by')::text[], '{}')) RETURNING *;

-- name: InsertJobTarget :exec
INSERT INTO job_targets (job_id, host_id, signed_envelope, expires_at) VALUES ($1, $2, $3, $4);

-- name: GetJob :one
SELECT * FROM jobs WHERE id = $1;

-- name: ListJobs :many
SELECT * FROM jobs
WHERE (sqlc.narg('host_id')::uuid IS NULL OR id IN (SELECT job_id FROM job_targets WHERE host_id = sqlc.narg('host_id')))
ORDER BY created_at DESC LIMIT sqlc.arg('lim');

-- name: JobTargetCounts :many
SELECT job_id, status, count(*)::int AS n FROM job_targets WHERE job_id = ANY (sqlc.arg('job_ids')::uuid[]) GROUP BY job_id, status;

-- name: ListJobTargets :many
SELECT t.job_id, t.host_id, h.hostname, t.status, t.exit_code, t.message, t.dispatched_at, t.started_at, t.finished_at
FROM job_targets t JOIN hosts h ON h.id = t.host_id WHERE t.job_id = $1 ORDER BY h.hostname;

-- name: GetJobTarget :one
SELECT * FROM job_targets WHERE job_id = $1 AND host_id = $2;

-- name: ListQueuedForHost :many
SELECT job_id, signed_envelope FROM job_targets
WHERE host_id = $1 AND status = 'queued' AND expires_at > now()
ORDER BY job_id LIMIT 100;

-- name: MarkTargetDispatched :execrows
UPDATE job_targets SET status = 'dispatched', dispatched_at = now() WHERE job_id = $1 AND host_id = $2 AND status = 'queued';

-- name: MarkTargetRunning :execrows
UPDATE job_targets SET status = 'running', started_at = coalesce(started_at, now())
WHERE job_id = $1 AND host_id = $2 AND status IN ('queued', 'dispatched');

-- name: FinishTarget :execrows
UPDATE job_targets SET status = $3, exit_code = $4, message = $5, finished_at = now()
WHERE job_id = $1 AND host_id = $2 AND status IN ('queued', 'dispatched', 'running');

-- name: AddTargetOutputBytes :one
UPDATE job_targets SET output_bytes = output_bytes + $3 WHERE job_id = $1 AND host_id = $2 RETURNING output_bytes;

-- name: InsertJobOutput :exec
INSERT INTO job_output (job_id, host_id, stream, data) VALUES ($1, $2, $3, $4);

-- name: ListJobOutput :many
SELECT id, ts, stream, data FROM job_output WHERE job_id = $1 AND host_id = $2 AND id > $3 ORDER BY id LIMIT 2000;

-- name: ExpireQueuedTargets :many
UPDATE job_targets SET status = 'expired', finished_at = now(), message = 'host did not receive the job before it expired'
WHERE status = 'queued' AND expires_at <= now()
RETURNING job_id, host_id;

-- name: TimeoutStaleTargets :many
UPDATE job_targets SET status = 'timed_out', finished_at = now(), message = 'no result from host'
WHERE status IN ('dispatched', 'running') AND coalesce(started_at, dispatched_at) < now() - make_interval(mins => sqlc.arg('minutes')::int)
RETURNING job_id, host_id;

-- name: CancelQueuedTargets :many
UPDATE job_targets SET status = 'canceled', finished_at = now(), message = 'canceled by user'
WHERE job_id = $1 AND status = 'queued'
RETURNING host_id;

-- name: OpenTargets :many
SELECT host_id FROM job_targets WHERE job_id = $1 AND status IN ('dispatched', 'running');

-- name: FinalizeJobIfDone :one
-- Sets the aggregate job status once no target is open. Returns the job status.
UPDATE jobs j SET
    status = CASE
        WHEN agg.canceled > 0 AND agg.ok = 0 AND agg.bad = 0 THEN 'canceled'
        WHEN agg.bad = 0 AND agg.canceled = 0 THEN 'succeeded'
        WHEN agg.ok = 0 THEN 'failed'
        ELSE 'partial' END,
    finished_at = now()
FROM (
    SELECT count(*) FILTER (WHERE status IN ('queued', 'dispatched', 'running')) AS open,
           count(*) FILTER (WHERE status = 'succeeded') AS ok,
           count(*) FILTER (WHERE status = 'canceled') AS canceled,
           count(*) FILTER (WHERE status IN ('failed', 'rejected', 'timed_out', 'expired')) AS bad
    FROM job_targets WHERE job_id = $1
) agg
WHERE j.id = $1 AND j.status = 'running' AND agg.open = 0
RETURNING j.status;

-- name: RequeueTarget :exec
UPDATE job_targets SET status = 'queued', dispatched_at = NULL WHERE job_id = $1 AND host_id = $2 AND status = 'dispatched';

-- name: DeleteOldJobOutput :execrows
DELETE FROM job_output WHERE ts < now() - make_interval(days => sqlc.arg('days')::int);

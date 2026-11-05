-- name: GetInventoryHash :one
SELECT hash FROM inventory_snapshots WHERE host_id = $1 AND kind = $2;

-- name: UpsertInventory :exec
INSERT INTO inventory_snapshots (host_id, kind, data, hash, collected_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (host_id, kind) DO UPDATE SET data = EXCLUDED.data, hash = EXCLUDED.hash, collected_at = EXCLUDED.collected_at, received_at = now();

-- name: ListInventory :many
SELECT kind, data, collected_at FROM inventory_snapshots WHERE host_id = $1 ORDER BY kind;

-- name: DeleteHostPackages :exec
DELETE FROM host_packages WHERE host_id = $1;

-- name: InsertHostPackages :copyfrom
INSERT INTO host_packages (host_id, name, arch, version, source, source_name, purl) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListHostPackages :many
SELECT * FROM host_packages WHERE host_id = $1
  AND (sqlc.narg('q')::text IS NULL OR name ILIKE '%' || sqlc.narg('q') || '%')
ORDER BY name LIMIT 5000;

-- name: UpsertUpdateStatus :exec
INSERT INTO host_update_status (host_id, manager, checked_at, reboot_required, reboot_reasons, error, total, security)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (host_id) DO UPDATE SET manager = EXCLUDED.manager, checked_at = EXCLUDED.checked_at,
    reboot_required = EXCLUDED.reboot_required, reboot_reasons = EXCLUDED.reboot_reasons, error = EXCLUDED.error,
    total = EXCLUDED.total, security = EXCLUDED.security;

-- name: GetUpdateStatus :one
SELECT * FROM host_update_status WHERE host_id = $1;

-- name: ListUpdateStatuses :many
SELECT * FROM host_update_status WHERE host_id = ANY (sqlc.arg('host_ids')::uuid[]);

-- name: DeletePendingUpdates :exec
DELETE FROM pending_updates WHERE host_id = $1;

-- name: InsertPendingUpdates :copyfrom
INSERT INTO pending_updates (host_id, name, arch, current_version, candidate_version, source, is_security, advisories)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListPendingUpdates :many
SELECT * FROM pending_updates WHERE host_id = $1 ORDER BY is_security DESC, name;

-- name: UpdatesTotals :one
SELECT
    count(*) FILTER (WHERE s.total > 0)::int AS hosts_with_updates,
    coalesce(sum(s.security), 0)::int AS security_updates,
    count(*) FILTER (WHERE s.reboot_required)::int AS reboot_required
FROM host_update_status s JOIN hosts h ON h.id = s.host_id WHERE h.status = 'active';

-- name: UpsertProcesses :exec
INSERT INTO host_runtime (host_id, processes, processes_at) VALUES ($1, $2, $3)
ON CONFLICT (host_id) DO UPDATE SET processes = EXCLUDED.processes, processes_at = EXCLUDED.processes_at;

-- name: GetProcesses :one
SELECT * FROM host_runtime WHERE host_id = $1;

-- name: DeleteCheckResults :exec
DELETE FROM security_check_results WHERE host_id = $1;

-- name: InsertCheckResult :exec
INSERT INTO security_check_results (host_id, check_id, status, severity, title, summary, evidence, collected_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (host_id, check_id) DO UPDATE SET status = EXCLUDED.status, severity = EXCLUDED.severity,
    title = EXCLUDED.title, summary = EXCLUDED.summary, evidence = EXCLUDED.evidence, collected_at = EXCLUDED.collected_at;

-- name: ListCheckResults :many
SELECT * FROM security_check_results WHERE host_id = $1 ORDER BY check_id;

-- name: FailingChecks :many
SELECT r.check_id, max(r.title)::text AS title, max(r.severity)::text AS severity, count(*)::int AS host_count
FROM security_check_results r JOIN hosts h ON h.id = r.host_id
WHERE h.status = 'active' AND r.status = 'fail' AND r.host_id = ANY (sqlc.arg('host_ids')::uuid[])
GROUP BY r.check_id ORDER BY host_count DESC, r.check_id;

-- name: CheckPassRate :one
SELECT count(*) FILTER (WHERE r.status = 'pass')::int AS passed, count(*) FILTER (WHERE r.status IN ('pass', 'fail', 'warn'))::int AS evaluated
FROM security_check_results r WHERE r.host_id = ANY (sqlc.arg('host_ids')::uuid[]);

-- name: CountExpiringCerts :one
-- Certificates (from inventory) expiring within 30 days, across active hosts.
SELECT count(*)::int FROM inventory_snapshots s
JOIN hosts h ON h.id = s.host_id AND h.status = 'active',
LATERAL jsonb_array_elements(coalesce(s.data -> 'certificates', '[]'::jsonb)) c
WHERE s.kind = 'certificates'
  AND (c ->> 'notAfterUnix') IS NOT NULL
  AND to_timestamp((c ->> 'notAfterUnix')::bigint) < now() + interval '30 days';

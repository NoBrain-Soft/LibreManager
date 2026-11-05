-- name: CreateHost :one
INSERT INTO hosts (id, hostname, fqdn, os_family, os_id, os_version, kernel, arch, agent_version, machine_id, labels, cert_serial, cert_not_after)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetHost :one
SELECT * FROM hosts WHERE id = $1;

-- name: ListHosts :many
SELECT * FROM hosts
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('q')::text IS NULL OR hostname ILIKE '%' || sqlc.narg('q') || '%' OR fqdn ILIKE '%' || sqlc.narg('q') || '%')
  AND (sqlc.narg('group_id')::uuid IS NULL OR id IN (SELECT host_id FROM host_group_members WHERE host_group_id = sqlc.narg('group_id')))
  AND (status <> 'decommissioned' OR sqlc.narg('status')::text = 'decommissioned')
ORDER BY hostname;

-- name: UpdateHostHello :exec
UPDATE hosts SET
    hostname = $2, fqdn = $3, os_family = $4, os_id = $5, os_version = $6, kernel = $7, arch = $8,
    agent_version = $9, machine_id = $10, boot_id = $11, policy = $12,
    connected = true, last_seen_at = now(), updated_at = now()
WHERE id = $1;

-- name: UpdateHostOS :exec
UPDATE hosts SET os_pretty_name = $2, primary_ip = coalesce(nullif(sqlc.arg('primary_ip')::text, ''), primary_ip), updated_at = now() WHERE id = $1;

-- name: SetHostDisconnected :exec
UPDATE hosts SET connected = false, last_seen_at = now(), updated_at = now() WHERE id = $1;

-- name: TouchHosts :exec
UPDATE hosts SET last_seen_at = now() WHERE id = ANY (sqlc.arg('ids')::uuid[]);

-- name: MarkAllDisconnected :exec
UPDATE hosts SET connected = false WHERE connected;

-- name: UpdateHostLabels :exec
UPDATE hosts SET labels = $2, updated_at = now() WHERE id = $1;

-- name: SetHostStatus :exec
UPDATE hosts SET status = $2, updated_at = now() WHERE id = $1;

-- name: SetHostCert :exec
UPDATE hosts SET cert_serial = $2, cert_not_after = $3, updated_at = now() WHERE id = $1;

-- name: GetHostStatus :one
SELECT status FROM hosts WHERE id = $1;

-- name: DashboardCounts :one
SELECT
    count(*) FILTER (WHERE status = 'active')::int AS total,
    count(*) FILTER (WHERE status = 'active' AND connected)::int AS connected,
    count(*) FILTER (WHERE status = 'active' AND NOT connected)::int AS offline
FROM hosts;

-- name: ListHostGroups :many
SELECT g.*, (SELECT count(*) FROM host_group_members m WHERE m.host_group_id = g.id)::int AS host_count
FROM host_groups g ORDER BY g.name;

-- name: GetHostGroup :one
SELECT * FROM host_groups WHERE id = $1;

-- name: CreateHostGroup :one
INSERT INTO host_groups (id, name, parent_id, description, settings) VALUES ($1, $2, $3, $4, $5) RETURNING *;

-- name: UpdateHostGroup :one
UPDATE host_groups SET name = $2, parent_id = $3, description = $4, settings = $5 WHERE id = $1 RETURNING *;

-- name: DeleteHostGroup :execrows
DELETE FROM host_groups WHERE id = $1;

-- name: CountChildGroups :one
SELECT count(*) FROM host_groups WHERE parent_id = $1;

-- name: GroupAncestors :many
-- The group itself and all its ancestors.
WITH RECURSIVE anc AS (
    SELECT g.id, g.parent_id, 0 AS depth FROM host_groups g WHERE g.id = $1
    UNION ALL
    SELECT g.id, g.parent_id, anc.depth + 1 FROM host_groups g JOIN anc ON g.id = anc.parent_id WHERE anc.depth < 32
)
SELECT id FROM anc;

-- name: HostGroupIDsWithAncestors :many
-- All groups a host is in, plus their ancestors.
WITH RECURSIVE anc AS (
    SELECT g.id, g.parent_id, 0 AS depth FROM host_groups g
    JOIN host_group_members m ON m.host_group_id = g.id WHERE m.host_id = $1
    UNION
    SELECT g.id, g.parent_id, anc.depth + 1 FROM host_groups g JOIN anc ON g.id = anc.parent_id WHERE anc.depth < 32
)
SELECT DISTINCT id FROM anc;

-- name: GroupSubtree :many
-- The group and all its descendants.
WITH RECURSIVE sub AS (
    SELECT g.id, 0 AS depth FROM host_groups g WHERE g.id = $1
    UNION
    SELECT g.id, sub.depth + 1 FROM host_groups g JOIN sub ON g.parent_id = sub.id WHERE sub.depth < 32
)
SELECT DISTINCT id FROM sub;

-- name: ListHostGroupRefs :many
SELECT m.host_id, g.id, g.name, g.settings FROM host_group_members m JOIN host_groups g ON g.id = m.host_group_id
WHERE m.host_id = ANY (sqlc.arg('host_ids')::uuid[]) ORDER BY g.name;

-- name: SetHostGroupsClear :exec
DELETE FROM host_group_members WHERE host_id = $1;

-- name: AddHostToGroup :exec
INSERT INTO host_group_members (host_id, host_group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: HostsInGroups :many
SELECT DISTINCT m.host_id FROM host_group_members m
JOIN hosts h ON h.id = m.host_id
WHERE m.host_group_id = ANY (sqlc.arg('group_ids')::uuid[]) AND h.status = 'active';

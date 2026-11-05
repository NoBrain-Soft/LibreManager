-- name: ListRoles :many
SELECT * FROM roles ORDER BY name;

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = $1;

-- name: ListUserBindings :many
SELECT rb.id, rb.role_id, rb.host_group_id, r.name AS role_name, r.permissions, g.name AS host_group_name
FROM role_bindings rb
JOIN roles r ON r.id = rb.role_id
LEFT JOIN host_groups g ON g.id = rb.host_group_id
WHERE rb.user_id = $1
ORDER BY r.name, g.name NULLS FIRST;

-- name: DeleteUserBindings :exec
DELETE FROM role_bindings WHERE user_id = $1;

-- name: CreateRoleBinding :exec
INSERT INTO role_bindings (id, user_id, role_id, host_group_id) VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING;

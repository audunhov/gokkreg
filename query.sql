-- name: ListUsers :many
SELECT * FROM users;

-- name: GetUserStats :one
SELECT
    COUNT(*) AS current_count,
    SUM(CASE WHEN CreatedAt <= NOW() - INTERVAL '1 month' THEN 1 ELSE 0 END) AS count_a_month_ago
FROM users;

-- name: UpdateUserPass :one
UPDATE users SET Password=$2 WHERE Id = $1 RETURNING *; 

-- name: GetUserById :one
SELECT * FROM users WHERE Id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE Email = $1 LIMIT 1;

-- name: SearchUsers :many
SELECT * FROM users WHERE Name ILIKE $1 OR Email ILIKE $1 OR Phone ILIKE 1;

-- name: InsertUser :one
INSERT INTO users (Name, Email, Phone, Birthday) VALUES ($1,$2,$3,$4) RETURNING *;

-- name: UpdateUser :one
UPDATE users SET
Name = $2, Email = $3, Phone = $4, Birthday = $5
WHERE Id = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE Id = $1;

-- name: NewSession :one
INSERT INTO sessions (UserId, ExpiresAt, IpAddress, UserAgent) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: GetSessionsForUser :many
SELECT * FROM sessions
WHERE UserId = $1
  AND IsActive = TRUE
  AND ExpiresAt > NOW();

-- name: GetSessionById :one
SELECT * FROM sessions
WHERE Id = $1
AND IsActive = TRUE
LIMIT 1;

-- name: SetSessionLastActive :one
UPDATE sessions SET LastSeenAt = NOW() WHERE Id = $1 AND IsActive = TRUE RETURNING *;

-- name: InvalidateSession :exec
UPDATE sessions SET IsActive = FALSE WHERE Id = $1;

-- name: ListRoleTypes :many
SELECT * FROM role_types;

-- name: GetRoleTypeById :one
SELECT * FROM role_types WHERE Id = $1 LIMIT 1;

-- name: InsertRoleType :one
INSERT INTO role_types (Title, AccessLevel) VALUES ($1, $2) RETURNING *;

-- name: DeleteRoleType :exec
DELETE FROM role_types WHERE Id = $1;

-- name: ListRoles :many
SELECT * FROM roles;

-- name: ListRolesWithTypesForUser :many
SELECT r.*, rt.* FROM roles as r INNER JOIN role_types as rt ON r.RoleTypeId = rt.Id AND r.UserId = $1; 

-- name: GetRoleById :one
SELECT * FROM roles WHERE Id = $1 LIMIT 1;

-- name: InsertRole :one
INSERT INTO roles (UserId, RoleTypeId) VALUES ($1, $2) RETURNING *;

-- name: DeleteRole :exec
DELETE FROM roles WHERE Id = $1;

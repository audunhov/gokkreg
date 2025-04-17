-- name: ListUsers :many
SELECT * FROM users;

-- name: GetUserById :one
SELECT * FROM users WHERE Id = $1 LIMIT 1;

-- name: SearchUsers :many
SELECT * FROM users WHERE Name ILIKE $1 OR Email ILIKE $1 OR Phone ILIKE 1;

-- name: InsertUser :one
INSERT INTO users (Name, Email, Phone, Birthday) VALUES ($1,$2,$3,$4) RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE Id = $1;

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

-- name: GetRoleById :one
SELECT * FROM roles WHERE Id = $1 LIMIT 1;

-- name: InsertRole :one
INSERT INTO roles (UserId, RoleTypeId) VALUES ($1, $2) RETURNING *;

-- name: DeleteRole :exec
DELETE FROM roles WHERE Id = $1;

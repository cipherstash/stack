-- name: CreateUser :exec
INSERT INTO users (id, email, email_eq, email_match, age, age_eq, age_ore, attrs, notes)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: FindUsersByEmail :many
SELECT * FROM users WHERE email_eq = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY id;

-- name: UpdateUserEmail :exec
UPDATE users SET email = $2, email_eq = $3, email_match = $4 WHERE id = $1;

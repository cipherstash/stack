-- name: CreateUser :exec
INSERT INTO users (id, email, name) VALUES ($1, $2, $3);

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY id;

-- One cast, straight to the query domain: sqlc types a parameter by its first
-- cast, so ::jsonb::eql_v3.query_text_eq would generate json.RawMessage.
-- name: FindUsersByEmail :many
SELECT * FROM users WHERE email = sqlc.arg(email)::eql_v3.query_text_eq;

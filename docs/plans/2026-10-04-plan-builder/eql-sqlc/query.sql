-- name: CreateUser :exec
INSERT INTO users (id, email, age, attrs) VALUES ($1, $2, $3, $4);

-- One cast, straight to the query domain: sqlc types a parameter by its first
-- cast, so ::jsonb::eql_v3.query_text_search would generate json.RawMessage.
-- name: FindUsersByEmail :many
SELECT * FROM users WHERE email = sqlc.arg(email)::eql_v3.query_text_search;

-- name: SearchUsersByEmail :many
SELECT * FROM users WHERE email @@ sqlc.arg(pattern)::eql_v3.query_text_search;

-- name: ListUsersOlderThan :many
SELECT * FROM users WHERE age > sqlc.arg(min_age)::eql_v3.query_integer_ord ORDER BY age;

-- name: InsertUser :one
INSERT INTO users (id, parent_id, created_at, status, given_name_eql4_search, nickname_eql4, email_eql4_eq, dob_eql4, annotations_eql4_search)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: FindUserEmail :one
SELECT email_eql4_eq FROM users WHERE email_eql4_eq = $1;

-- name: ListUserNames :many
SELECT id, given_name_eql4_search AS name FROM users ORDER BY id;

-- name: ListUserContacts :many
SELECT u.id, u.given_name_eql4_search, c.email_eql4_eq AS contact_email, c.notes_eql4
FROM users AS u
LEFT JOIN contacts AS c ON c.user_id = u.id
ORDER BY u.id, c.id;

-- name: ListUserParents :many
SELECT u.id, u.given_name_eql4_search, p.given_name_eql4_search AS parent_given_name, p.nickname_eql4 AS parent_nickname
FROM users AS u
LEFT JOIN users AS p ON p.id = u.parent_id
ORDER BY u.id;

-- name: ListChildNicknames :batchmany
SELECT id, nickname_eql4 FROM users WHERE parent_id = $1 ORDER BY id;

-- name: UpdateUserNickname :exec
UPDATE users SET nickname_eql4 = $1 WHERE email_eql4_eq = $2 RETURNING nickname_eql4;

-- name: SetUserNickname :execrows
UPDATE users SET nickname_eql4 = $1 WHERE id = $2 RETURNING nickname_eql4;

-- name: SearchUsers :many
SELECT id FROM users
WHERE given_name_eql4_search @@ sqlc.arg(name_match)::eql_v4.query_text_search
  AND email_eql4_eq = sqlc.narg(email)::eql_v4.query_text_eq
ORDER BY id;

-- name: SetUserNicknames :batchexec
UPDATE users SET nickname_eql4 = $1 WHERE id = $2;

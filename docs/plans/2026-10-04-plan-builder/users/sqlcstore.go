package users

import (
	"context"
	"database/sql"
	"errors"

	"example.com/app/internal/userdb"
	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

var ErrNotFound = errors.New("users: not found")

// SQLCStore keeps users in Postgres through the queries sqlc generates. sqlc
// writes its own row struct, userdb.User. It has the same fields as
// EncryptedUser, so Go converts one to the other, and a change to either
// stops this file compiling.
type SQLCStore struct {
	db      *sql.DB
	queries *userdb.Queries
}

func NewSQLCStore(db *sql.DB) *SQLCStore {
	return &SQLCStore{db: db, queries: userdb.New(db)}
}

func (s *SQLCStore) Import(ctx context.Context, cipher *stackencrypt.Cipher, people []User) error {
	encrypted, err := Encrypt(ctx, cipher, people)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	queries := s.queries.WithTx(tx)
	for _, e := range encrypted {
		if err := queries.CreateUser(ctx, userdb.CreateUserParams(e)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLCStore) Get(ctx context.Context, cipher *stackencrypt.Cipher, id int64) (User, error) {
	row, err := s.queries.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	users, err := Decrypt(ctx, cipher, []EncryptedUser{EncryptedUser(row)})
	if err != nil {
		return User{}, err
	}
	return users[0], nil
}

func (s *SQLCStore) FindByEmail(ctx context.Context, cipher *stackencrypt.Cipher, email string) ([]User, error) {
	query, err := Fields.Email.Query(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	rows, err := s.queries.FindUsersByEmail(ctx, query)
	if err != nil {
		return nil, err
	}
	return Decrypt(ctx, cipher, fromRows(rows))
}

// ChangeEmail rewrites one field. One EQL column holds the ciphertext and
// every term, so they cannot go out of step.
func (s *SQLCStore) ChangeEmail(ctx context.Context, cipher *stackencrypt.Cipher, id int64, email string) error {
	sealed, err := Fields.Email.Encrypt(ctx, cipher, email)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET email = $2 WHERE id = $1`, id, sealed)
	return err
}

func fromRows(rows []userdb.User) []EncryptedUser {
	encrypted := make([]EncryptedUser, len(rows))
	for i, row := range rows {
		encrypted[i] = EncryptedUser(row)
	}
	return encrypted
}

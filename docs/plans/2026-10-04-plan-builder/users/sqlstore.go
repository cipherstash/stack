package users

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

const (
	columns    = `id, email, name`
	insertUser = `INSERT INTO users (` + columns + `) VALUES ($1, $2, $3)`
	selectUser = `SELECT ` + columns + ` FROM users`
)

// SQLStore keeps users in Postgres through database/sql. Each field is one
// EQL column, so the generated type's fields go straight to Exec and Scan.
type SQLStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db}
}

// Import encrypts every user in one ZeroKMS request, then inserts them in one
// transaction.
func (s *SQLStore) Import(ctx context.Context, cipher *stackencrypt.Cipher, people []User) error {
	encrypted, err := Encrypt(ctx, cipher, people)
	if err != nil {
		return fmt.Errorf("encrypt %d users: %w", len(people), err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, insertUser)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range encrypted {
		if _, err := stmt.ExecContext(ctx, e.ID, e.Email, e.Name); err != nil {
			return fmt.Errorf("insert user %d: %w", e.ID, err)
		}
	}
	return tx.Commit()
}

func (s *SQLStore) Create(ctx context.Context, cipher *stackencrypt.Cipher, user User) error {
	return s.Import(ctx, cipher, []User{user})
}

// FindByEmail matches the whole address. Postgres compares the encrypted
// column through EQL's = operator.
func (s *SQLStore) FindByEmail(ctx context.Context, cipher *stackencrypt.Cipher, email string) ([]User, error) {
	query, err := Fields.Email.Query(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	rs, err := s.db.QueryContext(ctx, selectUser+` WHERE email = $1::eql_v3.query_text_eq`, query)
	if err != nil {
		return nil, err
	}
	defer rs.Close()

	var encrypted []EncryptedUser
	for rs.Next() {
		var e EncryptedUser
		if err := rs.Scan(&e.ID, &e.Email, &e.Name); err != nil {
			return nil, err
		}
		encrypted = append(encrypted, e)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	return Decrypt(ctx, cipher, encrypted)
}

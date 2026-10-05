package users

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

const (
	columns    = `id, email, age, attrs, notes`
	insertUser = `INSERT INTO users (` + columns + `) VALUES ($1, $2, $3, $4, $5)`
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
		if _, err := stmt.ExecContext(ctx, e.ID, e.Email, e.Age, e.Attrs, e.Notes); err != nil {
			return fmt.Errorf("insert user %d: %w", e.ID, err)
		}
	}
	return tx.Commit()
}

func (s *SQLStore) Create(ctx context.Context, cipher *stackencrypt.Cipher, user User) error {
	return s.Import(ctx, cipher, []User{user})
}

func (s *SQLStore) FindByEmail(ctx context.Context, cipher *stackencrypt.Cipher, email string) ([]User, error) {
	query, err := Fields.Email.Query(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.query(ctx, selectUser+` WHERE email = $1::eql_v3.query_text_search`, query)
	if err != nil {
		return nil, err
	}
	return Decrypt(ctx, cipher, encrypted)
}

// AtLeast returns users aged minAge or over, youngest first. Postgres compares
// and sorts the encrypted column through EQL's operators.
func (s *SQLStore) AtLeast(ctx context.Context, cipher *stackencrypt.Cipher, minAge int32) ([]User, error) {
	query, err := Fields.Age.Query(ctx, cipher, minAge)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.query(ctx, selectUser+` WHERE age >= $1::eql_v3.query_integer_ord ORDER BY age`, query)
	if err != nil {
		return nil, err
	}
	return Decrypt(ctx, cipher, encrypted)
}

func (s *SQLStore) WithRole(ctx context.Context, cipher *stackencrypt.Cipher, role string) ([]User, error) {
	query, err := Fields.Attrs.Contains(ctx, cipher, map[string]any{"role": role})
	if err != nil {
		return nil, err
	}
	encrypted, err := s.query(ctx, selectUser+` WHERE attrs @> $1::eql_v3.query_json`, query)
	if err != nil {
		return nil, err
	}
	return Decrypt(ctx, cipher, encrypted)
}

func (s *SQLStore) query(ctx context.Context, q string, params ...any) ([]EncryptedUser, error) {
	rs, err := s.db.QueryContext(ctx, q, params...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()

	var found []EncryptedUser
	for rs.Next() {
		var e EncryptedUser
		if err := rs.Scan(&e.ID, &e.Email, &e.Age, &e.Attrs, &e.Notes); err != nil {
			return nil, err
		}
		found = append(found, e)
	}
	return found, rs.Err()
}

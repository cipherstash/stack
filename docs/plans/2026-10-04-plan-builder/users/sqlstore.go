package users

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

const (
	columns    = `id, email, email_eq, email_match, age, age_eq, age_ore, attrs, notes`
	insertUser = `INSERT INTO users (` + columns + `) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	selectUser = `SELECT ` + columns + ` FROM users`
)

// SQLStore keeps users in Postgres through database/sql. Each tenant has its
// own keyset; every tenant shares the plan.
type SQLStore struct {
	db     *sql.DB
	client *stackencrypt.Client
}

func NewSQLStore(db *sql.DB, client *stackencrypt.Client) *SQLStore {
	return &SQLStore{db: db, client: client}
}

func (s *SQLStore) cipher(tenant string) *stackencrypt.Cipher {
	return s.client.Keyset(stackencrypt.KeysetName(tenant))
}

func (s *SQLStore) Create(ctx context.Context, tenant string, user User) error {
	enc, err := stackencrypt.Encrypt(ctx, s.cipher(tenant), user)
	if err != nil {
		return fmt.Errorf("encrypt user %d: %w", user.ID, err)
	}
	_, err = s.db.ExecContext(ctx, insertUser, args(enc)...)
	return err
}

// Import encrypts every user in one ZeroKMS request, then inserts them in one
// transaction.
func (s *SQLStore) Import(ctx context.Context, tenant string, people []User) error {
	encrypted, err := stackencrypt.EncryptAll(ctx, s.cipher(tenant), people)
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

	for _, enc := range encrypted {
		if _, err := stmt.ExecContext(ctx, args(enc)...); err != nil {
			return fmt.Errorf("insert user %d: %w", enc.ID, err)
		}
	}
	return tx.Commit()
}

func (s *SQLStore) FindByEmail(ctx context.Context, tenant, email string) ([]User, error) {
	cipher := s.cipher(tenant)
	term, err := UserFields.Email.Equality(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.query(ctx, selectUser+` WHERE email_eq = $1`, term)
	if err != nil {
		return nil, err
	}
	return stackencrypt.DecryptAll(ctx, cipher, encrypted)
}

// OldestFirst returns users aged minAge or over, oldest first. ORE terms
// compare in Go; a range scan inside the database needs EQL's ORE operators.
func (s *SQLStore) OldestFirst(ctx context.Context, tenant string, minAge uint32) ([]User, error) {
	cipher := s.cipher(tenant)
	floor, err := UserFields.Age.Ore(ctx, cipher, minAge)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.query(ctx, selectUser)
	if err != nil {
		return nil, err
	}
	encrypted = slices.DeleteFunc(encrypted, func(e EncryptedUser) bool { return e.Age.Ore.Compare(floor) < 0 })
	slices.SortFunc(encrypted, func(a, b EncryptedUser) int { return b.Age.Ore.Compare(a.Age.Ore) })
	return stackencrypt.DecryptAll(ctx, cipher, encrypted)
}

func (s *SQLStore) WithRole(ctx context.Context, tenant, role string) ([]User, error) {
	cipher := s.cipher(tenant)
	contains, err := UserFields.Attrs.Contains(ctx, cipher, map[string]any{"role": role})
	if err != nil {
		return nil, err
	}
	// Illustrative: the containment predicate is EQL's.
	encrypted, err := s.query(ctx, selectUser+` WHERE attrs @> $1`, contains)
	if err != nil {
		return nil, err
	}
	return stackencrypt.DecryptAll(ctx, cipher, encrypted)
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
		if err := rs.Scan(&e.ID, &e.Email.Ciphertext, &e.Email.Equality, &e.Email.Match,
			&e.Age.Ciphertext, &e.Age.Equality, &e.Age.Ore, &e.Attrs, &e.Notes); err != nil {
			return nil, err
		}
		found = append(found, e)
	}
	return found, rs.Err()
}

func args(e EncryptedUser) []any {
	return []any{e.ID, e.Email.Ciphertext, e.Email.Equality, e.Email.Match,
		e.Age.Ciphertext, e.Age.Equality, e.Age.Ore, e.Attrs, e.Notes}
}

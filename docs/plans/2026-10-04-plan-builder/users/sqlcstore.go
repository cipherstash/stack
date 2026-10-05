package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"example.com/app/internal/userdb"
	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

var ErrNotFound = errors.New("users: not found")

// SQLCStore keeps users in Postgres through the queries sqlc generates.
type SQLCStore struct {
	db      *sql.DB
	queries *userdb.Queries
	client  *stackencrypt.Client
}

func NewSQLCStore(db *sql.DB, client *stackencrypt.Client) *SQLCStore {
	return &SQLCStore{db: db, queries: userdb.New(db), client: client}
}

func (s *SQLCStore) cipher(tenant string) *stackencrypt.Cipher {
	return s.client.Keyset(stackencrypt.KeysetName(tenant))
}

func (s *SQLCStore) Create(ctx context.Context, tenant string, user User) error {
	row, err := SQLCUsers.Encrypt(ctx, s.cipher(tenant), user)
	if err != nil {
		return fmt.Errorf("encrypt user %d: %w", user.ID, err)
	}
	// CreateUserParams has the same fields as userdb.User, in the same order,
	// so Go converts one to the other. If a change to the query breaks that,
	// this line stops compiling.
	return s.queries.CreateUser(ctx, userdb.CreateUserParams(row))
}

// Import encrypts every user in one ZeroKMS request, then inserts them in one
// transaction.
func (s *SQLCStore) Import(ctx context.Context, tenant string, people []User) error {
	rows, err := SQLCUsers.EncryptAll(ctx, s.cipher(tenant), people)
	if err != nil {
		return fmt.Errorf("encrypt %d users: %w", len(people), err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	qtx := s.queries.WithTx(tx)
	for _, row := range rows {
		if err := qtx.CreateUser(ctx, userdb.CreateUserParams(row)); err != nil {
			return fmt.Errorf("insert user %d: %w", row.ID, err)
		}
	}
	return tx.Commit()
}

func (s *SQLCStore) Get(ctx context.Context, tenant string, id int64) (User, error) {
	row, err := s.queries.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return SQLCUsers.Decrypt(ctx, s.cipher(tenant), row)
}

func (s *SQLCStore) FindByEmail(ctx context.Context, tenant, email string) ([]User, error) {
	cipher := s.cipher(tenant)
	term, err := UserFields.Email.Equality(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	rows, err := s.queries.FindUsersByEmail(ctx, term)
	if err != nil {
		return nil, err
	}
	return SQLCUsers.DecryptAll(ctx, cipher, rows)
}

func (s *SQLCStore) List(ctx context.Context, tenant string) ([]User, error) {
	rows, err := s.queries.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	return SQLCUsers.DecryptAll(ctx, s.cipher(tenant), rows)
}

// ChangeEmail rewrites one field. The email field owns three columns, and all
// three change together: a stale email_eq would let FindByEmail match the old
// address.
func (s *SQLCStore) ChangeEmail(ctx context.Context, tenant string, id int64, email string) error {
	field, err := UserFields.Email.Encrypt(ctx, s.cipher(tenant), email)
	if err != nil {
		return err
	}
	return s.queries.UpdateUserEmail(ctx, userdb.UpdateUserEmailParams{
		ID:         id,
		Email:      field.Ciphertext,
		EmailEq:    field.Equality,
		EmailMatch: field.Match,
	})
}

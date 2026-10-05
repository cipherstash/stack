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
// own keyset; every tenant shares the plans.
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
	row, err := userRowPlan.Encrypt(ctx, s.cipher(tenant), user)
	if err != nil {
		return fmt.Errorf("encrypt user %d: %w", user.ID, err)
	}
	_, err = s.db.ExecContext(ctx, insertUser, args(row)...)
	return err
}

// Import encrypts every user in one ZeroKMS request, then inserts them in one
// transaction.
func (s *SQLStore) Import(ctx context.Context, tenant string, people []User) error {
	rows, err := userRowPlan.EncryptAll(ctx, s.cipher(tenant), people)
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

	for _, row := range rows {
		if _, err := stmt.ExecContext(ctx, args(row)...); err != nil {
			return fmt.Errorf("insert user %d: %w", row.ID, err)
		}
	}
	return tx.Commit()
}

func (s *SQLStore) FindByEmail(ctx context.Context, tenant, email string) ([]User, error) {
	cipher := s.cipher(tenant)
	term, err := emailPlan.Equality(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	rows, err := s.query(ctx, selectUser+` WHERE email_eq = $1`, term)
	if err != nil {
		return nil, err
	}
	return userRowPlan.DecryptAll(ctx, cipher, rows)
}

// OldestFirst returns users aged minAge or over, oldest first. ORE terms
// compare in Go; a range scan inside the database needs EQL's ORE operators.
func (s *SQLStore) OldestFirst(ctx context.Context, tenant string, minAge uint32) ([]User, error) {
	cipher := s.cipher(tenant)
	floor, err := agePlan.Ore(ctx, cipher, minAge)
	if err != nil {
		return nil, err
	}
	rows, err := s.query(ctx, selectUser)
	if err != nil {
		return nil, err
	}
	rows = slices.DeleteFunc(rows, func(r UserRow) bool { return r.AgeOre.Compare(floor) < 0 })
	slices.SortFunc(rows, func(a, b UserRow) int { return b.AgeOre.Compare(a.AgeOre) })
	return userRowPlan.DecryptAll(ctx, cipher, rows)
}

func (s *SQLStore) WithRole(ctx context.Context, tenant, role string) ([]User, error) {
	cipher := s.cipher(tenant)
	contains, err := attrsPlan.Contains(ctx, cipher, map[string]any{"role": role})
	if err != nil {
		return nil, err
	}
	// Illustrative: the containment predicate is EQL's.
	rows, err := s.query(ctx, selectUser+` WHERE attrs @> $1`, contains)
	if err != nil {
		return nil, err
	}
	return userRowPlan.DecryptAll(ctx, cipher, rows)
}

func (s *SQLStore) query(ctx context.Context, q string, params ...any) ([]UserRow, error) {
	rs, err := s.db.QueryContext(ctx, q, params...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()

	var found []UserRow
	for rs.Next() {
		var r UserRow
		if err := rs.Scan(&r.ID, &r.Email, &r.EmailEq, &r.EmailMatch, &r.Age, &r.AgeEq, &r.AgeOre, &r.Attrs, &r.Notes); err != nil {
			return nil, err
		}
		found = append(found, r)
	}
	return found, rs.Err()
}

func args(r UserRow) []any {
	return []any{r.ID, r.Email, r.EmailEq, r.EmailMatch, r.Age, r.AgeEq, r.AgeOre, r.Attrs, r.Notes}
}

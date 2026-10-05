// Package blocklist keeps blocked email addresses. A value with no record
// around it is a struct with one field.
package blocklist

import (
	"context"
	"database/sql"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

//go:generate go tool stashgen -type Blocked

type Blocked struct {
	_     struct{} `stash:"context=blocked_emails"`
	Email string   `stash:"email,encrypt,index=equality"`
}

type List struct {
	db     *sql.DB
	cipher *stackencrypt.Cipher
}

func New(db *sql.DB, cipher *stackencrypt.Cipher) *List {
	return &List{db: db, cipher: cipher}
}

func (l *List) Block(ctx context.Context, email string) error {
	encrypted, err := stackencrypt.Encrypt(ctx, l.cipher, []Blocked{{Email: email}})
	if err != nil {
		return err
	}
	enc := encrypted[0]
	_, err = l.db.ExecContext(ctx,
		`INSERT INTO blocked_emails (email, email_eq) VALUES ($1, $2) ON CONFLICT (email_eq) DO NOTHING`,
		enc.Email.Ciphertext, enc.Email.Equality)
	return err
}

func (l *List) Blocked(ctx context.Context, email string) (bool, error) {
	term, err := BlockedFields.Email.Equality(ctx, l.cipher, email)
	if err != nil {
		return false, err
	}
	var blocked bool
	err = l.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM blocked_emails WHERE email_eq = $1)`, term).Scan(&blocked)
	return blocked, err
}

// All returns every blocked address, for review. Decryption reads only the
// ciphertext column.
func (l *List) All(ctx context.Context) ([]string, error) {
	rs, err := l.db.QueryContext(ctx, `SELECT email FROM blocked_emails`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()

	var encrypted []EncryptedBlocked
	for rs.Next() {
		var e EncryptedBlocked
		if err := rs.Scan(&e.Email.Ciphertext); err != nil {
			return nil, err
		}
		encrypted = append(encrypted, e)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	blocked, err := stackencrypt.Decrypt(ctx, l.cipher, encrypted)
	if err != nil {
		return nil, err
	}
	emails := make([]string, len(blocked))
	for i, b := range blocked {
		emails[i] = b.Email
	}
	return emails, nil
}

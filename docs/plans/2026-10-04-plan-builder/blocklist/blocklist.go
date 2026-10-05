// Package blocklist keeps blocked email addresses. Each address is one value
// with no record around it, so it uses a value plan.
package blocklist

import (
	"context"
	"database/sql"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

var blockedPlan = stackencrypt.MustValuePlan[string]("blocked_emails/email", stackencrypt.Equality)

type List struct {
	db     *sql.DB
	cipher *stackencrypt.Cipher
}

func New(db *sql.DB, cipher *stackencrypt.Cipher) *List {
	return &List{db: db, cipher: cipher}
}

func (l *List) Block(ctx context.Context, email string) error {
	field, err := blockedPlan.Encrypt(ctx, l.cipher, email)
	if err != nil {
		return err
	}
	_, err = l.db.ExecContext(ctx,
		`INSERT INTO blocked_emails (email, email_eq) VALUES ($1, $2) ON CONFLICT (email_eq) DO NOTHING`,
		field.Ciphertext, field.Equality)
	return err
}

func (l *List) Blocked(ctx context.Context, email string) (bool, error) {
	term, err := blockedPlan.Equality(ctx, l.cipher, email)
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

	var fields []stackencrypt.EncryptedField
	for rs.Next() {
		var sealed stackencrypt.Ciphertext
		if err := rs.Scan(&sealed); err != nil {
			return nil, err
		}
		fields = append(fields, stackencrypt.EncryptedField{Ciphertext: sealed})
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	return blockedPlan.DecryptAll(ctx, l.cipher, fields)
}

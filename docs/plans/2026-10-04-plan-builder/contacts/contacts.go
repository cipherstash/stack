// Package contacts encrypts crm.Contact, a type that cannot carry stash tags.
package contacts

import (
	"context"
	"database/sql"

	"example.com/app/crm"
	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

//go:generate go tool stashgen -type contactStash -for crm.Contact

// contactStash declares the plan for crm.Contact. stashgen matches each field
// to the crm.Contact field with the same name and type, and refuses a
// crm.Contact field this struct does not name.
type contactStash struct {
	_           struct{} `stash:"context=contacts"`
	ID          int64    `stash:"id,passthrough"`
	Email       string   `stash:"email,encrypt,index=equality;match"`
	PhoneNumber string   `stash:"phone_number,encrypt,index=equality"`
	Internal    string   `stash:"-"`
}

func Create(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, contact crm.Contact) error {
	encrypted, err := ContactPlan.Encrypt(ctx, cipher, []crm.Contact{contact})
	if err != nil {
		return err
	}
	enc := encrypted[0]
	_, err = db.ExecContext(ctx, `
		INSERT INTO contacts (id, email, email_eq, email_match, phone_number, phone_number_eq)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		enc.ID, enc.Email.Ciphertext, enc.Email.Equality, enc.Email.Match,
		enc.PhoneNumber.Ciphertext, enc.PhoneNumber.Equality)
	return err
}

func IDByPhone(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, phone string) (int64, error) {
	term, err := ContactFields.PhoneNumber.Equality(ctx, cipher, phone)
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRowContext(ctx, `SELECT id FROM contacts WHERE phone_number_eq = $1`, term).Scan(&id)
	return id, err
}

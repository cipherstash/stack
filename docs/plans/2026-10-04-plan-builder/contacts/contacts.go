// Package contacts builds a plan by hand for a type with no stash tags.
package contacts

import (
	"context"
	"database/sql"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

// Contact has no stash tags. Bind matches each plan field to the struct field
// whose name, in snake_case, is the plan field's name.
type Contact struct {
	ID          int64
	Email       string
	PhoneNumber string
	Internal    string
}

var contactsPlan = stackencrypt.MustBind[Contact](stackencrypt.NewPlan("contacts").
	Passthrough("id").
	EncryptIndex("email", stackencrypt.Equality, stackencrypt.Match()).
	EncryptIndex("phone_number", stackencrypt.Equality).
	Omit("internal").
	MustBuild())

func Create(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, contact Contact) error {
	record, err := contactsPlan.Encrypt(ctx, cipher, contact)
	if err != nil {
		return err
	}
	email, err := record.Field("email")
	if err != nil {
		return err
	}
	phone, err := record.Field("phone_number")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO contacts (id, email, email_eq, email_match, phone_number, phone_number_eq)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		contact.ID, email.Ciphertext, email.Equality, email.Match, phone.Ciphertext, phone.Equality)
	return err
}

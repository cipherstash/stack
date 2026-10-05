// Package contacts encrypts crm.Contact, a type from another package, into
// separate columns: one for the ciphertext and one for each term.
package contacts

import (
	"context"
	"database/sql"

	"example.com/app/crm"
	"github.com/cipherstash/stack/languages/golang/encrypt"
	"gorm.io/gorm"
)

//go:generate go tool stashgen -type contactStash -for crm.Contact -model Rows=ContactRow

// contactStash declares the tags for crm.Contact, which cannot carry them.
// stashgen matches each field to the crm.Contact field with the same name and
// type, and refuses a crm.Contact field this struct does not name.
type contactStash struct {
	_           struct{} `stash:"context=contacts"`
	ID          int64    `stash:"id,passthrough"`
	Email       string   `stash:"email,encrypt,index=equality;match"`
	PhoneNumber string   `stash:"phone_number,encrypt,index=equality"`
	Internal    string   `stash:"-"`
}

// ContactRow is a model: one field for each column. Each tag names the output
// the field holds.
type ContactRow struct {
	ID            int64                `stash:"id"`
	Email         encrypt.Ciphertext   `stash:"email"`
	EmailEq       encrypt.EqualityTerm `stash:"email,equality"`
	EmailMatch    encrypt.MatchTerm    `stash:"email,match"`
	PhoneNumber   encrypt.Ciphertext   `stash:"phone_number"`
	PhoneNumberEq encrypt.EqualityTerm `stash:"phone_number,equality"`
}

func (ContactRow) TableName() string { return "contacts" }

// Create writes with database/sql and passes each output itself.
func Create(ctx context.Context, db *sql.DB, cipher *encrypt.Cipher, list []crm.Contact) error {
	encrypted, err := Encrypt(ctx, cipher, list)
	if err != nil {
		return err
	}
	for _, e := range encrypted {
		_, err := db.ExecContext(ctx, `
			INSERT INTO contacts (id, email, email_eq, email_match, phone_number, phone_number_eq)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			e.ID, e.Email.Ciphertext, e.Email.Equality, e.Email.Match,
			e.PhoneNumber.Ciphertext, e.PhoneNumber.Equality)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateWithGORM writes the model, which GORM maps one field to one column.
func CreateWithGORM(ctx context.Context, db *gorm.DB, cipher *encrypt.Cipher, list []crm.Contact) error {
	rows, err := EncryptRows(ctx, cipher, list)
	if err != nil {
		return err
	}
	return db.WithContext(ctx).Create(&rows).Error
}

func IDByPhone(ctx context.Context, db *sql.DB, cipher *encrypt.Cipher, phone string) (int64, error) {
	term, err := Fields.PhoneNumber.Equality(ctx, cipher, phone)
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRowContext(ctx, `SELECT id FROM contacts WHERE phone_number_eq = $1`, term).Scan(&id)
	return id, err
}

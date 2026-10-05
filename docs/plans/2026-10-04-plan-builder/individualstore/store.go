// Package individualstore keeps individuals in Postgres.
package individualstore

import (
	"context"
	"database/sql"

	"example.com/app/individuals"
	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

func Create(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, person individuals.Individual) error {
	encrypted, err := individuals.Encrypt(ctx, cipher, []individuals.Individual{person})
	if err != nil {
		return err
	}
	e := encrypted[0]
	_, err = db.ExecContext(ctx, `
		INSERT INTO individuals (id, nickname, name, email, email_eq, email_match, medicare_number, medicare_number_eq)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ID, e.Nickname, e.Name.Ciphertext, e.Email.Ciphertext, e.Email.Equality, e.Email.Match,
		e.MedicareNo.Ciphertext, e.MedicareNo.Equality)
	return err
}

func IDByMedicare(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, medicareNo string) (int64, error) {
	term, err := individuals.Fields.MedicareNo.Equality(ctx, cipher, medicareNo)
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRowContext(ctx, `SELECT id FROM individuals WHERE medicare_number_eq = $1`, term).Scan(&id)
	return id, err
}

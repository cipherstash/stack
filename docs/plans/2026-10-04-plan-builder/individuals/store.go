// Package individuals keeps protobuf Individual messages in Postgres. The
// rules in package rules decide how each field is encrypted, and stashgen
// writes individual_stash.go from them.
package individuals

import (
	"context"
	"database/sql"

	"example.com/app/internal/pb"
	"github.com/cipherstash/stack/languages/golang/encrypt"
)

func Create(ctx context.Context, db *sql.DB, cipher *encrypt.Cipher, people []*pb.Individual) error {
	encrypted, err := Encrypt(ctx, cipher, people)
	if err != nil {
		return err
	}
	for _, e := range encrypted {
		_, err := db.ExecContext(ctx, `
			INSERT INTO individuals (id, nickname, name, email, email_eq, email_match, medicare_number)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			e.Id, e.Nickname, e.Name.Ciphertext, e.Email.Ciphertext, e.Email.Equality, e.Email.Match, e.MedicareNo)
		if err != nil {
			return err
		}
	}
	return nil
}

func IDByMedicare(ctx context.Context, db *sql.DB, cipher *encrypt.Cipher, medicareNo string) (int64, error) {
	query, err := Fields.MedicareNo.Query(ctx, cipher, medicareNo)
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRowContext(ctx,
		`SELECT id FROM individuals WHERE medicare_number = $1::eql_v3.query_text_eq`, query).Scan(&id)
	return id, err
}

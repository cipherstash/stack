// Package documents seals each document as one value. Nothing inside it can
// be read or searched on its own, so its fields carry no tags.
package documents

import (
	"context"
	"database/sql"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

//go:generate go tool stashgen -type Document

type Document struct {
	_     struct{} `stash:"context=documents/v2/body,opaque"`
	Title string
	Body  string
	Tags  []string
}

func Save(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, id int64, doc Document) error {
	encrypted, err := Encrypt(ctx, cipher, []Document{doc})
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO documents (id, body) VALUES ($1, $2)`, id, encrypted[0].Sealed)
	return err
}

// Load decrypts with the client, which opens each value under the keyset that
// sealed it. A *stackencrypt.Cipher would also refuse a value from another
// keyset.
func Load(ctx context.Context, db *sql.DB, client *stackencrypt.Client, id int64) (Document, error) {
	var encrypted EncryptedDocument
	if err := db.QueryRowContext(ctx, `SELECT body FROM documents WHERE id = $1`, id).Scan(&encrypted.Sealed); err != nil {
		return Document{}, err
	}
	docs, err := Decrypt(ctx, client, []EncryptedDocument{encrypted})
	if err != nil {
		return Document{}, err
	}
	return docs[0], nil
}

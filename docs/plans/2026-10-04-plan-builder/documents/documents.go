// Package documents seals each document as one tree under one context. A
// document is stored and read whole, so it needs no plan.
package documents

import (
	"context"
	"database/sql"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

type Document struct {
	Title string
	Body  string
	Tags  []string
}

var bodyContext = mustLabel("documents", "v2", "body").Context()

func mustLabel(segments ...string) stackencrypt.Label {
	label, err := stackencrypt.NewLabel(segments...)
	if err != nil {
		panic(err)
	}
	return label
}

func Save(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, id int64, doc Document) error {
	sealed, err := cipher.Encrypt(ctx, doc, bodyContext)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO documents (id, body) VALUES ($1, $2)`, id, sealed)
	return err
}

// Load decrypts with the client, which opens each leaf under the keyset that
// sealed it. A *stackencrypt.Cipher would also refuse a leaf from another
// keyset.
func Load(ctx context.Context, db *sql.DB, client *stackencrypt.Client, id int64) (Document, error) {
	var sealed stackencrypt.Ciphertext
	if err := db.QueryRowContext(ctx, `SELECT body FROM documents WHERE id = $1`, id).Scan(&sealed); err != nil {
		return Document{}, err
	}
	return stackencrypt.DecryptValue[Document](ctx, client, sealed, bodyContext)
}

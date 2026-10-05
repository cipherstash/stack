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

func bodyContext() (stackencrypt.Context, error) {
	label, err := stackencrypt.NewLabel("documents", "v2", "body")
	if err != nil {
		return stackencrypt.Context{}, err
	}
	return label.Context(), nil
}

func Save(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, id int64, doc Document) error {
	body, err := bodyContext()
	if err != nil {
		return err
	}
	sealed, err := cipher.Encrypt(ctx, doc, body)
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
	body, err := bodyContext()
	if err != nil {
		return Document{}, err
	}
	var sealed stackencrypt.Ciphertext
	if err := db.QueryRowContext(ctx, `SELECT body FROM documents WHERE id = $1`, id).Scan(&sealed); err != nil {
		return Document{}, err
	}
	return stackencrypt.DecryptValue[Document](ctx, client, sealed, body)
}

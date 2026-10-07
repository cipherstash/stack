# Encrypt a document as one opaque value

This example encrypts each `Document` as one ciphertext column.
Its fields have no tags because the opaque layout does not expose or index them separately.
The Golang SDK for CipherStash Stack is planned and does not exist yet, so this code does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

`document_stash.go` is written by hand.
It shows what `stashgen` is planned to write.

## What you will learn

- Declare an opaque tagged struct and its encryption context.
- Read the opaque declaration and single ciphertext field.
- Save with a cipher and load with the client.

## Declare one opaque value

- **Purpose:** Understand why the document fields have no individual tags.
- **Related:** [The plan's struct tags](../../2026-10-04-plan-builder.md#struct-tags), [the plan's column layouts](../../2026-10-04-plan-builder.md#columns)

The `opaque` option is part of the encryption context tag.
It tells the planned generator to encrypt the complete `Document` as one value.
`Title`, `Body`, and `Tags` therefore have no `stash` tags.

[`documents.go`, lines 12 to 19](documents.go#L12-L19)

```go
//go:generate go tool stashgen -type Document

type Document struct {
	_     struct{} `stash:"context=documents/v2/body,opaque"`
	Title string
	Body  string
	Tags  []string
}
```

Nothing inside the document can be read or searched independently through this layout.

## Read the single ciphertext layout

- **Purpose:** Follow the opaque tag into the encrypted type and declaration.
- **Related:** [The plan's generated file design](../../2026-10-04-plan-builder.md#what-stashgen-writes)

`EncryptedDocument` has one `Sealed` ciphertext field.

[`document_stash.go`, lines 19 to 29](document_stash.go#L19-L29)

```go
type EncryptedDocument struct {
	Sealed encrypt.Ciphertext
}

func (e EncryptedDocument) String() string {
	return gensupport.Redacted("EncryptedDocument", nil, "Sealed")
}

func (e EncryptedDocument) LogValue() slog.Value {
	return gensupport.RedactedLog(nil, "Sealed")
}
```

`DeclareOpaque` builds the declaration for the complete value.
The codec maps all three document fields into `gensupport.OpaqueField`.

[`document_stash.go`, lines 41 to 49](document_stash.go#L41-L49)

```go
var declaration = gensupport.DeclareOpaque("documents/v2/body")

var codec = gensupport.New(gensupport.Generated[Document, EncryptedDocument]{
	TypeName:        "Document",
	Declaration:     declaration,
	PrintsPlaintext: true,
	Source: func(v Document) gensupport.Values {
		return gensupport.Values{gensupport.OpaqueField: map[string]any{"title": v.Title, "body": v.Body, "tags": v.Tags}}
	},
```

## Save with a cipher and load with the client

- **Purpose:** See why `Save` uses a cipher and `Load` uses the client.
- **Related:** [The plan's call design](../../2026-10-04-plan-builder.md#calls), [the root example program](../main.go)

`Save` encrypts one document by passing a one-element slice.
It stores `encrypted[0].Sealed` in the `body` column.

[`documents.go`, lines 21 to 28](documents.go#L21-L28)

```go
func Save(ctx context.Context, db *sql.DB, cipher *encrypt.Cipher, id int64, doc Document) error {
	encrypted, err := Encrypt(ctx, cipher, []Document{doc})
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO documents (id, body) VALUES ($1, $2)`, id, encrypted[0].Sealed)
	return err
}
```

`Load` decrypts with the client, not the cipher.
A `*Client` decrypts each value under the keyset that encrypted it.
A `*Cipher` refuses a value from another keyset with `ErrForeignKeyset`.

[`documents.go`, lines 30 to 43](documents.go#L30-L43)

```go
// Load decrypts with the client, which opens each value under the keyset that
// sealed it. A *encrypt.Cipher would also refuse a value from another
// keyset.
func Load(ctx context.Context, db *sql.DB, client *encrypt.Client, id int64) (Document, error) {
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
```

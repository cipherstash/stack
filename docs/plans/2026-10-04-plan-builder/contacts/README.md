# Encrypt a contact type from another package into separate columns

This directory declares encryption for `crm.Contact`, a type from another package.
It stores ciphertexts and search terms in separate columns, with a model for GORM.
An output is a ciphertext or one search term.
The Go software development kit (SDK) is planned and does not exist yet, so this code does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

`contactstash_stash.go` is written by hand.
It shows what `stashgen` is planned to write.

## What you will learn

- Declare tags for a type in another package.
- Read the nested encrypted field types and available indexes.
- Map separate outputs into a model with a shape check.
- Insert contacts through `database/sql` or GORM.
- Search a stored search term by phone number.

## Declare tags for a type in another package

- **Purpose:** Connect a tag declaration in your own package to `crm.Contact`.
- **Related:** [The `crm.Contact` type in another package](../crm/README.md), [the plan's design for types in another package](../../2026-10-04-plan-builder.md#types-in-another-package)
- **Needs:** Understand that the program does not own `crm.Contact`.

The `-for crm.Contact` flag makes `contactStash` declare tags for a type in another package.
The generator is planned to match fields by name and type.

[`contacts.go`, lines 14 to 25](contacts.go#L14-L25)

```go
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
```

`Email` declares the `equality` and `match` indexes.
`PhoneNumber` declares only the `equality` index.

The engine produces only the `TextEq` Encrypt Query Language (EQL) type today.
No EQL type is built from match search terms yet.
The plan therefore uses separate columns for `Email`, which needs a match search.
One EQL column for each field is the layout to use when a suitable EQL type exists.

The generated file uses a shape check for `crm.Contact`.
A change to `crm.Contact` stops the contacts package from building.

[`contactstash_stash.go`, lines 45 to 53](contactstash_stash.go#L45-L53)

```go
// Stops compiling when crm.Contact gains, loses, reorders or retypes a field.
var _ = contactShape(crm.Contact{})

type contactShape struct {
	ID          int64
	Email       string
	PhoneNumber string
	Internal    string
}
```

## Read the separate encrypted outputs

- **Purpose:** See how each encrypted field holds a ciphertext and its declared search terms.
- **Related:** [The plan's column layouts](../../2026-10-04-plan-builder.md#columns), [the plan's generated file design](../../2026-10-04-plan-builder.md#what-stashgen-writes)
- **Needs:** Understand the `contactStash` tags.

`EncryptedContact` nests one encrypted type for each encrypted field.

[`contactstash_stash.go`, lines 20 to 30](contactstash_stash.go#L20-L30)

```go
type EncryptedContact struct {
	ID          int64
	Email       EncryptedContactEmail
	PhoneNumber EncryptedContactPhoneNumber
}

type EncryptedContactEmail struct {
	Ciphertext encrypt.Ciphertext
	Equality   encrypt.EqualityTerm
	Match      encrypt.MatchTerm
}
```

[`contactstash_stash.go`, lines 32 to 35](contactstash_stash.go#L32-L35)

```go
type EncryptedContactPhoneNumber struct {
	Ciphertext encrypt.Ciphertext
	Equality   encrypt.EqualityTerm
}
```

The declaration uses `EncryptIndex` to request those separate outputs.

[`contactstash_stash.go`, lines 55 to 59](contactstash_stash.go#L55-L59)

```go
var declaration = gensupport.Declare("contacts").
	Passthrough("id").
	EncryptIndex("email", encrypt.Equality, encrypt.Match()).
	EncryptIndex("phone_number", encrypt.Equality).
	Omit("internal")
```

The generated file can add print methods to `EncryptedContact`.
It cannot add methods to `crm.Contact` because Go requires methods to belong to the type's package.

[`contactstash_stash.go`, lines 17 to 18](contactstash_stash.go#L17-L18)

```go
// crm.Contact prints its sealed fields in the clear, and stashgen cannot add
// print methods to a type from another package.
```

## Map outputs into a model

- **Purpose:** Flatten nested encrypted outputs into one field for each database column.
- **Related:** [The plan's model design](../../2026-10-04-plan-builder.md#models)
- **Needs:** Understand the separate encrypted outputs.

`-model Rows=ContactRow` asks for `EncryptRows` and `DecryptRows`.
`ContactRow` is a model with one tagged field for each column.
`EncryptedContact` nests structs, but GORM maps one struct field to one column.
This separate-column layout therefore needs `ContactRow` for GORM.

[`contacts.go`, lines 27 to 36](contacts.go#L27-L36)

```go
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
```

`rowsShape` is the model's shape check.
The conversions compile only while the fields, types, and order match.

[`contactstash_stash.go`, lines 155 to 164](contactstash_stash.go#L155-L164)

```go
// The -model flag: ContactRow converts to and from its shape only while the
// two have the same fields, with the same types, in the same order.
type rowsShape struct {
	ID            int64
	Email         encrypt.Ciphertext
	EmailEq       encrypt.EqualityTerm
	EmailMatch    encrypt.MatchTerm
	PhoneNumber   encrypt.Ciphertext
	PhoneNumberEq encrypt.EqualityTerm
}
```

[`contactstash_stash.go`, lines 187 to 193](contactstash_stash.go#L187-L193)

```go
func EncryptRows(ctx context.Context, cipher *encrypt.Cipher, contacts []crm.Contact) ([]ContactRow, error) {
	return rowsCodec.Encrypt(ctx, cipher, contacts)
}

func DecryptRows(ctx context.Context, d encrypt.Decrypter, rows []ContactRow) ([]crm.Contact, error) {
	return rowsCodec.Decrypt(ctx, d, rows)
}
```

## Insert contacts through two database APIs

- **Purpose:** Compare direct column writes with a model-based GORM write.
- **Related:** [The plan's database design](../../2026-10-04-plan-builder.md#databases)
- **Needs:** Understand both encrypted layouts.

`Create` passes each nested output to `database/sql`.

[`contacts.go`, lines 41 to 51](contacts.go#L41-L51)

```go
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
```

`CreateWithGORM` asks `EncryptRows` for the flat model before GORM receives it.

[`contacts.go`, lines 59 to 66](contacts.go#L59-L66)

```go
// CreateWithGORM writes the model, which GORM maps one field to one column.
func CreateWithGORM(ctx context.Context, db *gorm.DB, cipher *encrypt.Cipher, list []crm.Contact) error {
	rows, err := EncryptRows(ctx, cipher, list)
	if err != nil {
		return err
	}
	return db.WithContext(ctx).Create(&rows).Error
}
```

## Search by the phone search term

- **Purpose:** Derive and use the equality search term for a separate column.
- **Related:** [The plan's call design](../../2026-10-04-plan-builder.md#calls), [the plan's terminology](../../2026-10-04-plan-builder.md#terminology)
- **Needs:** Understand the `phone_number_eq` column.

`Fields.PhoneNumber.Equality` derives an `encrypt.EqualityTerm` search term.
The query compares that search term with the `phone_number_eq` column.

[`contacts.go`, lines 68 to 76](contacts.go#L68-L76)

```go
func IDByPhone(ctx context.Context, db *sql.DB, cipher *encrypt.Cipher, phone string) (int64, error) {
	term, err := Fields.PhoneNumber.Equality(ctx, cipher, phone)
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRowContext(ctx, `SELECT id FROM contacts WHERE phone_number_eq = $1`, term).Scan(&id)
	return id, err
}
```

## What was checked

- **Every Go file type-checks:**
  Run.
  `go vet ./...` passes against a stub of the SDK.
  The stub is not in this repository, and it has signatures only.
- **A change to a tagged struct, a model or a type in another package stops the build:**
  Run.
  Each change fails `go build` with "cannot convert".
- **A generated file from another version does not compile:**
  Run.
  A file that names an unknown version constant fails `go build`.
- **The files `stashgen` writes:**
  Not run.
  `stashgen` does not exist, and the five `_stash.go` files are written by hand.
- **The SDK can be built with these signatures:**
  Not run.
- **`stashgen` checks a declaration with the embedded guest:**
  Not run.
- **The code works with a database, GORM or pgx:**
  Not run.
  Nothing here has connected to a database.

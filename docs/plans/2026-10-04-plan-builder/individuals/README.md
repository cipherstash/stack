# Store a protobuf message with mixed encrypted layouts

This directory shows the generated file planned from the `Individual` policy rules.
One message combines passthrough fields, separate columns, and one Encrypt Query Language (EQL) column.
The Go software development kit (SDK) is planned and does not exist yet, so this code does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

`individual_stash.go` is written by hand.
It shows what `stashgen.Generate` is planned to write.

## What you will learn

- Read the mixed storage layouts chosen by the policy rules.
- Follow pointer messages through field-by-name reads instead of a shape check.
- Use the generated helpers and let the compiler reject an undeclared query.
- Insert encrypted fields and search the Medicare EQL column.

## Read the mixed storage layouts

- **Purpose:** Connect policy decisions to the encrypted type and declaration.
- **Related:** [The rules walkthrough](../rules/README.md), [the plan's policy declarations](../../2026-10-04-plan-builder.md#declarations-from-a-policy)
- **Needs:** Understand `rules.Individuals`.

`Id` and `Nickname` are passthrough fields.
`Name` has one ciphertext, while `Email` has a ciphertext and two search terms.
`MedicareNo` uses one `TextEq` EQL column named `medicare_number` in the declaration.

[`individual_stash.go`, lines 25 to 31](individual_stash.go#L25-L31)

```go
type EncryptedIndividual struct {
	Id         int64
	Name       EncryptedIndividualName
	Email      EncryptedIndividualEmail
	MedicareNo eql.TextEq
	Nickname   string
}
```

[`individual_stash.go`, lines 33 to 41](individual_stash.go#L33-L41)

```go
type EncryptedIndividualName struct {
	Ciphertext encrypt.Ciphertext
}

type EncryptedIndividualEmail struct {
	Ciphertext encrypt.Ciphertext
	Equality   encrypt.EqualityTerm
	Match      encrypt.MatchTerm
}
```

[`individual_stash.go`, lines 51 to 56](individual_stash.go#L51-L56)

```go
var declaration = gensupport.Declare("individuals").
	Passthrough("id").
	Encrypt("name").
	EncryptIndex("email", encrypt.Equality, encrypt.Match()).
	EncryptInto("medicare_number", "TextEq").
	Passthrough("nickname")
```

## Read pointer messages by field name

- **Purpose:** Understand why protobuf messages do not use the usual shape check.
- **Related:** [The generated protobuf walkthrough](../internal/pb/README.md), [the plan's design for types in another package](../../2026-10-04-plan-builder.md#types-in-another-package)
- **Needs:** Know that `pb.Individual` contains unexported protobuf fields.

The codec takes `*pb.Individual` values.
It reads each field through a generated getter because direct struct conversion cannot include unexported fields.

[`individual_stash.go`, lines 58 to 69](individual_stash.go#L58-L69)

```go
var codec = gensupport.New(gensupport.Generated[*pb.Individual, EncryptedIndividual]{
	TypeName:        "pb.Individual",
	Declaration:     declaration,
	PrintsPlaintext: true,
	Source: func(v *pb.Individual) gensupport.Values {
		return gensupport.Values{
			"id":              v.GetId(),
			"name":            v.GetName(),
			"email":           v.GetEmail(),
			"medicare_number": v.GetMedicareNo(),
			"nickname":        v.GetNickname(),
		}
```

The compiler finds a removed or retyped field through these named reads.
Adding a field to `Individual` does not stop the build.
Continuous integration (CI) runs `go generate ./...` and fails when a generated file differs from the committed file.

> **Take care**
>
> The [`String` method of `pb.Individual`](../internal/pb/individual.pb.go#L44-L46) prints every field in plaintext.
> `stashgen` cannot replace that method, because `pb.Individual` is a type in another package.
> Do not print or log `pb.Individual` values.

## Use the generated helpers

- **Purpose:** Follow protobuf pointers and the Medicare field through the generated API.
- **Related:** [The plan's call design](../../2026-10-04-plan-builder.md#calls), [the generation command walkthrough](../cmd/genencrypt/README.md)
- **Needs:** Understand the codec's pointer type.

`Encrypt` accepts a slice of `*pb.Individual` pointers.
`Decrypt` returns the same pointer form.

[`individual_stash.go`, lines 117 to 123](individual_stash.go#L117-L123)

```go
func Encrypt(ctx context.Context, cipher *encrypt.Cipher, individuals []*pb.Individual) ([]EncryptedIndividual, error) {
	return codec.Encrypt(ctx, cipher, individuals)
}

func Decrypt(ctx context.Context, d encrypt.Decrypter, encrypted []EncryptedIndividual) ([]*pb.Individual, error) {
	return codec.Decrypt(ctx, d, encrypted)
}
```

`Name` declares encryption without an index, so `NameField` has only an `Encrypt` method.

[`individual_stash.go`, lines 135 to 142](individual_stash.go#L135-L142)

```go
type NameField struct {
	field gensupport.Field[string]
}

func (f NameField) Encrypt(ctx context.Context, c *encrypt.Cipher, v string) (EncryptedIndividualName, error) {
	out, err := f.field.Encrypt(ctx, c, v)
	return EncryptedIndividualName{Ciphertext: out.Ciphertext}, err
}
```

`Fields.Name.Equality` does not compile because `NameField` does not declare that method.

`Fields.MedicareNo.Query` returns an `eql.TextEqQuery` query value.

[`individual_stash.go`, lines 168 to 176](individual_stash.go#L168-L176)

```go
func (f MedicareNoField) Encrypt(ctx context.Context, c *encrypt.Cipher, v string) (eql.TextEq, error) {
	out, err := f.field.Encrypt(ctx, c, v)
	return eql.TextEq(out.EQL), err
}

func (f MedicareNoField) Query(ctx context.Context, c *encrypt.Cipher, v string) (eql.TextEqQuery, error) {
	out, err := f.field.Query(ctx, c, v)
	return eql.TextEqQuery(out.EQL), err
}
```

## Insert fields and search Medicare numbers

- **Purpose:** Map each storage layout to its database columns and query.
- **Related:** [The plan's database design](../../2026-10-04-plan-builder.md#databases)
- **Needs:** Understand the mixed encrypted type.

`Create` passes the passthrough fields, ciphertexts, search terms, and EQL value to their columns.

[`store.go`, lines 14 to 23](store.go#L14-L23)

```go
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
```

`IDByMedicare` creates a query value and casts it to `eql_v3.query_text_eq` in SQL.

[`store.go`, lines 31 to 40](store.go#L31-L40)

```go
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
```

## What was checked

- **Every Go file type-checks:**
  Run.
  `go vet ./...` passes against a stub of the SDK.
  The stub is not in this repository, and it has signatures only.
- **The policy example compiles against real protobuf code:**
  Run.
  buf v1.50.0 and `protoc-gen-go` wrote `internal/pb/`, and `go vet` passes.
- **A field added to the protobuf message does not stop the build:**
  Run.
  It builds, as the plan says: CI finds that change.
- **A struct from another package with an unexported field cannot convert:**
  Run, with `sync.Once`.
- **A generated file from another version does not compile:**
  Run.
  A file that names an unknown version constant fails `go build`.
- **The protobuf source reads the field options, and the rules run:**
  Not run.
  Neither the source nor the generator exists.
- **The files `stashgen` writes:**
  Not run.
  `stashgen` does not exist, and the five `_stash.go` files are written by hand.
- **The SDK can be built with these signatures:**
  Not run.
- **The guest returns an EQL value for a field with `encrypt_into`:**
  Not run.
  The target form and the dispatch do not exist.
- **`stashgen` checks a declaration with the embedded guest:**
  Not run.
- **The code works with a database, GORM or pgx:**
  Not run.
  Nothing here has connected to a database.
- **The EQL types, and the value the guest returns for them:**
  Not run.
  `eql-codegen` does not write Go yet, and the examples use a stub of `eql.TextEq`.

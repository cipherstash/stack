# Encrypt and store users with generated helpers

This example shows the planned path from a tagged struct to three database stores: `database/sql`, GORM and [sqlc](https://github.com/sqlc-dev/sqlc).
Each encrypted field uses one Encrypt Query Language (EQL) column.
The Golang SDK for CipherStash Stack is planned and does not exist yet, so this code does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

`user_stash.go` is written by hand.
It shows what `stashgen` is planned to write.

## What you will learn

- Declare stored fields and create a tenant cipher.
- Read what the generated file contains.
- Insert and search users with `database/sql`.
- Batch encryption before GORM receives values.
- Convert between sqlc structs and update one EQL column.

## Declare fields and create a tenant cipher

- **Purpose:** Connect the tagged struct to its generator command and runtime cipher.
- **Related:** [The plan's struct tags](../../2026-10-04-plan-builder.md#struct-tags), [the root example program](../main.go)

The `go:generate` line asks `stashgen` to read `User`.
The encryption context is `users`, and every exported field has a `stash` tag.
`ID` is a passthrough field, while `Internal` is an omitted field.
`Email` and `Name` each become one `TextEq` EQL column.

[`model.go`, lines 3 to 13](model.go#L3-L13)

```go
//go:generate go tool stashgen -type User

// Every exported field needs a stash tag, so a new field cannot reach the
// database unencrypted by accident.
type User struct {
	_        struct{} `stash:"context=users"`
	ID       int64    `stash:"id,passthrough" db:"id" gorm:"primaryKey"`
	Email    string   `stash:"email,encrypt_into=TextEq" db:"email"`
	Name     string   `stash:"name,encrypt_into=TextEq" db:"name"`
	Internal string   `stash:"-"`
}
```

The root program creates the client and derives one cipher for tenant `tenant-42`.
The cipher has the tenant's keyset and its extension to each encryption context.
`Extend` adds the tenant segment to each field's declared encryption context.
No call takes a keyset or an encryption context, so the write, query, and read cannot use different ones.

[`../main.go`, lines 25 to 30](../main.go#L25-L30)

```go
func run(ctx context.Context) error {
	client, err := encrypt.NewClient(ctx, encrypt.WithCredentials(encrypt.AutoCredentials()))
	if err != nil {
		return err
	}
	defer client.Close()
```

[`../main.go`, lines 38 to 41](../main.go#L38-L41)

```go
	// One cipher for each tenant: its keyset, and its part of every field's
	// context. Every call through this cipher carries both.
	cipher := client.Keyset(encrypt.KeysetName("tenant-42")).Extend("tenant-42")
	store := users.NewSQLStore(db)
```

## Read what the generated file contains

- **Purpose:** Understand the main parts that `stashgen` is planned to write.
- **Related:** [The plan's generated file design](../../2026-10-04-plan-builder.md#what-stashgen-writes), [the plan's call design](../../2026-10-04-plan-builder.md#calls)

`EncryptedUser` keeps `ID` and replaces `Email` and `Name` with `eql.TextEq`.
Its `String` and `LogValue` methods hide the encrypted fields when code prints the encrypted type.

[`user_stash.go`, lines 20 to 32](user_stash.go#L20-L32)

```go
type EncryptedUser struct {
	ID    int64      `db:"id" gorm:"primaryKey"`
	Email eql.TextEq `db:"email"`
	Name  eql.TextEq `db:"name"`
}

func (e EncryptedUser) String() string {
	return gensupport.Redacted("EncryptedUser", map[string]any{"ID": e.ID}, "Email", "Name")
}

func (e EncryptedUser) LogValue() slog.Value {
	return gensupport.RedactedLog(map[string]any{"ID": e.ID}, "Email", "Name")
}
```

The `userShape(User{})` conversion is the shape check.
It stops compilation when the tagged struct and generated file have different fields.
The declaration crosses to the engine with the struct.
It names each field's encryption context, indexes, and EQL type.

[`user_stash.go`, lines 35 to 49](user_stash.go#L35-L49)

```go
var _ = userShape(User{})

type userShape struct {
	_        struct{}
	ID       int64
	Email    string
	Name     string
	Internal string
}

var declaration = gensupport.Declare("users").
	Passthrough("id").
	EncryptInto("email", "TextEq").
	EncryptInto("name", "TextEq").
	Omit("internal")
```

The codec maps the tagged struct to named values before the engine encrypts them.

[`user_stash.go`, lines 51 to 57](user_stash.go#L51-L57)

```go
var codec = gensupport.New(gensupport.Generated[User, EncryptedUser]{
	TypeName:        "User",
	Declaration:     declaration,
	PrintsPlaintext: true,
	Source: func(v User) gensupport.Values {
		return gensupport.Values{"id": v.ID, "email": v.Email, "name": v.Name}
	},
```

`Encrypt` and `Decrypt` process slices through that codec.
ZeroKMS is the CipherStash key service.
`Encrypt` and `Decrypt` send one ZeroKMS request for the whole slice.
`Fields.Email.Query` creates the query value for a `WHERE` clause.

[`user_stash.go`, lines 88 to 97](user_stash.go#L88-L97)

```go
// Encrypt seals every user in one ZeroKMS request. The result has one element
// for each user, in the same order.
func Encrypt(ctx context.Context, cipher *encrypt.Cipher, users []User) ([]EncryptedUser, error) {
	return codec.Encrypt(ctx, cipher, users)
}

// Decrypt opens every value in one ZeroKMS request.
func Decrypt(ctx context.Context, d encrypt.Decrypter, encrypted []EncryptedUser) ([]User, error) {
	return codec.Decrypt(ctx, d, encrypted)
}
```

[`user_stash.go`, lines 99 to 105](user_stash.go#L99-L105)

```go
var Fields = struct {
	Email EmailField
	Name  NameField
}{
	Email: EmailField{gensupport.NewField[string](declaration, "email")},
	Name:  NameField{gensupport.NewField[string](declaration, "name")},
}
```

> **Take care**
>
> `User` has no `String` or `LogValue` method, so a program that prints or logs it shows the plaintext of `Email` and `Name`.
> [`main.go`, line 76](../main.go#L76) prints only IDs and counts for that reason.
> Write both methods, or run `stashgen` with `-redact`.
> The [accounts walkthrough](../accounts/README.md) shows `-redact`.

## Insert and search with database/sql

- **Purpose:** Follow encrypted values through a transaction and an EQL equality query.
- **Related:** [The plan's database design](../../2026-10-04-plan-builder.md#databases), [the sqlc schema walkthrough](../sqlc/README.md)

`SQLStore.Import` encrypts the whole input slice before it starts inserting rows.
It passes each `EncryptedUser` field directly to `ExecContext`.

[`sqlstore.go`, lines 27 to 39](sqlstore.go#L27-L39)

```go
// Import encrypts every user in one ZeroKMS request, then inserts them in one
// transaction.
func (s *SQLStore) Import(ctx context.Context, cipher *encrypt.Cipher, people []User) error {
	encrypted, err := Encrypt(ctx, cipher, people)
	if err != nil {
		return fmt.Errorf("encrypt %d users: %w", len(people), err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
```

[`sqlstore.go`, lines 47 to 52](sqlstore.go#L47-L52)

```go
	for _, e := range encrypted {
		if _, err := stmt.ExecContext(ctx, e.ID, e.Email, e.Name); err != nil {
			return fmt.Errorf("insert user %d: %w", e.ID, err)
		}
	}
	return tx.Commit()
```

`FindByEmail` creates an `eql.TextEqQuery` query value through `Fields.Email.Query`.
The SQL casts `$1` directly to `eql_v3.query_text_eq`.

[`sqlstore.go`, lines 59 to 70](sqlstore.go#L59-L70)

```go
// FindByEmail matches the whole address. Postgres compares the encrypted
// column through EQL's = operator.
func (s *SQLStore) FindByEmail(ctx context.Context, cipher *encrypt.Cipher, email string) ([]User, error) {
	query, err := Fields.Email.Query(ctx, cipher, email)
	if err != nil {
		return nil, err
	}
	rs, err := s.db.QueryContext(ctx, selectUser+` WHERE email = $1::eql_v3.query_text_eq`, query)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
```

## Batch before GORM receives values

- **Purpose:** See why encryption happens before GORM maps the encrypted type.
- **Related:** [The plan's database design](../../2026-10-04-plan-builder.md#databases), [the plan's call design](../../2026-10-04-plan-builder.md#calls)

`EncryptedUser.TableName` sends GORM to `users` instead of `encrypted_users`.
A `driver.Valuer` hook cannot batch because it receives one field and no `context.Context`.
It also cannot observe cancellation through `ctx`.

[`gormstore.go`, lines 10 to 19](gormstore.go#L10-L19)

```go
// TableName lets GORM use the generated type as the model. Without it GORM
// would look for a table named encrypted_users.
func (EncryptedUser) TableName() string { return "users" }

// GormStore encrypts before GORM sees a value. driver.Valuer gets no
// context.Context and runs one field at a time, so it cannot batch a ZeroKMS
// request or stop when the request is cancelled.
type GormStore struct {
	db *gorm.DB
}
```

`GormStore.Create` encrypts the slice first, then gives GORM the encrypted values.

[`gormstore.go`, lines 25 to 31](gormstore.go#L25-L31)

```go
func (s *GormStore) Create(ctx context.Context, cipher *encrypt.Cipher, people ...User) error {
	encrypted, err := Encrypt(ctx, cipher, people)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).CreateInBatches(encrypted, 500).Error
}
```

## Convert sqlc structs and update one column

- **Purpose:** Connect generated sqlc shapes and field-level updates to the encrypted type.
- **Related:** [The generated `userdb` walkthrough](../internal/userdb/README.md), [the sqlc inputs](../sqlc/README.md)

`userdb.User` and `userdb.CreateUserParams` have the same fields as `EncryptedUser`.
Go therefore converts these structs directly, and a change to either shape stops the build.
The store converts `EncryptedUser` to `userdb.CreateUserParams` before each insert.

[`sqlcstore.go`, lines 39 to 45](sqlcstore.go#L39-L45)

```go
	queries := s.queries.WithTx(tx)
	for _, e := range encrypted {
		if err := queries.CreateUser(ctx, userdb.CreateUserParams(e)); err != nil {
			return err
		}
	}
	return tx.Commit()
```

It converts each sqlc row back with `EncryptedUser(row)` before decryption.

[`sqlcstore.go`, lines 68 to 76](sqlcstore.go#L68-L76)

```go
	rows, err := s.queries.FindUsersByEmail(ctx, query)
	if err != nil {
		return nil, err
	}
	encrypted := make([]EncryptedUser, len(rows))
	for i, row := range rows {
		encrypted[i] = EncryptedUser(row)
	}
	return Decrypt(ctx, cipher, encrypted)
```

`ChangeEmail` encrypts one field and updates the single EQL column.
That column stores the ciphertext and its search term together.

[`sqlcstore.go`, lines 79 to 88](sqlcstore.go#L79-L88)

```go
// ChangeEmail rewrites one field. One EQL column holds the ciphertext and
// its term, so they cannot go out of step.
func (s *SQLCStore) ChangeEmail(ctx context.Context, cipher *encrypt.Cipher, id int64, email string) error {
	sealed, err := Fields.Email.Encrypt(ctx, cipher, email)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET email = $2 WHERE id = $1`, id, sealed)
	return err
}
```

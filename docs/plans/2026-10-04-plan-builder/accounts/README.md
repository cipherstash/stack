# Preserve GORM fields and redact an account

This example shows an embedded GORM model, copied tags, and generated print methods.
It also distinguishes an unexported field from an omitted field.
The Golang SDK for CipherStash Stack is planned and does not exist yet, so this code does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

`account_stash.go` is written by hand.
It shows what `stashgen` is planned to write.

## What you will learn

- Tag an embedded GORM model and distinguish two fields that are not stored.
- Inspect the encrypted type, copied tags, warnings, and declaration.
- Add redacted print methods to the tagged struct.
- Give the encrypted type to GORM.

## Tag the account fields

- **Purpose:** Understand how one tag covers an embedded struct from another package.
- **Related:** [The plan's embedded struct design](../../2026-10-04-plan-builder.md#embedded-structs-unexported-fields-and-other-tags), [the plan's printing design](../../2026-10-04-plan-builder.md#printing)

The `stash:",passthrough"` tag stores every `gorm.Model` field as a passthrough field.
`Email` becomes one Encrypt Query Language (EQL) column with the `TextEq` type.
`stashgen` copies the `gorm` and `json` tags of `Email` to the same field of `EncryptedAccount`.

[`account.go`, lines 12 to 21](account.go#L12-L21)

```go
//go:generate go tool stashgen -type Account -redact

type Account struct {
	_ struct{} `stash:"context=accounts"`

	// One tag decides for every field of gorm.Model, which cannot carry tags.
	gorm.Model `stash:",passthrough"`

	// stashgen copies the gorm and json tags onto EncryptedAccount.
	Email string `stash:"email,encrypt_into=TextEq" gorm:"uniqueIndex" json:"email"`
```

The unexported `cache` field has no tag, so the generator ignores it with three notices:

- `stashgen` prints a warning.
- The generated file names `cache` in a comment.
- The program prints a warning to stderr once for each type, on first use.

The `token` field uses `stash:"-"`, so it is an omitted field and produces no warning.

[`account.go`, lines 23 to 29](account.go#L23-L29)

```go
	// An unexported field with no stash tag is ignored, and stashgen and the
	// running program both warn about it.
	cache string

	// The tag acknowledges the skip, so nothing warns.
	token string `stash:"-"`
}
```

## Inspect the encrypted account

- **Purpose:** Follow copied tags and fields that are not stored into the generated file.
- **Related:** [The plan's generated file design](../../2026-10-04-plan-builder.md#what-stashgen-writes), [the plan's embedded struct design](../../2026-10-04-plan-builder.md#embedded-structs-unexported-fields-and-other-tags)

The generated comment names `cache`, and `EncryptedAccount` embeds the same `gorm.Model`.
The encrypted `Email` field retains its GORM and JSON tags.

[`account_stash.go`, lines 19 to 25](account_stash.go#L19-L25)

```go
// Not encrypted and not stored: the unexported field "cache". Tag it
// `stash:"-"` to confirm that.

type EncryptedAccount struct {
	gorm.Model
	Email eql.TextEq `gorm:"uniqueIndex" json:"email"`
}
```

The codec's `Unexported` list enables the planned runtime warning for `cache`.
The declaration omits `token` and does not include `cache`.

[`account_stash.go`, lines 55 to 66](account_stash.go#L55-L66)

```go
var declaration = gensupport.Declare("accounts").
	Passthrough("id").
	Passthrough("created_at").
	Passthrough("updated_at").
	Passthrough("deleted_at").
	EncryptInto("email", "TextEq").
	Omit("token")

var codec = gensupport.New(gensupport.Generated[Account, EncryptedAccount]{
	TypeName:    "Account",
	Declaration: declaration,
	Unexported:  []string{"cache"},
```

## Redact the tagged struct

- **Purpose:** See what the `-redact` flag adds to `Account`.
- **Related:** [The plan's printing design](../../2026-10-04-plan-builder.md#printing)

`-redact` asks `stashgen` to add `String` and `LogValue` methods to `Account`.
These methods show `gorm.Model` and hide `Email`.

[`account_stash.go`, lines 35 to 42](account_stash.go#L35-L42)

```go
// Written because of -redact: Account no longer prints its sealed fields.
func (a Account) String() string {
	return gensupport.Redacted("Account", map[string]any{"Model": a.Model}, "Email")
}

func (a Account) LogValue() slog.Value {
	return gensupport.RedactedLog(map[string]any{"Model": a.Model}, "Email")
}
```

## Give encrypted accounts to GORM

- **Purpose:** Follow a slice through encryption and into GORM.
- **Related:** [The plan's database design](../../2026-10-04-plan-builder.md#databases)

`EncryptedAccount.TableName` maps the encrypted type to the `accounts` table.
`Create` encrypts the whole slice before GORM receives it.

[`account.go`, lines 31 to 39](account.go#L31-L39)

```go
func (EncryptedAccount) TableName() string { return "accounts" }

func Create(ctx context.Context, db *gorm.DB, cipher *encrypt.Cipher, accounts []Account) error {
	encrypted, err := Encrypt(ctx, cipher, accounts)
	if err != nil {
		return err
	}
	return db.WithContext(ctx).Create(&encrypted).Error
}
```

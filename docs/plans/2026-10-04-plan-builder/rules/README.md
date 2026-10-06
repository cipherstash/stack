# Decide protobuf encryption from data categories

This example defines planned policy rules for `pb.Individual` fields.
The first matching rule chooses each field's storage layout.
The Golang SDK for CipherStash Stack is planned and does not exist yet, so this code does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

## What you will learn

- Match Fideslang data categories with shared rules.
- Add message-specific decisions and a column name.
- Run the generation command without using rules at application runtime.

## Match data categories with shared rules

- **Purpose:** Understand how `Base` decides fields from protobuf annotations.
- **Related:** [The plan's policy declarations](../../2026-10-04-plan-builder.md#declarations-from-a-policy), [the protobuf source walkthrough](../proto/README.md)
- **Needs:** Understand the `data_categories` field option.

A protobuf field can carry [data categories](https://ethyca.github.io/fideslang/taxonomy/data_categories/) from [Fideslang](https://ethyca.github.io/fideslang/), such as the category `user.contact.email`.
`policy.Key` names the field option by its full name, `classification.data_categories`.
`policy.FirstOf` evaluates each `policy.When` in order, and the first match decides.

[`rules.go`, lines 13 to 21](rules.go#L13-L21)

```go
// The key is the full name of the field option in proto/classification.proto.
var category = policy.Key("classification.data_categories")

// Base applies to every message. The first rule that matches a field decides it.
var Base = policy.FirstOf(
	policy.When(category.Under("user.government_id"), policy.EncryptInto("TextEq")),
	policy.When(category.Under("user.contact.email"), policy.EncryptIndex(encrypt.Equality, encrypt.Match())),
	policy.When(category.Under("user"), policy.Encrypt()),
)
```

Each rule in `Base` makes one decision:

- `user.government_id` uses `EncryptInto("TextEq")` and stores one Encrypt Query Language (EQL) column.
- `user.contact.email` uses `EncryptIndex` and stores a ciphertext with equality and match search terms in separate columns.
- `user` uses `Encrypt()` and stores a ciphertext without an index.

`user.contact.email` is under `user`, so its rule must come before the broader `user` rule.
If the `user` rule came first, email would use `Encrypt()` without an index.
The policy API also defines `Index`, `Omit`, and `Fail` decisions.

## Add message-specific decisions

- **Purpose:** See how `Individuals` handles fields before it falls back to `Base`.
- **Related:** [The generated individuals walkthrough](../individuals/README.md), [the protobuf source walkthrough](../proto/README.md)
- **Needs:** Understand the shared rules.

`policy.ForMessage` binds the rules to `pb.Individual` and the `individuals` encryption context.
`policy.Field` handles uncategorised fields and overrides a categorised field.
`policy.Name("medicare_number")` changes the database column name for `medicare_no`.

[`rules.go`, lines 23 to 31](rules.go#L23-L31)

```go
// Individuals adds the rules for one message. A field with no data category
// needs a rule too: with none, the generator stops.
var Individuals = policy.ForMessage(&pb.Individual{}, policy.Context("individuals"),
	policy.FirstOf(
		policy.When(policy.Field("medicare_no"), policy.EncryptInto("TextEq"), policy.Name("medicare_number")),
		policy.When(policy.Field("id"), policy.Passthrough()),
		policy.When(policy.Field("nickname"), policy.Passthrough()),
	).OrElse(Base),
)
```

`OrElse(Base)` applies the shared rules when no message-specific rule matches.
A field with no matching rule stops the planned generator.
Adding a field to `Individual` does not stop the build.
CI runs `go generate ./...` and fails when a generated file differs from the committed file.

## Run rules during generation

- **Purpose:** Keep policy evaluation out of the application runtime.
- **Related:** [The generation command walkthrough](../cmd/genencrypt/README.md), [the plan's policy declarations](../../2026-10-04-plan-builder.md#declarations-from-a-policy)
- **Needs:** Understand the complete `Individuals` policy.

The `go:generate` line runs `cmd/genencrypt`.

[`rules.go`, lines 1 to 11](rules.go#L1-L11)

```go
// Package rules decides what to encrypt from the data categories that the
// protobuf schema gives each field. Only the generate program runs it.
package rules

import (
	"example.com/app/internal/pb"
	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
)

//go:generate go run ../cmd/genencrypt
```

The application uses the generated functions and never runs these rules.

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
- **The protobuf source reads the field options, and the rules run:**
  Not run.
  Neither the source nor the generator exists.
- **The files `stashgen` writes:**
  Not run.
  `stashgen` does not exist, and the five `_stash.go` files are written by hand.
- **The SDK can be built with these signatures:**
  Not run.
- **`stashgen` checks a declaration with the embedded guest:**
  Not run.

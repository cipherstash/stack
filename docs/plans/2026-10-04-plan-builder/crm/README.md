# Stand in for a type in another package

This example stands in for a package that the program does not own.
Its `crm.Contact` type has no `stash` tags because another package controls its source.
`crm` imports no code from the Golang SDK for CipherStash Stack.

The SDK is planned and does not exist yet.
The [`contacts` package](../contacts/README.md) uses SDK code, so that package does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

## What you will learn

- Declare encryption tags for a type in another package from your own package.
- Check changes to `crm.Contact` at compile time.

## Declare tags in your own package

- **Purpose:** Understand why `crm.Contact` stays free of encryption tags.
- **Related:** [The plan's design for types in another package](../../2026-10-04-plan-builder.md#types-in-another-package), [the contacts walkthrough](../contacts/README.md)
- **Needs:** Nothing

`crm.Contact` contains only the fields supplied by the stand-in package.

[`contact.go`, lines 1 to 9](contact.go#L1-L9)

```go
// Package crm stands in for a package this program does not own.
package crm

type Contact struct {
	ID          int64
	Email       string
	PhoneNumber string
	Internal    string
}
```

The [`contacts` package](../contacts/README.md) uses `contactStash` to declare tags for `crm.Contact`.
`contactStash` leaves out `Internal` with `stash:"-"`.

[`contacts.go`, lines 19 to 25](../contacts/contacts.go#L19-L25)

```go
type contactStash struct {
	_           struct{} `stash:"context=contacts"`
	ID          int64    `stash:"id,passthrough"`
	Email       string   `stash:"email,encrypt,index=equality;match"`
	PhoneNumber string   `stash:"phone_number,encrypt,index=equality"`
	Internal    string   `stash:"-"`
}
```

## Check the type's shape at compile time

- **Purpose:** See how a change to `crm.Contact` stops the contacts package from building.
- **Related:** [The contacts walkthrough](../contacts/README.md), [the plan's design for types in another package](../../2026-10-04-plan-builder.md#types-in-another-package)
- **Needs:** Understand the fields of `crm.Contact`.

The generated file converts `crm.Contact` to `contactShape` at compile time.
The conversion fails when `crm.Contact` gains, loses, reorders, or retypes a field.

[`contactstash_stash.go`, lines 45 to 53](../contacts/contactstash_stash.go#L45-L53)

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

## What was checked

- **Every Go file type-checks:**
  Run.
  `go vet ./...` passes against a stub of the SDK.
  The stub is not in this repository, and it has signatures only.
- **A change to a tagged struct, a model or a type in another package stops the build:**
  Run.
  Each change fails `go build` with "cannot convert".

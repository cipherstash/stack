# Language SDK design principles

These principles apply when you architect, design or build a language SDK for Stack Encrypt.
The first part applies to every language.
The second part applies to the Go SDK.
[ADR-0008](../packages/stack-encrypt/docs/adr/0008-language-sdk-design-principles.md) records the decision to adopt them.

## Terms

- **Engine:** the Rust code that encrypts, decrypts and derives search terms.
- **Binding:** the FFI or WASI interface between the engine and a target language.
- **Language SDK:** what users of the target language work with day to day.
- **Declaration:** the statement of how each field is encrypted: its context, and its indexes.
  The engine calls a saved declaration a plan.

## When two principles disagree

Apply them in this order:

1. The engine does the work, and the bytes are the same in every language.
2. A mistake is found at the earliest stage.
3. The SDK hides what the user cannot act on.
4. The SDK reads like the host language.

## Principles for every language SDK

### 1. One engine, and the SDK never executes

All encryption, decryption and term derivation happens in the engine.
An SDK declares what to do and sends that across the binding as data.
An SDK does not have its own loop over fields, its own batching, or its own sealing.

- A field crosses the binding only when its value does: an SDK sends a field's declaration with the field's value.
- An SDK can keep a field on its own side when the engine computes nothing from it.
  It then sends no declaration and no value for that field.
- An SDK tool that checks a declaration asks the engine, and holds no copy of the engine's rules.
- An SDK can assemble a wire format in the host language only when a cross-language test compares the bytes.

### 2. A language SDK takes its host language's shape

An SDK is designed for its language.
It is not a translation of the Rust API.

These must be the same in every SDK:

- the bytes for the same declaration;
- the words for engine behaviour that a user writes, such as `equality`, `match`, `ore`, `passthrough` and `context`;
- fail-closed behaviour.

Each engine capability is reachable from the SDK, or the SDK's documentation lists it as not supported.

An SDK can hide an engine concept when the host language has its own way to express it.
The SDK's documentation then names the engine's term once.

### 3. Run each check at the earliest stage the language allows

The stages are, in order: the compiler, a build or generate step, CI, startup, and the running program.
The running program checks only what depends on data.
An SDK should not use a stage when its language offers an earlier one.

For a dynamic language, the SDK ships hints, suggestions and rules for the language's type checkers and linters.
Users and LLMs then get a warning as early as possible.

### 4. One declaration serves the write, the query and the read

How a field is encrypted is declared once.
Encrypting a value, building a search for it and decrypting it all use that declaration.
No call takes a context or an index choice of its own.

What changes from one caller to the next, such as a tenant, attaches to the cipher and not to each call.

This principle covers one version of a declaration.
A change to a declaration over time needs its own design.

### 5. Batch by default

One call from the user makes one request to the key service, however many values it carries.
The natural way to call an SDK is the efficient way.

- An SDK does not offer a single-value form beside the batch form.
  The one exception is a call on one field, for an update of one column or for a search value.
- An SDK can put operations on different types in one request.

### 6. A second way in has to earn its place

An SDK has one way to declare what is encrypted, and its tooling has one way to be driven.
A second way must pass all four tests:

1. It serves a need that the first way cannot meet.
2. It produces the same output as the first way, through the same code.
3. It keeps every guarantee of the first way, at the same stage.
4. Someone owns it: it has documentation, tests and a place in the supported set.

There is one SDK for each language.

### 7. State the design, and run its claims

A design document says what the design is.
The reasons go in the commit that makes the change, and in ADRs.
A design document has no history and no rejected options.

A claim that the design depends on is run before it is written down.
The document lists what was compiled, what was run and what is untested.

Examples are complete programs.

### 8. Usage first, then reference

Documentation opens with the steps a new user follows, in order, to a working result.
The reference comes after.
The same order applies inside each section.

- Usage steps are tested, so a step that stops working fails CI.
- The agent skills under `skills/` follow the same rules.
- Sentences have one idea and 25 words or fewer, in the active voice, with one word for one thing.

## Principles for the Go SDK

### 1. Find mistakes at the earliest stage

The stages for Go are: the compiler, `go generate`, CI, and the running program.
The running program finds only a mistake that depends on data.

### 2. Return a concrete type that matches the input

A caller who encrypts a value gets a named Go type whose fields have the names of the input's fields.
The caller reaches every output through a field.
There is no type assertion, no map lookup and no string key.

With separate columns, every sealed field gets its own struct, including a field with one output.

### 3. No `Must` function and no panic

No function in the SDK or in generated code panics for a declaration.
No function has a name that starts with `Must`.
A mistake is a build failure, a `go generate` failure, or a returned error.

### 4. Generate code with a Go tool

A generator writes what Go's type system cannot express, before the program is built.
The generator is a Go command that `go generate` runs.
The SDK and its generated code do not use reflection.

### 5. Check a type the SDK does not own at the same stage

A struct that another tool or package owns gets the same checks, at the same stage, wherever Go allows it.
Where Go does not allow it, the check moves one stage later.
A struct from another package with an unexported field is that case.

With one EQL column for each field, this applies to sqlc, to a type in another package, and to a program that uses separate columns.

### 6. One call shape for every type

The generator writes `Encrypt`, `Decrypt` and `Fields` into the user's package.
Every type has the same call shape: `users.Encrypt(ctx, cipher, people)`.
`Encrypt` and `Decrypt` take a slice and return a slice.
A field's own `Encrypt` takes one value.

### 7. The user never sees the plan

A user declares what to encrypt with tags, and works with generated types and functions.
No type, function, variable or method that a user touches is called a plan or returns one.
This rule covers names and API surface.

### 8. Go idiom decides the shape

This principle comes after the guarantees and after hiding the plan.

- `ctx` is the first parameter, and it is never stored.
- Every call returns its result, and nothing needs a second call to finish.
- Errors are values that `errors.Is` and `errors.As` read.
- Names follow Go conventions.

### 9. Fail closed

When the SDK cannot tell whether a field is encrypted, it stops.
It does not store plaintext, skip a field or guess.

- Every exported field carries a `stash` tag.
- One tag on an embedded struct decides for all of its fields.
- An unexported field with no tag is ignored, with three notices.
  The generator prints one, the generated file holds one as a comment, and the running program prints one to stderr.
  The tag `stash:"-"` on the field states the choice and stops the notices.

### 10. What is encrypted is fixed before the program ships

Which fields are encrypted, with which indexes and under which context, is in source control before the build.
A change to it shows as a change to a committed file that a reviewer reads.
So generated files are committed, and CI fails when one is out of date.

### 11. Fit the way Go code reaches a database

The SDK is tested with `database/sql`, pgx, sqlc and GORM.
A library that uses `driver.Valuer` and `sql.Scanner` works with the SDK, and a failure with one is a bug.

- The SDK leads with one EQL column for each field.
- Encryption happens before the database library gets the value.
- The generator copies other libraries' tags to the generated type.

### 12. Never put plaintext in an error

No error, warning or log line from the SDK or its generated code holds a plaintext value.
A generated type hides its sealed fields when a program prints it.

For the struct the user wrote, the SDK warns from the generator and from the running program.
It writes print methods on request, and a `go vet` check reports a print of the struct.

### 13. A name says what the thing is for

No abbreviation that a reader must decode, and no name that repeats its package.
The words in a tag are the Rust API's words.
The generator does not guess a plural.

## Not yet decided

- Query building in Go.
- The design of the `go vet` check.
- A change to a declaration over time.

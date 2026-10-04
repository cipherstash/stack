# Go binding: `Encrypt` / `EncryptAs`, mirroring stack-encrypt

> **Plan, not specification.** This document is an indicative sketch of the
> steps required, written before the work was done. It is not kept in step
> with the implementation and must not be used as a formal specification or
> as a reference for reviewing what was actually built: the code, its godoc
> and the tests are the source of truth. Where the two disagree, the code
> wins and this document is simply out of date.

**Status:** planned; decisions settled 2026-10-04
**Date:** 2026-10-04
**Issue:** #1046
**Builds on:** #1050 (one context per column; `Label`, `Describe`), #971 (EQL v3
`TextEq` / `TextEqQuery` through stack-encrypt), #1025 (`plantest.Golden`)
**Followed by:** the audit-context PR and the lock-context PR, which attach to
the calls this plan shapes

## Goal

The Go binding (`languages/golang/stackencrypt`) runs stack-encrypt inside a
WASI guest, so Go gets Rust's behaviour byte for byte. Its API, though, is
organised around a split Rust does not have: single values versus records,
plus a separate probe function. stack-encrypt has two operations, and the
difference between them is *what comes back*, not what shape goes in:

| stack-encrypt | Meaning |
|---|---|
| `encrypt(value, context)` / `decrypt(ciphertext, context)` | Ciphertext only. Any value, sealed as one tree under one context. |
| `encrypt_as::<Target>(source, context)` / `decrypt_as` | Into a target. The target decides the output: a record whose fields each get a context and search terms, a single search term, an EQL v3 payload. Many targets batch into one ZeroKMS request through `Pending::all`. |

After this work, Go spells exactly those two operations, by name and by
meaning, and every per-call feature that follows (the audit context, the lock
context) attaches once, to calls whose shape is final. The binding has never
been released, so the old functions are removed, not deprecated.

## Terminology

- **Context**: the parts a value is sealed under; the ciphertext's AAD, the
  terms' PRF context and the ZeroKMS descriptor at once. A `Context` in Go, a
  `NonEmpty<impl IntoContext>` in Rust. See `packages/stack-encrypt/CONTEXT.md`.
- **Label**: a name for data, `users/email`, as a flat list of plain segments;
  the first-class `Describe` type. EQL's identifier is a two-segment label.
- **Target**: what `encrypt_as` produces. In Go, a value of type `Target[O]`
  whose type parameter `O` is the Go type of the output.
- **Reader**: the decrypt-side counterpart, `Reader[P]`, whose `P` is the
  plaintext type produced.
- **Pending**: a prepared operation that has not yet reached ZeroKMS. `Run`
  executes any number of pendings as one request.
- **Plan**: today's `Plan` / `FieldPlan`, the runtime form of
  `#[derive(EncryptFrom)]`: which fields, under which context, with which
  outputs.
- **EQL v3 domain**: a PostgreSQL column type EQL defines (`text_eq`,
  `integer_ord`, …), each a Rust type in `eql-bindings`.

## Decisions (settled with Dan, 2026-10-04)

1. **`Encrypt` takes a `Context`.** Today's `aad []byte` parameter is gone;
   the context is spelled the same way as everywhere else in the binding.
   Raw bytes stay possible, as they are in Rust (`&[u8]: IntoContext` is one
   bytes part): a Go caller writes `NewContext(rawBytes)`, which is the same
   bytes part, so what Rust can seal under Go can too. The change is that the
   bytes are a `Context` like any other, not a separate parameter type that
   steered callers away from naming their data.
2. **A target is a value that carries its output type: option B.** One
   function, `EncryptAs(ctx, keyset, source, target)`, with the return type
   inferred from the target argument. Nothing the caller writes can disagree
   with anything else, so misuse is a compile error rather than a runtime one.
   Rejected: a type parameter plus a `WithPlan` option (two things decide the
   target and can conflict), and "everything is a plan" (outputs lose their
   static type).
3. **Mixed batches.** One `Run` carries pendings of different targets, as
   `Pending::all` does. A slice of one source type into one target is the
   common case and gets a helper, but is not the only case.
4. **Compile-time rejection of inapplicable options, as far as Go allows.**
   Per-target options (`TargetOption`) and per-run options (`RunOption`) are
   distinct interfaces, so a context extension cannot be passed to `Run` and an
   audit map cannot be put on a target. What the type system cannot express is
   refused at run time; nothing is silently ignored.
5. **Generated Go lives under `languages/golang`.** The EQL domain types are
   emitted by `eql-codegen` into the Go module, not vendored from `packages/eql`.
6. **EQL support is a sub-package, `stackencrypt/eqlv3`, holding every EQL
   domain**, inside the existing Go module (one `go.mod`), and the single WASI
   guest carries all of `eql-bindings`. No second module variant. (If "a
   submodule" was meant as a separate `go.mod`, that is a one-line change to
   this plan: the package boundary is the same either way.)

## Phase A — the reshape

No new cryptography and no new guest capability: the same stack-encrypt
operations reached through a different Go shape. Lands before #971 is needed.

### The API

```go
// Ciphertext only: one value, one context. The Cipher chooses the keyset.
ct, err := keyset.Encrypt(ctx, value, label.Context(), opts...)
pt, err := client.Decrypt(ctx, ct, label.Context(), opts...)

// Into a target. The target carries the output type; EncryptAs returns it.
term, err := stackencrypt.EncryptAs(ctx, keyset, "bob@example.com", stackencrypt.Equality.Under(email))
rows, err := stackencrypt.EncryptAs(ctx, keyset, users, usersPlan.Rows())      // []EncryptedRecord
user, err := stackencrypt.DecryptAs(ctx, client, rows[0], stackencrypt.RowOf[User](usersPlan))

// The batched form, which EncryptAs and DecryptAs are sugar over.
email := stackencrypt.Prepare("alice@example.com", stackencrypt.Equality.Under(emailLabel))
rows  := stackencrypt.Prepare(users, usersPlan.Rows())
back  := stackencrypt.Open(stored, stackencrypt.RowOf[User](usersPlan))
err := stackencrypt.Run(ctx, keyset, email, rows, back)                         // one ZeroKMS request
```

Shapes, with the Rust they mirror:

| Go | Rust |
|---|---|
| `Target[O]` | the `Target` type parameter of `encrypt_as` |
| `Reader[P]` | the plaintext type of `decrypt_as` plus its `ExpectedContext` |
| `Prepare(source, Target[O]) Pending[O]` | `source.encrypt_into(..)` before `.await` |
| `Open(stored, Reader[P]) Pending[P]` | `stored.decrypt_into(..)` before `.await` |
| `Run(ctx, scope, ...Pending)` | `Pending::all(..).await` |
| `EncryptAs` / `DecryptAs` | `encrypt_as` / `decrypt_as` on one value |
| `Element[T]` as a reader | `Element<T>` |

Points of detail, each of which the PR settles in godoc:

- **`Pending[O]` is a value with `Value() O` and `Err() error`**, valid after
  the `Run` that carried it. Reading before `Run` is a programming error and
  panics, which is the one place a panic is right: it is unreachable by any
  input, only by a wrong program.
- **Go methods take no type parameters**, so `Prepare`, `Open`, `EncryptAs`,
  `DecryptAs`, `RowOf` and `ElementOf` are package functions. `Run` takes a
  `Scope`, which both `*Cipher` (encrypt and decrypt) and `*Client` (decrypt;
  the payload names its keyset) implement. A pending that needs a keyset run
  under a `*Client` is refused at run time with a clear error, the one check
  the type system cannot make.
- **Targets available in Phase A**: a term kind under a context
  (`Equality.Under(c)`, `Match.Under(c)`, `Ore.Under(c)`, `Ope.Under(c)`,
  giving `Target[EqualityTerm]` and so on); a plan's rows (`plan.Rows()`,
  `Target[[]EncryptedRecord]` from a slice source, and `plan.Row()` for one).
  The current record output map stays until Phase B replaces it with domains.
- **Readers available in Phase A**: `Plaintext[T](c)` for a ciphertext under
  context `c` (the `Decrypt` counterpart in batched form), `ElementOf[T](c)`
  for one element of a sealed sequence, `RowOf[T](plan)` and `RowsOf[T](plan)`
  for records. `DecryptElement` and friends are gone; element is a reader.
- **Options**. `TargetOption` is accepted by target constructors and
  `Prepare`: `ExtendContext(parts...)` today; lock entries later. `RunOption`
  is accepted by `Run`, `Encrypt`, `Decrypt`, `EncryptAs` and `DecryptAs`:
  nothing today; the audit map later. The two interfaces share no
  implementors, so passing one where the other belongs does not compile.
  `WithPlan` disappears: the plan is the target.
- **Removed**: `Encrypt(…, aad []byte)`, `EncryptElement`, `DecryptElement`,
  `EncryptRecord`, `EncryptRecords`, `DecryptRecord`, `DecryptRecords`, `Term`,
  `RecordOption`, `WithPlan`.

### The guest

The guest stays thin: each export calls one stack-encrypt function. The
exports become `se_encrypt`, `se_decrypt`, `se_encrypt_as`, `se_decrypt_as`,
`se_keyset`, `se_cipher_init`, `se_shutdown`. `se_encrypt_as` and
`se_decrypt_as` take a batch of items, each naming its target (a term kind and
context, a plan, later a domain) and its source, and return the outputs in
order. The element exports fold into `se_decrypt_as` (element is a reader).

That needs one addition on the Rust side so the guest does not grow a
dispatcher: a `dynamic::encrypt_as` / `dynamic::decrypt_as` entry in
stack-encrypt's `dynamic` module that takes the batch and builds the
`Pending::all`, beside today's `dynamic::record` and `dynamic::term`. The
guest decodes, calls it, encodes. Other bindings reuse it.

### Everything else in Phase A

- `doc.go`, `README.md`, `example/` and `example/explicit/` rewritten around
  the two operations. The examples show one `Run` carrying a record batch and
  a probe.
- `docs/plans/stack-encrypt-go-bindings.md` gains a status note pointing here
  for the API surface.
- `plantest.Golden` (#1025) snapshots are regenerated once; its inputs (plan
  contexts and targets) do not change meaning.
- The live test (`live_test.go`) and the guest tests exercise every target and
  reader, mixed batches, and every compile-time option rejection as a
  `go vet`-visible non-compiling example under `testdata`.

## Phase B — EQL v3 domains as targets

Depends on #971 (EQL v3 `TextEq` / `TextEqQuery` in `eql-bindings`, and
`Identifier` as a two-segment `Label`).

### What a Go developer writes

```go
col := eqlv3.Column("users", "email")                  // a two-segment Label

stored, err := stackencrypt.EncryptAs(ctx, keyset, "alice@example.com", eqlv3.TextEq(col))
// stored marshals to {"v":3,"i":{"t":"users","c":"email"},"c":"stack-encrypt:1:…","hm":"…"}

probe, err := stackencrypt.EncryptAs(ctx, keyset, "alice@example.com", eqlv3.TextEqQuery(col))
// a probe has no ciphertext, so Run fetches no data key for it

email, err := stackencrypt.DecryptAs(ctx, client, stored, eqlv3.Text[string](eqlv3.Expect(col)))
```

Records: a plan target is a domain, replacing `plan.EQL(terms...)`:

```go
var users = plan.ForMessage(&User{}, "users", plan.FirstOf(
    plan.When(category.Under("user.contact.email"), plan.Encrypt(eqlv3.TextEqDomain())),
    plan.When(category.Under("system"), plan.Plaintext()),
))
rows, err := stackencrypt.EncryptAs(ctx, keyset, userSlice, users.Rows())        // []eqlv3.Row
```

### Decisions carried from #1046

1. **The domain binds the pair (table, column).** It is a two-segment
   `Label`, the same context the Rust derive infers and `eql-bindings`'
   `Identifier` describes, rendering `users/email`. Go and Rust agree by
   construction; #1050 made `FieldPlan.Context` a typed `Context` already.
2. **Decryption mirrors `ExpectedContext`.** Record decrypt through a plan
   always passes each field's expected column, so a payload moved to another
   column fails before any key is fetched. Single-value decrypt takes an
   optional `Expect(col)`; without it only "the stored `i` is non-empty" is
   checked, as in Rust.
3. **The `eqlv3` package is generated by `eql-codegen`**, which already emits
   Rust, TypeScript and JSON Schema from one catalogue. A Go emitter adds the
   domain types (storage and query, every domain), their JSON shapes, and a
   `Target` constructor for each domain that carries the stack-encrypt derives.
   Which domains those are is `ENCRYPTION_DOMAINS` in the codegen: today
   `text/eq`, so `eqlv3.TextEq` and `eqlv3.TextEqQuery` are the first targets
   and the other 90-odd types exist for decoding and JSON only. A new domain
   gains a Go constructor the day it gains a Rust derive, by regeneration.
4. **The guest resolves a domain name through an explicit lookup in
   `eql-bindings`**, never by inferring from a payload's keys, matching
   `DomainPayload::parse`'s own rule. The encrypt-side counterpart (name to
   `EncryptFrom` type) is added to `eql-bindings` beside it, so other bindings
   reuse one table.
5. **The record output map (`{"c","eq","match","ore","ope"}`) is removed**
   once domains are plan targets. A record's fields are EQL v3 payloads.

### Module size

The guest links `eql-bindings` with its `stack-encrypt` feature and without
its TypeScript and JSON Schema derive features, which a WASI module does not
need. The PR records the `.wasm` size before and after; a large growth is
reported, not hidden, but does not by itself change decision 6.

### Tests

The `eql-encryption-tests` database setup from #971 (`test:encryption:postgres`)
is reused: a row written from Go is read by the Rust test and the reverse, and
a Go probe matches a Rust-written term. That is the Go row of the
interoperability matrix in `eql-bindings/README.md`.

## Sequencing

1. #1025 (`plantest.Golden`) merges, so Phase A regenerates snapshots once.
2. Phase A, one PR. Can start now; nothing in it waits on #971.
3. #971 merges, with `Identifier: Describe`.
4. Phase B, one PR stacked on Phase A, or after it merges.
5. The audit-context PR, then the lock-context PR, on the finished shape.

## Non-goals

- Changing the Rust API. `encrypt` keeps accepting raw bytes as a context
  part, and so does Go through `NewContext(bytes)`; neither side changes.
- The Node binding, which uses `cipherstash-client`, not stack-encrypt.
- Domains beyond those with Rust derives; they arrive by regeneration.
- Lock and audit context themselves; this plan only leaves them a place.

## Open questions

- **Guest module growth** from `eql-bindings`: measured in Phase B's PR.
- **`eqlv3` as a package or a separate `go.mod`**: a package, per decision 6
  as read; correct if a separate module was meant.

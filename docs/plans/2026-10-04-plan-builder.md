# The plan builder: one front door for stack-encrypt, the derive, the FFI and Go

> **Plan, not specification.** This document is an indicative sketch of the
> steps required, written before the work was done. It is not kept in step
> with the implementation and must not be used as a formal specification or
> as a reference for reviewing what was actually built: the code, its godoc
> and rustdoc, and the tests are the source of truth. Where the two disagree,
> the code wins and this document is simply out of date.

**Status:** planned; decisions settled 2026-10-04. Supersedes the same-day
draft of this file ("option B targets": `Target[O]`, `EncryptAs`,
`EncryptAll`, `Prepare` / `Run`), which was dropped before any code was
written. The reasons are in "Why the first draft was dropped".
**Date:** 2026-10-04
**Issue:** #1046
**Builds on:** #1050 (one context per column; `Label`, `Describe`), #971 (EQL v3
`TextEq` / `TextEqQuery` through stack-encrypt), #1025 (`plantest.Golden`)
**Followed by:** the audit-context PR and the lock-context PR, which attach to
the calls this plan shapes

## Goal

stack-encrypt has one execution engine, the `Encryption` / `Decryption`
descriptions and the batched `Pending` in `target/`, and today two separate
front ends drive it by hand: the `#[derive(EncryptFrom)]` codegen, which
composes the combinators, and `dynamic::record`, which the Go guest runs and
which re-implements the per-field loop beside them. Nothing but tests keeps
the two in step, and the record module's own docs record one place they
already differ (a derive over a bare `u32` seals untagged bytes; a plan seals
the tagged encoding).

After this work there is one front end, a **plan builder**, with three
authors: a person writing a chain, the derive writing it from attributes, and
the FFI writing it from data. The Go binding mirrors the same chain. The
combinators stay public as the extension point. Everything a Rust caller, the
derive, Go and the guest produce for the same declaration is the same bytes
by construction, because it is the same code.

## Why the first draft was dropped

The first draft kept the split the Go binding has today, values versus
records versus probes, and added a generic `Target[O]` so one `EncryptAs`
function could serve all three. Reviewing it against the Cipher showed the
split was the problem, not the function names:

- The Cipher already encrypts any value, including maps and structs, as one
  tree. What a database row needs that a tree does not give is exactly two
  things: a **context per field** (the tree seals every leaf under one
  descriptor; `target/core.rs` makes its key requests with
  `repeat_with(|| Request::generate_under(descriptor.clone()))`), and
  **indexes** per field. A plan is those two facts and nothing else.
- Given that, a plan is not a second kind of thing with its own API. It is
  the tail of the ordinary encrypt call with the value left out, saved so
  that the write, the query and the read all take the same declaration and
  cannot drift (the silent-probe failure of #1051 is a drift failure).
- `Plan`, `FieldPlan`, `WithPlan`, `EncryptRecord`, `Term`, `Target[O]`,
  `EncryptAs`, `EncryptAll`, `Prepare`, `Open` and `Run` were all names for
  that one idea.

## Terminology

- **Context**: the parts a value is sealed under; the ciphertext's AAD, the
  terms' PRF context and the ZeroKMS descriptor at once. See
  `packages/stack-encrypt/CONTEXT.md`.
- **Label**: a name for data, `users/email`, as a path of plain segments; the
  first-class `Describe` type (#1050).
- **Field by field**: sealing each top-level field of a value on its own,
  under `<context>/<field>`, so a field can be stored, read, indexed and
  logged without the rest of the value. The alternative is **one tree**, the
  Cipher's call today.
- **Index**: an operation that derives a search term beside a ciphertext;
  `Equality`, `Match`, `Ore`, `Ope`. A **type** on the Rust side, **data**
  (`IndexSpec`, today's `TermKind`) at the FFI boundary.
- **Passthrough**: a field carried in the output as it is, unsealed and
  unauthenticated. Already the Cipher's contract for a passthrough leaf.
- **Plan**: the saved tail of a chain, of any shape: a one-value plan
  (`Plan::context("users/age").with(..)`) or a fields plan
  (`Plan::context("users").fields()..`). Reusable; validated at `build()`.

## Decisions (settled with Dan, 2026-10-04)

1. **One call, chained, finalised by `.await`.** `cipher.encrypt(&value)`
   returns a builder that holds the value and a plan under construction;
   options chain; `IntoFuture` makes `.await` the finalizer. Before the
   await nothing has touched a key.
2. **The context slot is named `context`.** It is the honest name for what is
   supplied. `under` was rejected (borrowed from `Encryption::under`, and
   opaque to a reader). Go accepts the clash with `context.Context`; every
   Go call's first argument is already `ctx`.
3. **Field-by-field is a modifier, `.fields()`, not a second verb.**
   `columns` was rejected as database-centric; the SDKs are not only for
   databases. `fields` is the derive docs' own phrase ("field by field") and
   covers structs, maps, JSON objects and protobuf messages.
4. **A plan is the chain without the value.** `Plan::context(..)` starts the
   saved form; `build()` validates whole-plan rules; `.using(&plan)` runs it.
   `for` was wanted and is a keyword in Rust and Go; `using` was chosen.
5. **Two field verbs plus passthrough.** `encrypt(name)` seals with no index;
   `encrypt_index(name, indexes)` seals with a non-empty index set (one index
   or a tuple); `passthrough(name)` carries the field unsealed, mirroring the
   lower-level API's word. `plaintext` was rejected for the same reason.
6. **Indexes are types on the Rust side, data at the boundary.** An
   `Index<S>` trait generic over the plaintext, so an index that does not
   apply to a type (`Match` on an integer) does not compile. Tuples of
   indexes implement `Indexes<S>`; `()` deliberately does not, so an empty
   index set is a compile error rather than a quiet `encrypt`. `spec()`
   lowers an index to data for the FFI and for saved plans. The trait lives
   in a core crate so the index implementations can move to their own crates.
7. **The chain's output is `Encrypted<Terms>` with the terms as a tuple, read
   by destructuring.** Named accessors (`out.ore()`) need type-level tuple
   search and serve a case that barely exists; a typed struct with named
   fields is the derive's job.
8. **`query` is the word for a search term**, matching `encryptQuery` in the
   TypeScript package. `probe` was rejected.
9. **Fail closed in both directions.** Every field of a value must be named
   by the plan and every plan field must be present in the value, as
   `dynamic::record` enforces today. A value that marks a leaf passthrough
   where the plan says `encrypt` is an error. `passthrough` on an indexed
   field is a build error.
10. **The combinators stay public, as the extension point, and are not the
    main interface.** An `Encryption` is single-use (its body is a `FnOnce`)
    and cannot be data, so it cannot be a plan held in a variable or crossed
    to Go; and the combinator spelling of a four-field record is roughly
    thirty lines of `accepting`, `zip`, nested-pair `map` and `project`.
    Custom targets, EQL domain types and `transcode` keep using them.
11. **Variables that hold a plan are named as plans**: `users_plan`,
    `email_plan`, never `users`.

## The Rust API

```rust
use stack_encrypt::{Plan, Equality, Match, Ore};

// One value, one tree, one context. Today's call, by name.
let ct = cipher.encrypt(&doc).context("documents/v2/body").await?;

// One value, indexed. Typed end to end: the tuple types the output.
let out = cipher.encrypt(34u32).context("users/age").with((Equality, Ore)).await?;
let (eq, ore): (EqualityTerm, OreTerm<u32>) = out.terms;

// A value sealed field by field, each field under users/<field>.
let row = cipher.encrypt(&user).context("users").fields()
    .encrypt_index("email", (Equality, Match::default()))
    .encrypt_index("age",   (Equality, Ore))
    .encrypt("notes")
    .passthrough("id")
    .keyset("tenant-42")
    .await?;

// The same chain without the value: a plan, built once, validated at build().
let users_plan = Plan::context("users").fields()
    .encrypt_index("email", (Equality, Match::default()))
    .encrypt_index("age",   (Equality, Ore))
    .encrypt("notes")
    .passthrough("id")
    .build()?;

let age_plan = Plan::context("users/age").with((Equality, Ore));      // a one-value plan

let row   = cipher.encrypt(&user).using(&users_plan).keyset("tenant-42").await?;
let rows  = cipher.encrypt(&users).using(&users_plan).await?;        // users: &[User]; one key request
let user  = cipher.decrypt(row).using(&users_plan).await?;
let age   = cipher.encrypt(34u32).using(&age_plan).await?;

// Per-call context extension: the caller's parts extend every field's context,
// as the derive's DeclaredContext does today.
let row   = cipher.encrypt(&user).using(&users_plan).extend(tenant_id).await?;

// Queries take the plan the data was written with, so the context cannot drift,
// and asking for an index the field never declared is an error.
let email_plan = users_plan.field("email")?;
let q = cipher.query("bob@example.com").using(&email_plan).equality().await?;

// Several operations, one ZeroKMS request.
let (row, q) = stack_encrypt::all((
    cipher.encrypt(&user).using(&users_plan),
    cipher.query("bob@example.com").using(&email_plan).equality(),
)).await?;

// Typed, from the derive, which emits the same builder.
let row: EncryptedUser = cipher.encrypt(&user).using(EncryptedUser::plan()).await?;
```

`keyset(..)` may also sit on the cipher as it does today
(`cipher.keyset("tenant-42").encrypt(..)`); both forms coexist because a
`KeysetCipher` already exists. The chain form is there so a saved call site
does not have to hold two cipher handles.

### What `passthrough` means

Exactly what a passthrough leaf means in the Cipher today: the value is
carried in the output so the record is whole, it is not encrypted, and it is
**not authenticated**. A field that should be tamper-evident but readable is a
sealed field with an equality index, not a passthrough one. The rustdoc says
this on the method.

## The engine

### How the builder lowers to the combinators

| Builder | Engine | Note |
|---|---|---|
| `Plan::context("users")` | the `NonEmpty<impl IntoContext>` handed to `under` | with `fields()`, each field gets `Label::new([table, field])` |
| `with(idx)` / `encrypt_index(name, idx)` | `ciphertext::<S>().accepting::<CallerContext>().zip(equality()).zip(matching::<O>())…` then `map` into `Encrypted<Terms>` | each `Index<S>` returns its `term_operation` constructor; the tuple folds with `zip` |
| `encrypt(name)` | `ciphertext::<S>()` alone | `under` accepts it: `AeadContext: From<CallerContext>` |
| `passthrough(name)` | **new** `passthrough::<S>()` | build is `Pending::ready(cipher, Ok(source.clone()))`, ignores the context |
| `fields()` | `project(select)` per field, `.under(label)`, `zip` across fields, `map` into the record | `project` is the derive's `struct = ..` mode; for the FFI `select` picks by name from an `FfiValue` object |
| `build()` | boxes the finished `Encryption<S, Out, K, DeclaredContext>` inside a reusable recipe | whole-plan rules checked here: names once, labels plain, no shared label, passthrough not indexed |
| `using(&plan)` | **new** `KeysetCipher::run(&plan, &source, ctx)` | execute-by-value; `encrypt_as` does this for a type through `T::encryption()`, and the closure is private today |
| `extend(parts)` | the runtime `DeclaredContext` value, `DeclaredContext::extend(own)` | not a combinator; it is the `ctx` argument |
| `keyset(..)` | the `KeysetCipher` passed to build; `Pending::scoped_to` | |
| `.await` | `IntoFuture for Pending` | exists |
| `all((a, b))` | `Pending::zip` / `Pending::all` | exists |
| `encrypt(&slice).using(&plan)` | `Pending::collect` over one build per row | what `Vec<T>: EncryptFrom` does |
| `query(v).using(&field_plan).equality()` | `equality().under(label)` alone | the field plan with `ciphertext()` dropped and one index selected |
| `decrypt(row).using(&plan)` | `open::<P>(tree, ctx)` per field, `Decryption::zip` / `all`, `map`, run by `decrypt_as` | the stored side is read by name via `DecryptField` already |
| a field whose target is an EQL domain | `<TextEq as EncryptFrom<String>>::encryption()` as that field's description | no builder work; `transcode` is the domain's |

### Additions

1. **`passthrough::<S>()`**, a constructor beside `ciphertext()` and the term
   operations.
2. **Execute-by-value**: a public way to run an `Encryption` and a
   `Decryption` held in a variable. The builder's `Plan` is a recipe that
   produces a fresh description per call, since a description is single-use.
3. **`Index<S>` and `Indexes<S>`**, with `indexed::<S>(idx)` in the engine
   doing the `ciphertext().accepting().zip(..).map(..)` dance once, so a field
   is one line at the combinator level too and the builder's lowering is
   trivial. `Indexes::select::<I>()` serves the query side. `()` does not
   implement `Indexes`.
4. **The one-value chain's `Encrypted<Terms>` output type.**

### Consolidation

- **The derive emits the builder.** `#[derive(EncryptFrom)]` generates
  `EncryptedUser::plan()` as a builder chain, and `EncryptFrom::encryption()`
  returns the plan's description. The derive stops knowing combinator names;
  `accepting`, `zip` and nested-pair `map` bookkeeping happen once, in the
  builder, instead of per generated impl.
- **`dynamic::record` becomes a lowering, not an executor.** It parses the
  data plan and drives the builder, with `dynamic::term`'s dispatch from a
  runtime scalar to a typed index as the one step that stays dynamic. Its own
  per-field loop, batching and output shaping are deleted. The
  tagged-versus-untagged divergence closes because both paths seal leaves
  through the same code.
- **The Index-key load.** Term derivation awaits the keyset's index key per
  field, which is why `dynamic::record::encrypt` is an `async fn` and cannot
  hand back a `Pending` synchronously. `.await` on one operation hides this.
  `all(..)` is an async function and works as written. Hoisting the load so a
  plan yields a `Pending` directly is a contained follow-up.

## The index crates

The `Index<S>` trait and `IndexSpec` live where the engine can see them (a
small core crate, or stack-encrypt until the split). `Equality`, `Match`,
`Ore` and `Ope` implement the trait and can move to their own crates with no
change to the builder, because the builder only ever sees the trait and the
tuple. An index with parameters (`Match` already has `MatchOptions`) carries
them on the struct and lowers them through `spec()`. The data form is what
crosses the FFI and what a saved plan in Go holds; the Rust side never loses
the type.

## The Go mirror

Go mirrors the chain with one difference: no `await`, so the finalizer is an
explicit `Run(ctx)`. The plan is a value, because in Go it is produced by the
policy package (`plan.PlanFor`) and by struct tags (`PlanFromTags`), and
because it is the data the guest receives.

```go
usersPlan, err := stackencrypt.PlanContext("users").Fields().
    EncryptIndex("email", stackencrypt.Equality, stackencrypt.Match).
    EncryptIndex("age", stackencrypt.Equality, stackencrypt.Ore).
    Encrypt("notes").
    Passthrough("id").
    Build()

row,  err := cipher.Encrypt(user).Using(usersPlan).Run(ctx)
rows, err := cipher.Encrypt(users).Using(usersPlan).Run(ctx)
err        = cipher.Decrypt(row).Using(usersPlan).Into(&user).Run(ctx)
emailPlan, err := usersPlan.Field("email")
q,    err := cipher.Query("bob@example.com").Using(emailPlan).Equality().Run(ctx)
```

- Indexes are the existing `TermKind` values (data); Go has no way to make
  `Match` on an integer a compile error, so it is a `Build()` error, as today.
- `Encrypt` takes a `Context` where today it takes `aad []byte`; raw bytes
  stay possible as `NewContext(bytes)`, the same bytes part Rust accepts.
- The output types are what the binding has: `EncryptedRecord` and
  `EncryptedField`. A typed `Plan[T]` through a generic struct, giving
  `Encrypt(ctx, T)` and `Decrypt(..) (T, error)`, is an open question below.
- Removed: `Encrypt(…, aad []byte)`, `EncryptElement`, `DecryptElement`,
  `EncryptRecord(s)`, `DecryptRecord(s)`, `Term`, `RecordOption`, `WithPlan`.
  The binding has never been released, so they are removed, not deprecated.
- Mixed batches: `Prepare` on each chain and one `stackencrypt.Run(ctx, p1,
  p2)`, mirroring `all(..)`. Sugar, not the entry point.

### The guest

Unchanged in substance. The plan already crosses as data and the guest
already calls `dynamic::record`; once that module is a lowering into the
builder, the guest's exports run the same engine the derive does. The export
set is renamed once the Go surface settles (`se_encrypt`, `se_decrypt`,
`se_query`, with the plan as an argument), and the element exports fold into
`se_decrypt`.

## EQL v3 domains as field targets

Depends on #971 (EQL v3 `TextEq` / `TextEqQuery` in `eql-bindings`, and
`Identifier` as a two-segment `Label`). A field's target may be any
`EncryptFrom` type, so an EQL domain plugs into a plan with no builder work:

```rust
let users_plan = Plan::context("users").fields()
    .encrypt_into::<TextEq>("email")          // the domain's own EncryptFrom; renders {"v":3,"i":{"t":"users","c":"email"},…}
    .encrypt_index("age", (Equality, Ore))
    .build()?;
```

In Go the domain types are emitted by `eql-codegen` into
`stackencrypt/eqlv3`, inside the one Go module and the one WASI guest, every
domain, with constructors only for domains that have a Rust derive
(`ENCRYPTION_DOMAINS`). The guest resolves a domain name through an explicit
lookup in `eql-bindings`, never by inferring from a payload's keys. The record
output map (`{"c","eq","match","ore","ope"}`) is removed once domains are
field targets. Module size is measured in that PR and reported, not hidden.

## Sequencing

1. **Engine additions in stack-encrypt**: `passthrough()`, execute-by-value,
   `Index<S>` / `Indexes<S>` / `indexed()`, `Encrypted<Terms>`. One PR;
   stack-encrypt 0.3.0. The combinators' public surface does not shrink.
2. **The builder**, lowering to the engine, with the one-value chain, the
   fields chain, `Plan`, `using`, `query`, `decrypt`, `all`. Same or next PR.
3. **The derive emits the builder**; `tests/ui` snapshots and the label
   fixture prove the same bytes before and after.
4. **`dynamic::record` becomes a lowering.** The guest is rebuilt; Go's
   `plantest.Golden` snapshots must not change, which is the proof.
5. **The Go mirror** (#1046 proper): the chain above, removals, docs,
   examples, live tests. #1025 merges first so snapshots regenerate once.
6. **EQL domains as field targets**, after #971 merges.
7. The audit-context PR, then the lock-context PR, on the finished shape.

## Non-goals

- The Node binding, which uses `cipherstash-client`, not stack-encrypt.
- Domains beyond those with Rust derives; they arrive by regeneration.
- Lock and audit context themselves; this plan only leaves them a place.
- Named term accessors on `Encrypted<Terms>` (decision 7).

## Open questions

- **A typed Go plan, `Plan[T]`**, through a generic struct, so `Decrypt`
  returns `T` rather than filling an `out any`. Fits the chain; deferred until
  the untyped form lands.
- **The decrypt side of the one-value chain**: `decrypt(ct).using(&age_plan)`
  returns the plaintext type the plan was built for; whether a hand-built plan
  carries `S` or the caller names it is settled in the builder PR.
- **The index-key hoist** so a plan yields a `Pending` synchronously.
- **`eqlv3` as a package or a separate `go.mod`**: a package as read; correct
  if a separate module was meant.

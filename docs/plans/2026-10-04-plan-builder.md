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
written. The reasons are in "Why the first draft was dropped". Amended
the same day, after the first three implementation PRs (#1068, #1069 and
the builder itself, #1071), with a second round of decisions: decrypt is
spelled `open`, the two starts and the three context sources, the typed
verb and the picker, the derive narrowed before it emits the plan, and EQL
types assembled per language with no registry.
**Date:** 2026-10-04
**Issue:** #1046
**Builds on:** #1050 (one context per column; `Label`, `Describe`), #971 (EQL v3
`TextEq` / `TextEqQuery` through stack-encrypt), #1025 (`plantest.Golden`)
**Followed by:** the audit-context PR and the lock-context PR, which attach to
the calls this plan shapes
**Records:** ADR-0007 (bindings enter through a plan, never a second
executor); glossary changes in `packages/stack-encrypt/CONTEXT.md` (Plan,
Index, Term, Field-by-field record, Passthrough, Identity, Query, Open,
Context field, Target, and the two directions)

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
the FFI writing it from data. The Go SDK declares the same thing with struct tags and
generated code. The combinators stay public as the extension point. Everything a Rust caller, the
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
  (`Plan::value::<u32>().context("users/age").with(..)`) or a fields plan
  (`Plan::fields().context("users")..`, also spelled
  `Plan::context("users").fields()..`). Reusable; validated at `build()`.
- **Record**: what a fields plan produces and reads back, a value sealed
  field by field. The glossary's word; this document does not call it a
  "row", which is a database's word for where a record is stored.
- **Open**: decrypting through a plan, `cipher.open(record).using(&plan)`.
- **Target**: a type that decides a field's layout, named with
  `encrypt_into::<T>`. Rust-only; Go's counterpart is generated code.

## Decisions (settled with Dan, 2026-10-04)

1. **One call, chained, finalised by `.await`.** `cipher.encrypt(&value)`
   returns a builder that holds the value and a plan under construction;
   options chain; `IntoFuture` makes `.await` the finalizer. Before the
   await nothing has touched a key.
2. **The context slot is named `context`.** It is the honest name for what is
   supplied. `under` was rejected (borrowed from `Encryption::under`, and
   opaque to a reader). The Go SDK has no `context` method; see "The Go
   SDK".
3. **Field-by-field is a modifier, `.fields()`, not a second verb.**
   `columns` was rejected as database-centric; the SDKs are not only for
   databases. `fields` is the derive docs' own phrase ("field by field") and
   covers structs, maps, JSON objects and protobuf messages.
4. **A plan is the chain without the value.** `Plan::value::<S>()` or
   `Plan::fields()` starts the saved form (`Plan::context(..)` is a shorter
   spelling of the same); `build()` validates whole-plan rules;
   `.using(&plan)` runs it.
   `for` was wanted and is a keyword in Rust and Go; `using` was chosen.
5. **Three field verbs plus passthrough.** `encrypt(name)` seals with no
   index; `encrypt_index(name, indexes)` seals with a non-empty index set (one
   index or a tuple); `index(name, indexes)` derives the indexes alone, with
   no ciphertext, so the field is written and searched but comes back from
   `open` only if an index's own output is reversible; `passthrough(name)`
   carries the field unsealed, mirroring the lower-level API's word.
   `plaintext` was rejected for the same reason. JSON is an `index` field:
   the SteVec has no canonical `c` beside it, its entries carry the node
   ciphertexts and entry 0 is the document's, so it is an index whose output
   happens to be reversible, not a target (`encrypt_into` was considered and
   rejected for it).
6. **Indexes are types on the Rust side, data at the boundary.** An
   `Index<S>` trait generic over the plaintext, so an index that does not
   apply to a type (`Match` on an integer) does not compile. Tuples of
   indexes implement `Indexes<S>`; `()` deliberately does not, so an empty
   index set is a compile error rather than a quiet `encrypt`. `spec()`
   lowers an index to data for the FFI and for saved plans. The trait lives
   in a core crate so the index implementations can move to their own crates.
   An index answers queries by **source type**: `Equality` answers a query
   whose source is the field's own type; `Json` answers a `Value`
   (containment), a `JsonPath` (a selector, for `->`) and a `JsonAtPath`
   (equality at a path). `Indexes::select::<I>()` picks the index, the query's
   source type picks the form, and `.equality()` on a scalar field is sugar.
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
12. **The plan is the only front door for a binding; native Rust keeps its
    two.** Cipher-directed and target-directed encryption remain the preferred
    entry points for a Rust caller, and target-directed is Rust-only. The
    chain is their fluent spelling: `cipher.encrypt(&v).context(c)` is
    cipher-directed, `cipher.encrypt(&v).using(T::plan())` is target-directed
    through the derive, and `.with((Equality, Ore))` on a value is
    target-directed without declaring a type, which has no spelling today. A
    hand-built `Plan::context(..).fields()..` at run time is what a binding
    lowers data into and what the derive emits; a Rust caller with a struct in
    hand uses the derive. Recorded as ADR-0007
    (`packages/stack-encrypt/docs/adr/0007-…`), which also forbids a second
    executor beside the engine.

## The Rust API

```rust
use stack_encrypt::{Plan, Encrypted, Equality, Match, Ore};

// One value, one tree, one context. Today's call, by name.
let ct = cipher.encrypt(&doc).context("documents/v2/body").await?;

// One value, indexed. Typed end to end: the tuple types the output.
let out = cipher.encrypt(&34u32).context("users/age").with((Equality, Ore)).await?;
let (eq, ore): (EqualityTerm, OreTerm<u32>) = out.terms;

// A value sealed field by field, each field under users/<field>. Rust cannot
// learn a field's type from its name, so a verb given a bare name names it.
let record = cipher.encrypt(&user).context("users").fields()
    .encrypt_index::<String>("email", (Equality, Match::default()))  // ciphertext with indexes beside it
    .encrypt_index::<u32>("age", (Equality, Ore))
    .index::<Value>("attrs", Json::default())                        // indexes alone: the searchable document is the stored form
    .encrypt::<String>("notes")                                      // ciphertext alone
    .passthrough::<u64>("id")
    .keyset("tenant-42")
    .await?;

// The same chain without the value: a plan, built once, validated at build().
// Plan::context("users").fields() is the same start, and the common spelling.
let users_plan = Plan::fields().context("users")
    .encrypt_index::<String>("email", (Equality, Match::default()))
    .encrypt_index::<u32>("age", (Equality, Ore))
    .encrypt::<String>("notes")
    .passthrough::<u64>("id")
    .build()?;

// A one-value plan carries its plaintext type, and needs build() too.
let age_plan = Plan::value::<u32>().context("users/age").with((Equality, Ore)).build()?;

let record  = cipher.encrypt(&user).using(&users_plan).keyset("tenant-42").await?;
let records = cipher.encrypt(&users).using(&users_plan).await?;     // users: &[User]; one key request
let user    = cipher.open(record).using(&users_plan).await?;
let age     = cipher.encrypt(&34u32).using(&age_plan).await?;
let back: u32 = cipher.open(age).using(&age_plan).await?;           // the plan's S

// Per-call context extension: the caller's parts extend every field's context,
// as the derive's DeclaredContext does today.
let record  = cipher.encrypt(&user).using(&users_plan).extend(tenant_id).await?;

// Queries take the plan the data was written with, so the context cannot drift,
// and asking for an index the field never declared is an error.
let email_plan = users_plan.field("email")?;
let q = cipher.query("bob@example.com").using(&email_plan).equality().await?;

// A JSON field answers three query forms, chosen by the source type.
let attrs_plan = users_plan.field("attrs")?;
let q = cipher.query(json!({"role": "admin"})).using(&attrs_plan).await?;                     // containment
let q = cipher.query(JsonPath::root().field("role")).using(&attrs_plan).await?;              // selector, for ->
let q = cipher.query(JsonPath::root().field("role").value("admin")).using(&attrs_plan).await?; // equality at a path

// Several operations, one ZeroKMS request.
let (record, q) = stack_encrypt::all((
    cipher.encrypt(&user).using(&users_plan),
    cipher.query("bob@example.com").using(&email_plan).equality(),
)).await?;

// Typed, from the derive, which emits the same plan. `plan()` returns a
// `Result` and is generic over the key source, so it is borrowed after `?`.
let record: EncryptedUser = cipher.encrypt(&user).using(&EncryptedUser::plan()?).await?;
```

The one-value start has a context-field form too: `Plan::value::<S>().context_field::<C>()`
carries the call's context (a `NonEmpty<C>`) out beside the output, which is
`(C, T)`. `encryption_with_context` and `decryption_with_context(record,
ExpectedContext<C>)` run it, and the stored context is checked against the
`ExpectedContext` before any key request. A tuple of targets takes the context
every element accepts (`JoinContext`): the shared one when all agree, an
`AeadContext` for ciphertexts alone, and a `CallerContext` for a ciphertext
beside a term.

`keyset(..)` may also sit on the cipher as it does today
(`cipher.keyset("tenant-42").encrypt(..)`); both forms coexist because a
`KeysetCipher` already exists. The chain form is there so a saved call site
does not have to hold two cipher handles.

**Decrypt through a plan is `open`.** `StackCipher::decrypt(ct, aad)` is the
cipher-directed decrypt, with callers across the repo, and Rust has no
overloading, so a one-argument `decrypt` would break them all; `open` is
already the engine's word for reading leaves (`target::open`, `Opening`).

### Two starts

`Plan::value::<S>()` starts a one-value plan over plaintext `S`;
`Plan::fields()` starts a fields plan. `.context(c)` is optional on either.
`Plan::context(c).fields()` and `Plan::context(c).with(..)` keep working as
the common spellings. Both forms end in `.build()?`, so validation has one
place. A one-value plan is a `ValuePlan<S, X>`: it keeps `S`, so opening
through it yields `S`, and it keeps its index types, so a query selects its
index by type and an undeclared index does not compile.

### Where the context comes from

A plan takes its context from exactly one of three sources:

1. **Build time**: `.context(c)` on the plan.
2. **The chain at run time**: `cipher.encrypt(&v).context(c).using(&plan)`,
   for a plan built with no context of its own.
3. **A field of the value**: `.context_field(name)`. That field's value is the
   context of every other field. It is stored as a passthrough field, so the
   record can be opened, and on open it is checked against the context each
   field was sealed under.

A one-value plan also has a typed call-context path,
`encryption_with_context::<K, C>()`, which runs the plan under the caller's
context exactly as given: a `NonEmpty` of any context type, an integer or an
AEAD-only context, not only a `Label`. This is how a derived `plaintext = T`
record receives its caller's context. Parsing it into a label would change its
bytes (`nonempty!("users/email")` is one escaped part, `Label::parse("users/email")`
is two segments), so a two-part caller context stays one escaped part. A plan
built with its own context refuses this path (`TwoContextSources`), without I/O.

Two sources is an error. `.extend(parts)` is the only way to add to the
context, and it extends whichever source the plan has. A plan given two
sources is refused (`TwoContextSources`), at build or when the call adds one.
A plan run with no source is refused at run, before any key request
(`NoContext`), because only the call can supply one. A context field's value
must be a plain label segment (a `String` or `Label`); an integer tenant id goes
in `.extend(parts)`.

### The typed verb and the picker

`encrypt_into::<T>` names a **target**: a type whose own `EncryptFrom` impl
decides the field's layout and the queries it answers. It has two positions:

```rust
// Field form: the field's layout is TextEq's.
Plan::fields().context("users").encrypt_into::<TextEq, _>("email")

// One-value form: each tuple element is an EncryptFrom<S>.
Plan::value::<String>().encrypt_into::<(Ciphertext, Hmac256)>()
```

A field is either data verbs (`encrypt`, `encrypt_index`, `index`,
`passthrough`) or one target, never both. `.with(indexes)` is sugar for
`encrypt_into::<Encrypted<Terms>>`. The typed verb is Rust-only: it names a
Rust type, so it has no data form.

A verb's field argument is either a name or a **picker**, a name with an
accessor:

```rust
.encrypt_index::<String>("email", (Equality, Match::default()))          // by name, through Field<String>
.encrypt_index(pick("email", |u: &User| &u.email), (Equality, Match::default())) // picker: the type is inferred
```

A bare name is looked up through the value's `Field<F>` impl, which is what a
dynamic value (`FfiValue`) provides. The picker reads the field directly and
needs no turbofish. The derive emits the picker form; bindings use names. The
picker is Rust-only.

Two spellings follow from how Rust infers types:

- A closure picker is written `pick("email", |u: &User| &u.email)`, not as a
  bare tuple `("email", |u| &u.email)`, because Rust infers no higher-ranked
  closure signature inside a tuple. A bare tuple holding a function item or
  function pointer, `("email", email_fn)`, works as well.
- The field form of `encrypt_into` takes two type arguments, `::<T, _>(field)`
  (the field's type is inferred), because Rust has no partial turbofish. The
  one-value form takes one: `Plan::value::<S>().encrypt_into::<(A, B)>()`.

`EncryptFrom::indexes() -> Vec<IndexSpec>` is a defaulted method (empty unless
overridden) with which a typed target says which queries it answers. A typed
field whose target declares no indexes answers no queries; a query for anything
else is refused. Each term type names its own index, `Encrypted<Terms>` names
its set, and a tuple concatenates.

The built plan's accessors: `Plan::field_plans()` returns the field
descriptions (`Plan::fields()` is the start, so it cannot be the accessor);
`Plan::label()` and `FieldPlan::label()` return `Option<&Label>` (there is no
label until the call supplies the context); `Plan::context_field()` returns
`Option<&str>`.

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
| `Plan::value::<S>()`, `Plan::fields()`, `.context(c)` | the `NonEmpty<impl IntoContext>` handed to `under` | with `fields()`, each field gets `Label::new([context, identity])` |
| `with(idx)` / `encrypt_index(name, idx)` | `indexed::<S>(idx)`: `ciphertext().accepting::<CallerContext>().zip(..)…` then `map` into `Encrypted<Terms>` | each `Index<S>` returns its term operation; the tuple folds with `zip` |
| `encrypt_into::<T>(name)`, and the one-value form | `<T as EncryptFrom<F>>::encryption().under(label)` | the target's own description; no builder work |
| `EncryptFrom::indexes()` on a typed field | the indexes a query against that field may name | defaulted to empty: a typed field whose target declares none answers no queries (`IndexNotDeclared`) |
| `with(idx)` as `encrypt_into::<Encrypted<Terms>>` | `Encrypted<Terms>: EncryptFrom<S>`, whose `encryption()` is `indexed()` | both spellings lower to the same `indexed()`; a standing byte-identity test covers every index combination |
| `encrypt(name)` | `ciphertext::<S>()` alone | `under` accepts it: `AeadContext: From<CallerContext>` |
| `index(name, idx)` | the index operations alone, zipped, no `ciphertext()` | `Json` is one such operation; it mints one document key and seals every entry under it, a **new core operation** (one generate request, a fulfilment that seals N entries with selector-derived nonces) |
| `passthrough(name)` | `passthrough::<S>()` (#1069) | build is `Pending::ready(cipher, Ok(source))`, ignores the context |
| `context_field(name)` | `passthrough()` for that field; its value is the context every other field runs `under` | on open, the field's value is the `ExpectedContext` each field is opened under, so a record whose context field was changed in storage does not open |
| `fields()`, a field by name | `project_by` (crate-internal) through the value's `Field<F>`, `.under(label)`, `zip` across fields, `map` into the record | the path a dynamic value (`FfiValue`) takes |
| `fields()`, a field by picker `pick(name, accessor)` | `project(accessor)` | the derive's `struct = ..` mode today; borrowed-only |
| `build()` | a reusable recipe that produces a fresh `Encryption` per run | whole-plan rules checked here: names once, labels plain, no shared identity, passthrough not indexed, one context source |
| `using(&plan)` | `KeysetCipher::run(encryption, source, ctx)` (#1068) of `Plan::encryption()` | execute-by-value; `encrypt_as` does this for a type through `T::encryption()` |
| `extend(parts)` | the runtime `DeclaredContext` value, `DeclaredContext::extend(own)` | not a combinator; it is the `ctx` argument |
| `keyset(..)` | the `KeysetCipher` passed to build; `Pending::scoped_to` | |
| `.await` | `IntoFuture for Pending` | exists |
| `all((a, b))` | `Pending::zip` / `Pending::all` | exists |
| `encrypt(&slice).using(&plan)` | `Pending::collect` over one build per record | what `Vec<T>: EncryptFrom` does |
| `query(v).using(&field_plan).equality()` | `equality().under(label)` alone | the field plan with `ciphertext()` dropped and one index selected |
| `open(record).using(&plan)` | `open::<P>(tree, ctx)` per field, `Decryption::zip` / `all`, `map`, run by `run_decryption` (#1069) | the stored side is read by name via `DecryptField` already |

**Source modes.** #1068 gave every `Encryption` a source mode: `Borrowed`
(the default) hands an operation `&S`, `Owned` hands it `S` by value, so a
value that is deliberately not `Clone`, such as `FfiValue`, can run a single
operation without a copy. Only an owned `zip` needs `S: Clone`. `project` is
borrowed-only: it reads a field out of a borrowed struct. Every chain borrows
today, and each field is cloned once where its operation consumes it, as the
derive does. An owned fields plan over an `FfiValue` object needs a combinator
that moves each field out of the value without cloning the rest; that belongs
with the lowering (#1059).

### Additions

Items 1 to 4 shipped in #1068 and #1069; #1071 built the chain on them.

1. **`passthrough::<S>()`**, a constructor beside `ciphertext()` and the term
   operations.
2. **Execute-by-value**: `KeysetCipher::run(encryption, source, ctx)` and
   `run_decryption`, which run an `Encryption` or a `Decryption` held in a
   variable. The builder's `Plan` is a recipe that produces a fresh
   description per call, since a description is single-use.
3. **`Index<S>` and `Indexes<S>`**, with `indexed::<S>(idx)` in the engine
   doing the `ciphertext().accepting().zip(..).map(..)` dance once, so a field
   is one line at the combinator level too and the builder's lowering is
   trivial. `Indexes::select::<I>()` serves the query side. `()` does not
   implement `Indexes`.
4. **The one-value chain's `Encrypted<Terms>` output type.**
5. **The JSON index**: `Json: Index<Value>` with its options (array index
   mode, `Compat` or `Standard`, case filters) on the struct, producing a
   searchable document; the MAC `prefix` of today's `JsonIndexer` is replaced
   by the field's context. One new core operation seals N entries under one
   data key with selector-derived nonces. EQL's JSON type is the `EncryptFrom`
   that wraps the document into its EQL form, the way `TextEq` wraps an
   equality term. Decrypt of an extracted entry (`->`) grafts the document
   header onto it.
6. **`Encrypted<Terms>: EncryptFrom<S>`**, whose `encryption()` is
   `indexed()`, so `.with(indexes)` and `encrypt_into::<Encrypted<Terms>>`
   are one lowering.
7. **A wire form for match and JSON index options.** Today a `Match` index
   lowers to the data key `"match"` with its options dropped, and reading it
   back yields the default options: a saved non-default match field would
   derive different Bloom positions on the query side and match nothing,
   with no error (raised in the #1069 review). The data plan carries the
   options, or refuses a non-default index it cannot carry.

### Consolidation

- **The derive emits the plan, after the derive is narrowed and the plan
  widened (done in #1076).** The derive and a data plan are two authors of one grammar over
  one executor; the derive is not kept on the combinators.
  `#[derive(EncryptFrom)]` generates `EncryptedUser::plan()` as a plan chain
  in the picker form, and `EncryptFrom::encryption()` returns the plan's
  description. The derive stops knowing combinator names; `accepting`, `zip`
  and nested-pair `map` bookkeeping happen once, in the builder, instead of
  per generated impl. Today the derive can say four things a plan cannot, and
  each is removed from the derive rather than added to the plan (bytes change
  for a few tests; the crate is unpublished):
  1. Field-level literal `#[stash(context = "..")]` -> replaced by
     `#[stash(identity = "..")]` (label becomes `<context>/<identity>`);
     "seal one field outside the record context" goes.
  2. Non-plain literal contexts such as `"readings/unit"`.
  3. `#[stash(nested)]` (a nested record is an ordinary field sealed under
     `<context>/<field>`, its inner layout being its own type's business via
     `encrypt_into`).
  4. A second `#[stash(from = field)]` output per source field in `struct`
     derives (use one field of type `Encrypted<(EqualityTerm, MatchTerms)>`
     instead). `plaintext = T` records keep producing many outputs from the
     whole value: that is the one-value plan.

  Kept, and added to the plan so the derive can emit it (Rust; the typed parts
  have no data form): the two starts `Plan::value::<S>()` and
  `Plan::fields()`; the three context sources and the one-source rule; the
  typed verb `encrypt_into` in both positions, with `.with(indexes)` as its
  sugar; `Encrypted<Terms>: EncryptFrom<S>` with its byte-identity test; and
  the picker.

  What #1076 settled, beyond the list above:
  - A `struct` record's `DecryptInto` opens each field through its own
    `DecryptField` under `<context>/<identity>` (extended by the caller's
    context), which is what the plan's opener does for a typed field, rather
    than through `Plan::decryption`. A decrypt-only derive has field types with
    no `EncryptFrom`, and a plan cannot be built without it. For the same
    reason a `plaintext = T` record's `DecryptInto` calls the tuple's
    `DecryptInto` directly.
  - Two outputs of a `plaintext = T` record that declare the same index are
    refused when run (`PlanError::DuplicateIndex`, before any key request), not
    at compile time: the derive sees type names, not the indexes they declare.
  - No derive attribute maps to `passthrough` (a `default` field is filled with
    a default, not carried from the source), so the derive emits none.
- **`dynamic::record` becomes a lowering, not an executor.** It parses the
  data plan and drives the builder, with `dynamic::term`'s dispatch from a
  runtime scalar to a typed index as the one step that stays dynamic. Its own
  per-field loop, batching and output shaping are deleted. The
  tagged-versus-untagged divergence closes because both paths seal leaves
  through the same code.
- **A plan yields a `Pending` synchronously.** Term derivation is local:
  `KeysetCipher::equality_term` and its siblings are plain functions that run
  the PRF the keyset cipher already holds (the index key was loaded once, when
  `cipher.keyset(..)` resolved the keyset) and return `Pending::ready`. The
  typed term operations are synchronous for the same reason.
  `dynamic::record::encrypt` is an `async fn` only because it settles each
  term's ready pending eagerly instead of zipping it into the batch; lowering
  it into the builder removes that, with nothing to hoist. An earlier draft of
  this document claimed a per-field index-key load here; there is none. The
  future this guards is the opposite one: term derivation may one day be a
  ZeroKMS call (a PRF derived server-side, batched with the data keys in one
  round trip, which `pending::dispatch` already names as the one place that
  changes). That arrives as a new `Request` kind whose fulfilment reads the
  term from `Responses`, so an index still returns a `Pending` synchronously
  and no plan, chain, derive or binding changes shape.

## The index crates

The `Index<S>` trait and `IndexSpec` live where the engine can see them (a
small core crate, or stack-encrypt until the split). `Equality`, `Match`,
`Ore` and `Ope` implement the trait and can move to their own crates with no
change to the builder, because the builder only ever sees the trait and the
tuple. An index with parameters (`Match` already has `MatchOptions`) carries
them on the struct and lowers them through `spec()`. The data form is what
crosses the FFI and what a saved plan in Go holds; the Rust side never loses
the type.

## The Go SDK

The Go SDK is what a Go program uses: struct tags, a generator, and the code the generator writes.
The binding is the WASI interface between that code and the Rust engine.
The SDK follows [the language SDK design principles](../sdk-design-principles.md).

A struct's `stash` tags declare how each field is encrypted.
A generator, `stashgen`, writes the encrypted type and its functions from the tags.
A program calls those functions, and it never builds or names a plan.
[The Go examples](2026-10-04-plan-builder/README.md) show each part below as a complete program.

```go
//go:generate go tool stashgen -type User
type User struct {
	_     struct{} `stash:"context=users"`
	ID    int64    `stash:"id,passthrough"`
	Email string   `stash:"email,encrypt_into=TextSearch"`
	Age   int32    `stash:"age,encrypt_into=IntegerOrd"`
}

cipher := client.Keyset(stackencrypt.KeysetName("tenant-42"))

encrypted, err := users.Encrypt(ctx, cipher, people)                   // []users.EncryptedUser, one ZeroKMS request
people, err := users.Decrypt(ctx, cipher, encrypted)                   // []users.User
query, err := users.Fields.Email.Query(ctx, cipher, "bob@example.com") // eql.TextSearchQuery
```

### Use the SDK

1. Add the generator to your module.
   This needs Go 1.24 or later.

   ```sh
   go get -tool github.com/cipherstash/stack/languages/golang/cmd/stashgen
   ```

2. Put a `stash` tag on every exported field of the struct, and a `go:generate` comment beside it.

3. Run the generator.
   It writes `user_stash.go` beside the struct.

   ```sh
   go generate ./...
   ```

4. Commit the generated file.

5. Call the generated functions where you write and read.

   ```go
   encrypted, err := users.Encrypt(ctx, cipher, people)
   people, err := users.Decrypt(ctx, cipher, encrypted)
   ```

6. Store the encrypted type.
   Each field is one column, so `database/sql`, pgx, sqlx and GORM take it as it is.

7. Run the generator again after each change to the struct or to a tag.
   A change to the fields of the struct stops the build until you do.

8. In CI, run the generator and fail when a generated file changes.

   ```sh
   go generate ./... && git diff --exit-code
   ```

The rest of this section is the reference.

### Struct tags

The first part of a tag is the field's name, which is the column name in a database.

| Tag | Meaning |
|---|---|
| `` _ struct{} `stash:"context=users"` `` | the context of every field in the struct |
| `stash:"email,encrypt_into=TextSearch"` | seal the field into one EQL value, with the indexes that EQL type has |
| `stash:"notes,encrypt"` | seal the field, with no index |
| `stash:"email,encrypt,index=equality;match"` | seal the field, and derive each index beside it |
| `stash:"attrs,index=json"` | derive the index alone |
| `stash:"id,passthrough"` | store the field as it is |
| `stash:"-"` | leave the field out |
| `` _ struct{} `stash:"context=documents,opaque"` `` | seal the struct as one value |

The index names are `equality`, `match`, `ore`, `ope` and `json`.
An index takes its options in the tag, in parentheses after its name.
These words are the same as the Rust API's words for the same behaviour.

An `opaque` struct has no tags on its fields.
Nothing inside it can be read or searched on its own.
A value with no struct around it is a struct with one field.

### Columns

A field maps to its columns in one of two layouts.

**One EQL column for each field** is the layout to use.
`encrypt_into` names an EQL type, and the generated field holds one EQL value.
The value has the ciphertext and every term, and Postgres searches it through EQL's operators.
The generated type is then flat: one field, one column.

**Separate columns** is the other layout.
`encrypt,index=...` gives one column for the ciphertext and one for each term.
The generated field is then a struct with one field for each output, such as `Email.Ciphertext` and `Email.Equality`.
Every sealed field gets such a struct, including a field with one output.
A library that maps one struct field to one column needs a model for this layout.

### What stashgen writes

For `-type User`, the file `user_stash.go` holds:

- **`EncryptedUser`.**
  It has one field for each field of `User` that is stored, with the same name.
  A passthrough field keeps its Go type.
- **`Encrypt` and `Decrypt`.**
  `Encrypt` takes a `[]User` and returns a `[]EncryptedUser`.
  `Decrypt` goes the other way.
- **`Fields`.**
  It has one entry for each sealed field.
  An entry encrypts one value of that field, and it has a query method only for what the field declares.
- **`Encryption` and `Decryption`.**
  They describe the same work without running it, for a batch.
- **Print methods on `EncryptedUser`.**
  `String` and `LogValue` print the passthrough fields and hide the sealed ones.
- **The declaration.**
  It is data that only generated code uses, and no function a program calls names it.

The file also converts `User` to a copy of its fields, so a change to the fields of `User` stops the build.
Generated code uses no reflection.
See [`users/model.go`](2026-10-04-plan-builder/users/model.go) and [`users/user_stash.go`](2026-10-04-plan-builder/users/user_stash.go).

### Calls

| Call | Returns |
|---|---|
| `users.Encrypt(ctx, c *stackencrypt.Cipher, vs []User)` | `[]EncryptedUser` |
| `users.Decrypt(ctx, d stackencrypt.Decrypter, es []EncryptedUser)` | `[]User` |
| `users.Fields.Email.Encrypt(ctx, c, v string)` | the field's generated type, for an update of one column |
| `users.Fields.Email.Query(ctx, c, v string)` | an EQL query value, for a field with `encrypt_into` |
| `users.Fields.Email.Equality`, `.Match`, `.Ore`, `.Ope` | one term, for a field with `index=` |
| `users.Fields.Attrs.Contains(ctx, c, v)` | a JSON containment query |
| `users.Encryption(vs []User)`, `users.Decryption(es []EncryptedUser)` | a `stackencrypt.Operation`, for a batch |
| `stackencrypt.Batch2(ctx, c, a, b)`, `Batch3` | the result of each operation |

Every call also returns an `error`.
`Encrypt` and `Decrypt` take a slice, and send one ZeroKMS request for all of it.
The result has one element for each element of the input, in the same order.
For one value, pass a slice with one element.

A field entry's `Encrypt` and its query methods take one value.
A term derives with no request, so there is nothing to batch.

`Batch2` and `Batch3` run operations on two or three types in one ZeroKMS request.
Each returns one typed result for each operation.

```go
encryptedUsers, encryptedContacts, err := stackencrypt.Batch2(ctx, cipher,
	users.Encryption(people), contacts.Encryption(list))
```

`*Client` and `*Cipher` both implement `Decrypter`.
A `*Client` decrypts each value under the keyset that sealed it.
A `*Cipher` also refuses a value from another keyset, with `ErrForeignKeyset`.

### The cipher

The cipher holds what changes from one caller to the next: the keyset, and any extension of the context.

```go
cipher := client.Keyset(stackencrypt.KeysetName("tenant-42")).Extend("tenant-42")
```

`Extend` returns a cipher that extends the context of every field, in every call through it.
No call takes a keyset or a context.
So the write, the query and the read cannot use different ones.

### Names

In a package with one tagged struct, the generated names are `Encrypt`, `Decrypt` and `Fields`.
The package name says what they encrypt: `users.Encrypt`.

A package holds one function named `Encrypt`.
For a second struct in the package, `-name Account` gives `EncryptAccount`, `DecryptAccount` and `AccountFields`.
The flag works on any struct, so both can carry a name.
The generator stops when two structs in a package would both write `Encrypt`.

### Embedded structs, unexported fields and other tags

**An embedded struct of your own** adds its tagged fields to the outer struct.

**An embedded struct from another package** cannot carry tags, so one tag on the embedded field decides for all of its fields:

```go
type Account struct {
	_          struct{} `stash:"context=accounts"`
	gorm.Model          `stash:",passthrough"`
	Email      string   `stash:"email,encrypt_into=TextEq" gorm:"uniqueIndex"`
}
```

`stash:",passthrough"` stores every field of the embedded struct as it is, and `stash:"-"` leaves them all out.
The generated type embeds the same struct, so its own tags still apply.
With no tag on the embedded field, the generator stops and names the fields.

**Tags for other libraries**, such as `gorm`, `db` and `json`, are copied to the same field of the generated type.

**An unexported field with no `stash` tag** is ignored, with three notices:

- `stashgen` prints a warning.
- The generated file names the field in a comment.
- The program prints a warning to stderr, once for each type, on first use.

`stash:"-"` on the field states the choice, and all three notices stop.
See [`accounts/account.go`](2026-10-04-plan-builder/accounts/account.go).

### Printing

A generated type hides its sealed fields when a program prints or logs it.

The struct you wrote is not protected.
A `User` that a program prints or logs shows every field.
The SDK gives four tools for that:

- `stashgen` warns when a struct has sealed fields and no `String` and `LogValue` methods.
- The program prints the same warning to stderr, once for each type, on first use.
- `-redact` makes `stashgen` write those two methods on the struct.
- A `go vet` check reports a struct with sealed fields that is passed to `fmt`, `log` or `slog`.

No warning, error or log line from the SDK holds a plaintext value.
Each names the type and the field only.

### Models

A model is a struct with one field for each column, such as a GORM model.
With one EQL column for each field, the generated type is already such a struct, and no model is needed.

sqlc writes its own row struct in every case.
With one EQL column for each field, that struct has the same fields as the generated type, and Go converts one to the other.
A change to either struct stops the build.
See [`users/sqlcstore.go`](2026-10-04-plan-builder/users/sqlcstore.go).

With separate columns, `-model Rows=ContactRow` names a model.
Each field of the model carries a `stash` tag that names one output:
`stash:"email"` is the ciphertext of `email`, and `stash:"email,equality"` is its equality term.
`stashgen` writes `EncryptRows` and `DecryptRows`, which return and take the model.

The generated file holds a copy of the model's fields, and it converts between the copy and the model.
Go allows that conversion only while the two have the same fields, with the same types, in the same order.
So a change to the model stops the build until `go generate` runs again.

For a model that cannot carry tags, `-model Rows=R:D` names a struct `D` in your own package that declares them.
See [`contacts/contacts.go`](2026-10-04-plan-builder/contacts/contacts.go).

### Types in another package

A type in another package cannot carry `stash` tags.
For such a type, a struct in your own package declares them:

```go
//go:generate go tool stashgen -type contactStash -for crm.Contact
type contactStash struct {
	_           struct{} `stash:"context=contacts"`
	ID          int64    `stash:"id,passthrough"`
	Email       string   `stash:"email,encrypt,index=equality;match"`
	PhoneNumber string   `stash:"phone_number,encrypt,index=equality"`
	Internal    string   `stash:"-"`
}
```

`stashgen` matches each field to the field of `crm.Contact` with the same name and type.
It refuses a field of `crm.Contact` that the struct does not name.
The generated functions have the same names and shapes as for a struct of your own.
The file converts `crm.Contact` to a copy of its fields, so a change to `crm.Contact` stops the build.

That conversion needs a struct whose fields are all exported.
A struct from another package with an unexported field, such as a protobuf message, cannot convert.
For such a struct the generated file assigns each field by name.
The compiler then finds a removed field and a field with a new type, and CI finds an added field.

### stashgen reference

`stashgen` is a Go command at `languages/golang/cmd/stashgen`.

| Flag | Meaning |
|---|---|
| `-type T` | The struct that carries the `stash` tags. Required. |
| `-name N` | Write `EncryptN`, `DecryptN` and `NFields`. |
| `-for P.F` | `T` declares the tags for `F`, a type in another package. |
| `-model Name=R` | A model `R` for separate columns. Writes `EncryptName` and `DecryptName`. Any number. |
| `-model Name=R:D` | The same, for an `R` that cannot carry tags. The struct `D` declares them. |
| `-redact` | Write `String` and `LogValue` methods on `T`. |
| `-output file` | The file to write. The default is the type's name in lower case, with `_stash.go`. |

The generator loads the package with `golang.org/x/tools/go/packages` and reads types, not text.
It runs none of the package's code.
It ignores its own output file when it loads the package, so a stale file does not stop it.
The same input always gives the same file: fields keep their declared order, and the file carries no version and no time.

`stashgen` stops with an error, and writes no file, for each of these:

- an exported field with no `stash` tag;
- a tag that does not parse, or two fields with one name;
- a struct with no `context=` field;
- an index or an EQL type that does not apply to the field's Go type, such as `match` on an `int32`;
- a field type that the engine cannot seal;
- a `passthrough` field that has an index;
- a model with a field that has no tag, or with no field for an output;
- two structs in one package that would both write `Encrypt`.

### Declarations from a policy

A policy decides what to encrypt from the data categories that a schema gives each field.
The policy is Go code, so a program must run it.
That program is a generate program that you own, and `go generate` runs it:

```go
//go:generate go run -tags stashgen ../cmd/genplans

func main() {
	err := stashgen.Generate(policy.Source, policy.Individuals, stashgen.Output("individual_stash.go"))
	if err != nil {
		log.Fatal(err)
	}
}
```

`stashgen.Generate` is the generator as a library, at `languages/golang/stashgen`.
It runs the policy over the facts and writes the same file that the tags give.
The application never runs the policy.

- A field that no rule decides stops `go generate`, with the field's name and its annotations.
- A change to the policy changes the generated file, so a reviewer reads what the change encrypts.
- A field that the policy stores as plaintext is a passthrough field of the generated type.

The generate program imports the package that holds the type.
So that package must build when the generated file is stale.
The generated file carries the build constraint `!stashgen`, and the generate program runs with `-tags stashgen`.
Code that uses the generated names goes in another package.
See [`policy/policy.go`](2026-10-04-plan-builder/policy/policy.go), [`cmd/genplans/main.go`](2026-10-04-plan-builder/cmd/genplans/main.go) and [`individualstore/store.go`](2026-10-04-plan-builder/individualstore/store.go).

### When a mistake is found

The SDK finds each mistake at the earliest of these stages: the compiler, `go generate`, CI, and the running program.
The running program finds only a mistake that depends on data.

| Mistake | Found by |
|---|---|
| A read of an output that the field does not declare | the compiler |
| A query that the field does not declare | the compiler |
| An encrypted value passed where another type's is expected | the compiler |
| A field added to, removed from or retyped in the tagged struct | the compiler |
| A change to a model, to sqlc's row struct, or to a type in another package | the compiler |
| A generated file and a library from versions that do not agree | the compiler |
| A tag that does not parse, an untagged field, or a field that no policy rule decides | `go generate` |
| A field added to a struct from another package that has an unexported field | CI |
| A change to a tag or to a policy, with no `go generate` run | CI |
| A value that does not decrypt, or that decrypts to another type | the running program, as an error |

CI runs `go generate ./...` and fails when a generated file differs from the committed file.

No function in the SDK or in generated code panics for a declaration, and none has a name that starts with `Must`.

### What crosses the binding

The engine does all encryption, decryption and term derivation.
Generated code sends the engine the full declaration: every field, including each passthrough field and each field left out.
It sends the value of each sealed field.
It does not send the value of a passthrough field, and it copies that value to the generated type itself.

Generated code assembles an EQL value from the engine's ciphertext and terms.
A cross-language fixture guards those bytes: encode in Rust, decode and encode again in Go, and compare.

The package `stackencrypt/gensupport` holds what only generated code calls.
No function in it panics.
Each generated file names a constant, such as `gensupport.GeneratedVersion1`, that only a library of an agreeing version declares.
So a file from another version does not compile.

### Errors

The generator and the compiler find a mistake in a declaration, so no call returns an error for one.
A call returns an error for a key, for the network, or for stored data:

- `ErrForeignKeyset`: a `*Cipher` got a value that another keyset sealed.
- A ciphertext that does not decrypt under the field's context.
- A decrypted value that is not the field's Go type.

Use `errors.Is` and `errors.As` to read it.

### Databases

The SDK is tested with `database/sql`, pgx, sqlc and GORM.

Every stored type implements `driver.Valuer` and `sql.Scanner`.
A library that uses those two interfaces works with the SDK.
A failure with such a library is a bug in the SDK.

Encryption happens before the database library gets the value.
A driver's value hook gets no `context.Context` and one field at a time, so it cannot batch a request.

- **database/sql and pgx:** pass the fields of the generated type to `ExecContext`, and `Scan` into them.
  See [`users/sqlstore.go`](2026-10-04-plan-builder/users/sqlstore.go).
- **GORM:** the generated type is the model.
  See [`users/gormstore.go`](2026-10-04-plan-builder/users/gormstore.go).
- **sqlc:** type overrides give each EQL column its Go type, and sqlc's row struct converts to the generated type.
  sqlc reads a file that declares the EQL domains in place of the EQL install bundle, which it cannot parse.
  See [the three rules for EQL columns](2026-10-04-plan-builder/README.md#use-sqlc-with-eql-columns).

The SDK gives the values for a search, and the program writes the SQL that uses them.

### Removed

The existing Go package has never been released, so these are removed, not deprecated:

- `Cipher.Encrypt`, `Cipher.Decrypt` and `Client.Decrypt`: an `opaque` struct replaces them.
- `EncryptElement` and `DecryptElement`.
- `EncryptRecord`, `EncryptRecords`, `DecryptRecord` and `DecryptRecords`, on `Cipher` and on `Client`.
- `EncryptedRecord` and `EncryptedField`: a generated type replaces them.
- `Cipher.Term`: the query methods of a field entry replace it.
- `RecordOption`, `WithPlan` and `ExtendContext`: `Cipher.Extend` replaces the last.
- `TermKind`: `Index` replaces it, for generated code.
- `Plan`, `FieldPlan`, `NewPlan` and `Plan.Validate`: the generator replaces them.
- `PlanFromTags`, and every other function that reads `stash` tags at run time.
- `plan.PlanFor` and `plan.MustPlanFor`: `stashgen.Generate` replaces them.
- `Context`, `NewContext`, `Label`, `NewLabel` and `ParseLabel`: the `context=` tag replaces them.
- The rule that a zero `Plan` means the struct's tags.
- `Sealed`, `SealedNone`, `SealedEmptyMap` and `SealedEmptySeq` as storage types: `Ciphertext` replaces them.

### The guest

Unchanged in substance. The plan already crosses as data and the guest
already calls `dynamic::record`; once that module is a lowering into the
builder, the guest's exports run the same engine the derive does. The export
set is renamed once the Go surface settles (`se_encrypt`, `se_decrypt`,
`se_query`, with the plan as an argument), and the element exports fold into
`se_decrypt`.

## Other languages

Checked 2026-10-04 against Node/TS, Python and C#, and then the JVM, PHP,
Ruby, Swift and Kotlin on mobile, Dart, Elixir, C and C++, R and Julia. None
is being built yet.

**Native bindings are the default; Wasm only where it is the reason for the
binding.** A binding is a thin **shell** in the host language's native
extension mechanism (napi-rs, PyO3, JNI or Panama, a cdylib with a C header
for Swift, Dart, PHP, Ruby, R and Julia), running stack-encrypt in-process
with its own HTTP client, stack-auth's strategies, and the host's own async
runtime. The WASI guest is one shell among them, used where native is not
available or is the thing being avoided: Go (no cgo), the edge runtimes
(Cloudflare Workers, Supabase Edge, Deno Deploy, browsers), and anywhere
sandboxing the cryptographic code is itself the requirement.

With ADR-0007 there is no executor to port either way: every shell lowers a
plan into the same `dynamic` entry. What a shell writes is a conversion from
the host's values to `FfiValue` (direct in napi-rs and PyO3; the byte codec,
Go's `vcvalue`, is a guest concern), a mapping from the error type to the
language's errors, the chain, and whatever memory hygiene the platform allows.
A guest host additionally supplies the two imports, HTTP transport and a token
source.

| Concern | Rust | Go | Node/TS | Python | C# |
|---|---|---|---|---|---|
| Shell | in-process | WASI guest (wazero) | napi; the guest for `wasm-inline` on the edge | PyO3 | P/Invoke to a cdylib |
| Finalizer | `.await` | none: each method runs when called, `ctx` first | `await` (thenable chain) | `await` plus sync `.run()` | `await` (`GetAwaiter`) or `RunAsync(ct)` |
| Plan from a type | derive | tags and `stashgen` | schema builder or decorators | `Plan.of(User)` over `Annotated` | attributes; reflection or a source generator |
| Index applies to type | compile time | `go generate` | partly via conditional types | build | partly via constraints |
| Typed output | `Encrypted<Terms>`, derived struct | a generated struct (`stashgen`) | inferred from the plan | dict or the dataclass | `Plan<T>`, `Task<T>` |
| Query form | source type | one method for each form | overloads or union | runtime type | overloads |

The fail-closed `build()` checks are the floor everywhere; compile-time checks
are a bonus where the language has them.

**TypeScript already has a plan in another spelling.** `encryptedTable('users',
{ email: types.TextEq() })` is `Plan::context("users").fields()
.encrypt_into::<TextEq, _>("email")`, with the EQL domain as the field's target.
Today that schema drives cipherstash-client through protect-ffi, a second
engine. The intended path is to retire protect-ffi and ship a new major of
`@cipherstash/stack` on stack-encrypt, with breaking changes; that release is
the TS version of retiring `dynamic::record`, and the schema builder becomes
the TS spelling of a plan. Its Node entry is a napi shell; only `wasm-inline`
uses the guest.

### Where the design strains

1. **Plaintext type in dynamically typed hosts.** Independent of the shell.
   Index semantics are type-specific (`Match` is text only; `Ore` on `34` and
   `34.0` differ; JavaScript's one number type cannot hold an `i64` without
   `BigInt`). A plain JS object, PHP array, Ruby hash or R data frame does not
   say what `34` is. **The plan carries a type per field**, and `build()`
   refuses an index on a field whose type it cannot resolve; typed hosts fill
   it from the type, dynamic hosts state it, and the engine verifies each
   tagged value against the declaration rather than trusting the shell. The TS
   schema builder already does this (`types.IntegerOrd()`). The type is
   load-bearing three times: `encrypt` uses it to admit indexes and derive the
   right term bytes, `query` to read the query value (`query(34)` against a
   `u64` field is a `u64` term), and `open` to know what to hand back in a
   host with no type to infer from (an Integer, not a Float; bytes, not a
   String). The vocabulary is vitaminc's frozen tag table plus the composite
   kinds, not new names. A wire-format addition, so it goes in the first
   engine PR. This is the one gap in the plan approach itself that the
   language check found. #1069 added the type to the grammar as an optional
   key, so a field with none is still dispatched on each value's own tag;
   that is transitional, until Go fills the type (#1046) and the key becomes
   required on indexed fields.
2. **The guest's synchronous transport import, on the edge path only.**
   `transport_send` is synchronous from the guest's point of view and the ABI
   relies on it ("`block_on` never parks"). A wazero host function may block a
   goroutine, so Go is fine; a Wasm import in a browser, Deno, Bun or an edge
   worker may not block the event loop. Native shells never meet this. The
   one binding that does is TypeScript's `wasm-inline`. Asyncify, JSPI and a
   worker with `Atomics.wait` are each fragile; the robust fix is latent in
   `Pending`, which already separates building requests from dispatching them:
   the guest exports the two halves, the host performs the ZeroKMS round trip
   in its own idiom, and the guest does no I/O. **A guest-ABI requirement to
   settle before the edge binding is built**, and not before.
3. **What the derive could say that a plan could not.** The plan was meant to
   have three authors over one grammar, but the derive's attribute grammar had
   grown past the plan's: a field sealed under a literal context outside the
   record's, a literal context that was not a plain label (`"readings/unit"`),
   a `nested` field handed the caller's context, and several outputs from one
   source field. Emitting a plan from that grammar would either drop those
   forms or widen the data grammar with Rust-shaped features no binding needs.
   **Resolved by meeting in the middle.** The derive loses the four forms (see
   "Consolidation"; `identity` replaces the literal field context), and the
   plan gains what the derive genuinely needs: the two starts, the three
   context sources, the typed verb and the picker. The typed parts stay
   Rust-only and have no data form, so the wire grammar does not grow. Only
   then does the derive emit the plan, with byte identity proven on the
   narrowed grammar.

Encrypting inside the database (a Postgres extension, PL/pgSQL) is outside the
model rather than a strain: it puts key material in the database.

## EQL v4 types as field targets

Naming: **EQL v4** is the EQL form of a stack-encrypt payload. **EQL v3** is
the existing SQL bundle and its `eql_v3_*` domains, which this section does
not change. Depends on #971 (`TextEq` / `TextEqQuery` through stack-encrypt
in `eql-bindings`, and `Identifier` as a two-segment `Label`).

**The engine never returns an EQL type.** It returns standard outputs:
ciphertexts, terms and passthrough values. Each language's typed layer
assembles EQL types from them:

- **Rust**, through the EQL type's own `EncryptFrom` impl, named with the
  typed verb. A field target may be any `EncryptFrom` type, so an EQL type
  plugs into a plan with no builder work:

  ```rust
  let users_plan = Plan::context("users").fields()
      .encrypt_into::<TextEq, _>("email")     // TextEq's own EncryptFrom decides the layout
      .encrypt_into::<Json, _>("attrs")       // EQL's JSON type frames the Json index's document
      .encrypt_index::<u32>("age", (Equality, Ore))
      .build()?;
  ```

- **Go**, through code the generator in #1070 writes. The generated code asks
  the guest for the standard outputs of the field's indexes and assembles the
  EQL type in Go.

So there is **no registry** of EQL types, **no target name in the data
grammar**, and no `Target<S>` trait. The WASI guest stays EQL-free: it runs
data plans and returns standard outputs, exactly as for any other field. A
shape mismatch (the outputs do not fit the EQL type) is a run-time error in
Go, and codegen makes it unreachable in practice.

An EQL type is still a target that wraps an index's output; the index itself
stays in stack-encrypt. The JSON type is the clearest case: the `Json` index
produces the searchable document, and EQL's JSON type frames it.

**The cost: the EQL byte encoding lives twice**, in `eql-bindings` (Rust) and
in a Go EQL package. A standing cross-language fixture guards it: encode in
Rust, decode and re-encode in Go, and compare the bytes.

Match and JSON index options need a wire form first (Additions, item 7): the
Go side derives its terms from a data plan, and a dropped option there is a
query that matches nothing.

## Sequencing

Done:

1. **Source modes** (#1068): a non-`Clone` plaintext runs one operation;
   `KeysetCipher::run`.
2. **Engine pieces** (#1069): `passthrough()`, `run_decryption`, `Index<S>` /
   `Indexes<S>` / `indexed()`, `Encrypted<Terms>`, and a type per field in
   the plan grammar.
3. **The builder** (#1071): the one-value chain, the fields chain, `Plan`,
   `using`, `query`, `open`, `all`.

Next, as stacked drafts on #1071 (4, 5 and 6 are open drafts):

4. **Narrow the derive** (#1073, open draft): the four removals in
   "Consolidation". The byte changes are isolated in this PR and listed.
5. **Widen the plan** (#1074, open draft): the two starts, the three context
   sources, `encrypt_into` in both positions, `Encrypted<Terms>: EncryptFrom<S>`,
   the picker, and the match and JSON options on the wire.
6. **The derive emits the plan** (#1058, PR #1076, open draft), with byte
   identity proven on the narrowed grammar.

Then:

7. **`dynamic::record` becomes a lowering** (#1059). The guest is rebuilt;
   Go's `plantest.Golden` snapshots must not change, which is the proof.
8. **The Go binding** (#1046), against the design in #1070. #1025 merges
   first so snapshots regenerate once.
9. **The EQL typed verb** (#1062), Rust-only; Go assembles EQL types through
   the generator.
10. The audit-context PR, then the lock-context PR, on the finished shape.

## Non-goals

- The Node binding, which uses `cipherstash-client`, not stack-encrypt.
- Domains beyond those with Rust derives; they arrive by regeneration.
- Lock and audit context themselves; this plan only leaves them a place.
- Named term accessors on `Encrypted<Terms>` (decision 7).

## Open questions

- **The Go EQL names.**
  The package `eql`, its type names and the values of `encrypt_into` are placeholders.
  The EQL typed verb (#1062) settles them.
- **Query building in Go.**
  The SDK gives the values for a search, and the program writes the SQL.
  A design for building that SQL is separate work.
- **A `go vet` check.**
  It reports a struct with sealed fields that a program prints, and an `Encrypt` call inside a loop.
  Its design is separate work.
- **A change to a declaration over time.**
  This design covers one version of a declaration.
  Reading data that an older declaration wrote needs its own design.
- **How the generator gets the engine's rules.**
  The generator must refuse what the engine refuses, from one source of rules.
  Whether it calls the engine or reads rules the engine publishes is not decided.
- **The policy package.**
  Its approach is under review, so "Declarations from a policy" can change.
- **Converging the TypeScript schema builder onto the plan grammar**, so
  `@cipherstash/stack` stops being a second engine beside stack-encrypt.
  Out of scope here; recorded so a TS binding does not grow an executor.
- **The Go EQL package (`eqlv3` in the first draft) as a package or a
  separate `go.mod`**: a package as read; correct if a separate module was
  meant.

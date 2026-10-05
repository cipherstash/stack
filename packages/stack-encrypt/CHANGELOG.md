# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- **A target description carries a source mode.** `Encryption` gains a
  last type parameter, `M: SourceMode = Borrowed`, saying how it is handed
  its plaintext. Code that names `Encryption<'s, S, T, K, Ctx>` still
  compiles and means the borrowed mode it always ran in.
- `ciphertext`, `equality`, `matching`, `ore` and `ope` gain a source-mode
  type parameter, `M`. A turbofish must name it: `ciphertext::<S, K, M>()`,
  and in `matching` it comes before `O` (`matching::<S, K, M, O>()`). A call
  whose result type does not fix the mode must name it; `Borrowed` is the
  old behaviour. In return `ciphertext`, `equality`, `ore` and `ope` no
  longer ask `S: Clone` themselves: only borrowed mode does.
- `sem::MatchTerm` is renamed `MatchTerms`: a match index produces a set of
  terms, not one. `MatchTerm` remains as a deprecated alias.
- `TermBytesError::OddMatchTermLength` is renamed `OddMatchTermsLength`. An
  enum variant cannot be aliased, so a `match` that names it must change.
- `dynamic::TermKind` is gone; `target::IndexSpec` is the one data form of
  an index. `Output::Term`, `Error::Term`'s `kind`, `Scalar::of` and
  `dynamic::term` take an `IndexSpec` (the last two by reference), and
  `Output` is no longer `Copy`. A plan's wire form is unchanged: a bare
  `"match"` still means the default options.
- **`stack-encrypt-derive`: a field-level `#[stash(context = "..")]` is
  removed on every derive form** (0.2.0 accepted it). On a `plaintext = T`
  record, remove it: all outputs of the record share the caller's context. On
  a field of a `struct = ..` derive, write `#[stash(identity = "..")]`, which
  keys the field under `("<context>", "<identity>")` (`users/nickname`), not
  under the bare literal (`nickname`). Either way the field moves to a
  different context from the one 0.2.0 used: data written by 0.2.0 does not
  decrypt under it (ZeroKMS refuses the key, `Error::Kms`) and its equality,
  match and order terms do not match new query terms, so re-encrypt that
  data. Before the literal went, a non-plain literal such as
  `"readings/unit"` was already refused, for the same reason.
- **`stack-encrypt-derive`: `#[stash(nested)]` is removed** (0.2.0 accepted
  it). Remove it: a record-typed field of a `struct = ..` derive is an
  ordinary field, keyed under `("<context>", "<field>")`, and its inner
  fields sit under that (`("user/age", "accounts/user")` where `nested` gave
  `user/age`). That is a different context from the one 0.2.0 used: data
  written by 0.2.0 does not decrypt under it and its terms do not match, so
  re-encrypt that data.
- **`stack-encrypt-derive`: a plaintext field of a `struct = ..` derive has
  one output.** 0.2.0 accepted several fields `from` one plaintext field
  (`email: StackCipherText` beside `#[stash(from = email)] email_hm:
  EqualityTerm`). Write one field of type `Encrypted<Terms>` instead
  (`email: Encrypted<EqualityTerm>`). Its ciphertext and terms are derived
  under the same context as before (an equality term is the same bytes), so
  stored data still opens and its terms still match; what changes is the
  record's shape, one field where it held two.
- **The plan API listed under Added changes shape before its first
  release** (none of this is in 0.2.0; it matters only to code built
  against the unreleased tree). `Plan::fields()` now starts a fields plan,
  so a built plan's field iterator is `Plan::field_plans()`. A one-value
  plan is `ValuePlan<S, Indexed<X>>` (from `with`) or
  `ValuePlan<S, Typed<T>>` (from `encrypt_into`), in place of
  `ValuePlan<S, X>`. `Plan::label` and `ValuePlan::label` return
  `Option<&Label>` (`None` for a plan whose context comes from the call or
  a context field), as `FieldPlan::label` does. `Runs::pending`,
  `Opens::decryption`, `Plan::encryption`, `Plan::decryption` and
  `ValuePlan::encryption` take the context the call names (an
  `Option<Label>`) beside the extension, and `Runs::check` /
  `Opens::check` take it too. The field verbs take a `FieldRef` (a name or
  a picker) in place of `&str`; a name still works as before.

### Added

- `KeysetCipher::run`: run a description held in a variable over a value,
  under a context, without an `EncryptFrom` declaration.
- `target::{SourceMode, ConsumeSource, ShareSource, Borrowed, Owned}`. In
  `Owned` mode a description is handed the plaintext by value, so a single
  operation consumes it with no copy and a plaintext that is not `Clone`
  (a zeroizing FFI value) can be sealed or indexed. The traits are sealed.
- Indexes as types: `target::{Index, Indexes, Equality, Match, Ore, Ope}`,
  `indexed`, `Encrypted`, `Select` / `At` / `Whole`. A match index on an
  integer does not compile, and an index set is one index or a tuple of two
  to five, never `()`. `Index::spec` lowers an index to its `IndexSpec`.
- `target::passthrough`: a field carried unsealed and unauthenticated.
- `KeysetCipher::run_decryption` and `StackCipher::run_decryption`: run a
  `Decryption` held in a variable.
- A dynamic plan's match index can carry options, as
  `{"match": {"tokenizer", "downcase", "k", "m"}}`.
- A dynamic plan field may declare its type, as `"type": "<kind>"`. The
  vocabulary is vitaminc's `ValueKind` (re-exported as
  `dynamic::ValueKind`), not a new enum, so this crate now needs vitaminc
  0.5.1. A declared type refuses an index it is not defined for
  (`dynamic::admits`) and a value of another kind, on encrypt and on
  decrypt. `dynamic::read` reads a query value as a kind;
  `FieldPlan::with_type` and `field_type` set and read the declaration.
- The `plan` module, the chained plan builder: `cipher.encrypt(&value)`,
  `cipher.query(&value)` and `cipher.open(record)`, each finished by
  `.await`, with `.keyset(..)` and `.extend(..)` on every chain. A value is
  sealed under a context as one tree (`.context(c)`), with indexes beside
  it (`.with(indexes)`), or field by field (`.fields()` then `encrypt`,
  `encrypt_index`, `index`, `passthrough` and `identity`). Every chain lowers
  to the combinators in `target` and produces the same bytes they do.
- Saved plans: `Plan::context(c).fields()...build()` (a fields plan,
  `Plan<S, K>`) and `Plan::context(c).with(indexes).build()` (a one-value
  plan, `ValuePlan<S, X>`), run with `.using(&plan)` over a value, a slice
  or a `Vec`, queried through `Plan::field(name)` (a `FieldPlan`) or the
  `ValuePlan` itself, and opened with `cipher.open(record).using(&plan)`.
  `FieldValues` is a fields plan's record; `Fields`, `Field` and
  `FieldSchema` describe a value's fields; `FieldKind` says what a field
  does.
- `all((..))`: two to four chains settled in one ZeroKMS request per
  request kind, under one keyset. Chains from different ciphers are
  refused; an opening that names no keyset still reads any keyset.
- `PlanError`, carried in the new `Error::Plan`: every way a plan, or the
  value, record or query it runs with, is refused. A chain is checked
  (`Operation::check`) before it loads a keyset it names.
- A passthrough field's name may be any text: it is under no label, so
  `FieldPlan::label` is `None` for one.
- `IntoLabel` for `&String`, and `KeysetChoice` from a `&String`.
- `target::TermSet`: a term type, or a tuple of two to five, names the
  indexes that derive it (`MatchTerms<O>` names `Match<O>`, options
  included).
- `Encrypted<Terms>` is a target: it implements `EncryptFrom<S>`
  (described as `indexed(Terms::INDEXES)`), `Decryptable` and
  `DecryptField`, so a derived record can hold a ciphertext and its terms
  in one field.
- `stack-encrypt-derive`: `#[stash(identity = "..")]` on a field of a
  `struct = ..` derive keys it under that segment in place of the plaintext
  field's name, the plan builder's `.identity(segment)`.
- Two plan starts, each with an optional `.context(c)`: `Plan::fields()`
  (field by field) and `Plan::value::<S>()` (one value, then `.with(indexes)`
  or `.encrypt_into::<T>()`). `Plan::context(c).fields()` / `.with(..)` keep
  working.
- A plan's context comes from exactly one place: the plan, the call that
  runs it (`cipher.encrypt(&v).context(c).using(&plan)`, and `.context(c)`
  on `cipher.query(..)` and `cipher.open(..)`), or a field of the value
  (`FieldsBuilder::context_field`, carried as a passthrough and checked on
  open against the context the caller expects). Two is
  `PlanError::TwoContextSources`; none is `PlanError::NoContext`, raised
  before any key is requested. `Plan::context_field()` names the field.
- `encrypt_into::<T, _>(field)` on a fields plan, and
  `Plan::value::<S>().encrypt_into::<T>()`: the field or value is laid out by
  the target `T`'s own `EncryptFrom`, under `<context>/<identity>`, and
  answers the queries `T` declares. A field is a target or data verbs, never
  both (`PlanError::TargetWithVerbs`).
  `Plan::value::<S>().encrypt_into::<T>()` builds for a target of any
  context (`plan::ValueLayout`); running it through `.using(..)` or
  `ValuePlan::encryption` asks that a `CallerContext` converts into the
  target's context (`plan::ValueShape`).
- `EncryptFrom::indexes()`: the indexes a target's terms answer, as data
  (empty by default; terms, `Encrypted<Terms>` and tuples name theirs).
- A tuple of two to five targets is a target (`EncryptFrom`, `Decryptable`,
  `DecryptInto`, `DecryptField`): each element derived from the one
  plaintext under one context, opened through the element that holds a
  ciphertext. A tuple of terms alone is no field to open a record through.
- Pickers: every field verb takes a `FieldRef`, a name or a name with an
  accessor (`plan::pick("email", |u: &User| &u.email)`), which reads the
  field directly and needs no `Fields` impl or turbofish.
- `FieldPlan::identity()`; a pinned identity lets a field name that is not a
  plain segment (`"0"`, `"2fa_secret"`) be sealed and queried.
- `PlanError::IndexOptions`: a query asked for an index the field declares
  with other match options.

## [0.2.0] - 2026-10-04

### Breaking

- **A column has one encryption context, and its ZeroKMS descriptor renders
  `users/email`.** `Descriptor::SEPARATOR` is `/` (was `|`); a text part that
  contains `/` is escaped with URL-safe base64 (the standard alphabet contains
  `/`). A data key minted through 0.1.0 was bound to the old rendering of the
  same context and cannot be retrieved under this one. 0.1.0 had one known
  consumer, aware of this; see ADR-0006.
- `#[derive(EncryptFrom)]` with `struct = User, context = "users"` binds each
  field under the pair `("users", "<field>")`, the same context EQL's
  `Identifier` is. A `#[stash(context = "…")]` literal on a field stays one
  text part, exactly as written.
- `Encryption::under` / `extend` and the context types accept any
  `NonEmpty<impl IntoContext>` as the own context, not only a static string.

### Added

- `Describe` and `Description`: a value whose parts are the descriptor of
  the data it keys. `to_context` is what the type's `IntoContext` returns, so
  the AAD and the ZeroKMS descriptor are one tree seen two ways. EQL's
  `Identifier` (table, column) implements it in `eql-bindings`.
- `Label` and `LabelError`: a path of plain segments written and read as
  `users/email`, for direct consumers. One segment is the same context as the
  bare literal; two are the pair a `struct = ..` derive binds.

## [0.1.0] - 2026-10-04

The first crates.io release. Everything below was in it; the heading was
added after the fact — this section said "Unreleased" when 0.1.0 shipped.

### Breaking

- **Sealed leaves gained a version byte, and the leaf AAD that binds it.**
  Leaves sealed before this change used an unlabelled `PAE(aad, tag)` leaf
  AAD with no version byte; the derivation is now
  `PAE("stack-encrypt/leaf", version, derived_aad, tag)`. Leaves sealed under
  the old derivation cannot be opened by this build — however they were
  persisted (`serde`, `into_parts`, or raw bytes) they fail AEAD verification
  with a plain authentication error, indistinguishable from tampering,
  because the old form carries no version byte to raise
  `LeafBytesError::UnknownVersion` against. Acceptable only because the crate
  is `publish = false` and only dev-persisted data exists; from
  `SealedValue::FORMAT_VERSION` onwards a format move is signalled by the
  version byte instead.

### Added

- `SealedValue::to_bytes` / `from_bytes` / `TryFrom<&[u8]>`: the canonical,
  frozen v1 leaf encoding
  (`version ‖ iv ‖ u16 tag_len ‖ tag ‖ local_ciphertext`), with
  `LeafBytesError` for structural decode failures.
- Frozen transport encodings for every index term (`EqualityTerm`,
  `MatchTerm`, `OreTerm`, `OpeTerm`) with `TermBytesError` for decode
  failures, plus golden vectors in `tests/frozen_bytes.rs`.

### Changed

- `TermError`, `TermBytesError` and `LeafBytesError` are `#[non_exhaustive]`,
  so the versioned decoders can gain variants without a source break.

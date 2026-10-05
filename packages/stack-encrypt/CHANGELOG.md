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
  to four, never `()`. `Index::spec` lowers an index to its `IndexSpec`.
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

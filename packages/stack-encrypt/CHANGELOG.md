# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

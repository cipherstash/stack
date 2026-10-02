# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

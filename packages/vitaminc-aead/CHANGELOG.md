# Changelog

All notable changes to `vitaminc-aead` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]


### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- bump quickcheck from 1.0.3 to 1.1.0

### Added

- `Encrypt` and `Decrypt` traits with lifetime at the trait level (`Encrypt<'a>`)
  to support borrowed AAD like `&str` without higher-ranked trait bounds.
- `ContextTag` for binding AAD to plaintext values at the type level, with
  `refine()` for building hierarchical context.
- `ContextTag::decrypt` and `ContextTag::decrypt_with_aad` for symmetric
  decryption without exposing internal AAD encoding details.
- PAE (Pre-Authentication Encoding) for compound AAD types, preventing
  canonicalization attacks where different AAD components could produce
  identical byte strings.

### Changed

- **Breaking:** Tuple `(A, B)` AAD is now PAE-encoded instead of naively
  concatenated. Existing ciphertexts encrypted with tuple AAD will not decrypt.
- **Breaking:** `Option<T>` AAD is now domain-separated using PAE.
  `None` encodes as `PAE([])` and `Some(v)` encodes as `PAE([v])`, making them
  distinct from each other, from `()`, and from bare values. Existing
  ciphertexts encrypted with `Option<T>` AAD will not decrypt.
- **Breaking:** `ContextTag` fields `inner` and `aad` are now private.
  Use `ContextTag::new()` to construct values.

### Removed

- **Breaking:** `Extend<u8>` impl for `Aad`. This prevented bypassing PAE
  encoding by manually extending AAD with raw bytes.

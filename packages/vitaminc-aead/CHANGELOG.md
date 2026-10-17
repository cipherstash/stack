# Changelog

All notable changes to `vitaminc-aead` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** make the value model reusable
- **Breaking:** raise the MSRV to 1.88 and pin kms to the AWS SDK floor
- **Breaking:** refuse what encryption could not read back, and say why
- **Breaking:** bind the physical kind and logical id in LeafTypeAad
- **Breaking:** refuse a LeafTypeAad whose kind contradicts its logical type
- **Breaking:** build a LeafTypeAad only from pairs that cannot contradict
- **Breaking:** walk Protected<T> by reference and retire visit_protected
- **Breaking:** say where in the value EncryptSink refused it
- **Breaking:** rename aead-value to aead-frame and reduce it to the transport
- **Breaking:** reduce Aes256Cipher to seal and open
- **Breaking:** tag the static cipher's payloads so absence and a value cannot be swapped
- **Breaking:** seal tagged leaves as wire version 2 so 0.5 ciphertext is refused, not misread
- **Breaking:** pin the ADR 0001 format changes in the corpus and carry them in Go
- **Breaking:** remove Encrypt, Decipher, DecipherVisitor, SeqAccess and MapAccess
- **Breaking:** name the source trait Encrypt so it pairs with Decrypt
- **Breaking:** handle Timestamp as plaintext: constant-time equality, wiped on drop, no copies or ordering

### Documentation

- say how to add a logical type
- show the leaf and frame forms in write_leaf and read examples
- say a derived enum reads its discriminant, and skip unreachable mutants
- say why encryption failures are errors and leaf-type binding is opt-in
- name every runtime failure a derived type can still hit, and say an Encrypt

### Features

- preserve database scalar kinds
- add Plaintext, Sink and the physical/logical scalar kinds
- add the tagged leaf codec with the logical-type envelope
- add Cipher, AsyncCipher, EncryptSink and the seal/open traversals
- add the sink-based Decrypt and FromScalar
- decode maps and any wipeable scalar into Protected
- decrypt into Protected containers through DecryptProtected
- derive Plaintext and the sink-based Decrypt
- add vitaminc-normalize with the Terms sink
- compare paths and steps by value
- share EncryptSink's shape rules with other sinks
- carry PassthroughFrame across the ciphertext transport
- refuse derived types too deep to encrypt at compile time
- add Timestamp, a UTC instant that cannot be a leap second
- derive Default for Timestamp so skip and take fields can switch to it

### Fixes

- wipe owned byte leaves walked inside a Protected container
- treat scalars as plaintext in Debug and equality
- keep a failed walk from dropping protected elements bare
- derive an integer's sign without branching on its value
- redact Bytes in Debug and keep a source error's cause chain
- redact Raw in Debug like the other plaintext scalars
- check a frame length before writing any of the scalar
- make ScalarError a printable error and refuse an unfittable length
- report cipher failures on decrypt as the cipher's own error
- use core::error::Error for FrameError and Debug for scalars in tests
- skip the batch cipher call for a document with no leaves
- redact Frame's Debug and drop its plaintext equality
- derive Frame's redacted Debug and constant-time equality
- implement core::error::Error for DecodeError
- let a derived struct with borrowed fields walk by reference
- give ContextTag its async methods and say what the walk authenticates
- stop ContextTag's Debug from printing the plaintext
- clear the CI clippy, guest fmt and mutants failures from the rename
- check lifetime-only types and same-named path fields at compile time

### Performance

- allocate each map key once in EncryptSink

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

### Documentation

- show the typed context in the Element example, not the raw-byte escape hatch

## [0.4.0] - 2026-09-12

### Breaking

- **Breaking:** Context display now renders unit as `()` and an empty list as `None`. ([#338](https://github.com/cipherstash/vitaminc/pull/338))

### Features

- Runtime `AadPiece` contexts now support PRF derivation and `NonEmpty`, matching equivalent Rust contexts. Existing ciphertexts remain compatible. ([#338](https://github.com/cipherstash/vitaminc/pull/338))

## [0.3.0] - 2026-09-07

### Breaking

- **Breaking:** rename `IsEmpty` to `MaybeEmpty`

### Features

- `NonEmpty::with` and `From<integer>` for `NonEmpty`
- a context exposes its parts as an `AadPiece` tree, not only its bytes
- `ContextTag` hands its cipher the context's parts at no extra cost

## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** Ciphertexts written by 0.2.0-pre.1 do not decrypt with this release. Every leaf now begins with an authenticated wire-version byte, container shape, map keys and empty composites are authenticated, and several AAD encodings changed. Re-encrypt prerelease data; there is no migration path.
- **Breaking:** Decryption now takes the same AAD the encrypt side was given — the decrypt path mirrors encrypt, so callers that supplied AAD when encrypting must supply it again to decrypt.
- **Breaking:** The ciphertext container is now the generic `CipherText<Leaf, P>` (`AesCipherText` is an alias) and ciphers carry a `Passthrough` associated type; code that matched on the old container or used `T: Any` passthrough needs updating.
- **Breaking:** Map keys are authenticated, may be derived at runtime, and duplicates are rejected on both encrypt and decrypt.
- **Breaking:** Composite AAD is captured once at sub-cipher construction, closing bypasses where absence markers and passthrough entries escaped authentication; static nested map entries now bind their outer key.

### Features

- Derive `Encrypt`/`Decrypt` on structs (via `vitaminc-aead-derive`), including `#[aead(passthrough)]` to store chosen fields in the clear — passthrough values are unencrypted and **not authenticated**.
- `ContextTag` returns on the revised `Cipher`/`Decipher` traits, with `context`, `decrypt` and `decrypt_with_aad` helpers.
- Self-describing decryption: `decrypt_any` plus a typed passthrough channel re-homes unencrypted subtrees without knowing the plaintext type up front.
- `Element` wrapper for row-at-a-time sequence access — element order is a caller obligation, not an authenticated fact.
- Contexts must be non-empty, checked once at construction (`NonEmpty`); `Equatable` values encrypt directly; `Aad::for_leaf_type` binds the expected plaintext type on the decrypt side.

### Fixes

- Hostile input can no longer force quadratic scans or eager allocations during decode.
- A decipher without a passthrough channel now inherits a refusal instead of accepting values it cannot represent.

### Documentation

- The `#[aead(...)]` attribute reference is written once and inlined everywhere it applies; intra-doc links are fixed and gated in CI.


### Documentation

- rewrite READMEs for revised Cipher/Decipher traits
- rustdoc public items and link TODOs to tracking issues

### Features

- revised Cipher/Decipher traits with visitor pattern
- add encrypt_some/encrypt_none/passthrough
- add HList-based static cipher shape behind `hlist` feature

### Fixes

- enforce MapCipher key→value pairing; route u32 via array path
- address #175 review on the hlist static cipher

### Refactoring

- address PR #148 review feedback
- thread Protected<T> through cipher boundary
- thread Protected<T> through the hlist Cipher boundary

### Style

- cargo fmt


### Features

- add IntoAad impls for [u8; N] and &[u8; N]

### Testing

- assert None IntoAad produces PAE zero-piece encoding


### Documentation

- update doctests to show vitaminc::* import paths


### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- bump quickcheck from 1.0.3 to 1.1.0
- release v0.1.0-pre4.1


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

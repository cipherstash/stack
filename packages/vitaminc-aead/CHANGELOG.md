# Changelog

All notable changes to `vitaminc-aead` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.6.1] - 2026-10-18

### Fixes

- keep reads aligned, bound variant depth, and wipe buffers on error

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.
- **Breaking:** the encryption data model is replaced (ADR 0001). A type now describes itself once, by walking into a sink, and a cipher only seals and opens single leaves. For a caller upgrading from 0.5.1:
  - `Encrypt` keeps its name but is a new trait: `fn visit<S: Sink>(self, sink: S)` instead of `encrypt_with_aad(self, cipher, aad)`. Implement it for both `T` and `&T` (the derive does this for you). `Protected<T>` walks the value by reference and never moves it out.
  - `Decrypt<'c>` becomes `Decrypt` with no lifetime: it names a `Sink` that builds the type (`type Sink; fn sink()`). Single-scalar types implement `FromScalar` instead.
  - `Decipher`, `DecipherVisitor`, `SeqAccess`, `MapAccess`, `SeqCipher`, `MapCipher`, `Element` and `Passthrough` are removed. The old `Cipher` trait (eight methods with sequence and map sub-ciphers) becomes `Cipher` with `seal` and `open` over one leaf, plus `AsyncCipher` for a cipher that has to be awaited. Container rules (entry and element AAD, empty markers, duplicate keys) now live once in the crate, not in each cipher.
  - Call the free functions instead of trait methods: `encrypt(value, &cipher, aad)` and `decrypt::<T, _, _>(&cipher, node, aad)`, with `encrypt_async` and `decrypt_async` for an `AsyncCipher`, and `decrypt_into` to decrypt into any sink. Failures are `EncryptError` and `DecryptError` instead of `Unspecified`. A cipher's own failure comes back as `DecryptError::Cipher`, so a key service outage is not reported as tampering.
  - `CipherText::None` is removed: `None` encrypts as a null leaf, the same as a host `null`. A passthrough payload is now a `PassthroughFrame`, not a `Box<dyn Any + Send>`.
  - `ContextTag` no longer implements `Encrypt`. Use its `encrypt`, `encrypt_with_aad`, `decrypt` and `decrypt_with_aad` methods, or their `_async` forms. The AAD it binds is unchanged.
  - `Equatable<T>` is no longer a source or a target.
- **Breaking:** leaves are now sealed as wire version 2, and every leaf's plaintext starts with a type tag. 0.6.0 ciphertext does not decrypt under 0.5.x. A 0.5 leaf (version 1) is refused by default, not misread. What you can still open depends on how it was written:
  - Written through 0.5's `Encrypt` trait or derive: those leaves hold raw, untagged bytes and do not open under 0.6.0. Decrypt the data with 0.5 and encrypt it again with 0.6.
  - Written through the tagged 0.5 `Value` path (`vitaminc-aead-value`, `vitaminc-aead-napi` and the Go binding): those leaves open through `vitaminc-encrypt`'s `Aes256Cipher::opening_version_1`.

### Security

- Opening a leaf now wipes the working buffer when the cipher refuses it. A backend decrypts in place and checks the tag afterwards, so in 0.5.x a genuine ciphertext with a tampered tag left its plaintext in freed memory.

### Features

- More scalar types encrypt and decrypt: `bool`, every integer width except `u8` (8, 16, 32, 64 and 128 bits, signed and unsigned), `f32` and `f64`. Behind the new `chrono`, `rust_decimal` and `uuid` features: `NaiveDate`, `DateTime<Utc>`, `Decimal` and `Uuid`. A scalar is a physical kind (`Physical`, `Kind`) plus an optional logical type (`Logical`, `KnownLogical`) that says what it means. `u8` is left out so that `Vec<u8>` and `[u8; N]` stay byte strings.
- A logical type this build does not know is carried through encryption and decryption unchanged (`Logical::Unknown`).
- `Timestamp`, behind `chrono`: a UTC instant that cannot be a leap second, so a field of this type always encrypts. It encrypts to the same leaf as `DateTime<Utc>`. Its equality is constant time and it is wiped on drop.
- `#[derive(Encrypt, Decrypt)]` supports fieldless enums, `#[aead(skip)]`, `#[aead(take)]` and `#[aead(recursive)]`, and refuses at compile time a type nested too deep to encrypt.
- `EncryptError::Shape` says why a value was refused (`Unencryptable`) and where (`Refusal::path`). A value that could not be decrypted back, such as one nested deeper than `MAX_DEPTH`, is refused at encryption. `Display` shows only the reason, and `Debug` masks map keys.
- `Tee` feeds one walk to two sinks, for example to encrypt and compute index terms in one pass. The shape rules are public in `vitaminc_aead::shape`, so another sink refuses exactly what encryption refuses.
- Decrypt into `Protected<T>` containers (`Protected<Vec<T>>`, `Protected<Option<T>>` and nested forms) through `DecryptProtected`. A failure part way wipes what was already decoded.
- `AsyncCipher::seal_many` and `open_many` seal or open every leaf of a document in one call, for a key service with a batch API. A document with no leaves makes no cipher call.
- `Frame`, `FrameWriter` and `to_frame` carry a value as transport bytes, for host-language bindings.
- `LeafTypeAad`, moved here from `vitaminc-aead-value`, binds a column's expected physical kind and logical type into the AAD, under the domain `vitaminc/aead/leaf-type/v2`. Build it with `LeafTypeAad::physical`, `logical` or `unknown`. A ciphertext bound with 0.5's `vitaminc_aead_value::LeafTypeAad` does not open under it. The binding is opt-in, and it is a declaration both ends make: nothing checks it against the value being sealed.
- The new plaintext types (`Physical`, `Int`, `Float`, `Raw`, `Bytes`, `Frame`, `Timestamp`) and `ContextTag` redact their value in `Debug`. `Physical`, `Int`, `Float`, `Frame` and `Timestamp` compare in constant time.

### Documentation

- A sequence's order and length are not authenticated. Each element is bound to its sequence, not to its index, so elements can be reordered or dropped without a cipher failure. This was also true in 0.5. Put them in a map or in the AAD if you need that.

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

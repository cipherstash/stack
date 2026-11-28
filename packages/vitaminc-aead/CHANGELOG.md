# Changelog

All notable changes to `vitaminc-aead` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking

- This crate no longer has derives of its own (#2013).
  `#[derive(Encrypt)]` and `#[derive(Decrypt)]` are Stack Encrypt's.
  `vitaminc_aead::Encrypt` and `vitaminc_aead::Decrypt` are now the traits alone.
  Import the derives from `stack_encrypt` instead, as `stack_encrypt::{Decrypt, Encrypt}`.
  The attributes and the wire shape are the same.
  A crate that cannot depend on `stack-encrypt` can use `stack-encrypt-derive` with `#[aead(crate = "::vitaminc_aead")]` on each derived type, as this crate's own tests do.
- The hidden `plaintext::__private` module is gone.
  The items that the derived code names are in the hidden `__derive` module.
  `stack_encrypt::__derive` re-exports that module.
  Neither module is an API.

### Wire format

- A timestamp is always sealed in nanoseconds.
  `leaf::write_leaf` and the encrypting sink convert a timestamp in seconds, milliseconds or microseconds to the same instant in nanoseconds, under the `TIMESTAMP` tag.
  A typed null of a timestamp in any unit is sealed as a nanosecond timestamp's null, so it is as long as a value.
  A leaf sealed in another unit by an earlier version still decrypts.
- Transport frames are unchanged: a frame keeps the unit it was given.

### Added

- `plaintext::ValueKind`: what a value is, without the value, with the text name a schema spells it with (`"int32"`, `"timestamp"`, `"object"`, `"json"`, …).
  It covers every scalar, an array, an object and a JSON document.
  `ValueKind::Uuid` (`"uuid"`) is a UUID: `Logical::Uuid` over sixteen bytes. Its zero is sixteen zero bytes, its null is a typed null as long as a UUID leaf, and it holds only a UUID.
  It does not depend on the `uuid` feature, which gates only the conversions to and from `uuid::Uuid`.
  It differs from `Kind`, which is the physical storage of one scalar leaf alone.
  `ValueKind::of` gives the kind of a scalar (never `Json`: a document crosses as text or bytes), and `ValueKind::zero` a scalar of the kind.
  `ValueKind::holds` says whether a value of one kind is a value of a declared kind.
  `ValueKind::sealed_null` says how an absent value of the kind is sealed (`SealedNull`), so that it is as long as a present one.
  `ParseValueKindError` is the error from parsing a name.
- `leaf::sealed_null_type`, the type a typed null is sealed as.
- `frame::OwnedFrame` (also at the crate root): a `Buffer` that holds exactly one frame, wiped when it drops.
  It is for a value kept past the call that wrote it, and for what a ciphertext opens into.
  A value read only within a call is borrowed as a `Frame` instead.
  `OwnedFrame::of` writes any source as `to_frame` does, `from_buffer` keeps a `Buffer` a `FrameWriter` filled once `Frame::parse` accepts it, with no copy, and `null` and `typed_null` make a null.
  `frame` lends the frame as a `Frame`, and `into_buffer` hands the `Buffer` back.
  It is a source (`Encrypt`) that walks its bytes in place, and a decrypt target (`Decrypt`, through `frame::OwnedFrameSink`): a ciphertext opens into one buffer, its containers' children written in place, with no copy of any child.
  It has no `==`: compare two with `Frame`'s, which runs in constant time. `Debug` masks the bytes.
  `zeroize` wipes the bytes and leaves the plain null, so a zeroized frame is still one frame.
  No frame or sealed byte changes: an `OwnedFrame` holds the bytes `to_frame` writes.
- `Frame::kind`, `Frame::is_null` and `Frame::has_passthrough` read a frame in place, and `Frame::elements` lends a sequence's elements as `Frame`s, in order, through `frame::Elements`, with no copy.
  An element keeps the bytes it has in the sequence, so a typed null stays a typed null.
- `FrameWriter`, `FrameSeq` and `FrameMap` take a second type parameter, the error they report, which defaults to `FrameWriteError`.
  Code that names `FrameWriter<'_>` is unchanged.
  The decrypt sink of `OwnedFrame` writes through them, reporting `DecodeError`.
- `DecodeError` implements `From<FrameWriteError>`: a scalar its logical type does not admit is `DecodeError::Expected`, a source's failure is `DecodeError::Source`, and any other refusal is `DecodeError::Source` with the writer's error as its source.
- `#[derive(Encrypt)]` implements `Scalar`, by value and by reference, for two kinds of type.
  The first is a newtype whose inner type is a `Scalar`.
  The second is a fieldless enum.
  So `struct Email(String)` needs no `Scalar` impl of its own.
  A `Protected<Email>` is a `Scalar` too.
  `struct Tags(Vec<String>)` still derives `Encrypt`, but it is not a `Scalar`.
  A `Scalar` impl you wrote for such a type now conflicts with the derived impl, even when the inner type is not a `Scalar`.
  For a fieldless enum, or for a newtype whose inner type is a `Scalar`, delete your impl.
  When the inner type is not a `Scalar`, but you know that its value is one leaf, stop deriving `Encrypt`.
  Write `Encrypt` for the type and for its borrow by hand, with `const DEPTH: Option<usize> = depth::SCALAR;`, and keep your `Scalar` impl.
- The `Scalar` docs now say that a hand-written `Scalar` type must set `const DEPTH: Option<usize> = depth::SCALAR;`.
  A caller that checks `DEPTH` refuses a `Scalar` type whose `DEPTH` is the default `None`.

## [0.10.0] - 2026-11-19

### Wire format

- Sealed leaves and frames are written the same way as in 0.9.1.
  The supported range of dates and timestamps is narrower.
  The range is now years -9999 to 9999.
  Version 0.9.1 allowed years -262143 to 262142.
  The exact limits are the limits of the `jiff` crate:

  - dates from `-009999-01-01` to `9999-12-31`
  - timestamps from `-009999-01-02T01:59:59Z` to `9999-12-30T22:00:00.999999999Z`

- Version 0.10.0 decrypts every value that version 0.9.1 encrypted, except a date or timestamp outside the new range.
  A leaf like that still passes authentication.
  The reader then refuses it as an invalid scalar.
  Version 0.9.1 decrypts every value that version 0.10.0 encrypts.
- Encryption now refuses a date or timestamp outside the new range.
  Every binding uses the same range, so a value that one binding encrypts, every binding can decrypt.

### Breaking

- **Breaking:** dates and timestamps now come from the `jiff` crate, not `chrono`.
  RUSTSEC-2026-0543 marks `chrono` as unmaintained.
  To upgrade:

  - Enable the `jiff` feature in place of the `chrono` feature.
  - Encrypt and decrypt `jiff::civil::Date` in place of `chrono::NaiveDate`.
  - Encrypt and decrypt `jiff::Timestamp` in place of `chrono::DateTime<Utc>`.
  - Use the `plaintext::kinds::jiff` module in place of `plaintext::kinds::chrono`.

- **Breaking:** `Timestamp::new` now takes a `jiff::Timestamp`, and returns `Result<Timestamp, OutOfRange>`.
  `Timestamp::to_datetime` is renamed `to_jiff`, and returns a `jiff::Timestamp`.
  `jiff` has no leap seconds, so the `LeapSecond` error is removed.
  `OutOfRange` replaces it.
  `jiff` 1.0.0 can create an instant up to one second before its own minimum, when it parses text with a UTC offset.
  `Timestamp::new` refuses that instant, so a `Timestamp` still always encrypts.
  Encrypting a `jiff::Timestamp` directly refuses it as well.
- **Breaking:** `Sink::passthrough` now takes a reference, `&P`, where `P: ?Sized + EncryptRef`.
  In 0.9.1, it took `P` by value, where `P: Encrypt + Clone`.
  If you implement `Sink`, walk the passthrough value with `visit_ref`.
  If you call `passthrough`, pass a reference.
  A passthrough type no longer needs to implement `Clone`.
- **Breaking:** remove the bound `'a: 'r` from any `impl Encrypt for &'r Foo<'a>` that you wrote by hand.
  With that bound, the compiler cannot encrypt a `Foo` inside a `Vec`, `Option`, or map, unless `'a` is `'static`.

### Features

- The new `EncryptRef` trait lets generic code encrypt a value that it only borrows, without copying the value.
  Every type whose borrow implements `Encrypt` also implements `EncryptRef`.
  Bound a type parameter `T` on `EncryptRef` to accept a `&T`.
  In 0.9.1, the bound `for<'a> &'a T: Encrypt` failed to compile with error E0275, an overflow in the trait solver, when the compiler still had to infer `T`.
  So a caller that held a borrow had to clone the value.
- `EncryptRef::lend` returns the new `Lent` type, a borrowed value that you can encrypt.
  A `Vec`, `Option`, or derived struct of `Lent` values encrypts the same way as the values they borrow.
- The new `Date`, `Decimal`, and `Uuid` types protect a date, a decimal, and a UUID, as `Timestamp` protects an instant.
  The `jiff`, `rust_decimal`, and `uuid` features enable them.
  Each type:

  - wipes its value when it is dropped
  - hides its value in `Debug` output
  - compares in constant time
  - does not implement `Copy` or `Clone`

  Each type encrypts to the same leaf as the type it wraps.
  So you can change a field to the new type without changing its ciphertext.
  Creating one from `jiff::civil::Date`, `rust_decimal::Decimal`, or `uuid::Uuid` cannot fail.

- The new `Decimal` type keeps its scale, so `1.50` stays `1.50`.
  Two `Decimal` values compare by value, as `rust_decimal` compares them: `1.5` equals `1.50`.
  The comparison uses no division instruction.
  On wasm32, and in builds without optimisation, the time a division takes can depend on the values it divides.

### Performance

- Encrypting a passthrough field no longer copies its frame a second time.

## [0.9.1] - 2026-11-06

### Wire format

- Sealed leaves and frames are the same as in 0.9.0.
  Version 0.9.1 decrypts data that version 0.9.0 encrypted, and the other way round.

### Features

- You can now encrypt the bytes in a `vitaminc_protected::Buffer` without reading them first.
  A `Buffer` lends a `ProtectedRef<[u8]>`. That borrow seals as a byte leaf.
  A `Protected<Vec<u8>>` or `Protected<[u8; N]>` reaches the same leaf through the new `ProtectedRef::as_deref` and `ProtectedRef::as_ref_of` methods.
  The 0.9.1 changelog for `vitaminc-protected` has the details.

## [0.9.0] - 2026-11-04

### Wire format

- Sealed leaves and frames are the same as in 0.8.1.
  Version 0.9.0 decrypts data that version 0.8.1 encrypted, and the other way round.

### Breaking

- **Breaking:** `to_frame` and `decrypt_to_frame` now return a `vitaminc_protected::Buffer`, not `Protected<Vec<u8>>`.
  `FrameWriter::new` now takes `&mut Buffer`, not `&mut Vec<u8>`.
  To read the bytes in a `Buffer`, call `Controlled::risky_ref`.
  To take the `Vec<u8>` out of it, call `Controlled::risky_unwrap`.
- **Breaking:** when you lend a `&str` or `Cow<str>` through `as_protected_ref()`, you now need to name the target type.
  Name `str` to seal the string as text, or `[u8]` to seal the string as bytes.
  In 0.8.1, a string could be sealed as bytes by mistake, and then fail to decrypt as a `String`.
  The 0.9.0 changelog for `vitaminc-protected` has the details.
- **Breaking:** the crate now needs Rust 1.89 or later.
  Version 0.8.1 needed Rust 1.88.

### Features

- The new `Scalar` trait marks an `Encrypt` source that seals as exactly one leaf.
  Generic code can require `Scalar` to accept only single values, and the compiler checks the requirement.
  A bound on `DEPTH` cannot do this, because stable Rust cannot bound a generic type on a constant.
  These types implement `Scalar`:

  - every built-in leaf type except `u8`
  - the borrowed, `Protected`, and `ProtectedRef` forms of those types
  - `Timestamp`
  - the chrono, `rust_decimal`, and uuid types, behind their features

  `Option<T>` does not implement `Scalar`, because a caller that asks for a scalar expects a value to be present.
  You can implement `Scalar` for your own type that wraps one leaf.
  The function `depth::is_scalar` checks a `DEPTH` value at compile time.
- You can now encrypt a `ProtectedRef` or a `&ProtectedRef` directly.
  The value seals exactly as the `&Protected` it borrows from.
  A derived struct can now contain `ProtectedRef` fields.

### Fixes

- In debug builds, writing a leaf into a `Vec<u8>` without enough spare capacity now panics.
  A `Vec` that grows frees its old memory without wiping it.
  The old memory contains plaintext.
  To avoid the panic, size the `Vec` with `leaf::max_len` before you write to it.
  Release builds do not run this check.
- Two code paths no longer leave plaintext in memory that is not wiped:

  - The check for a repeated map key now reads the key where it lies in the frame.
    In 0.8.1, the check copied the key out, and freed the copy without wiping it.
  - The `Int` and `TimeUnit` helpers are now inlined into their callers.
    Callers in other crates, such as `vitaminc-normalize`, no longer receive plaintext through a stack slot that is not wiped.

### Performance

- The frame validator no longer allocates a hash set for an object with 16 keys or fewer.
  Measurements for this change showed record reads 18% faster in the storage format.
  Record reads in the transport format were 23% faster.
- Frame writers now wipe outgrown buffers 16 bytes at a time, not 1 byte at a time.

### What is not authenticated

- Encryption does not authenticate which entries a map contains.
  Encryption also does not authenticate the order or length of a sequence.
  Architecture decision record (ADR) 0002 records this design decision.
  The behavior is the same as in 0.8.1.
  If an entry is removed from a map, the remaining leaves still decrypt.
  If the decrypt target needs the missing entry, the target reports a shape mismatch, not an authentication failure.
  Each leaf is still bound to its context, key, role, type, and wire version.
  An empty map or sequence is sealed as an authenticated marker.
  A container with entries can lose some of them.
  If every entry is removed, decryption fails.

## [0.8.1] - 2026-10-26

### Features

- `tags::STORAGE_SOME` (`0xF5`) and `tags::STORAGE_MAP` (`0xF6`) name the two bytes the storage profile in `vitaminc-aead-frame` uses. Neither is a leaf or frame tag: `Frame::parse` refuses both, as it did in 0.8.0, and no sealed leaf or frame changes.

## [0.8.0] - 2026-10-21

Ciphertexts written by 0.7 still decrypt: the one-byte null it wrote for a `None` opens as `None` as before. The reverse does not hold. A `None` of a fixed-width type now seals as a new kind of leaf, which a 0.7 reader refuses, so upgrade readers before writers.

### Breaking

- **Breaking:** A `None` of a fixed-width type (an integer, a float, a date, a timestamp, a decimal, a uuid) seals as a typed null, padded to the length of a `Some` of the type. AES-GCM keeps the plaintext's length, and a one-byte null stood in for a value of up to seventeen, so anyone holding the ciphertexts could list the absent rows of a column without a key. A typed null is the new `TYPED_NULL` tag, the header a value of the type starts with, then zero padding; it opens only as `None` of an `Option` of a type that reads values of that type, so a widened field (`u32` to `u64`, `f32` to `f64`) reads its old `None`s as it reads its old values, and any other target refuses it as the wrong kind. A `None` of a bool, text or bytes still seals as the one-byte null, since those types have no fixed length to pad to.
- **Breaking:** `Sink` has a new required method, `typed_null`. A sink that only needs to know a value is absent treats it as a null. A sink that forwards to other sinks must forward it as it is, or the padding is lost and absent values show again.
- **Breaking:** `Encrypt` gains a `FIXED` constant, the type's fixed width if it has one, and `Decrypt` gains `reads_null`, which says whether an `Option` of the type reads a given typed null as `None`. Both have defaults, so existing impls compile. A hand-written scalar type sets `FromScalar::FIXED` only if it refuses zero, such as a fieldless enum with no variant at zero, so that its own `None` reads back.

### Not guaranteed

- Padding belongs to the sealed leaf, not to a frame. A frame is never sealed, so every frame this crate writes (`decrypt_to_frame`, `to_frame`, a passthrough subtree) carries the plain one-byte null, and a frame a host sends may carry either.

## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

### Features

- `FrameWriter::at_depth` and `FrameWriter::depth`, for writing a subtree to a buffer of its own while `MAX_DEPTH` still counts from the top of the document.

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

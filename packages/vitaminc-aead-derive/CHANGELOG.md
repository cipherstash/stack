
## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.
- **Breaking:** `#[derive(Encrypt)]` and `#[derive(Decrypt)]` keep their names but generate `vitaminc-aead` 0.6's sink-based traits (ADR 0001), and need `vitaminc-aead` 0.6. `Encrypt` is generated for both `T` and `&T`. Code that called the generated impls directly must move to the 0.6 entry points (`encrypt`, `decrypt`). Types derived with 0.5 produce ciphertext that 0.6 does not open; see `vitaminc-aead`.
- **Breaking:** a `#[aead(passthrough)]` field's type must now implement `Encrypt + Clone` on the way in and `Decrypt` on the way out, instead of `Any + Send + 'static`. Borrowed types such as `&'a str` are now allowed.
- **Breaking:** a field's type must be at least as visible as the struct, because the generated decrypt sink names it in a public type. Otherwise the derive fails with E0446. A type that should stay private can be declared `pub` inside a private module.

### Features

- A fieldless enum can be derived. It encrypts as one `u32` leaf holding the variant's discriminant, so every variant has the same ciphertext length. Data-carrying enums are still refused.
- `#[aead(skip)]` leaves a field out and rebuilds it with `Default` on decryption. `#[aead(take)]` moves a field out with `mem::take`, so a `ZeroizeOnDrop` type can derive.
- A derived type nested deeper than `MAX_DEPTH` fails to compile, so it is never refused as too deep at runtime unless it is recursive. Mark mutually recursive types with `#[aead(recursive)]`, or rustc reports a const-evaluation cycle (E0391).

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

First release.

### Features

- `#[derive(Encrypt, Decrypt)]` encrypts structs field by field with no hand-written impls.
- `#[aead(passthrough)]` stores chosen fields in the clear — those fields are unencrypted and **not authenticated**.

### Documentation

- The `#[aead(...)]` attribute reference is written once and inlined everywhere it applies.

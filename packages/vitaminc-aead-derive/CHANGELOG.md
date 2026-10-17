
## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** raise the MSRV to 1.88 and pin kms to the AWS SDK floor
- **Breaking:** walk Protected<T> by reference and retire visit_protected
- **Breaking:** remove Encrypt, Decipher, DecipherVisitor, SeqAccess and MapAccess
- **Breaking:** name the source trait Encrypt so it pairs with Decrypt

### Features

- derive Plaintext and the sink-based Decrypt
- refuse derived types too deep to encrypt at compile time

### Fixes

- accept u32::MAX as an enum's last discriminant
- give ContextTag its async methods and say what the walk authenticates
- check the borrowed impl's depth at compile time for non-generic types
- check lifetime-only types and same-named path fields at compile time

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

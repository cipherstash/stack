
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

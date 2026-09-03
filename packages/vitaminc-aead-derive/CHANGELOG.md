
## [0.2.0] - 2026-09-03

### Documentation

- write the `#[aead(...)]` reference once and inline it everywhere

### Features

- derive Encrypt and Decrypt so structs need no hand-written impls
- store chosen fields in the clear with #[aead(passthrough)]

### Fixes

- close the derive's three review findings and pin the guards with trybuild

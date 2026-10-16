
## [0.5.1] - 2026-10-05

### Features

- name an FfiValue's kind without a value

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

### Features

- `LeafTypeAad` names its parts

## [0.2.0] - 2026-09-03

First release.

### Features

- Language-neutral, self-describing `FfiValue` tree — null, booleans, a full numeric family (including `INT64`/`UINT64`), UTF-8 strings, bytes, arrays and maps — for encrypting dynamically typed FFI values with the vitaminc AEAD traits.
- Unencrypted subtrees travel via `FfiValue::Passthrough`, framed in the transport codec; the Go bindings and the wasm guest share the same tag table.
- Ciphertext leaves carry the authenticated wire-version byte, and empty-composite markers survive the transport round-trip.
- Transport decoders reject duplicate keys, and hostile input cannot force quadratic scans or eager allocations.

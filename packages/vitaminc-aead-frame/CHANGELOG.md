
## [0.6.1] - 2026-10-18

### Documentation

- say that expecting text is printed and that a container length is checked

### Features

- serde over the transport frame, for data that is not plaintext

### Fixes

- keep an unknown key off the error path, so it is never printed
- never print an unknown variant, and read a bare variant as a null payload
- keep reads aligned, bound variant depth, and wipe buffers on error
- never put a key a host chose on an error's path
- read each kind only as itself, so a struct is never an array and text is never bytes
- refuse a map key out of turn, so a read stays aligned and a written key is never lost

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.
- **Breaking:** `vitaminc-aead-value` is renamed `vitaminc-aead-frame` and holds only the transport: the frame for values and the codec for ciphertext trees. `vitaminc-aead-value` gets no further release; 0.5.1 is its last version. Change the dependency to `vitaminc-aead-frame = "0.6"`. What moved where:
  - `FfiValue`, `Utf8String`, `ValueKind`, `ParseValueKindError`, the `tagged` module, `encode_value` and `decode_value` are deleted, per ADR 0001. A host binding no longer converts to a Rust value tree: it implements `vitaminc_aead::Encrypt` for values coming in and `Sink` for values going out. For a value as bytes, use `Frame::parse`, `FrameWriter` and `to_frame`, which live in `vitaminc-aead` and are re-exported here.
  - `LeafTypeAad` moves to `vitaminc_aead::LeafTypeAad`. `LeafTypeAad::new(base, tag)` becomes `LeafTypeAad::physical(base, kind)`, `logical(base, known_logical)` or `unknown(base, kind, id)`, and binds under a new domain, so a ciphertext bound with the 0.5 type does not open under the new one.
  - `tags` is now a re-export of `vitaminc_aead::tags`. `ARRAY`, `OBJECT`, `PASSTHROUGH` and `MAX_DEPTH` are re-exported from `vitaminc_aead::frame`.
  - `encode_ciphertext` takes a `&Node<Leaf>`, whose passthrough payloads are `PassthroughFrame`s. `decode_ciphertext` takes the bytes directly instead of a `Reader`, and refuses trailing bytes. `encode_ciphertext_boxed`, `decode_ciphertext_boxed`, `Reader` and `TransportPassthrough` are removed.
- **Breaking:** the value frame's container tags move from `0x10`, `0x11` and `0x12` to `0xF0`, `0xF1` and `0xF2` (`0x10` and `0x11` are now the `INT128` and `UINT128` leaf tags). A frame holding an array, an object or a passthrough is not read correctly across versions, so hosts and guests must upgrade together. Scalar tags `0x00` to `0x0B` are unchanged.
- **Breaking:** the encoded ciphertext tree keeps its node tags, except that the `None` node (`0x02`) is retired: it is never written and is refused on read, since `None` is now a null leaf. An encoded ciphertext from 0.5.1 still decodes, and its leaves, which were sealed on the tagged `Value` path, open only through `vitaminc-encrypt`'s `Aes256Cipher::opening_version_1`. Leaves written by 0.6 are wire version 2 and do not open under 0.5.x.

### Features

- The frame and the codec carry every scalar `vitaminc-aead` 0.6 has: 8-, 16- and 128-bit integers, dates, timestamps, decimals and UUIDs, plus the `0xF3` envelope that carries a logical type this build does not know unchanged.
- `CodecError` implements `Display` and `std::error::Error`.

### Fixes

- `encode_ciphertext` refuses a tree the decoder would refuse, and then leaves the output untouched: duplicate map keys, a tree deeper than `MAX_DEPTH`, and a passthrough payload that is not exactly one frame node. In 0.5.1 such a tree was written and only refused when it was read back.

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

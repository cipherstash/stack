
## [0.8.1] - 2026-10-26

Nothing 0.8.0 wrote or read changes: the transport frame, the transport serde format and the ciphertext codec write the same bytes, and existing ciphertexts are unaffected.

### Features

- A storage profile, `vitaminc_aead_frame::storage` (feature `serde`), for serialized values that are kept, such as the plaintext of a sealed value. `storage::to_vec` writes any `Serialize` type as a versioned blob and `storage::from_slice` reads one back into any `Deserialize` type. Unlike the rest of the crate, its bytes are a compatibility commitment: version 1 is specified in `STORAGE.md`, frozen, and pinned by the golden corpus in `testdata/storage-v1.json`, so a blob this release writes reads the same in every later release. The commitment covers `to_vec`, `from_slice`, `HEADER`, `MAGIC`, `VERSION`, `SOME`, `MAP` and `ErrorKind`; the transport frame, the transport serde format and the ciphertext codec may still change in any release. A blob is not a transport frame, and neither reads as the other. `STORAGE.md` also says why the profile is used for sealed values rather than MessagePack or Borsh.
- The profile keeps what the transport format loses at rest. A `Some` is marked, so `None`, `Some(())` and `Some(None)` are three blobs, and an option inside an untagged, internally tagged or flattened type survives serde's buffering. A serde map's keys may be integers, text or bytes, and each keeps its kind. Only plain scalars are admitted: a logical type, `undefined` and a passthrough are refused.
- `storage::to_vec` returns the blob as `Protected<Vec<u8>>`, since it is plaintext: the buffer is wiped as it grows and when it is dropped.
- Every refusal has a stable class, `storage::Error::kind`: `NotABlob`, `UnsupportedVersion` (the reader needs upgrading; the blob is not corrupt), `Malformed`, `Mismatch` and `Unwritable`. As with the transport format, an error never contains a value.
- Blobs are not canonical, by design. Equal values of different types write different bytes (`1u8` and `1u32`), NaN payloads are kept, and a reader accepts forms a writer does not produce. Compare values, not blobs.

### Fixes

- The transport serde format reads a map key that is a newtype around a string back into its type. A `BTreeMap<Id, _>` with `struct Id(String)` was written but failed to read, with "expected tuple struct Id, found a string". The bytes written are unchanged.

## [0.8.0] - 2026-10-21

The `serde` format refuses a typed null (`vitaminc-aead` 0.8.0) as malformed wherever it appears, an `Option` included, and never writes one. A typed null is how plaintext hides the length of an absent fixed-width value once sealed, which is no concern of data that is not sealed. The frame's bytes are otherwise unchanged.

## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

### Features

- A serde data format over the frame, behind the new `serde` feature. `vitaminc_aead_frame::serde::from_slice` and `from_frame` read any `Deserialize` type from frame bytes, and `to_vec` writes any `Serialize` type as frame bytes. Use it for data a host exchanges with Rust that is not plaintext to seal, such as a call's options or a result; plaintext still crosses as a frame walked into a sink. The frame's bytes are unchanged, so hosts need no changes and existing ciphertexts are unaffected.
- The mapping keeps what a frame carries: integers read at their exact width, text and bytes are borrowed from the input, and enums are externally tagged (a unit variant is its name, any other variant an object of one entry). A scalar with a logical type and a passthrough are refused, except JavaScript's `undefined`, which reads as null.
- An `Error` never contains a value. It names the kind of value found and the path to it (`Error::path`, `Error::field`), and drops a type's own message, such as one from a `try_from` or `serialize_with` check, since it may print the value it refused. A type's `expecting` text is kept, so a hand-written one must not include a value. A map key that is data, or a key or variant name the type does not declare, never appears in an error; such an entry is placed by position.
- Reading is strict. The whole frame is validated before serde sees it, so a malformed frame or a repeated key is refused up front. A container must be read to its end, each kind reads only as itself (a struct never from an array, text never as bytes), and a map key out of turn is refused, so a type that stops early cannot misread what follows. Writing refuses a value nested past `MAX_DEPTH` instead of overflowing the stack, and wipes its buffers if it fails part way.

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

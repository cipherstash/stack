# vitaminc-aead-frame

The transport for carrying Vitamin-C AEAD values and ciphertexts across an
FFI boundary in one linear-memory copy: the frame for values, and the
ciphertext codec for the trees `encrypt` produces.

A host binding does not convert its values into a Rust value tree. It
implements [`Encrypt`] for values coming in and [`Sink`] for values going
out. A frame represents a value independently of the host language:

- [`Frame`] is a validated, borrowed frame. `Frame::parse` checks the
  whole buffer up front, and the frame then implements `Encrypt` by
  walking its own bytes in place, so no value tree is built and no scalar
  leaves the buffer except to go straight to a sink.
- [`FrameWriter`] is a `Sink` that writes frame bytes, and [`to_frame`]
  walks any `Encrypt` into one. The Node binding snapshots a JavaScript
  value this way to encrypt it off the JavaScript thread.
- [`PassthroughFrame`] is an owned frame: the payload a ciphertext carries
  for a passthrough subtree, in every binding and in static Rust.

These live in `vitaminc-aead`, next to the leaf codec they share with the
sealed leaf format, and are re-exported here.

The ciphertext codec, [`encode_ciphertext`] and [`decode_ciphertext`],
carries a [`CipherText`] tree whose passthrough payloads are frames. The
Go guest uses it in both directions.

```rust
use vitaminc_aead::{CipherText, Node};
use vitaminc_aead_frame::{decode_ciphertext, encode_ciphertext};

let tree: Node<Vec<u8>> = CipherText::Single(vec![0xAB; 16]);
let mut bytes = Vec::new();
encode_ciphertext(&tree, &mut bytes).expect("encodes");

let back: Node<Vec<u8>> = decode_ciphertext(&bytes).expect("decodes");
let mut again = Vec::new();
encode_ciphertext(&back, &mut again).expect("encodes");
assert_eq!(again, bytes);
```

## Installation

```sh
cargo add vitaminc-aead-frame
```

## Transport, and one storage profile

The frame, the ciphertext codec and the serde format in `serde` are
transport: nothing about them is a compatibility commitment, since hosts
and guests ship together. The one exception is the storage profile,
`storage::to_vec` and `storage::from_slice` (feature `serde`), which
write and read a value as a versioned blob for bytes that are kept. Its
format is specified in [STORAGE.md](https://github.com/cipherstash/vitaminc/blob/main/packages/aead-frame/STORAGE.md) and frozen at version 1. Use this storage profile for bytes
that outlive the process that wrote them. The other frozen format in the
stack is the sealed leaf payload (`[tag] ++ payload`, the tag table in
[`tags`]), which lives inside the AEAD envelope and never touches this
codec.

A value frame is one node: a scalar in its leaf encoding, with text and
bytes carrying a `u32` length, or a container. The framing tags `0xF0`
(array), `0xF1` (object) and `0xF2` (passthrough) sit above the scalar
tags, and `0xF3` is the envelope for a logical type with no shorthand tag.
A ciphertext node is one byte of kind (`CT_SINGLE`, `CT_SEQ`, `CT_MAP`,
`CT_PASSTHROUGH`, `CT_EMPTY_SEQ`, `CT_EMPTY_MAP`), then a sealed leaf as
length and bytes, a container as count and children, or a passthrough as
the frame of its subtree. All lengths and counts are `u32` little-endian;
map keys are UTF-8. The retired absence marker `0x02` (`CT_NONE`) is
never written and is rejected when read. `None` is encoded as a null leaf.

## serde (feature `serde`)

`vitaminc_aead_frame::serde` is a serde data format over the frame:
`from_slice` reads any `Deserialize` type from frame bytes and `to_vec` writes
any `Serialize` type as frame bytes. It is for data a host exchanges with
Rust that is not plaintext to seal, such as a call's options or a result.
Plaintext still crosses as a frame walked into a sink.

The mapping keeps what a frame carries: an integer reads at its exact width
through `deserialize_any`, text and bytes are borrowed from the input, and
the format is not human readable, so a type with a binary form (a UUID) uses
it. Enums are externally tagged: a unit variant is its name, any other
variant an object of one entry. A scalar with a logical type and a
passthrough are refused, except JavaScript's `undefined`, which reads as
null. An error names the kind of value it found and the path to it, never
the value, and drops a type's own message (from a `try_from` check, say),
which may print it. A type's `expecting` text is kept, so a hand-written one
must not include a value. The path names only the fields and variants a type
declares; an entry whose key is data, such as a map's, is placed by
position.

## Storage profile (feature `serde`)

`storage::to_vec` writes any `Serialize` type as a blob: the header
`"VCS"` and a version byte, then the value as a node. It differs from the
transport format in four ways. A `Some` is marked (`0xF5`, then its
value), so `None`, `Some(())` and `Some(None)` are three blobs, and an
option inside an untagged, internally tagged or flattened type survives
serde's buffering. A serde map is a node of its own (`0xF6`) whose keys
are nodes, so an integer, text or bytes key keeps its kind. Only the plain
scalars are admitted: no logical types, no `undefined`, no passthrough.
And every refusal has a stable `ErrorKind`, so a caller can tell a reader
that needs upgrading from a corrupt blob. The blob is plaintext, so it
comes back in a `Buffer`: read through `risky_ref`, wiped when dropped.

```rust
# #[cfg(feature = "serde")]
# {
use vitaminc_aead_frame::storage;
use vitaminc_protected::Controlled;

let blob = storage::to_vec(&Some(Option::<u8>::None)).expect("writes");
assert_eq!(blob.risky_ref().as_slice(), &[0x56, 0x43, 0x53, 0x01, 0xF5, 0x00]);
let back: Option<Option<u8>> = storage::from_slice(blob.risky_ref()).expect("reads");
assert_eq!(back, Some(None));
# }
```

## Hardening

Both directions are attacker-reachable input. Nesting is bounded at
[`MAX_DEPTH`] (128), counted across a ciphertext tree and the frame
payload behind a passthrough as one structure. A count or length is
checked against the bytes remaining before anything is reserved, and the
eager part of a reservation is clamped so a megabyte of hostile bytes
cannot pin gigabytes. Duplicate map keys are refused, as the frame
refuses them. Errors are opaque ([`CodecError`], [`FrameError`]): they
carry no detail about the bytes.

## Performance

The storage profile and the transport serde format were measured against `serde_json`, MessagePack (`rmp_serde`) and Borsh, writing and reading five values with Criterion.

MessagePack is written with field names (`rmp_serde::to_vec_named`), since the storage profile, the transport format and JSON all carry them. Borsh carries no field names and no kinds, only the values in order, so it shows what a format costs that carries nothing else. The storage profile and the transport format wipe their buffers as they grow and when they are dropped. The other three wipe nothing: they write into a plain `Vec<u8>`, so each time the buffer grows the old one is freed with its bytes still in it, and the result is freed unwiped when it is dropped. Wrapping their output in `Zeroizing` would cover only the drop, not the copies left as the buffer grows.

These results are from an Apple M4 (4 performance and 6 efficiency cores, 24 GB) on macOS 26.5 with rustc 1.98.1, on 2026-10-26, using Criterion's default settings. Each time is the median of 100 samples. A write includes dropping the result.

The record is an integer id, a name, an email, a flag, a float, a list of two tags and an optional integer.

Size of the bytes written:

| Value | Storage | Transport | JSON | MessagePack | Borsh |
| --- | --- | --- | --- | --- | --- |
| One record of 7 fields | 164 B | 159 B | 126 B | 98 B | 86 B |
| 1,000 records | 160 KB | 159 KB | 132 KB | 102 KB | 86 KB |
| Map of 1,000 text keys | 22.0 KB | 21.0 KB | 14.9 KB | 11.6 KB | 20.0 KB |
| 64 KiB of text | 65.5 KB | 65.5 KB | 65.5 KB | 65.5 KB | 65.5 KB |
| 64 KiB of bytes | 65.5 KB | 65.5 KB | 234 KB | 65.5 KB | 65.5 KB |

Time to write:

| Value | Storage | Transport | JSON | MessagePack | Borsh |
| --- | --- | --- | --- | --- | --- |
| One record of 7 fields | 986 ns | 1.09 µs | 198 ns | 337 ns | 72 ns |
| 1,000 records | 937 µs | 741 µs | 217 µs | 139 µs | 30.3 µs |
| Map of 1,000 text keys | 115 µs | 80.0 µs | 18.0 µs | 13.6 µs | 6.21 µs |
| 64 KiB of text | 35.5 µs | 33.8 µs | 33.8 µs | 1.93 µs | 2.03 µs |
| 64 KiB of bytes | 33.7 µs | 33.7 µs | 280 µs | 1.87 µs | 1.99 µs |

Time to read:

| Value | Storage | Transport | JSON | MessagePack | Borsh |
| --- | --- | --- | --- | --- | --- |
| One record of 7 fields | 1.35 µs | 1.41 µs | 440 ns | 313 ns | 196 ns |
| 1,000 records | 1.48 ms | 1.47 ms | 489 µs | 467 µs | 230 µs |
| Map of 1,000 text keys | 268 µs | 303 µs | 216 µs | 202 µs | 85.4 µs |
| 64 KiB of text | 8.48 µs | 8.49 µs | 11.6 µs | 4.14 µs | 6.16 µs |
| 64 KiB of bytes | 1.91 µs | 1.99 µs | 881 µs | 1.88 µs | 2.85 µs |

Most results held within a few percent of their median. Two did not: the MessagePack read of 1,000 records ranged from 387 to 567 µs, and the transport write of 1,000 records from 724 to 773 µs.

What the numbers show:

- Writing a large value is limited by the wipe, not by the format. MessagePack and Borsh write 64 KiB in about 2 µs; the storage profile takes 33.7 µs, and wiping the 64 KiB buffer is 31.5 µs of that, because `zeroize` wipes one byte at a time with volatile stores, so the compiler cannot remove the wipe. The transport format has the same cost. JSON writes no wipe, but writes bytes as a list of numbers, 3.6 times as large and 8 times as slow.
- Reading text or bytes costs little more than copying them out: 64 KiB of bytes reads at about 32 GiB/s, as fast as MessagePack.
- On values with many small parts, the storage profile is the slowest of the five. It writes 1,000 records 6.7 times as slowly as MessagePack and 31 times as slowly as Borsh, and reads them 3.2 and 6.4 times as slowly. MessagePack carries the same field names, so the names are not the cost; each element or field costs the storage writer about 40 to 90 ns more.
- The storage profile is also the largest: 1,000 records take 57% more bytes than in MessagePack, and the map 89% more. Every length and count is a fixed four bytes and every value has a kind byte, where MessagePack packs small lengths and integers into one byte. Borsh is the smallest for records, but writes an integer at its full width, so the map of `u64` values is nearly as large as in the storage profile.
- The tables predate a change to the storage writer. It used to read the whole blob back before returning it, to find a repeated key, and that pass was 55% of a 1,000-record write. It now refuses a repeated field name as it writes, comparing the names an object has written on the stack, and checks a map's keys where they lie in the blob when the map ends. Measured against the tables' code on the same machine, that made a 1,000-record write 47% faster, a single record 41% faster and the map 28% faster, and left reads unchanged. The tables will be re-measured before this is released.

## Cargo features

No optional features are enabled by default.

| Feature | Effect |
| --- | --- |
| `serde` | Exposes `serde` transport conversion and the versioned `storage` profile; adds Serde and protected-buffer dependencies. |

## Compatibility

Requires Rust <!-- msrv:vitaminc-aead-frame -->**1.88.0**<!-- /msrv --> and the Rust standard library (`std`).
MSRV increases require a minor release; patch releases retain the existing
floor. See the [workspace compatibility policy](https://github.com/cipherstash/vitaminc#compatibility).

License: MIT.

<!-- GitHub API links target the latest release; src/lib.rs resolves these for rustdoc. -->
[`CipherText`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/enum.CipherText.html
[`CodecError`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/transport/struct.CodecError.html
[`Encrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Encrypt.html
[`FrameError`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/struct.FrameError.html
[`FrameWriter`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/struct.FrameWriter.html
[`Frame`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/struct.Frame.html
[`MAX_DEPTH`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/constant.MAX_DEPTH.html
[`PassthroughFrame`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/struct.PassthroughFrame.html
[`Sink`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Sink.html
[`decode_ciphertext`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/transport/fn.decode_ciphertext.html
[`encode_ciphertext`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/transport/fn.encode_ciphertext.html
[`tags`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/tags/index.html
[`to_frame`]: https://docs.rs/vitaminc-aead-frame/latest/vitaminc_aead_frame/fn.to_frame.html

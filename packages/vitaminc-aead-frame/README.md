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

## Why the storage profile

On small values it is slower and larger than MessagePack and Borsh (see [Performance](#performance)). It is used for what they do not do:

- ✅ [Strict zeroization](#strict-zeroization)
- ✅ [Defensive by design](#defensive-by-design)
- ✅ [Self-describing](#self-describing)
- ✅ [Versioned and proved](#versioned-and-proved)

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

### Strict zeroization

A blob comes back in a `Buffer`, wiped sixteen bytes at a time as it grows and when it is dropped, and read through `risky_ref`. MessagePack and Borsh write into a plain `Vec<u8>`, which frees the old allocation unwiped each time it grows, and frees the result unwiped when it is dropped.

### Defensive by design

The reader treats every blob as hostile until it has proved otherwise. `storage::from_slice` walks the whole blob against the format first, building nothing, and either refuses it whole or walks it again to build the value. MessagePack and Borsh build as they read. That order buys four things:

- **A refusal builds nothing.** A malformed blob never has its contents copied into a half-built value and freed, and never gets an allocation from a forged length or count.
- **Corrupt is told apart from wrong type.** A blob that passes is well formed, so a refusal on the second walk is the type's. The stable refusal kinds rest on this: a caller can tell tampering or corruption from a reader that is too old.
- **One walker to prove and to port.** The validator is independent of any type, so it is what the Kani proofs cover, what the golden corpus pins, and what a reader in another language must match. Two readers that accept different blobs are a vulnerability class of their own.
- **Document rules hold before anything is committed.** A repeated key, the nesting bound and every length against the end of the blob are checked for the whole document, so a blob means one thing or is refused, and no entry is silently replaced by a later one.

The bounds are under [Hardening](#hardening).

### Self-describing

Every node carries its kind. An integer carries its width, where MessagePack packs a `u64` of 42 into one byte and a reader cannot tell what it was. `None`, `Some(())` and `Some(None)` are three blobs, where MessagePack writes all three as `nil`. A map key keeps its kind. Borsh carries only the values in order, so a blob cannot be checked, or even walked, without the type that wrote it.

### Versioned and proved

The header names the version, [STORAGE.md](https://github.com/cipherstash/vitaminc/blob/main/packages/aead-frame/STORAGE.md) specifies version 1, a golden corpus pins it, the validator has Kani proofs, and a refusal has a stable kind, so a reader can tell a blob it is too old to read from a corrupt one. Neither MessagePack nor Borsh carries a version.

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

The storage profile is neither the fastest nor the smallest format in the tables below, and is not meant to be: what it is for is under [Why the storage profile](#why-the-storage-profile). The benches put a price on those properties.

The storage profile and the transport serde format were measured against `serde_json`, MessagePack (`rmp_serde`) and Borsh, writing and reading five values with Criterion.

MessagePack is written with field names (`rmp_serde::to_vec_named`), since the storage profile, the transport format and JSON all carry them. Borsh carries no field names and no kinds, only the values in order, so it shows what a format costs that carries nothing else. The storage profile and the transport format wipe their buffers as they grow and when they are dropped. The other three wipe nothing: they write into a plain `Vec<u8>`, so each time the buffer grows the old one is freed with its bytes still in it, and the result is freed unwiped when it is dropped. Wrapping their output in `Zeroizing` would cover only the drop, not the copies left as the buffer grows.

These results are from an Apple M4 (4 performance and 6 efficiency cores, 24 GB) on macOS 26.5 with rustc 1.98.1, on 2026-10-29, on mains power, using Criterion's default settings. The bench was run three times, and each time is the median of the three runs' medians of 100 samples. A write includes dropping the result.

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
| One record of 7 fields | 215 ns | 245 ns | 108 ns | 189 ns | 35 ns |
| 1,000 records | 141 µs | 139 µs | 111 µs | 70.2 µs | 15.4 µs |
| Map of 1,000 text keys | 28.8 µs | 16.5 µs | 9.77 µs | 7.15 µs | 3.21 µs |
| 64 KiB of text | 1.92 µs | 1.89 µs | 17.8 µs | 1.11 µs | 1.17 µs |
| 64 KiB of bytes | 1.93 µs | 1.90 µs | 145 µs | 1.10 µs | 1.16 µs |

Time to read:

| Value | Storage | Transport | JSON | MessagePack | Borsh |
| --- | --- | --- | --- | --- | --- |
| One record of 7 fields | 488 ns | 472 ns | 244 ns | 196 ns | 132 ns |
| 1,000 records | 526 µs | 493 µs | 267 µs | 204 µs | 134 µs |
| Map of 1,000 text keys | 138 µs | 144 µs | 99.6 µs | 93.3 µs | 31.4 µs |
| 64 KiB of text | 3.24 µs | 3.34 µs | 6.39 µs | 2.13 µs | 3.04 µs |
| 64 KiB of bytes | 1.06 µs | 1.06 µs | 438 µs | 1.02 µs | 1.64 µs |

The three runs' medians were within 3% of each other for every result but the JSON write of the map, which ranged from 9.24 to 9.77 µs.

What the numbers show:

- Writing a large value costs the format little more than the wipe. MessagePack and Borsh write 64 KiB in about 1.1 µs; the storage profile and the transport format take 1.9 µs, and the difference is wiping the buffer, sixteen bytes at a time, when it is dropped. JSON writes no wipe, but writes bytes as a list of numbers, 3.6 times as large and 75 times as slow.
- Reading text or bytes costs little more than copying them out: 64 KiB of bytes reads in 1.06 µs, as fast as MessagePack.
- On values with many small parts, the storage profile and the transport format are the slowest of the five, with JSON close behind. The storage profile writes 1,000 records twice as slowly as MessagePack and 9 times as slowly as Borsh, and reads them 2.6 and 3.9 times as slowly. MessagePack carries the same field names, so the names are not the cost; each record costs the storage writer about 70 ns more and the reader about 320 ns more. One record is slower even than JSON, twice as slow to write and to read. About half of the writing gap is allocation: the buffer starts empty and grows through 64, 128 and 256 bytes, each growth a copy and a wipe of the old allocation, where `serde_json` starts at 128 bytes and grows once. The reading gap is the two walks: validating the blob costs about as much as JSON's whole parse, and building the value on the second walk costs about twice JSON's, since the reader classifies a node before it reads it.
- The storage profile and the transport format are written by one writer, and read by one reader, so their times differ only where the formats do: the transport map is written faster because its repeated-key check compares the keys' text where it lies in the buffer, where the storage profile works out each key's identity from its node first.
- The storage profile is also the largest: 1,000 records take 57% more bytes than in MessagePack, and the map 89% more. Every length and count is a fixed four bytes and every value has a kind byte, where MessagePack packs small lengths and integers into one byte. One record is larger even than its JSON, 164 bytes to 126: its thirteen lengths and counts cost 52 bytes where JSON's quotes, colons, commas and brackets cost 40; its eleven kind bytes cost 11; its three numbers cost 24 bytes at full width where JSON prints them in 8; and the header costs 4. The flag is the one saving, a kind byte where JSON writes `false`. Borsh is the smallest for records, but writes an integer at its full width, so the map of `u64` values is nearly as large as in the storage profile.

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

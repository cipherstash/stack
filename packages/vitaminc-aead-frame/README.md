# vitaminc-aead-frame

The transport for carrying Vitamin-C AEAD values and ciphertexts across an
FFI boundary in one linear-memory copy: the frame for values, and the
ciphertext codec for the trees `encrypt` produces.

A host binding does not convert its values into a Rust value tree. It
implements [`Encrypt`] for values coming in and [`Sink`] for values going
out (ADR 0001). The frame is the one binding-neutral shape of a value:

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

## Transport, and one storage profile

The frame, the ciphertext codec and the serde format in `serde` are
transport: nothing about them is a compatibility commitment, since hosts
and guests ship together. The one exception is the storage profile,
`storage::to_vec` and `storage::from_slice` (feature `serde`), which
write and read a value as a versioned blob for bytes that are kept. Its
format is specified in `STORAGE.md`, frozen at version 1, and pinned by the
golden corpus in `testdata/storage-v1.json`. Use it, and only it, for bytes
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
map keys are UTF-8. The kind `0x02` was the `CT_NONE` absence marker,
which ADR 0001 retires: a `None` is a null leaf now, so the marker is
never written and refused when read.

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
comes back `Protected`, and is wiped when dropped.

```rust
# #[cfg(feature = "serde")]
# {
use vitaminc_aead_frame::storage;
use vitaminc_protected::Controlled;

let blob = storage::to_vec(&Some(Option::<u8>::None)).expect("writes");
assert_eq!(blob.risky_ref(), &[0x56, 0x43, 0x53, 0x01, 0xF5, 0x00]);
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

`benches/storage.rs` writes and reads five values with the storage profile, with the transport serde format, and, for comparison, with `serde_json`, MessagePack (`rmp_serde`) and Borsh, using Criterion:

```sh
cargo bench -p vitaminc-aead-frame --features serde --bench storage
```

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
- On values with many small parts, the storage profile is the slowest of the five. It writes 1,000 records 6.7 times as slowly as MessagePack and 31 times as slowly as Borsh, and reads them 3.2 and 6.4 times as slowly. MessagePack carries the same field names, so the names are not the cost; each element or field costs the storage writer about 40 to 90 ns more. This is the clearest place to look for a speedup.
- The storage profile is also the largest: 1,000 records take 57% more bytes than in MessagePack, and the map 89% more. Every length and count is a fixed four bytes and every value has a kind byte, where MessagePack packs small lengths and integers into one byte. Borsh is the smallest for records, but writes an integer at its full width, so the map of `u64` values is nearly as large as in the storage profile.
- A storage write costs more than a transport write on values with many parts, 26% more for 1,000 records and 43% more for the map, because it reads the blob back to find a repeated key before it returns it. Storage and transport reads are within about 12% of each other.

## Tests

`tests/conformance.rs` runs the shared binding corpus,
`testdata/value-conformance.json`, which Rust, Node and Go all read:
every vector parses as one frame and writes back byte for byte, from its
own walk and from a scalar built independently with std, chrono and
rust_decimal, and every malformed vector is refused.
`tests/storage.rs` reads and writes every row of the storage corpus,
`testdata/storage-v1.json`, which describes each value in a model any
language can build, refuses every malformed row with the error of its
class, and reads every typed row as its type says. A second reader,
written from STORAGE.md alone in `tests/support/reference.rs`, must agree
with the crate on every row and on random and corrupted blobs. CI checks
that no row the corpus had is changed or removed, with
`scripts/storage_corpus_append_only.py` (`mise run storage:corpus:check`).
`tests/storage_coverage.rs` checks that the corpus covers the
specification. Every tag is a value in a vector, and every map key kind is
a key in one, and a refused row starts a key with every byte a key may not
start with. Every part of every numbered reading rule has a row: a refused
row that breaks it, where the reference reader says which rule and part
that is, or for what a rule allows or keeps apart, a vector. Every clause
of *Reading by type* and of *Map keys* on reading has a `reads` row of the
right shape, that reads as the clause says. A refused row only counts if
it reads once the clause's cause is removed.
The test holds STORAGE.md's rules, clauses and key grammar word for word,
so a change to any of them fails it until the change is covered.

`src/storage/proofs.rs` holds Kani proofs about the storage reader, for
every input within their bounds:

- the header is refused exactly as rules 1 and 2 say (up to 6 bytes);
- a count is the four bytes at the cursor, and never more than the bytes
  left (up to 8 bytes, from any position);
- reading a scalar, an object's key or a map's key never panics, reads
  the bytes at the cursor, and accepts a plainly valid one (up to 6 bytes,
  from any position); an object's key is read exactly when its length and
  UTF-8 are good, and a four-byte key exactly when it is UTF-8, checked
  against RFC 3629's table; a map's key starts only with a tag STORAGE.md
  allows; a wide scalar is read whole when the input holds it, and refused
  otherwise, and a float is never a key (up to 17 bytes);
- the depth bound is 128: a node past it is refused before any of it is
  read, a node at it is still read, and a `some`, an array and a map pass
  their children down a level (an object's hash set asks the OS for random
  bytes, which Kani cannot model, so the corpus pins its depth);
- two integer map keys are one key exactly when their values are equal,
  across every pair of widths and every value;
- two text keys, or two bytes keys, are one key exactly when their bytes
  are equal, and keys of different kinds never are (up to 2 bytes).

A proof over whole bodies did not solve in a usable time, even for three
bytes, so whole bodies are left to the property tests and fuzzing. Run
the proofs with `cargo kani -p vitaminc-aead-frame --features serde`; CI
runs them in `.github/workflows/kani-storage.yml`.

`tests/storage_wipe.rs` and `tests/transport_wipe.rs` install an
allocator that inspects every block as it is freed, and fail if one still
holds a key or a value the storage writer, the transport writer or
`to_frame` wrote: through growth, `Display` values, a map's keys, a
failed write, or the dropped result.

`tests/legacy_fixture.rs` opens a ciphertext sealed before ADR 0001 on
the new path and gets the frame it was sealed from, so the leaf format,
the AAD derivations and the container rules stay what shipped.

[`Encrypt`]: vitaminc_aead::Encrypt
[`Sink`]: vitaminc_aead::Sink
[`CipherText`]: vitaminc_aead::CipherText
[`Frame`]: crate::Frame
[`FrameWriter`]: crate::FrameWriter
[`to_frame`]: crate::to_frame
[`PassthroughFrame`]: crate::PassthroughFrame
[`encode_ciphertext`]: crate::encode_ciphertext
[`decode_ciphertext`]: crate::decode_ciphertext
[`tags`]: crate::tags
[`MAX_DEPTH`]: crate::MAX_DEPTH
[`CodecError`]: crate::CodecError
[`FrameError`]: crate::FrameError

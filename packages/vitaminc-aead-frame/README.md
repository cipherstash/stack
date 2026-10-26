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

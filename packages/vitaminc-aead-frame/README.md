# vitaminc-aead-frame

The transport for carrying Vitamin-C AEAD values and ciphertexts across an
FFI boundary in one linear-memory copy: the frame for values, and the
ciphertext codec for the trees `encrypt` produces.

A host binding does not convert its values into a Rust value tree. It
implements [`Plaintext`] for values coming in and [`Sink`] for values going
out (ADR 0001). The frame is the one binding-neutral shape of a value:

- [`Frame`] is a validated, borrowed frame. `Frame::parse` checks the
  whole buffer up front, and the frame then implements `Plaintext` by
  walking its own bytes in place, so no value tree is built and no scalar
  leaves the buffer except to go straight to a sink.
- [`FrameWriter`] is a `Sink` that writes frame bytes, and [`to_frame`]
  walks any `Plaintext` into one. The Node binding snapshots a JavaScript
  value this way to encrypt it off the JavaScript thread.
- [`PassthroughFrame`] is an owned frame: the payload a ciphertext carries
  for a passthrough subtree, in every binding and in static Rust.

These live in `vitaminc-aead`, next to the leaf codec they share with the
sealed leaf format, and are re-exported here.

The ciphertext codec, [`encode_ciphertext`] and [`decode_ciphertext`],
carries a [`CipherText`] tree whose passthrough payloads are frames. The
Go guest uses it in both directions.

## Transport, not storage

Nothing here is a compatibility commitment. The only frozen byte format
in the stack is the sealed leaf payload (`[tag] ++ payload`, the tag table
in [`tags`]), which lives inside the AEAD envelope and never touches this
codec. Durable cross-language storage is the EQL layer's job. Hosts and
guests ship together.

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

## Hardening

Both directions are attacker-reachable input. Nesting is bounded at
[`MAX_DEPTH`] (128), counted across a ciphertext tree and the frame
payload behind a passthrough as one structure. A count or length is
checked against the bytes remaining before anything is reserved, and the
eager part of a reservation is clamped so a megabyte of hostile bytes
cannot pin gigabytes. Duplicate map keys are refused, as the frame
refuses them. Errors are opaque ([`CodecError`], [`FrameError`]): they
carry no detail about the bytes.

## Tests

`tests/conformance.rs` runs the shared binding corpus,
`testdata/value-conformance.json`, which Rust, Node and Go all read:
every vector parses as one frame and writes back byte for byte, from its
own walk and from a scalar built independently with std, chrono and
rust_decimal, and every malformed vector is refused.
`tests/legacy_fixture.rs` opens a ciphertext sealed before ADR 0001 on
the new path and gets the frame it was sealed from, so the leaf format,
the AAD derivations and the container rules stay what shipped.

[`Plaintext`]: vitaminc_aead::Plaintext
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

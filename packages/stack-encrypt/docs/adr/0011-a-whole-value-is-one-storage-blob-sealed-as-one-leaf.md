---
status: accepted
date: 2026-11-02
extends: ADR-0003, ADR-0010
---

# A whole value is one storage blob, sealed as one leaf, and only when named

The owned scalar API (`KeysetCipher::encrypt`) seals one scalar as one
`Ciphertext` and refuses everything else: there is no `Serialize` fallback,
so a struct handed to `encrypt` does not compile. That leaves a real need
unmet. An application often has a value it wants stored as **one**
ciphertext, under one data key, with nothing inside it searchable: a card,
a profile, a settings object. The structural API seals a struct as one leaf
per field, which is a different thing (one key per field, a tree of
ciphertexts, a record shape to store), and a searchable JSON document is a
third. This ADR records how a whole value becomes one ciphertext.

## Decision

**`OpaqueBlob<T>` is the one way to encrypt a composite value as one
ciphertext, and it is explicit.** `encrypt(OpaqueBlob::new(value))` and
`decrypt::<OpaqueBlob<T>>(ct)`. The wrapper implements the sealed
`OpaqueEncode` / `OpaqueDecode` capabilities; `T` does not, and no blanket
impl over `Serialize` is added. A reviewer can find every whole-value
ciphertext in a codebase by searching for the name.

**The encoding is Vitamin C's storage profile, version 1, and nothing
else.** `vitaminc_aead_frame::storage` is the library-owned codec: a
self-describing binary encoding built from the sealed leaf's own scalar
tags and the transport frame's containers, with a header (`VCS` and a
version byte), a marker for a present `Option`, typed map keys and a frozen
specification pinned by a golden corpus. It is the format the Go SDK
already writes and reads for its opaque structs (`vcffi.MarshalStorage`,
`UnmarshalStorage`), so a Go-written opaque column and a Rust `OpaqueBlob`
are one stored format, and this crate adds no second wire format. The
transport serde codec in the same crate is not used: it is ephemeral by
design and carries no compatibility commitment.

**The encoded blob is sealed as one bytes leaf of the ordinary envelope,
through the scalar path.** No new envelope, no new KMS request shape, no
new AAD: the ciphertext is exactly what sealing a `Vec<u8>` of the encoded
bytes produces, and `SealedValue` v1 is unchanged. The header is inside the
plaintext, so the discriminator and the version are encrypted and
authenticated with the value, and nothing about a blob is visible before
decryption.

**Decryption authenticates before it decodes, and refusals are told
apart.** The leaf opens first; only then does the profile's reader see the
bytes, and it validates the whole blob before `T`'s `Deserialize` sees any
of it. A leaf that does not open is `Error::Aead`. A leaf that opens but is
not a bytes leaf is `Error::OpenedType`. Bytes that are not a blob this
type reads are `Error::Blob`, one `BlobError` variant and one code per
class: not a blob, an unsupported (later) version, malformed, or a
well-formed blob of another shape. Every `Error::Blob` is a refusal of an
authentic ciphertext, consistent with ADR-0010: the data was written as
something else, not tampered with.

**The version is the profile's, not the application's.** `blob::VERSION`
names the byte grammar and the serde mapping together; version 1 is frozen
and a reader reports a later version apart from corruption. An
application's own schema evolves through `T` and serde's attributes
(`default`, `alias`, `Option`), and an application that must tell its own
versions apart carries that in the value.

**Ownership and cleanup follow the scalar API's contract.** `T: Zeroize` is
required to encrypt and to decrypt. On encrypt the owned source is guarded,
encoded into the self-wiping `Buffer` the profile returns, planned, and wiped
before the pending is returned; an encoding refusal wipes it too and
requests no key. On decrypt the opened bytes are held `Protected` until the
reader returns. The returned `OpaqueBlob<T>` is an ordinary owned value
and is **not wiped on drop**; `OpaqueBlob<Zeroizing<T>>` is the opt-in
drop-guarded result. A `Zeroizing<T>` serializes as its `T`, so it stores
the same blob, and no new adapter is needed. The guard sits inside the blob
because `OpaqueDecode`'s blanket impl over Vitamin C's `FromScalar` leaves
no room for a `Zeroizing<_>` impl in this crate: Rust's coherence rules
allow Vitamin C to add `FromScalar` for `Zeroizing` later. A drop-guarded
scalar (`Zeroizing<String>`) needs that impl in Vitamin C.

## What is not claimed

- **Constant time.** Neither serde's impls nor the profile's writer and
  reader are constant time, and `OpaqueBlob` does not make them so. The
  cryptography is unchanged; the encoding runs on plaintext the caller
  already holds.
- **Length hiding.** AES-GCM keeps the plaintext's length and the profile
  adds no padding, so the ciphertext's length is the encoded length plus a
  constant, and the encoded length depends on string lengths, element
  counts and whether each `Option` is present. The same disclosure a
  `String` scalar makes; padding is the application's.
- **Complete erasure.** A derived `Deserialize` that built some fields and
  refuses a later one drops those fields unwiped, because no `T` existed to
  wipe; `tests/heap_hygiene.rs` holds this as a negative control rather
  than hiding it. A `Copy` value moved out of leaves its bytes behind, and
  compiler temporaries are not wiped. The promise covers the owned source,
  the encoded buffer, the opened buffer and the library's copies.
- **Searchability or partial reads.** A blob is opaque. Nothing inside it
  can be queried or read on its own; that is what the structural API and
  the JSON index are for.

## Alternatives considered

- **A blanket `impl OpaqueEncode for T: Serialize`.** Rejected: it decides
  the stored bytes of every composite silently, lets a `Vec<u8>` or a
  struct become one ciphertext by accident, and cannot be told apart from
  the structural API at a call site.
- **The transport serde codec.** Rejected: it is lockstep transport with
  no compatibility commitment, and it collapses `Some(None)` and keeps no
  map-key kinds. The storage profile exists because of exactly these gaps.
- **MessagePack or another general format.** Rejected upstream, where the
  profile's specification records why: no header or version, options that
  collapse, struct layout left to each library, repeated keys and integer
  widths left to the reader, and plaintext copies left in buffers.
- **A `Decrypt` impl so a blob can be a field of a structural record.**
  Deferred: the sink's error type cannot carry the blob's refusal classes,
  so it would report every blob error as a shape mismatch. The owned API
  is the contract this ADR settles; a field-level blob is separate work.

## Consequences

- `OpaqueEncode` and `OpaqueDecode` stay sealed and gain `OpaqueBlob<T>`
  implementors. `OpaqueDecode` no longer requires
  vitaminc's `Decrypt`, since a blob opens through a bytes leaf and decodes
  after; the sealed `open` is the capability instead.
- `Error` gains `Blob(BlobError)`, transparent, with five codes under
  `stack_encrypt::blob_*`.
- The crate depends on `vitaminc-aead-frame` with its `serde` feature
  unconditionally (0.8.1, the first release with the profile); the
  `dynamic` feature no longer gates that dependency.
- The conformance coverage map enrolls the fixed blob vectors, the
  Rust/Go storage exchange and the heap observations under the existing
  requirements rather than a new profile; a fresh sealed exchange with Go
  (Go seals, Rust opens, and back) is still open and listed as such.

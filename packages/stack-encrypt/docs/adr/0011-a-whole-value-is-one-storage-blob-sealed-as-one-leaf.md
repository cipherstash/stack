---
status: accepted
date: 2026-11-02
extends: ADR-0003, ADR-0010
---

# A whole value is one storage blob, sealed as one leaf, and only when named

## Decision

To encrypt a struct, map, or `Vec` as one ciphertext, the caller wraps it in
`OpaqueBlob<T>`. The value is encoded with version 1 of Vitamin C's storage
profile. The encoded bytes are sealed as one bytes leaf of the ordinary
envelope. Decrypting a blob authenticates the leaf first, then decodes it.

## Context

The owned scalar API, `KeysetCipher::encrypt`, seals one scalar as one
`Ciphertext`. It refuses everything else. There is no `Serialize`
fallback, so a struct passed to `encrypt` does not compile.

Applications often need to store a value as **one** ciphertext, under one
data key, with nothing inside it searchable. Examples are a card, a
profile, or a settings object. The existing APIs do something different:

- The structural API seals a struct as one leaf per field. That means one
  key per field, a tree of ciphertexts, and a record shape to store.
- A searchable JSON document is indexed so that it can be queried.

This decision record says how a whole value becomes one ciphertext.

## The parts of the decision

### The caller names the wrapper

`OpaqueBlob<T>` is the only way to encrypt a composite value as one
ciphertext. The caller writes `encrypt(OpaqueBlob::new(value))` and
`decrypt::<OpaqueBlob<T>>(ct)`.

The wrapper implements the sealed `OpaqueEncode` and `OpaqueDecode`
traits. `T` does not implement them. No blanket impl covers every
`Serialize` type. So a reviewer can find every whole-value ciphertext in a
codebase by searching for the name.

### The encoding is Vitamin C's storage profile, version 1

The codec is `vitaminc_aead_frame::storage`, a part of Vitamin C. The
profile is a binary encoding that describes its own structure. It uses the
sealed leaf's scalar tags and the transport frame's containers. It adds:

- a header: the bytes `VCS` and a version byte
- a marker for an `Option` that is `Some`
- map keys that keep their kind
- a frozen specification, pinned by a golden corpus of test vectors

The Go SDK already uses this format for its opaque structs. It writes
with `vcffi.MarshalStorage` and reads with `UnmarshalStorage`. So a Go-written
opaque column and a Rust `OpaqueBlob` are one stored format, when the field
types correspond. This crate adds no second stored format.

The same crate also has a transport serde codec. `OpaqueBlob` does not use
it. The transport codec is for messages between processes, and makes no
promise that stored bytes stay readable.

### The blob is sealed as one bytes leaf

Sealing a blob adds no new envelope, no new kind of key request and no new
AAD. The ciphertext is the same as sealing a `Vec<u8>` of the encoded
bytes. `SealedValue` v1 does not change.

The header is part of the plaintext. So the header and the version are
encrypted and authenticated with the value. Nothing about a blob is
visible before it is decrypted.

### Decryption authenticates first, and refusals are told apart

The leaf is opened first. Only then does the storage profile's reader see
the bytes. The reader checks the whole blob before `T`'s `Deserialize` sees
any of it.

Each refusal has its own error:

- A leaf that does not open is `Error::Aead`.
- A leaf that opens, but holds a scalar other than bytes, is
  `Error::OpenedType`.
- Bytes that are not a blob that `T` reads are `Error::Blob`. Each class
  has its own `BlobError` variant and error code: not a blob, a later
  version, malformed, or a valid blob of another shape.

Every `Error::Blob` refuses a ciphertext that is authentic. As ADR-0010
says, such a refusal means the data was written as something else. It
does not mean the data was tampered with.

### The version belongs to the profile, not to the application

`blob::VERSION` names the byte format and the serde mapping together.
Version 1 is frozen. A reader reports a later version with an error that is
different from the error for a damaged blob.

An application's own schema changes through `T` and serde's attributes,
such as `default`, `alias`, and `Option`. If an application must tell its
own versions apart, it stores a version in the value.

### Cleanup follows the scalar API's rules

`T: Zeroize` is required to encrypt and to decrypt.

On encrypt, these steps happen before the pending request is returned:

1. The owned source is guarded.
2. The source is encoded into the `Buffer` that the profile returns. That
   buffer wipes itself.
3. The buffer is planned into the leaf.
4. The source is wiped.

If encoding fails, the source is wiped too. No key is requested.

On decrypt, the opened bytes are held in a `Protected` buffer until the
reader returns.

The returned `OpaqueBlob<T>` stores its value in a `Zeroizing<T>`, so **the
value is wiped on drop**. `into_inner` returns that `Zeroizing<T>`, not a
bare `T`, so the value is still guarded after it leaves the wrapper. A blob
is already a wrapper that the caller chose, so the guard costs the caller
nothing extra.

A scalar decrypt still returns an ordinary owned value. This crate cannot
add an opt-in drop guard for a scalar, such as `Zeroizing<String>`.
`OpaqueDecode` has a blanket impl over Vitamin C's `FromScalar`, and Rust's
coherence rules then forbid a `Zeroizing<_>` impl in this crate. Vitamin C
can add `FromScalar` for `Zeroizing` later, so that impl belongs in
Vitamin C.

## What is not claimed

- **Constant time.** Serde's impls are not constant time. The profile's
  writer and reader are not constant time either. `OpaqueBlob` does not
  change that. The
  cryptography is unchanged. The encoding runs on plaintext the caller
  already has.
- **Length hiding.** AES-GCM keeps the plaintext's length, and the profile
  adds no padding. So the ciphertext's length is the encoded length plus a
  constant. The encoded length depends on the length of each string, the
  number of elements, and whether each `Option` is present. A `String`
  scalar shows its length in the same way. Padding is the application's
  job.
- **Complete erasure.** A derived `Deserialize` might build some fields and
  then refuse a later one. It drops those fields without wiping them,
  because no `T` existed to wipe. `tests/heap_hygiene.rs` records this as a
  negative control, so the gap stays visible. A `Copy` value that is moved
  leaves its bytes behind. Compiler temporaries are not wiped. The
  promise covers the owned source, the encoded buffer, the opened buffer,
  and the library's own copies.
- **Search or partial reads.** A blob is opaque. Nothing inside it can be
  queried or read on its own. The structural API and the JSON index are for
  those needs.

## Alternatives considered

- **A blanket `impl OpaqueEncode for T: Serialize`.** Rejected. It would
  choose the stored bytes of every composite value without the caller
  asking. It would let a `Vec<u8>` or a struct become one ciphertext by
  accident. And a reader could not tell it apart from the structural API at
  a call site.
- **The transport serde codec.** Rejected. Its two ends must run the same
  version, and it makes no promise that stored bytes stay readable. It also
  writes `Some(None)` the same as `None`, and loses the kind of each map
  key. The storage profile exists to close these gaps.
- **MessagePack or another general format.** Rejected in Vitamin C, where
  the profile's specification gives the reasons. Such formats have no
  header or version, and they write some different values the same way.
  Each library chooses its own struct layout. Each reader decides how to
  treat repeated keys and integer widths. Plaintext copies are left in
  buffers.
- **A `Decrypt` impl, so a blob can be a field of a structural record.**
  Deferred. The structural decoder's error type has no variants for the
  blob's classes of refusal. So it would report every blob error as a shape
  mismatch. This decision covers the owned API. A blob as a field is
  separate work.

## Consequences

- `OpaqueEncode` and `OpaqueDecode` stay sealed. `OpaqueBlob<T>` implements
  both.
- `OpaqueDecode` no longer requires Vitamin C's `Decrypt` trait. A blob
  opens through a bytes leaf and is decoded afterwards, so it cannot
  implement `Decrypt`. The sealed `open` method takes its place.
- `Error` has a new transparent variant, `Blob(BlobError)`. `BlobError`
  has five error codes, all named `stack_encrypt::blob_*`.
- The crate always depends on `vitaminc-aead-frame`, with its `serde`
  feature. The `dynamic` feature no longer controls that dependency.
- The conformance coverage map lists three kinds of evidence for blobs:
  - the fixed blob vectors
  - the exchange of storage bytes between Rust and Go
  - the heap checks

  The evidence is listed under the existing requirements, not a new
  profile. The map lists one case as still open. In that case Go seals a
  fresh blob and Rust opens it, and then the other way round.

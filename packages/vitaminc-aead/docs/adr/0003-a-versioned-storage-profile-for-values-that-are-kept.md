---
status: proposed
---

# A versioned storage profile for values that are kept

> **Proposed.** Implements
> [cipherstash/vitaminc#519](https://github.com/cipherstash/vitaminc/issues/519).
> The format is frozen once this is accepted and released, and not
> before: review `packages/aead-frame/STORAGE.md` with this record.

Stack Encrypt will seal an `OpaqueBlob<T>` as one ciphertext whose plaintext
is `T` serialized with Vitamin C's frame machinery. That plaintext is kept,
for as long as the customer keeps the row. The frame and its serde format
were built for a host and a guest that ship together, and say so: nothing
in them is a compatibility commitment, and #332 dropped a version byte from
the transport for exactly that reason. Stored bytes need the opposite
promise. This decision adds a storage profile that makes it, and leaves the
transport as it is.

## Context

The transport serde format (`vitaminc_aead_frame::serde`) has three
properties that are fine in flight and wrong at rest:

- **No version.** A reader cannot tell a blob written under other rules
  from a corrupt one.
- **Options lose information.** `serialize_some` writes its payload as is,
  and `None` and unit are both null, so `Some(())` reads back as `None`,
  and `Some(None)` as `None`, in an `Option<Option<_>>`.
- **It reads what a JavaScript host sends.** `undefined` reads as null,
  and the grammar is the frame's, which grows when the plaintext model
  does: a stored blob would accept whatever the leaf codec learns next.

## Decision

1. **A separate profile with its own entry points.**
   `vitaminc_aead_frame::storage::{to_vec, from_slice}` write and read a
   blob. They, the blob's bytes, and the constants `HEADER`, `MAGIC`,
   `VERSION` and `SOME` are stable. Everything else in the crate stays
   transport. The profile shares the transport's deserializer, error type
   and key handling, and has its own validator and writer.

2. **A header.** `"VCS"`, then a version byte, `0x01`. No header byte is a
   node tag, so a transport frame never reads as a blob, nor a blob as a
   frame. A version the reader does not read gets its own error,
   distinct from a malformed blob.

3. **A presence marker, `0xF5`.** `Some(x)` is `0xF5` then `x`. The marker
   is a node of its own, outside the transport grammar, so
   `deserialize_any` reports it as `visit_some`, and an option survives
   serde's buffering for untagged, internally tagged and flattened types.
   A reader takes a bare non-null node where an option is expected as
   `Some`, so a field that becomes optional still reads its old blobs.

4. **An allow-list of scalars.** Version 1 admits null, the booleans, the
   ten integer widths, the two floats, text and bytes: the sealed leaf's
   frozen tags in frame form. Logical types, `undefined`, the typed null,
   the passthrough and the envelopes are refused. A tag the leaf codec
   gains later is not admitted until a new version says so.

5. **Text keys only.** As in the transport. Integer keys are not in
   version 1; adding them is a new version.

6. **A version is frozen, and changes come in two steps.** Any change to
   the grammar or the mapping is a new version. A release first reads it
   while still writing the old one, and a later release writes it. Readers
   never drop a version.

7. **A golden corpus that only grows.**
   `packages/aead-frame/testdata/storage-v1.json` describes each value in
   a language-neutral model and pins its bytes, and pins each refusal with
   its class. A Rust test reads and writes every row, and a CI job fails a
   pull request that edits or removes a row the merge base had.

## Consequences

- Stack Encrypt can keep blobs while the writer's allocation, wiping and
  timing improve: the corpus holds any such change to the bytes.
- The blob's version and Stack Encrypt's envelope version are separate.
  The header is inside the sealed plaintext, so it is authenticated, and a
  caller that wants to refuse an unknown codec before decrypting can bind
  `HEADER` into its associated data. Stack's dynamic interoperability
  specification and its Rust and Go acceptance tests should read this
  corpus; that work is in the Stack repository.
- Bytes are deterministic for deterministic `Serialize` impls, and not
  canonical beyond that: equal values of different widths differ, and a
  `HashMap`'s order is not fixed. The specification says so rather than
  promising more.
- Reading a newtype struct as a map key now works in both profiles. Before,
  the transport wrote one and refused to read it back.

## Alternatives considered

- **`Some(x)` as an array of one.** Stays inside the frame grammar and
  needs no new tag, but `deserialize_any` sees an array, so an option in
  an untagged, internally tagged or flattened type fails to read, and an
  `Option<serde_json::Value>` reads `Some(1)` back as `Some([1])`.
- **Reusing the passthrough tag `0xF2` as the marker.** Works with
  buffering and stays inside the frame grammar, but gives a tag that means
  "leave this subtree in the clear" a second meaning: a blob body walked as
  plaintext would skip encrypting every `Some`.
- **Versioning the transport instead.** Would put a compatibility promise
  on a format whose peers ship together, and on paths (the ciphertext
  codec, the control plane) that do not need it.

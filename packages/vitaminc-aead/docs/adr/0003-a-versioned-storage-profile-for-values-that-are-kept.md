---
status: accepted
---

# A versioned storage profile for values that are kept

> **Accepted**, and implemented in #520, which closes
> [cipherstash/vitaminc#519](https://github.com/cipherstash/vitaminc/issues/519).
> First released in 0.8.1. Version 1 is frozen: CI refuses any change to a
> corpus row. The format is specified in `packages/aead-frame/STORAGE.md`.

Stack Encrypt will seal an `OpaqueBlob<T>` as one ciphertext whose plaintext
is `T` serialized with Vitamin C's frame machinery. That plaintext is kept,
for as long as the customer keeps the row. The frame and its serde format
were built for a host and a guest that ship together, and say so: nothing
in them is a compatibility commitment, and #332 dropped a version byte from
the transport for exactly that reason. Stored bytes need the opposite
promise. This decision adds a storage profile that makes it, and leaves the
transport as it is.

## Context

The transport serde format (`vitaminc_aead_frame::serde`) has four
properties that are fine in flight and wrong at rest:

- **No version.** A reader cannot tell a blob written under other rules
  from a corrupt one.
- **Options lose information.** `serialize_some` writes its payload as is,
  and `None` and unit are both null, so `Some(())` reads back as `None`,
  and `Some(None)` as `None`, in an `Option<Option<_>>`.
- **Map keys are text only.** A `HashMap<u32, _>` is refused, and a
  `HashMap<Uuid, _>` too, since a `Uuid` is written as bytes.
- **It reads what a JavaScript host sends.** `undefined` reads as null,
  and the grammar is the frame's, which grows when the plaintext model
  does: a stored blob would accept whatever the leaf codec learns next.

## Decision

1. **A separate profile with its own entry points.**
   `vitaminc_aead_frame::storage::{to_vec, from_slice}` write and read a
   blob. They, the blob's bytes, the constants `HEADER`, `MAGIC`,
   `VERSION`, `SOME` and `MAP`, and `ErrorKind` are stable. Everything
   else in the crate stays transport. The profile shares the transport's
   deserializer, and has its own validator, writer and error type. `to_vec`
   returns the blob `Protected`, since it is the value's plaintext.

2. **A header.** `"VCS"`, then a version byte, `0x01`. No header byte is a
   node tag, so a transport frame never reads as a blob, nor a blob as a
   frame. A version the reader does not read gets its own `ErrorKind`,
   distinct from a malformed blob, so a caller never matches on a message.

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

5. **A map node, `0xF6`, whose keys are nodes.** A serde map is
   `0xF6`, a count, then a key node and a value node for each entry. A key
   is an integer of any width, text or bytes, and keeps its kind, so a
   `HashMap<u32, _>` and a `HashMap<Uuid, _>` are stored as they are, and
   a reader in another language can tell a map from a struct. Structs and
   enum variants stay objects, whose keys are names. Two keys are the same
   when they are integers of equal value, whatever their widths, or text,
   or bytes, with the same bytes; a repeat is refused. `0xF5` and `0xF6`
   are reserved in `vitaminc_aead::tags`.

6. **A version is frozen, and changes come in two steps.** Any change to
   the grammar or the mapping is a new version. A release first reads it
   while still writing the old one, and a later release writes it. Readers
   never drop a version.

7. **A golden corpus that only grows.**
   `packages/aead-frame/testdata/storage-v1.json` describes each value in
   a language-neutral model and pins its bytes, pins each refusal with its
   class, and pins what a type reads a blob as, for the reading rules that
   go beyond the bytes (a bare value read as `Some`, integer widening, a
   variant's forms). A Rust test reads and writes every row, a second
   reader written from the specification alone must agree with the crate,
   and a CI job fails a pull request that edits or removes a row the merge
   base had.

## Consequences

- Stack Encrypt can keep blobs while the writer's allocation, wiping and
  timing improve: the corpus holds any such change to the bytes.
- The blob's version and Stack Encrypt's envelope version are separate.
  The header is the start of the plaintext Stack seals, so it is
  encrypted with the value and covered by the envelope's authentication:
  nothing about the blob shows before decryption. A reader that meets a
  version it does not read decrypts and gets `UnsupportedVersion`. If
  Stack wants the version visible before decryption, its envelope records
  it in the clear and passes it as associated data, so a changed version
  fails authentication; that is the envelope's choice. Stack's dynamic
  interoperability specification and its Rust and Go acceptance tests
  should read this corpus; that work is in the Stack repository.
- Bytes are deterministic for deterministic `Serialize` impls, and not
  canonical beyond that: equal values of different widths differ, and a
  `HashMap`'s order is not fixed. The specification says so rather than
  promising more.
- Reading a newtype struct as a map key now works in both profiles. Before,
  the transport wrote one and refused to read it back.
- A flattened `Option<T>` field gets no marker, since serde writes its
  `Some` without telling the format; its `None` reads back as `Some` when
  `T` reads from nothing. serde does this in every format; the
  specification says so, and a test pins it.

## Alternatives considered

- **`Some(x)` as an array of one.** Stays inside the frame grammar and
  needs no new tag, but `deserialize_any` sees an array, so an option in
  an untagged, internally tagged or flattened type fails to read, and an
  `Option<serde_json::Value>` reads `Some(1)` back as `Some([1])`.
- **Reusing the passthrough tag `0xF2` as the marker.** Works with
  buffering and stays inside the frame grammar, but gives a tag that means
  "leave this subtree in the clear" a second meaning: a blob body walked as
  plaintext would skip encrypting every `Some`.
- **Integer keys as decimal text**, as JSON does. No new node, but a key
  loses its kind, and one value has many spellings (`"1"`, `"01"`, `"+1"`)
  unless the reader refuses all but one: the weakest choice for a format
  other languages read.
- **The map node only when a key is not text.** Text-keyed maps stay
  objects, but serde names neither the key types nor whether a map is
  coming before the first key, so the writer would have to go back and
  rewrite the tag, and a map whose keys mix kinds has no good form.
- **MessagePack** (`rmp-serde`). Self-describing and widely implemented,
  but it has no version and one `nil`, so `Some(None)` reads as `None`.
  How a struct, an enum or an option is written is each library's choice:
  `rmp-serde` writes a struct as an array, while Go's common libraries
  write a map. The specification leaves repeated keys undefined, and lets
  an integer be written at any width. The writer leaves unwiped copies as
  its buffer grows, and its errors quote values. *Why not MessagePack or
  Borsh* in STORAGE.md has the detail.
- **Borsh.** Strict and canonical, but not self-describing: a blob reads
  only into the exact type that wrote it. A field that is added, removed,
  renamed or made optional leaves the existing blobs unreadable, and two
  swapped fields of one type read back swapped, with no error. It does not
  use serde, so every sealed type, and every foreign type inside one, would
  need its derives. Canonical bytes are worth that cost for values that
  are hashed or signed. A sealed value is compared after it is opened, so
  it is not worth that cost here.
- **CBOR** (`ciborium`). The closest fit: self-describing, keys of any
  kind, and a deterministic encoding defined in RFC 8949. Its serde
  mapping still writes `Some(x)` as `x`, so options collapse as they do in
  MessagePack. It has no version unless a tag is added, and it would bring
  a second grammar and a dependency to review in Rust and Go, where the
  frame's grammar is already implemented in both.
- **Versioning the transport instead.** Would put a compatibility promise
  on a format whose peers ship together, and on paths (the ciphertext
  codec, the control plane) that do not need it.

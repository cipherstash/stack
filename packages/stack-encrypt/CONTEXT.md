# Stack Encrypt

Client-side encryption of values under per-value ZeroKMS data keys, and the
derivation of searchable index terms from the same values. Covers
`stack-encrypt`, `stack-encrypt-derive`, and the WASI guest in
`bindings/go/stackencrypt/guest` that exposes them to Go.

## Language

**Cipher-directed**:
Encryption driven by the value's shape: the value's `Encrypt` implementation
walks the cipher and the caller decides the context, which may be absent.
_Avoid_: raw path, low-level path

**Target-directed**:
Encryption driven by the output type: the type being produced (a ciphertext, a
term, a record) declares what it is derived from and which context it demands.
_Avoid_: typed path, high-level path

**Context**:
The value a ciphertext is authenticated under and a term is derived under. A
leaf takes a `NonEmpty<T>` — vitaminc's proof that the value carries caller
bytes — and nothing else; a `nonempty!("users/email")` literal, a
`NonEmpty::new(value)?` at runtime, or a bare integer. It becomes the
ciphertext's associated data, the term's PRF context, and the ZeroKMS
descriptor of the data key.
_Avoid_: AAD (that is one of its encodings, not the concept), lock context

**Own context**:
The context a field carries itself: a `context = ".."` literal, or the one a
`struct = ..` derive infers as `<struct context>/<field>`. A caller's context
*extends* it (`("users/age", id)`); it is never discarded.
_Avoid_: default context, field prefix

**Descriptor**:
The context, rendered as the string ZeroKMS binds into every data key and
logs per retrieval, rendered from the context's parts: plain text verbatim,
integers by their width, sign-blind (`7u64`, and `7i64` is `7u64`), a
composite's parts joined by `|` (`users/email|7u64`); text that could read as
another form is `b64:`-escaped, and an empty part inside a list is the bare
`b64:`. Injective over encodings, and finer than them for a pre-encoded
`Aad` (opaque bytes) and for shapes that encode alike (`None` vs `0u64`):
seal and open must present the context in the same shape.
_Avoid_: key name, key id

**Leaf**:
An output type that authenticates or derives directly — a ciphertext or a
single index term — and therefore owes nothing to a context but the one it is
handed.
_Avoid_: primitive, scalar output

**Record**:
An output type assembled from leaves derived from one plaintext (a `plaintext
= T` derive); a **struct record** (a `struct = T` derive) is one whose fields
are each derived from one field of the plaintext under their own context.
_Avoid_: composite, struct (the plaintext is the struct; the record is derived from it)

**EQL type**:
An output type that participates in EQL — a ciphertext or index term stored
for query — and so carries the contract that its context is supplied and
non-empty. Every leaf and record in the target-directed path is one.
_Avoid_: searchable type, indexed type

**Term**:
A deterministic, one-way index value derived from a plaintext under a
context — equality, match, ORE or OPE.
_Avoid_: index, token, hash

**Pending**:
An output whose local work (term derivation, per-leaf sealing plan) is done
and whose ZeroKMS key requests are queued but not sent. Pendings compose
(`zip`, `map`, `all`) so a whole struct or `Vec` settles in one batched call.
_Avoid_: future, promise

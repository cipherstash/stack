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
term, a record) declares what it is derived from, which operations produce it,
and which context it demands; execution belongs to the cipher.
_Avoid_: typed path, high-level path

**Operation description**:
The target's declaration of the ciphertext and term operations, source selections,
and context requirements needed to produce it.
_Avoid_: user-supplied encryption callback, caller-supplied plan (a **plan**
is the runtime form of a record's description, not a callback)

**Plan**:
A record's operation description given as data rather than as a type, per
field: the context to bind and the outputs (`"c"`, `"eq"`, `"match"`, `"ore"`,
`"ope"`) to produce. What a binding has instead of a `struct = T` derive;
`stack_encrypt::dynamic::record` drives one. Its contexts are proven
nonempty once, when it is built, and its output keys are wire format.
_Avoid_: schema (that is the source's shape, which a plan does not describe),
mapping, config

**Ciphertext transcoding**:
Construction or inspection of an encrypted target through its native encrypted
structure, preserving the distinctions between ciphertext, terms, metadata, and
authenticated structural markers.
_Avoid_: plaintext serialization, re-encryption

**Context**:
The value a ciphertext is authenticated under and a term is derived under. A
leaf requires a nonempty context, validated by Vitamin C and owned in a
`CallerContext` (both encodings — what a term is derived under, and what a
record deriving terms threads to every field) or an `AeadContext` (the AAD
encoding alone — what a ciphertext is sealed and opened under; a record
deriving terms hands its ciphertext fields that half of its `CallerContext`);
a `nonempty!("users").with("email")` pair (a table and a column are two
parts, rendered `users/email`), a `NonEmpty::new(value)?` at runtime, or a
bare integer. It becomes the ciphertext's associated data,
the term's PRF context, and the ZeroKMS descriptor of the data key.
_Avoid_: AAD (that is one of its encodings, not the concept), lock context

**Own context**:
The context a field carries itself: a `context = ".."` literal (one text
part, exactly as written), or the pair a `struct = ..` derive infers,
`(<struct context>, <field>)`. A caller's context *extends* it
(`(("users", "age"), id)`); it is never discarded. A subtree of a
declaration is given one with `under` (the caller's is then optional) or
`extend` (the caller's stays required).
_Avoid_: default context, field prefix

**Threaded context**:
The one context a target's declaration tree hands to every operation beneath
it (ADR-0004): a type parameter of `Encryption`, so a target cannot route what
it is handed to one operation and something else to another, and two subtrees
needing different kinds of context do not zip. `under` and `extend` are the
only ways to change it; each covers a whole subtree and is written in the
declaration, and the tree does not tell a record's two fields from a target's
two halves.
_Avoid_: scope (that is a `Pending`'s), shared context, per-operation context

**Descriptor**:
The context, rendered as the string ZeroKMS binds into every data key and
logs per retrieval, rendered from the context's parts: plain text verbatim,
integers by their width, sign-blind (`7u64`, and `7i64` is `7u64`), a list's
parts joined by `/` (`users/email`; a nested list is parenthesised,
`(users/email)/7u64`); text that could read as another form — containing
`/`, `(` or `)`, beginning with `b64:`, a digit or `-` — is `b64:`-escaped,
so one text part can never read as two, and an empty part inside a list is
the bare `b64:`. Rendered by one function, `Descriptor::from_piece`, and
**frozen**: a change re-keys everything. Finer than the encodings for a
pre-encoded `Aad` (opaque bytes) and coarser for shapes that render alike
(`7i64` and `7u64`): seal and open must present the context in the same
shape. The descriptor is derived, never authored: nothing takes a descriptor
string from a caller.
_Avoid_: key name, key id, path (that is a `Label`)

**Describe**:
The trait of a value whose parts are a descriptor of its own — the identity
data is keyed under, as opposed to an arbitrary context. An implementor
pushes parts into a `DescriptorBuilder` and never writes rendered text, so
the one renderer keeps distinct values apart whoever implements it. Open:
a consumer's own column or document type implements it; `Label` and EQL's
`Identifier` do. A `Describe` type is also a context, through the same
parts (`to_context` is what its `IntoContext` returns).
_Avoid_: descriptor trait, Descriptor (the rendered string)

**Label**:
The first-class `Describe` type: a path of plain segments, each checked
(non-empty, no `/`, `(`, `)` or control characters, not beginning with
`b64:`, a digit or `-`), so it renders verbatim and its `Display`
(`users/email`) is its descriptor and parses back losslessly. The one way to
spell a name, binding one context: its segments as a flat list. `with` is
not another way to build a label; it scopes a context by appending a part
(tenant, row id) and nests, `(users/email)/7u64`. The two meet where a
two-segment label equals the pair a `struct = ..` derive binds, which is how a
label opens a row a derive wrote. A direct consumer of the
crate names its data with a `Label`; an EQL consumer names it with an
`Identifier`, the same shape with exactly two segments.
_Avoid_: path, name, identifier (that is EQL's two-segment case)

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
non-empty. EQL integration supplies a concrete identifier; generic target records need not be EQL types.
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

**Keyset**:
The ZeroKMS key domain a data key is minted under and an index key belongs
to — one per tenant is the common shape. A client may use any number;
`StackCipher` is scoped to the client, not to a keyset. Its **id** (a UUID)
is its identity: globally unique, carried in every sealed leaf, never
re-checked.
_Avoid_: dataset, key ring, tenant (a tenant *has* a keyset)

**Keyset cipher**:
`KeysetCipher`, the cipher bound to one keyset, and what every operation
that *mints* binds to — sealing values, sealing records, deriving terms.
An owned handle (a cipher reference plus the keyset's loaded state), cheap
to clone and to hold per request. Decrypting through one is a *constraint*,
not a capability: it refuses a leaf from any other keyset.
_Avoid_: keyset handle (use "handle" only for the object, not the concept),
sub-cipher, tenant cipher

**Scope**:
What a `Pending` was built through, and therefore what it is allowed to do:
a `KeysetCipher` scope mints under its keyset and opens leaves from no
other; a `StackCipher` scope mints nothing and opens leaves from any keyset.
`CipherScope` is the sealed trait both references implement; `dynamic::Scope`
is the same choice as a runtime value, for a binding whose caller makes it
per call. Two pendings merge when their scopes agree on a keyset — which
cipher *value* each came from is not part of the rule.
_Avoid_: binding (that is a name's), context (that is the AAD's), opener

**Name binding**:
The cache's record that a keyset name resolved to a keyset id, and when.
A name is a *lookup ZeroKMS answers*, not an identity — ZeroKMS allows
renames — so a binding is trusted only within a window, a keyset holds at
most one at a time, and no binding outlives the id it names.
_Avoid_: alias (the struct is called `Alias`; the concept is a binding),
name cache entry

**Freshness window**:
How long a name binding is trusted before the next selection by that name
asks ZeroKMS again (`DEFAULT_NAME_TTL`, five minutes;
`StackCipherBuilder::keyset_name_ttl`). It bounds how long a rename can go
unnoticed by a running process, the way a resolver's TTL does; `ZERO` makes
every selection by name a round trip. Selection by id has no window.
_Avoid_: cache expiry, staleness (a binding past its window is *stale*, the
window itself is not)

**Resolution ticket**:
A monotonic stamp (`Resolution`) a lookup takes on its way to ZeroKMS and
hands back on insert. Resolutions run outside the cache lock, so answers
land in any order; the ticket is what says which *question* was later, and a
binding follows the later question rather than the earlier arrival.
_Avoid_: generation, version, sequence number

**Watermark**:
The place in the resolution order of the latest answer the cache holds
nothing of to order an older answer against: an entry eviction has dropped,
or ZeroKMS's answer that a name is bound to nothing. Once an entry is gone
there is nothing left to order an older answer for that keyset against, and
a negative answer is held as no binding at all, so no binding is made from
an answer older than the watermark. One watermark for every name, not one
per forgotten name — a cache whose whole contract is a bound must not grow
a record per eviction or per unbound name.
_Avoid_: tombstone, negative cache, evicted binding (it is the entry's
place, not a binding's), eviction watermark (eviction is one of two things
that raise it)

**Foreign keyset**:
A keyset other than the one a `KeysetCipher` is bound to, from that
handle's point of view. Handing it a leaf sealed under one is
`Error::ForeignKeyset`, refused before any key is retrieved — the
guarantee a tenant-scoped handler asked for by taking a handle.
_Avoid_: wrong keyset, other tenant

## Guest memory (Go host)

**Reservation**:
The guest's whole linear memory, address space of the module's declared
maximum taken once (`mmap PROT_NONE`, `VirtualAlloc MEM_RESERVE`) so the
memory never moves. Growth commits more of it from the front.
_Avoid_: buffer (that is wazero's view of the committed part), allocation

**Commit**:
Making a range of the reservation readable and writable as the guest grows,
and locking it. A commit is what a lock is granted or refused on.
_Avoid_: grow (that is the guest's request; the commit is the host's answer)

**Lock**:
Pinning committed memory in RAM (`mlock`, `VirtualLock`) so it is never
written to swap, and on Linux excluding the reservation from core dumps
(`MADV_DONTDUMP`). "Locked", of a client, means both held.
_Avoid_: pinned, wired

**Lock policy**:
What a refused lock means for a client. *Best effort*, the default: the
refusal is recorded and reported (`MemoryLocked`, `MemoryLockError`) and
the client works on with memory that may be swapped. *Strict*
(`RequireLockedMemory`): `NewClient` fails with `ErrMemoryLock`, and so
does any later call whose growth cannot be locked.
_Avoid_: mode, hard/soft

**Growth refusal**:
Under the strict policy, a commit whose lock was refused and was therefore
given back before the guest saw it. It fails the call that needed it and
leaves the client's lock report unchanged, since nothing unlocked was
admitted. A refusal of the guest's own allocation aborts the guest and
closes the client.
_Avoid_: lock failure (that is the report of memory admitted unlocked)

**Heap fallback**:
A Go slice standing in for a reservation where none can be made: a
platform with no primitive this package uses, or a 32-bit host asked for
wasm's 4 GiB default. It still wipes on growth and release; it cannot be
locked, and the client reports so.
_Avoid_: default allocator (wazero's, which is never used), unlocked mode


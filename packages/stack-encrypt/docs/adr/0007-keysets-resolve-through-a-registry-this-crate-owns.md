---
status: accepted
date: 2026-09-24
---

# Keysets resolve through a registry this crate owns, and a key provider is bound to one backend key

CIP-3965 moves `stack-encrypt` onto `vitaminc-kms`'s key-provider traits, so
that ZeroKMS becomes one backend among several. The question that decides the
shape of everything else is where the **keyset** lives.

A keyset is a CipherStash concept. Vitamin C is a general-purpose cryptography
suite. An earlier proposal put a keyset-to-provider factory inside
`vitaminc-kms`, so that one provider could serve many keysets. This ADR records
why that was refused and what replaced it.

## Decision

**`vitaminc-kms` knows nothing about keysets.** A `KeyProvider<N>` is bound at
construction to **one backend key** — a KMS key ARN, a Key Vault key name, a
Transit key name, a `CryptoKey`, or a ZeroKMS keyset. It has no per-call
selector. Selecting *which* backend key to use is the caller's business, and
the caller here is this crate. See cipherstash/vitaminc ADR-0003 and ADR-0004.

**`stack-encrypt` owns the keyset boundary**, through `KeysetRegistry`:

```rust
pub trait KeysetRegistry {
    type Provider: KeyProvider<32> + IndexKeyProvider<32>;
    type Error: std::error::Error + Send + Sync + 'static;

    fn resolve(&self, keyset: &KeysetRef)
        -> impl Future<Output = Result<Option<Resolved<Self::Provider>>, Self::Error>> + MaybeSend;
}
```

`StackCipher<R: KeysetRegistry>` keeps the LRU and the name TTL that ADR-0002
describes, so every backend inherits one tested implementation of them. A
registry does no caching of its own.

**`impl KeysetRegistry for Arc<StackKms>` lives here**, behind a `zerokms`
feature, because the orphan rule leaves it nowhere else: `impl KeyProvider for
ZeroKmsKeyset` is a foreign trait on a local type and must be in `stack-kms`;
this one is a local trait on a foreign type and must be here.

## Why the boundary is free

The obvious objection is that a provider bound to one keyset must cost a round
trip per keyset, where a provider taking a keyset per call would not.

It does not, because **ZeroKMS's own protocol carries `keyset_id` once per
request, not per payload.** `RetrieveKeyRequest` and `GenerateKeyRequest` each
hold one `keyset_id: Option<IdentifiedBy>`, which the server resolves to one
authority key for the whole batch through `get_authority_key`; `None` means the
client's default keyset. `RetrieveKeySpec` — the per-payload part — carries no
keyset id at all.

So the per-call `keyset_id: Option<Uuid>` on the trait this replaced was never
a selector. It was a per-request constant the caller had already fixed before
it built the batch, and `main` already fanned out one `retrieve_keys` call per
distinct keyset.

A provider bound at construction is therefore a **more faithful** model of the
wire protocol than the trait it replaces, and costs zero extra round trips. The
boundary this ADR draws is not a compromise paid for with latency; it is the
protocol's own shape.

## What a keyset is when the backend is not ZeroKMS

On ZeroKMS a keyset is a service-side object with an id, an optional name, and
a root from which the index key derives, and `load_keyset` returns all of it in
one round trip.

Elsewhere there is no such object, so a keyset is a **deployment config entry**:
a backend key handle plus the persisted `KeyId` of that key's index key,
resolved from a static map. `vitaminc-kms`'s `FixedIndexKeySource<T>` already
pairs exactly those two things, which is why this change needs no new vitaminc
code. A single-entry map is the common case — one backend key, one keyset,
`KeysetRef::Default`.

**Every keyset must have an index key, loaded eagerly at resolution.** On
ZeroKMS it arrives in the same `load_keyset` round trip, so this is free; a
vendor registry must be configured with one. A keyset that resolved without an
index key would fail at the first *query* rather than at resolution, and a
freshly minted index key makes every term already written under the old one
unfindable. Neither failure is one a caller can act on where it appears.

## Consequences

- **`resolve` returns `Result<Option<_>, _>`, not `Result<_, _>`.** The three
  outcomes are distinct because the name cache treats them differently.
  `Ok(Some(_))` is an answer. `Ok(None)` is *also* an answer — a definite "no
  such keyset" — and it unbinds a name the cache had bound, so a stale binding
  cannot outlive the registry's own denial. `Err(_)` is **not** an answer: a
  transport failure says nothing about the name and leaves the cache as it was.
  Folding the negative into `Self::Error` would put that distinction out of
  reach, since the cache cannot name a backend-specific error variant.

- **`Provider` is an associated type, not a boxed one.** `KeyProvider` is
  generic over `const N` and returns `impl Future`, so it is not
  dyn-compatible and there is no `Box<dyn KeyProvider>` to hand back. Every FFI
  consumer must therefore name one concrete registry type. The WASI guest names
  `Arc<StackKms<..>>`.

- **`stack-kms` is an optional dependency of `stack-encrypt`.** With `zerokms`
  off, `cargo tree` carries no ZeroKMS crate at all. That is what makes the
  backend-neutral claim checkable rather than aspirational, and it is why
  `Descriptor::MAX_LEN` is spelled here rather than imported from the ZeroKMS
  protocol (with a `zerokms`-gated test pinning the two equal).

- **No gating on `BINDING`, `ISOLATION` or `RECONSTRUCTION`.** A deployment
  that requires a `Bound` backend asserts on the constant itself. Refusing to
  build a cipher over an `Unbound` provider would make the traits' own
  capability constants a policy this crate enforces on everyone.

- **The keyset stays the whole merge rule.** Two `Pending`s merge when they
  name the same keyset. Provider *instance* identity is deliberately not the
  rule: two ciphers built separately over one keyset must merge, and a registry
  is free to hand out a fresh provider value per resolution.

- **A keyset the registry cannot resolve fails the whole batch**
  (`Error::UnknownKeyset`), matching ZeroKMS's all-or-nothing batch semantics.

## Not decided here

Backend key rotation for vendor keysets. `CachingKeyProvider`, which would
rarely hit against `PerValue` isolation and would drop the per-retrieval audit
entry against a `Bound` backend.

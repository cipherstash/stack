---
status: accepted
date: 2026-09-12
---

# The keyset id goes in the v1 leaf without a format bump, and a keyset name is a bounded lookup

CIP-4037 made `StackCipher` client-scoped — one ZeroKMS client, many keysets —
and moved everything that *mints* onto `KeysetCipher`, the cipher bound to one
of them. Two decisions in that change are worth recording, because both trade
something away and neither is obvious from the code alone.

## 1. The v1 leaf layout gained 16 bytes in place, with no `FORMAT_VERSION` bump

A `SealedValue` now carries the id of the keyset its data key was minted under:
16 raw UUID bytes immediately after the version byte, ahead of the `iv`. That
is what lets `StackCipher::decrypt` open leaves from any keyset — the leaf says
which keyset to retrieve from, so the caller does not have to — and what lets a
leaf lifted out of its tree, which is what a database column holds, stay
self-describing.

The field was inserted into the v1 layout and `SealedValue::FORMAT_VERSION`
stayed at `0x01`. Normally that is exactly the change a version byte exists to
mark. Here it is safe, and a bump would have bought nothing:

- The crate is unpublished (`publish = false`, 0.1.0) and nothing produced by
  it is stored anywhere. There is no old-layout leaf in the world to read.
- An old-layout leaf could not be *silently* misread even if one existed. The
  keyset id is bound into the leaf AAD alongside the version byte —
  `PAE("stack-encrypt/leaf", version, keyset_id, derived_aad, tag)` — so a leaf
  sealed under the old derivation fails authentication, rather than parsing
  under the wrong rules and yielding plausible bytes. The same binding is what
  stops a stored leaf being re-pointed at another keyset.
- The commit is already a breaking change (`!`) for other reasons:
  `SealedValue::from_parts` / `into_parts` carry the keyset id first, encrypt
  moved to `cipher.default_keyset()`, and `Request::retrieve_data_key` takes a
  keyset id.

So the version byte is spent once, when there is a reader to protect. The next
layout change — after the first release that stores leaves — must bump it.

### Amendment, 2026-09-24: the same reasoning, applied a second time

CIP-4140 changed the layout again, and again left `FORMAT_VERSION` at `0x01`.
The ZeroKMS-shaped `iv` (16 bytes) and `tag` (`u16` length + bytes) became one
opaque `key_id` (`u16` length + bytes):

```text
version(0x01) ‖ keyset_id:16 ‖ key_id_len:u16 ‖ key_id ‖ ciphertext
```

with the leaf AAD `PAE("stack-encrypt/leaf", version, keyset_id, derived_aad,
key_id)`.

The reason for the field is ADR-0007: a `KeyProvider`'s `KeyId` is **opaque**.
A ZeroKMS key id happens to be an `(iv, tag)` pair, but an AWS or Vault one is
not, and the envelope must not know. Splitting the provider's own id into
ZeroKMS's two parts would have been generic-looking code that silently
corrupted leaves on every other backend.

The three reasons above hold unchanged, and the first is still the load-bearing
one: the crate is unpublished and nothing it produces is stored anywhere. The
second is if anything stronger here — `key_id` is bound into the leaf AAD in
the position `tag` used to hold, so an old-layout leaf fails authentication
rather than parsing its `iv` as a length prefix.

The keyset id stays in the envelope rather than moving inside `key_id`, for a
reason that only appears once the backend is a variable: `decrypt` must know
**which backend to ask** before it can parse a blob that only that backend
defines. Routing metadata cannot live inside the thing it routes.

This is the second and last spend. The rule above is unchanged — the next
layout change, after the first release that stores leaves, must bump the
version byte.

### Amendment, 2026-10-06: the key-id layout is format 2, and format 1 is still read

The amendment above was written in cipherstash-suite, when nothing was
published. That changed before the key-id layout landed: stack-encrypt 0.1.0
and 0.2.0 shipped to crates.io on 2026-10-04 with the format-1 layout below,
and a deployment on 0.2 stores leaves in it. The reason the amendment gave for
keeping `0x01` — nothing is stored — is no longer true. So the rule applies,
and the key-id layout bumps the version byte.

**Format 2** is the key-id layout, and every new leaf is written in it:

```text
version(0x02) ‖ keyset_id:16 ‖ key_id_len:u16 LE ‖ key_id ‖ ciphertext
AAD = PAE("stack-encrypt/leaf", [0x02], keyset_id, derived_aad, key_id)
```

**Format 1** is what 0.1 and 0.2 wrote. It is still read, never written:

```text
version(0x01) ‖ keyset_id:16 ‖ iv:16 ‖ tag_len:u16 LE ‖ tag ‖ ciphertext
AAD = PAE("stack-encrypt/leaf", [0x01], keyset_id, derived_aad, tag)
```

The format-1 AAD is the derivation 0.2 computed, byte for byte. It binds the
tag and not the IV. A wrong IV still fails, because it names another data key
and the AEAD refuses the result.

How a format-1 leaf is read:

- `SealedValue::from_bytes` parses the format-1 layout and forms the opaque
  key id `iv ‖ tag`. That is exactly the key id a ZeroKMS provider
  (`stack_kms::ZeroKmsKeyset`) mints and splits: a 16-byte IV, then the tag.
  So the ZeroKMS provider retrieves the key with the same IV, tag and
  descriptor that 0.2 sent, and nothing in `stack-kms` changes.
- The leaf remembers its format. It opens under the format-1 AAD, and
  `to_bytes` writes it back in the format-1 layout, so the stored bytes
  round-trip unchanged. `SealedValue::from_v1_parts` rebuilds one from the
  `(keyset_id, iv, tag, ciphertext)` parts that 0.2's `into_parts` returned.
  The serde form carries the format too.
- Any other version byte is `LeafBytesError::UnknownVersion`.

**A format-1 leaf on a registry that is not ZeroKMS fails closed.** Only
ZeroKMS ever wrote format 1. Another backend would read `iv ‖ tag` as a key id
of its own: an AWS or Vault provider would send those bytes to its service, and
a fake might hand back some key. The AEAD would still refuse the result, but
the request should not be made, and the failure should say what is wrong. So
`KeysetRegistry` has a defaulted constant, `READS_V1_LEAVES = false`. Only
`impl KeysetRegistry for Arc<StackKms>` sets it to `true`. When a batch holds a
format-1 leaf and the registry does not read them, the dispatch refuses the
whole batch with `Error::V1LeafNeedsZeroKms { keyset_id }` before it resolves a
keyset or asks for a key.

We put the signal on the registry, not on the provider, because the provider
traits are `vitaminc-kms`'s and know nothing of this crate's leaf formats. A
registry also answers for every keyset it resolves, and a format-1 leaf can
only come from a ZeroKMS keyset. We considered two other choices and rejected
them. Hand any registry the `iv ‖ tag` key id: this works for ZeroKMS, but on
any other backend it fails late, with a backend error or an AEAD error that
reads like tampering. Guess ZeroKMS from the provider's constants
(`ClientAndServer`, `PerValue`, `Bound`): another backend can declare the same
values.

The tests that hold this are in `tests/format_v1.rs`. Two leaves there are real
format-1 ciphertext: stack-encrypt at cipherstash/stack `327b4dbce` (the 0.2.0
line) sealed them under a fixed data key. The new code decrypts them, and the
same file shows a format-1 leaf reaching ZeroKMS as its IV and tag. The file
also shows that index terms derive exactly as 0.2 derived them under the same
index key. `src/cipher.rs` pins both AAD derivations and both layouts.

The version byte is now spent for real. The next layout change must bump it to
`0x03`, and it must keep reading formats 1 and 2 for as long as stored data
can hold them.

## 2. A keyset name is a lookup with a bounded freshness window, not an identity

A keyset's **id** is its identity: globally unique, carried in every leaf, and
never re-checked once resolved. A **name** is not. ZeroKMS answers a name with
an id and allows a keyset to be renamed, so a name this process resolved
earlier can mean a different keyset later. The cache therefore treats a
name-to-id binding the way a resolver treats a DNS record.

The rules, each of which exists because the alternative was a live defect
found in review:

- **A binding is fresh only within a window** (`DEFAULT_NAME_TTL`, five
  minutes; `StackCipherBuilder::keyset_name_ttl`; strictly `<`, so
  `Duration::ZERO` is never fresh whatever the clock's resolution). After it,
  the next selection by that name asks ZeroKMS again and the binding is
  refreshed or moved. Within it, a rename is invisible — that is the cost, and
  it is bounded. Selection by id is never re-asked.
- **One binding per keyset.** A keyset has one name at a time in ZeroKMS, so
  resolving it under a new name means its old name was renamed away, and that
  binding goes; a name that moves to another keyset is dropped from the keyset
  it used to name. Without this a renamed hot keyset grew the name index
  without bound, which is unacceptable in a structure whose whole contract is
  a bound.
- **A binding follows the later *lookup*, not the earlier *arrival*.**
  Resolutions run outside the cache lock, so their answers land in any order.
  Every lookup that goes to ZeroKMS carries a monotonic `Resolution` ticket
  from `get` to `insert`, and an answer is applied only if it is later than the
  one that already spoke for that keyset or name.
- **An answer older than the one a keyset already holds is dropped whole**, not
  just for the name it asked under. Comparing per name only was not enough: a
  rename could be undone *across two names* — a selection by the old name
  starts, the keyset is renamed, a selection by the new name starts and answers
  first, and the older answer then found no binding for the old name to lose to
  and rebound it, routing a name ZeroKMS may since have given to another keyset
  here for a whole window.
- **Eviction leaves a watermark.** Evicting an entry drops both the keyset's
  place in the order and its binding, and an answer older than what went would
  then find nothing left to say it is the older one. Every eviction therefore
  records the *entry's* place (not its binding's — an entry whose name has
  already moved to another keyset is precisely the one an old answer would
  rebind), and no binding is made from an answer older than that. It is one
  watermark for all names rather than one per forgotten name, which is what
  keeps the structure bounded; the price is that it also refuses some bindings
  an older lookup could have made safely, costing a round trip on the next
  selection by such a name — in the eviction regime that is already paying
  them.
- **A negative answer raises the same watermark.** ZeroKMS answering a name
  lookup with "no such keyset" is an answer about the name, held as no binding
  at all: the binding an earlier lookup made goes, and the watermark rises to
  that lookup so an earlier positive answer still in flight cannot bind the
  name after ZeroKMS has said it is bound to nothing. Only ZeroKMS's own answer
  counts; a lookup that failed to get one leaves the cache as it was.

## Consequences

- **Key material is never the thing at risk.** An id's index key is the same
  whichever lookup asked for it, so every rule above governs *names only*; an
  answer too old to order still caches its keyset by id. Nothing stored depends
  on the cache at all — a leaf carries its keyset id and a term carries nothing
  — so eviction is invisible except for the round trip the next lookup pays.
- **A rename is visible within the window, never sooner.** Callers that cannot
  tolerate that select by id, or set `keyset_name_ttl(Duration::ZERO)` and pay
  a round trip per selection.
- **The default keyset is not a special case in any of this.** Its state never
  changes and it never evicts, but its builder-time name ages, moves and
  reorders exactly like any other keyset's, and the cache reaches it through
  the same accessors.
- **These rules are the cache's, not ZeroKMS's.** ZeroKMS remains the authority
  on what a name means and on whether the client may use the keyset at all; the
  window only bounds how long this process trusts an answer it already has.

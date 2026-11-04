---
status: proposed
date: 2026-11-04
---

# Two key modes for key vendor backends

CIP-5203 makes Stack Encrypt usable with AWS KMS, Azure Key Vault, HashiCorp
Vault Transit and Google Cloud KMS as alternatives to ZeroKMS. An earlier
project tried to make KMS support fully general in the vitaminc layer. That
was too complex, so this work adds key vendor backends at the
`DataKeySource` / `IndexKeySource` seam in `stack-kms` and accepts less than
ZeroKMS parity. Each gap is a stated trade-off.

ZeroKMS gives each value its own data key and settles a batch of N values in
one call. The vendors cannot do this. AWS KMS, Google Cloud KMS and Azure Key
Vault unwrap one key per call and have no batch operation. Only Vault Transit
batches. There is no single vendor design that is both "per-value keys" and
"few vendor calls". We therefore give each vendor backend two key modes, and
the customer chooses one per keyset:

- **Wrapped data key.** No key outlives the settle that needed it. Each value
  has its own data key, generated and wrapped by the vendor key, and stored
  wrapped in the leaf. The index key is wrapped in the keyset record and
  unwrapped once per settle. A settle of N values costs about 1 + N vendor
  calls. The vendor sees, and can refuse, every settle and every value.
- **Derived data key.** The keyset record holds a root key wrapped by the
  vendor key. The cipher unwraps it once and caches it for a TTL. Each data
  key is HKDF-SHA256(root key, salt = iv, info = keyset id ‖ descriptor), and
  the index key is derived from the same root key under a separate label.
  Vendor calls are O(keysets), not O(values). The vendor sees, and can refuse,
  the keyset unwrap, not the value.

In both modes, search terms are built in the client, as they are today, and
Postgres holds no usable key material.

## Considered options

- **One mode per vendor.** Rejected. A customer who needs per-value audit and
  refusal and a customer who needs throughput would each have no option on
  some vendors.
- **Vendor-side PRF for search terms** (AWS `GenerateMac`, GCP MAC keys,
  Vault `hmac`), so that the index key is never in the client. Rejected. The
  vendor would receive the search input, or a hash of it that it can
  brute-force for low-entropy values. One call per term would make a match
  index cost about 20 calls per value. Azure has no MAC operation. "No key
  outlives one settle" gives the same refusal property without these costs.
- **A hybrid mode** (per-value data keys and a cached index key). Rejected.
  Its trade-off is not clear enough to justify a third mode in the test
  matrix.
- **Vendor-side encryption of plaintext.** Rejected. It moves the trust
  boundary to the vendor and has size limits (4 KiB on AWS).

## Consequences

- The cipher enforces key lifetime, not each backend. `load_index_key`
  returns a lifetime (*this settle only*, *cache for TTL*), and the per-keyset
  cache obeys it. One test then covers every backend.
- Under wrapped data keys, each separate `encryptQuery` costs one vendor
  round trip. A caller who wants one round trip composes query terms into one
  settle.
- The static key backend offers derived data keys only, because a static key
  is always in memory.
- A vendor backend refuses ZeroKMS-only features (decryption policy, lock
  context, `UnverifiedContext`) with a typed error. It never ignores them.
- A cipher holds ZeroKMS and at most one key vendor backend. v1 has no
  migration between backends in either direction.

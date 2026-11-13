---
status: proposed
date: 2026-11-04
---

# Derived data keys for key vendor backends

CIP-5203 makes Stack Encrypt usable with AWS KMS, Azure Managed HSM, HashiCorp
Vault Transit and Google Cloud KMS as alternatives to ZeroKMS. An earlier
project tried to make KMS support fully general in the vitaminc layer. That
was too complex, so this work adds key vendor backends at the
`DataKeySource` / `IndexKeySource` seam in `stack-kms` and accepts less than
ZeroKMS parity. Each gap is a stated trade-off. `stack-encrypt` does not
change.

ZeroKMS gives each value its own data key and settles a batch of N values in
one call. The vendors cannot do this. AWS KMS, Google Cloud KMS and Azure
Managed HSM unwrap one key per call and have no batch operation. Only Vault Transit
batches. A vendor call for each value would make a settle of N values cost
about N vendor calls.

We therefore use **derived data keys**. The keyset record holds a root key
wrapped by the vendor key. The vendor key source unwraps it once and caches
it for a TTL. Each data key is HKDF-SHA256(root key, salt = iv, info =
keyset id ‖ vendor ‖ mode ‖ descriptor), and the index key is derived from
the same root key under a separate label. Vendor calls are O(keysets), not
O(values). The vendor sees, and can refuse, the unwrap of the keyset's root
key, not each value.

Search terms are built in the client, as they are today, and Postgres holds
no usable key material.

## Considered options

- **Vendor-side PRF for search terms** (AWS `GenerateMac`, GCP MAC keys,
  Vault `hmac`), so that the index key is never in the client. Rejected. The
  vendor would receive the search input, or a hash of it that it can
  brute-force for low-entropy values. One call per term would make a match
  index cost about 20 calls per value. Azure has no MAC operation.
- **Vendor-side encryption of plaintext.** Rejected. It moves the trust
  boundary to the vendor and has size limits (4 KiB on AWS).

## Consequences

- The TTL is on the root key, in the vendor key source
  (`VendorKeySource::with_root_key_ttl`). It covers the data keys. It does
  not cover the index key: the cipher keeps that until its keyset cache
  evicts it, as it does for ZeroKMS. After the vendor refuses a keyset, a
  running process can no longer seal or open its values once the cached
  root key expires, but it can still build that keyset's query terms until
  the keyset leaves the cache. The capability matrix in the
  `stack-kms-vendor` crate docs states this.
- The vendor cannot see or refuse each value.
- The keyset record stores a key mode byte, and the mode is bound into each
  derivation, so a later mode changes no format.
- A vendor backend refuses ZeroKMS-only features (decryption policy, lock
  context, `UnverifiedContext`) with a typed error. It never ignores them.
- A vendor with no associated data (Azure Managed HSM, a Vault Transit
  key that is not derived) gets a bound key: the key with a digest of the
  associated data beside it, which the client checks after the unwrap.
  The digest has no secret key, so this needs a wrap that only the vendor
  key can make. A public-key wrap cannot give that: anyone with the public
  key could put a root key that they know into a keyset record. So Azure
  is supported only through Managed HSM (AES key wrap). Azure Key Vault
  holds only RSA and EC keys, and is not supported.
- A cipher holds ZeroKMS and at most one key vendor backend. There is no
  migration between backends in either direction.

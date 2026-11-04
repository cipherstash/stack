---
status: proposed
date: 2026-11-04
---

# A v2 leaf names its key backend and key mode

A v1 leaf (`SealedValue`, `cipher.rs`) is
`0x01 ‖ keyset_id ‖ iv ‖ tag_len ‖ tag ‖ ct`. It has no field that names a
key backend, because ZeroKMS was the only one. ADR-0009 lets one cipher hold
ZeroKMS and one key vendor backend, with two key modes. A reader must
therefore know which backend and which mode sealed a leaf before it asks for
a key.

We keep v1 unchanged, byte for byte, and ZeroKMS writers continue to write
it. Every value sealed under ZeroKMS stays decryptable with no migration.
Leaves sealed by a key vendor backend use v2:

```
0x02 ‖ backend ‖ mode ‖ keyset_id ‖ iv ‖ tag_len ‖ tag ‖ ct
```

Under wrapped data keys the tag holds the wrapped data key. Under derived
data keys the tag is empty, and the iv is the derivation salt. `leaf_aad`
already binds the version and the header into the AAD, so the new bytes are
authenticated with no new mechanism.

A v1-only reader refuses a v2 leaf with `UnknownVersion`. A cipher that does
not hold the backend a v2 leaf names refuses it before any key call, as it
refuses a foreign keyset today. EQL carries the leaf as opaque `SealedValue`
bytes, so the EQL payload shape does not change. The TypeScript FFI does not
use this leaf format (protect-ffi goes through `cipherstash-client`), so it is
not affected.

## Considered options

- **A v2 for every leaf, ZeroKMS included.** Rejected. It changes stored data
  and every writer for no gain, and it puts existing data at risk.
- **Infer the backend from the keyset id.** Rejected. A reader would need
  every keyset record before it could even route a leaf, and a wrong record
  would produce a failed unwrap rather than a clear refusal.

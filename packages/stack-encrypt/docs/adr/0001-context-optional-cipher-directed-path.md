---
status: superseded by ADR-0003
date: 2026-09-03
---

# The cipher-directed path takes any context; the target-directed path takes a `NonEmpty`

Superseded on 2026-09-12 by
[ADR-0003](0003-declarative-targets-and-ciphertext-transcoding.md). The replacement
retains the allowance for absent context on the cipher-directed path and the
nonempty-context requirement for EQL operations, but moves target context
requirements into declarations executed by core code. The original rationale
below is retained as history; ADR-0003 records the accepted design, which
this crate's operation descriptions, native readers, and derives implement.

`StackCipher::encrypt` / `decrypt` / `decipher` (the cipher-directed path) accept
any `IntoAad`, including `()`, exactly as vitaminc's `Aes256Cipher` does: sealing
under no associated data is a legitimate AEAD use, and the same `StackCipherText`
type opens symmetrically. The requirement that a context be **supplied and
non-empty** is a property of EQL types — ciphertexts and index terms stored for
query, where an empty context would make ciphertexts transplantable between
fields and collapse per-field term domains — so it is enforced on *their*
`EncryptFrom` / `DecryptInto` / term-generator implementations, by type (a leaf
is implemented for `vitaminc_protected::NonEmpty<T>` alone; the crate owns no
context trait of its own), and nowhere else.

The WASI guest mirrors the split: its value exports (`se_encrypt` and friends)
are the cipher-directed path and take any AAD, a `nil` Go slice included; its
record and term exports parse their context into a `NonEmpty` and refuse an
empty one with `STATUS_ENCODING`.

## Considered options

- **Require `NonEmpty` on the cipher-directed path too** (remove the public
  `Cipher` impl, route every seal through a `StackCipher` method that takes a
  `NonEmpty`). Rejected: it forces a context on callers that are not producing
  EQL types, and diverges from the vitaminc cipher contract the type is meant to
  mirror.
- **Re-check emptiness on the encoded bytes** (the previous `is_degenerate_aad`
  / `is_degenerate_prf_context` predicates). Rejected: an encoded context can
  only be judged on its bytes, and framing makes empty composites non-empty as
  bytes; vitaminc deliberately keeps `MaybeEmpty` (`IsEmpty` before 0.3.0) off `Aad` and `PrfContext`
  for that reason.

## Consequences

- A tree sealed cipher-directed under `()` and opened target-directed under a
  `NonEmpty` fails as an ordinary context mismatch — ZeroKMS refuses the key
  retrieval under the other descriptor (`Error::Kms`), and a key source that
  ignores descriptors lets it reach the AEAD (`Error::Aead`) — not as a
  special case. The two paths are different contracts on one ciphertext type;
  a front-end that seals cipher-directed but opens target-directed (the WASI
  guest's record plans) binds the same `NonEmpty` value on both sides.
- `0u64` and eight zero bytes are valid contexts: vitaminc's rule is that an
  integer is never empty. The byte collision the old predicate guarded
  against is real — `None::<&str>` encodes as `pae([])`, eight zero bytes,
  the same as `0u64`, and `None` is constructible on the cipher-directed path
  and inside a `NonEmpty` tuple — but it is the AEAD's collision, not the
  crate's to police: the two shapes render to different descriptors (`()` and
  `0u64`), so ZeroKMS binds them to different keys and a cross-open is
  refused there. See the descriptor module docs.
- The context is also the ZeroKMS descriptor of every data key
  (`Descriptor::from_piece`), so a cipher-directed seal under `()` requests its
  keys under the empty descriptor. That is the caller's choice, made visible
  in the ZeroKMS log.
- Future architecture reviews should not re-propose "closing" the
  cipher-directed path; the asymmetry is the design.

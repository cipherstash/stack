---
'@cipherstash/stack': minor
---

Add the EQL v3 bigint (int8) domain family and Supabase adapter support
(CIP-3291).

`@cipherstash/stack/eql/v3` gains `types.Bigint`, `types.BigintEq`,
`types.BigintOrdOre`, and `types.BigintOrd` — the same capability families
every other int has (`*_ord_ope` is out of scope, tracked as CIP-3403) —
plus the corresponding `EncryptedBigint*Column` classes, union membership,
and plaintext inference. The SDK-wide `Plaintext` union gains `bigint`.

**Semantics:**

- plaintext is a JS `bigint`: encrypt takes a `bigint` and a bigint column
  ALWAYS decrypts to a `bigint` (never a precision-lossy `number`);
- bounds are the full PostgreSQL `bigint`/i64 range (`-2^63 … 2^63 - 1`),
  enforced at the protect-ffi boundary — out-of-range values surface as
  encryption errors, not silent truncation;
- index emission follows the non-text numeric rule: `bigint_eq` emits
  `unique` (hm); `bigint_ord` / `bigint_ord_ore` emit `ore` only (equality is
  answered via `ob`, like `integer_ord`);
- the Supabase v3 adapter (`encryptedSupabaseV3`) is value-generic, so bigint
  columns work across insert / filters (`eq`, `gte`, …) / decrypted results,
  with filter value types pinned to `bigint` at the type level.

**GATED — pending protect-ffi release.** The domains are fully typed and
schema-complete, but LIVE encrypt/decrypt requires the next
`@cipherstash/protect-ffi` release: the pinned 0.27.0 `JsPlaintext` cannot
marshal a JS `bigint` across the native (Neon) boundary, so encrypting a
`bigint` throws at runtime today. Live matrix coverage is explicitly skipped
with this reason (`liveGate` in the v3 test catalog) and activates when the
pin is bumped; runtime coverage in this release is mock-based.

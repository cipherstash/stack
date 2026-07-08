---
'@cipherstash/stack': minor
---

Add the EQL v3 bigint (int8) domain family and Supabase adapter support
(CIP-3291), and bump `@cipherstash/protect-ffi` to `0.28.0` to activate live
bigint encrypt/decrypt.

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

**Live since protect-ffi 0.28.** `@cipherstash/protect-ffi` 0.28.0 marshals a
JS `bigint` across the native (Neon) boundary — i64-bounds-checked, with a
`RangeError` for out-of-range values — so the bigint domains encrypt and
decrypt end-to-end. The full v3 matrix suites (`matrix-live`,
`matrix-live-pg`) exercise every bigint domain against a live client and a
real `eql_v3` Postgres extension.

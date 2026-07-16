---
'@cipherstash/stack': minor
---

`@cipherstash/stack/wasm-inline` now exposes `encryptQuery` and
`encryptQueryBulk` on `WasmEncryptionClient` (#662) — searchable encryption
is reachable on Deno/edge runtimes. Previously the WASM entry exposed only
`encrypt`/`decrypt`/`isEncrypted`, so encrypted WHERE-clause search was
architecturally impossible on the edge even though the underlying protect-ffi
WASM build carries the capability.

The new methods mint ciphertext-free EQL v3 query terms — equality,
free-text match, ORE range, and JSON containment/selector — with the same
index-type resolution as the native client (explicit `queryType`, or
inference from the column's configured indexes). Cast the term to the
column's `eql_v3.query_<domain>` type in SQL to reach the indexed operators.
Errors throw, consistent with the WASM surface's `encrypt`/`decrypt`; the
bulk form is position-stable (`null` values pass through as `null`).

---
'@cipherstash/stack': patch
---

`encryptedDynamoDB` now refuses a `@cipherstash/stack/wasm-inline` client paired
with a legacy EQL v2 table, instead of failing at the first read with a
misleading error.

The adapter's v2 read path deliberately calls `decryptModel(item)` with **no**
table — a v2 table means nothing to a v3 client's reconstructor map, and the
native clients derive the table from the payloads anyway. `WasmEncryptionClient`
cannot do that: its decrypt requires the table and resolves date fields from a
per-table map, so the omitted argument surfaced as
`TypeError: Cannot read properties of undefined (reading 'tableName')` thrown
from deep inside the client — on the documented entry for Deno, Cloudflare
Workers and Supabase Edge Functions, which satisfies the adapter's client type
structurally and so was accepted with no cast.

The pairing is now rejected at the call site, with a message naming both the
combination and the fix. EQL v3 tables are unaffected: they are always passed
the table, so the wasm-inline client keeps working there.

Three comments in this package claimed audit metadata was forwarded "regardless
of client shape" and that "every client this package ships carries `.audit()` on
decrypt". Neither was true of the wasm-inline client, whose decrypt returns a
plain promise — the metadata is dropped, observably (it is logged at debug), and
the comments and the debug message now say so.

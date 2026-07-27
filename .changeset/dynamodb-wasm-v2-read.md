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
combination and the fix. The message is operation-neutral: the guard runs on all
four operations, so a plain-JS caller reaching the write path with a v2 table
gets a message that does not claim a read it never attempted.

`encryptModel` / `bulkEncryptModels` now also tolerate a client whose encrypt
returns a plain promise. They chained `.audit()` onto the result
unconditionally, which the wasm-inline client does not carry — so **every EQL v3
write through this adapter on that entry** failed with
`client.encryptModel(...).audit is not a function`, surfaced as a
`DYNAMODB_ENCRYPTION_ERROR` and so indistinguishable from a real encryption
fault. The read path already handled this; the write path now matches, via the
same fail-closed check that rejects a malformed result rather than passing an
unencrypted item through as a success. Audit metadata still has nowhere to go on
that client, so it is dropped and logged at debug — the write itself succeeds.

Three comments in this package claimed audit metadata was forwarded "regardless
of client shape" and that "every client this package ships carries `.audit()` on
decrypt". Neither was true of the wasm-inline client, whose decrypt returns a
plain promise — the metadata is dropped, observably (it is logged at debug), and
the comments and the debug message now say so.

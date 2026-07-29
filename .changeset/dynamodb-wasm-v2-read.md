---
'@cipherstash/stack': patch
---

`encryptedDynamoDB` now serves legacy `{ storedEqlVersion: 2 }` reads on the
`@cipherstash/stack/wasm-inline` entry, not just the native one.

The legacy read reconstructs the EQL v2 envelope around the **current v3 table**
and forwards that table exactly as a v3 read does, so both entries can serve it:
protect-ffi's `decrypt` accepts either wire generation regardless of the
client's `eqlVersion`, and the reconstructor map is keyed by the current schema
either way. Deno, Cloudflare Workers and Supabase Edge Functions can therefore
read rows written before the v3 migration; previously the pairing was refused
outright and those runtimes had no way to read that data at all.

Writes remain EQL v3-only on both entries.

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

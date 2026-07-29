---
'@cipherstash/stack': patch
---

`encryptedDynamoDB` now refuses a `@cipherstash/stack/wasm-inline` client when a
legacy read is requested with `{ storedEqlVersion: 2 }`, instead of failing at
the first read with a misleading error.

The adapter's native v2 read path relies on generation-agnostic payload decrypt.
`WasmEncryptionClient` cannot perform that compatibility read, so the former
path surfaced a deep client error on Deno, Cloudflare Workers and Supabase Edge
Functions rather than explaining the unsupported combination.

The pairing is now rejected at the call site, with a message directing callers
to the native entry for legacy reads. Writes remain EQL v3-only on both entries.

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

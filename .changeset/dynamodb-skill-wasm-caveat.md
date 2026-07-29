---
'stash': patch
---

The `stash-dynamodb` and `stash-encryption` skills now state which entries serve
a legacy EQL v2 DynamoDB read: both of them. Schema authoring is EQL v3-only
everywhere, but the read is not — it reconstructs the v2 envelope around the
current v3 table, and `decrypt` accepts either wire generation. Deno, Bun,
Cloudflare Workers and Supabase Edge Functions can therefore read pre-migration
items through `@cipherstash/stack/wasm-inline`.

The `stash-dynamodb` API reference also claimed audit metadata forwards to
ZeroKMS "regardless of client shape". It does not: the wasm-inline client's
operations return a plain promise with no `.audit()`, so its audit metadata is
dropped (logged at debug). The reference now says so, and says the operation
still succeeds.

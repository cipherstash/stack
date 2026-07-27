---
'stash': patch
---

The `stash-dynamodb` and `stash-encryption` skills documented EQL v2 decrypt as
unconditionally supported, without noting that `@cipherstash/stack/wasm-inline`
is EQL v3 only. Since that is the documented entry for Deno, Bun, Cloudflare
Workers and Supabase Edge Functions — runtimes commonly paired with DynamoDB — a
reader following the skill hit a runtime refusal with no forewarning. Both skills
now state that legacy v2 items are readable on the native `@cipherstash/stack`
entry only.

The `stash-dynamodb` API reference also claimed audit metadata forwards to
ZeroKMS "regardless of client shape". It does not: the wasm-inline client's
operations return a plain promise with no `.audit()`, so its audit metadata is
dropped (logged at debug). The reference now says so, and says the operation
still succeeds.

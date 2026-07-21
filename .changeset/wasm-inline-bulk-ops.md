---
'@cipherstash/stack': minor
'stash': patch
---

Add `bulkEncrypt` / `bulkDecrypt` to `@cipherstash/stack/wasm-inline`, so a list of encrypted rows costs **one** ZeroKMS round trip instead of one per row.

The WASM entry previously exposed no bulk operations at all — only `encrypt` / `decrypt` — so rendering an N-row list on Deno, Cloudflare Workers, or Supabase Edge Functions meant N sequential ZeroKMS calls. Combined with the WASM cold start, that made list endpoints impractical on the edge, and it left the entry with no access to the bulk path the docs recommend for throughput.

```typescript
// Write: several columns across many rows, one round trip
const encrypted = await client.bulkEncrypt([
  { plaintext: "alice@example.com", table: users, column: users.email },
  { plaintext: "hello", table: users, column: users.bio },
])

// Read: a whole page in one call
const emails = await client.bulkDecrypt(rows.map((r) => r.email))
```

Both are index-aligned with their input, and `null` / `undefined` entries yield `null` at the same index without reaching ZeroKMS (an all-null batch makes no call at all). Because each entry names its own table and column, a single `bulkEncrypt` can cover several columns across many rows.

**The signature deliberately differs from the native entry's** `bulkEncrypt` / `bulkDecrypt`. It follows `encryptQueryBulk`, the bulk primitive already on this client: a plain index-aligned array with per-item routing, and errors that throw rather than a `{ data } | { failure }` envelope. There are no `{ id, plaintext }` payload envelopes — protect-ffi's `EncryptPayload` has no `id` field, so the native one is dropped at the FFI boundary and buys nothing when positions are already stable.

`bulkDecrypt` builds on the fallible FFI primitive, so when items fail it throws once and names **every** failing index with its reason, rather than surfacing the first and discarding the rest.

The model helpers (`encryptModel` / `decryptModel` and their bulk forms) remain Node-only: the WASM entry has no single-model operation to build them on, so those need their own port.

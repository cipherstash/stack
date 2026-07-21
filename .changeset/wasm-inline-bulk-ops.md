---
'@cipherstash/stack': minor
'stash': patch
---

**Breaking (`@cipherstash/stack/wasm-inline`):** every fallible method now returns a `Result` — `{ data } | { failure }` — instead of throwing. And `bulkEncrypt` / `bulkDecrypt` are added, so a list of encrypted rows costs **one** ZeroKMS round trip instead of one per row.

### Result alignment

`encrypt`, `decrypt`, `encryptQuery` and `encryptQueryBulk` previously threw on failure, and returned bare values on success. They now return `{ data } | { failure }`, with `failure.type` drawn from `EncryptionErrorTypes` (`EncryptionError` for encrypt-side operations, `DecryptionError` for decrypt-side) and `failure.code` carrying the FFI error code where there is one.

```typescript
// before
const encrypted = await client.encrypt(plaintext, { table: users, column: users.email })

// after
const result = await client.encrypt(plaintext, { table: users, column: users.email })
if (result.failure) throw new Error(result.failure.message)
const encrypted = result.data
```

This is the contract the native entry has always honoured, and the one `AGENTS.md` states outright: *"Operations return `{ data }` or `{ failure }`. Preserve this shape and error `type` values in `EncryptionErrorTypes`."* The WASM entry never followed it. That was drift rather than a design decision — nothing about WASM prevents it (`@byteslice/result` is already bundled into `dist/wasm-inline.js`), and it meant edge code had to be written in a different shape from every other surface, with failures that were easy to miss.

Fixed now because it is a breaking change and 1.0.0 has not shipped: `@cipherstash/stack@latest` is still `0.19.0`, so this surface has only ever been published under the `rc` tag. After GA it would have had to wait for a major.

`isEncrypted` is unchanged — a pure predicate with nothing to fail at, exactly as on the native entry.

### Bulk operations

```typescript
// Write: several columns across many rows, one round trip
const encrypted = await client.bulkEncrypt([
  { plaintext: "alice@example.com", table: users, column: users.email },
  { plaintext: "hello", table: users, column: users.bio },
])

// Read: a whole page in one call
const emails = await client.bulkDecrypt(rows.map((r) => r.email))
```

The WASM entry previously exposed no bulk operations at all, so rendering an N-row list on Deno, Cloudflare Workers, or Supabase Edge Functions meant N sequential ZeroKMS calls. Combined with the WASM cold start, that made list endpoints impractical on the edge.

Both are index-aligned with their input, and `null` / `undefined` entries yield `null` at the same index without reaching ZeroKMS (an all-null batch makes no call at all). Because each entry names its own table and column, a single `bulkEncrypt` can cover several columns across many rows — which is what makes the saving real, since a single-column batch would still cost one round trip per column.

`bulkDecrypt` builds on the fallible FFI primitive, so when items fail the `failure.message` names **every** failing index with its reason, rather than surfacing the first and discarding the rest.

The model helpers (`encryptModel` / `decryptModel` and their bulk forms) remain Node-only: the WASM entry has no single-model operation to build them on, so those need their own port.

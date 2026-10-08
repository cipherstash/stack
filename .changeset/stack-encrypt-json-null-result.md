---
'@cipherstash/stack': patch
'@cipherstash/stack-supabase': patch
'stash': patch
---

`encrypt` on a `types.Json` column now types its result as `Encrypted | null` when the plaintext may be `null`. A `null` document has always resolved to `{ data: null }` at runtime (it is stored as SQL NULL, not encrypted), but the result was typed `Encrypted`, so `result.data.c` compiled and then threw. `encrypt` is now generic over the plaintext's type: a literal `null`, or a value typed `JsonDocument`, gives `data: Encrypted | null`, through `.withLockContext()` and `.audit()` too. A value TypeScript knows is non-null, and every scalar column, still gives `data: Encrypted`. No runtime change. If your code reads `result.data` after encrypting a Json value that may be `null`, it must now check for `null` first. `EncryptOperation` and `EncryptOperationWithLockContext` take an optional result type parameter (default `Encrypted`), and the `EncryptResult<P>` helper type is exported from `@cipherstash/stack/encryption`.

`@cipherstash/stack-supabase`: the per-term query-encryption fallback (used when the client has no `bulkEncrypt`) now rejects a `null` envelope instead of sending the string `"null"` as a filter operand, matching the bulk path.

`stash`: the `stash-encryption` skill now says what `encrypt` returns for a `null` Json document.

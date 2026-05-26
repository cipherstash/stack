---
"@cipherstash/stack": patch
---

Fix: restore runtime null short-circuits in the encryption operation classes.

A prior refactor (`feat(stack): remove null from Encrypted type`) tightened the type signatures to disallow `null` and, alongside that, deleted the `if (value === null) return null` guards from every operation in `packages/stack/src/encryption/operations/`. The type guard does not survive runtime: callers reaching the operation through a cast (e.g. `null as any`), dynamic model walking, or JS interop would then have their null silently encrypted by protect-ffi into a real SteVec ciphertext (`{ k: 'sv', v: 2, ... }`) — which is observable, surprising, and breaks symmetry with the model-helpers layer that does still treat null as "absent" at the field level.

Restored, mirroring the pattern in `@cipherstash/protect`:

- `encrypt` / `encryptWithLockContext`: `if (plaintext === null) return null`.
- `bulkEncrypt` / `bulkEncryptWithLockContext`: per-element null filter; nulls are preserved in position in the output.
- `decrypt` / `decryptWithLockContext`: `if (encryptedData === null) return null`.
- `bulkDecrypt` / `bulkDecryptWithLockContext`: per-element null filter, position-preserving merge.
- `encryptQuery` / `encryptQueryWithLockContext`: `if (plaintext === null || plaintext === undefined) return { data: null }`.
- `batchEncryptQuery` / `batchEncryptQueryWithLockContext`: per-element null/undefined filter; null slots in the input array stay null in the result array.

Type adjustments to support the runtime behavior honestly:

- `BulkEncryptPayload['plaintext']`, `BulkEncryptedData['data']`, `BulkDecryptPayload['data']`, and the `T` of `BulkDecryptedData` all widen to `... | null`. Bulk APIs now accept and return mixed nullable arrays without filtering ahead of time.
- `EncryptedQueryResult` widens to include `null` so the batch query path can return position-stable arrays with null slots.
- `Encryption.decrypt()` accepts `Encrypted | null` (returns null for null input).
- `Encryption.encrypt()`'s public signature is unchanged — still `JsPlaintext` (no null). The runtime guard is defense in depth for the cases the type system can't catch.

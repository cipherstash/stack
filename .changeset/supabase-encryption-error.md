---
'@cipherstash/stack-supabase': patch
---

Populate `EncryptedSupabaseError.encryptionError` on encryption failures (#626).
The query builder's catch block previously hardcoded `encryptionError: undefined`,
so the typed field was always empty and callers had to detect encryption failures
indirectly (via `status`/`statusText` or `.throwOnError()`). It now threads the
underlying `EncryptionError` through — for both the v2 and v3 dialects — when the
failure originates in an encrypt/decrypt step, and leaves it unset for plain
PostgREST/API errors.

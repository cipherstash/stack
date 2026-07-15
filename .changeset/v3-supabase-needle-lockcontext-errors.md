---
'@cipherstash/stack-supabase': patch
'@cipherstash/stack': patch
---

Three correctness fixes surfaced while documenting the v3 surface:

- **Supabase `matches()` now rejects a short free-text needle.** A needle
  below the tokenizer's `token_length` blooms to zero tokens, so `bloom @> {}`
  matched (and the caller decrypted) every row — a fail-open exposure. The
  guard (`matchNeedleError`) was wired into the Drizzle adapter only; the
  Supabase adapter now applies it at the same term-resolution choke point, so
  both first-party surfaces reject identically. (Authoritative FFI-level backstop
  for the `encryptQuery` paths tracked in cipherstash/protectjs-ffi#138.)
- **Supabase `.withLockContext()` accepts the plain `{ identityClaim }` form**,
  not only a `LockContext` instance — matching the stack-level operations and
  the documented identity-aware example (widened to `LockContextInput`).
- **`EncryptionErrorTypes` is now `as const`**, so the `StackError` union
  actually discriminates: `switch (error.type)` narrows and `error.code` is
  reachable on the relevant branches. Without it every `type` was `string` and
  the documented exhaustive error handler did not compile.

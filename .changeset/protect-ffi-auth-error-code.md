---
'@cipherstash/protect-ffi': minor
---

Carry `stack-auth` diagnostics across the JavaScript boundary. Errors that
originate in `stack-auth` now expose `authCode`, `help`, and `url` on both the
native and WASM bindings, alongside protect-ffi's existing `code` field.

The boundary remains deliberately thin: `Error::Auth` and `Error::ZeroKMS` are
transparent miette diagnostics, so stack-auth continues to own the message,
instructions, and destination URL. Protect-ffi only serializes those fields and
reads the stable auth code from the typed `AuthError`; it does not classify the
message or maintain its own remedy taxonomy.

`getAuthErrorCode(err)` reads the new field and `ProtectAuthErrorCode` types it.
The auth taxonomy is separate from protect-ffi's closed `ProtectErrorCode` set.

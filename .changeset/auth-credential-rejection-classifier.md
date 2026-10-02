---
"@cipherstash/auth": patch
---

Internal addition to the underlying Rust crate: `AuthError` gains an
`is_credential_rejection()` classifier used by FFI front-ends to decide
whether refreshing the credential and retrying is sensible. No API or
behaviour change for `@cipherstash/auth` consumers.

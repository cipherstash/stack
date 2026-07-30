---
'@cipherstash/stack': patch
---

Fix the `Encryption()` auth-strategy doc examples to unwrap `create()`'s Result.

Since `@cipherstash/auth` 0.41, `AccessKeyStrategy.create()` and
`OidcFederationStrategy.create()` return a `Result<Strategy, AuthFailure>`,
but the JSDoc examples on the native entry still passed the return value
straight into `config.authStrategy` — demonstrating exactly the mistake that
fails opaquely at the first `getToken()` call. The examples now check
`.failure` and pass `.data`, matching the WASM entry's docs and the
integration tests.

Also corrects the lock-context wording in the `WasmEncryptionClient` doc
comment: a lock context decides who can *retrieve a value's data key* (the
claim from the encrypting caller's service token is bound to the key), not
"which key the value is encrypted under" — key material is identical either
way; the binding gates retrieval.

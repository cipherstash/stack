---
"@cipherstash/stack": patch
---

Fix the README's OIDC federation example, which passed the `Result` from `OidcFederationStrategy.create()` straight to `config.authStrategy` and failed in `Encryption()` with `opts.strategy.getToken is missing`.
It now unwraps the `Result` and passes `strategy.data`, and so does the `LockContext` JSDoc example.

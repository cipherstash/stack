---
'@cipherstash/auth': patch
'stash': patch
'@cipherstash/eql': minor
---

Validate token-discovered ZeroKMS destinations before sending bearer credentials, including device provisioning during login. Discovery accepts only HTTPS endpoints for supported regions under the CipherStash ZeroKMS domains. Once ZeroKMS has accepted a token, every later token must carry a valid hosted claim for that region; missing, non-hosted, or different-region claims are refused. A token ZeroKMS refuses does not fix the region. Same-region domain migrations update the destination used by long-lived clients. Explicit KMS configuration remains authoritative; staging and regions unknown to the SDK require explicit configuration or an SDK upgrade.

The Rust releases are `stack-auth`/`stack-profile` 0.43.1, `stack-kms` 0.2.0, and `stack-encrypt`/`stack-encrypt-derive` 0.3.0. The pending EQL Rust encryption integration uses `stack-encrypt` 0.3.0. Custom `ZeroKMSConnection` transports receive the discovered endpoint as a third `send` argument, and use it only when they were not configured with one; `ensure_base_url` is removed. The CLI's bundled agent guidance describes these discovery requirements.

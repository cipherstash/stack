---
'@cipherstash/auth': patch
'stash': patch
'@cipherstash/eql': minor
---

Validate token-discovered ZeroKMS destinations before sending bearer credentials, including device provisioning during login. Discovery accepts only HTTPS endpoints for supported regions under the CipherStash ZeroKMS domains. Every later token must carry a valid hosted claim for the original region; missing, non-hosted, or different-region claims are refused. Same-region domain migrations update the destination used by long-lived clients. Explicit KMS configuration remains authoritative; staging and regions unknown to the SDK require explicit configuration or an SDK upgrade.

The Rust releases are `stack-auth`/`stack-profile` 0.43.1, `stack-kms` 0.2.0, and `stack-encrypt`/`stack-encrypt-derive` 0.3.0. The pending EQL Rust encryption integration uses `stack-encrypt` 0.3.0. Custom `ZeroKMSConnection` transports that opt into discovery must update discovered URLs on later `ensure_base_url` calls while preserving URLs supplied at initialization. The CLI's bundled agent guidance describes these discovery requirements.

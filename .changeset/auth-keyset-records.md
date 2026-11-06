---
'@cipherstash/auth': minor
---

Add `keysetCreate` and `keysetRewrap` (Node only). They create and rewrap keyset records for the key vendor backends (AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault Transit and the static key backend), through the same Rust vendor clients that the Rust and Go SDKs use. Each vendor's credentials come from its environment chain. Both return a `Result`; a failure is a `KeysetFailure`. `stash keyset create` and `stash keyset rewrap` call them. ZeroKMS users do not need them. `keysetRewrap` does not re-key stored values, so a record in the wrapped key mode may move only to a new version of its own vendor key; a move to another key fails with `REWRAP_REFUSED` before any vendor call. A record in the derived key mode may move to any key.

For Google Cloud KMS, set `GOOGLE_OAUTH_ACCESS_TOKEN` (for example from `gcloud auth print-access-token`) or run on Google Cloud. Service account key files are not read, so that the binary has no RSA signing code.

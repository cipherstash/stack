---
'@cipherstash/auth': minor
---

Add `keysetCreate` and `keysetRewrap` (Node only). They create and rewrap keyset records for the key vendor backends (AWS KMS, Google Cloud KMS, Azure Managed HSM, HashiCorp Vault Transit and the static key backend), through the same Rust vendor clients that the Rust and Go SDKs use. ZeroKMS users do not need them. `stash keyset create` and `stash keyset rewrap` call them.

- Each vendor's credentials come from its environment chain.
- `backend` takes the short names (`aws`, `gcp`, `azure`, `vault`, `static`) and the full names that the result gives (`aws-kms`, `gcp-kms`, `azure-managed-hsm`, `vault-transit`).
- `mode` is `derived`, the only key mode in this release. Another mode is refused with `INVALID_OPTIONS`.
- `keysetRewrap` wraps the record's root key under another vendor key of the same backend. It does not re-key stored values, and every stored value still opens.
- Both return a `Result`; a failure is a `KeysetFailure`.

For Google Cloud KMS, set `GOOGLE_OAUTH_ACCESS_TOKEN` (for example from `gcloud auth print-access-token`) or run on Google Cloud. Service account key files are not read, so the binary has no RSA signing code.

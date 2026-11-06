---
'@cipherstash/auth': patch
---

Internal change to the key vendor clients that `keysetCreate` and `keysetRewrap` use. Each client now names its vendor with a typed value, not a string. The `vendor` field of a `VENDOR_ERROR` failure keeps the same values (`aws-kms`, `gcp-kms`, `azure-key-vault`, `vault-transit`, `static`).

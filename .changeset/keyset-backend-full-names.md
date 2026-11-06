---
'@cipherstash/auth': patch
'stash': patch
---

`keysetCreate` and `stash keyset create --backend` now also take the full backend names that their output gives: `aws-kms`, `gcp-kms`, `azure-key-vault` and `vault-transit`. The short names (`aws`, `gcp`, `azure`, `vault`, `static`) still work. Before, the output named a backend `aws-kms`, but the input refused that name. The error for an unknown backend now lists both forms.

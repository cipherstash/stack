---
"@cipherstash/auth": patch
---

The key vendor backends that `stash keyset` uses now share one credential
cache. Before, the AWS, Google Cloud, Azure and Vault backends each had their
own copy. The cache behavior is the same: it gets a new credential 5 minutes
before expiry, or a third of its life before expiry for a short-lived
credential. It does one fetch at a time and keeps a credential that has not
expired if a fetch fails. AWS temporary credentials that live less than 15
minutes now also refresh a third of their life before expiry. The package's
API is unchanged.

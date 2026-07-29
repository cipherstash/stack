---
'stash': patch
'@cipherstash/stack': patch
---

Use the consolidated v3 client name in generated code and shipped guidance.

`stash init` now scaffolds `Encryption` from `@cipherstash/stack/v3`, so a v3
schema and its client come from one import specifier. The former suffixed client
alias has been removed from the public API.

Corrects the bundled agent skills and package docs, which described
`encryptedSupabase` as the legacy EQL v2 wrapper. It is the EQL v3 factory;
the v2 wrapper was removed. Also drops the stale "DynamoDB still requires v2"
note from the `@cipherstash/stack` README — DynamoDB writes EQL v3 and reads
existing v2 items.

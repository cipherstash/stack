---
'stash': patch
'@cipherstash/stack': patch
---

De-suffix the v3 client name in generated code and shipped guidance.

`stash init` scaffolded `import { EncryptionV3 } from '@cipherstash/stack/v3'`
into the client file it writes. `EncryptionV3` is a deprecated alias of
`Encryption`, so new projects were started on the deprecated name. The
scaffold now emits `Encryption`.

`@cipherstash/stack/v3` now re-exports `Encryption` alongside the deprecated
`EncryptionV3` alias, so a v3 schema and its client come from one import
specifier — the deprecation notice already documented this import, but it did
not resolve.

Corrects the bundled agent skills and package docs, which described
`encryptedSupabase` as the legacy EQL v2 wrapper. It is the EQL v3 factory;
the v2 wrapper was removed. Also drops the stale "DynamoDB still requires v2"
note from the `@cipherstash/stack` README — DynamoDB writes EQL v3 and reads
existing v2 items.

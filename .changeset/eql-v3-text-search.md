---
"@cipherstash/stack": minor
---

Add the EQL v3 `text_search` authoring DSL on a new `@cipherstash/stack/eql/v3`
subpath (`types.TextSearch`, v3 `encryptedTable` / `buildEncryptConfig`). The v3
builders emit the existing `EncryptConfig` shape, so encryption, payloads, and
query paths are unchanged at runtime.

Also widens the public client types (`EncryptionClientConfig.schemas`,
`EncryptOptions`, `SearchTerm`/`EncryptQueryOptions`) to a structural contract so
both v2 and v3 builders are accepted by `Encryption` / `encrypt` / `decrypt` /
`encryptQuery`. This is a backward-compatible widening — existing v2 usage is
unaffected. The structural contracts themselves (`BuildableColumn`,
`BuildableQueryColumn`, `BuildableV3QueryableColumn`, `BuildableTable`,
`BuildableTableColumns`) and the `encryptModel` return-type mapper
(`EncryptedFromBuildableTable`) are exported from `@cipherstash/stack/types` so
consumers can name them.

---
'@cipherstash/stack': major
---

**Breaking (DynamoDB adapter):** `encryptedDynamoDB(...).encryptModel` and
`bulkEncryptModels` no longer accept an EQL v2 table — write is EQL v3 only. The
v2 write type overloads have been removed, narrowing encrypt to `AnyV3Table`.

**Decrypt still reads existing v2 items.** `decryptModel` / `bulkDecryptModels`
continue to accept an EQL v2 table (`encryptedColumn` / `encryptedField` from
`@cipherstash/stack/schema`), so previously stored v2 DynamoDB items remain
readable — the adapter keeps its v2 envelope reconstruction. Only the v2 write
surface is gone.

Migrate v2 write call sites to an EQL v3 table (`encryptedTable` + `types.*` from
`@cipherstash/stack/eql/v3`). To keep reading old data, pass the v2 table to the
decrypt methods.

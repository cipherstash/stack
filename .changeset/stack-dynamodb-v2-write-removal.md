---
'@cipherstash/stack': major
---

**Breaking (DynamoDB adapter):** `encryptedDynamoDB(...).encryptModel` and
`bulkEncryptModels` no longer accept an EQL v2 table. The v2 write type overloads
have been removed, narrowing encrypt to `AnyV3Table`. The narrowing is
type-level — treat the type as the contract, not a runtime guard.

**Decrypt still reads existing v2 items.** Pass the corresponding EQL v3 table
and `{ storedEqlVersion: 2 }` to `decryptModel` / `bulkDecryptModels`; the adapter
uses that explicit storage-version hint for legacy envelope reconstruction.

Migrate v2 write call sites to an EQL v3 table (`encryptedTable` + `types.*` from
`@cipherstash/stack/eql/v3`) and reuse that table for reads, adding the explicit
legacy-read option only while reading stored v2 data.

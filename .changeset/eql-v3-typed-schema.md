---
'@cipherstash/stack': minor
---

Add EQL v3 schema builders for all generated SQL domains under `@cipherstash/stack/eql/v3`, exposed as the `types` namespace (one member per EQL v3 domain, e.g. `types.TextEq` / `types.Int4Ord` / `types.Timestamptz`), including explicit query capability metadata (`getQueryCapabilities()` / `isQueryable()`) and v3 table support in model encryption helpers (`encryptModel` / `bulkEncryptModels`).

Also widen the accepted plaintext input type for `encrypt` / `encryptQuery` to include `Date` and `bigint` (via the new `Plaintext` type), so v3 `date` / `timestamptz` / `int8` domains can be encrypted and queried with their natural JavaScript values.

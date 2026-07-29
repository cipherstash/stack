---
"@cipherstash/stack": minor
---

Add a strongly typed EQL v3 client surface on `@cipherstash/stack/v3`.
`Encryption` returns the generic `EncryptionClient<S>` type and the subpath
re-exports the v3 `types` namespace and table API (from
`@cipherstash/stack/eql/v3`), so one import provides everything needed to author
and use a v3 schema.

Every method derives its types from the concrete `table` / `column` builder
arguments:

- `encrypt` / `encryptQuery` pin the plaintext to the column's domain type
  (`text → string`, `timestamp → Date`, …).
- `encryptQuery` constrains `queryType` to the column's capabilities and rejects
  storage-only columns at compile time.
- `encryptModel` / `bulkEncryptModels` validate schema-column fields against their
  inferred plaintext type (passthrough fields are untouched) and return a precise
  encrypted model.
- `decryptModel` / `bulkDecryptModels` return the precise plaintext model,
  reconstructing `Date` values from the encrypt-config `cast_as`.

Because the typed methods bind to the concrete branded v3 classes, a hand-rolled
structural table/column is rejected — closing the soundness gap where a non-branded
table could be encrypted at runtime while typed as plaintext.

The model-decrypt paths add per-column `Date` reconstruction. New clients author
EQL v3 only; native decrypt operations remain compatible with stored EQL v2
payloads.

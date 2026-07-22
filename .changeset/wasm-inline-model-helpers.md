---
'@cipherstash/stack': minor
---

`@cipherstash/stack/wasm-inline` now has the model helpers: `encryptModel` / `decryptModel` and `bulkEncryptModels` / `bulkDecryptModels` (#742). They run the same schema traversal as the native entry (shared code, so the two entries cannot drift on which fields get encrypted): declared columns are encrypted — matched by JS property name, nested fields via the column's dotted path — everything else passes through, and `null`/`undefined` fields are preserved without reaching ZeroKMS. Each call is one ZeroKMS round trip regardless of how many fields or models it covers, `types.Date`/`types.Timestamp` columns round-trip `Date` → `Date` (ISO strings on the wire), and failures follow this entry's `{ data } | { failure }` Result contract, with decrypt failures naming every failing field by its model path. Edge code no longer needs the hand-written `bulkEncrypt` field mapping whose failure mode was a schema column silently persisted in plaintext.

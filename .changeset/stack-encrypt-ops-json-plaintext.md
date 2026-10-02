---
'@cipherstash/stack': patch
---

Internal type cleanup of the encryption client (no runtime change). The exported operation classes `EncryptOperation`, `EncryptQueryOperation`, `BatchEncryptQueryOperation` and `BulkEncryptOperation` now declare that they accept a `types.Json` document as plaintext, which they always did at runtime; their `getOperation()` return types widen to match. The `EncryptionClient` interface is unchanged.

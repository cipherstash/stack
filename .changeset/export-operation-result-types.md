---
"@cipherstash/stack": minor
---

Export the operation classes returned by the encryption and DynamoDB clients as public API.

The classes returned from public methods are now exported and documented in the API reference, so their types can be named and their TSDoc links resolve.

- From `@cipherstash/stack/encryption`: `EncryptOperation`, `EncryptQueryOperation`, `BatchEncryptQueryOperation`, `DecryptOperation`, `EncryptModelOperation`, `DecryptModelOperation`, `BulkEncryptOperation`, `BulkDecryptOperation`, `BulkEncryptModelsOperation`, `BulkDecryptModelsOperation`. `EncryptQueryOperation` and `BatchEncryptQueryOperation` were previously marked `@internal`; since they are returned from `EncryptionClient.encryptQuery`, they are now public for consistency with the other operations.
- From `@cipherstash/stack/dynamodb`: `EncryptModelOperation`, `DecryptModelOperation`, `BulkEncryptModelsOperation`, `BulkDecryptModelsOperation`.
- From `@cipherstash/stack/types`: `EncryptedQuery` and `EncryptedFromSchema`.

The `*WithLockContext` variants returned by `.withLockContext()` remain internal — they share the same awaitable shape and are not intended to be named directly.

No runtime behaviour changes; this only widens the exported surface and corrects TSDoc cross-references that previously failed to resolve.

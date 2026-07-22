---
'@cipherstash/stack': patch
'@cipherstash/nextjs': patch
---

Remove the EQL v2-only published packages `@cipherstash/protect`,
`@cipherstash/schema`, and `@cipherstash/protect-dynamodb` from the repository
and the release train. They formed a closed dependency chain
(`@cipherstash/protect-dynamodb` → `@cipherstash/protect` → `@cipherstash/schema`)
and are superseded by `@cipherstash/stack`:

- `@cipherstash/protect` (core encryption) → `@cipherstash/stack`, which now
  carries the encryption client directly.
- `@cipherstash/schema` (schema builders) → `@cipherstash/stack/schema`.
- `@cipherstash/protect-dynamodb` (standalone DynamoDB adapter) →
  `@cipherstash/stack/dynamodb` (`encryptedDynamoDB`), the maintained
  implementation.

Already-published versions remain installable from npm; the git history
preserves the source for any emergency maintenance. Existing EQL v2 ciphertext
stays decryptable through `@cipherstash/stack` — this removes the v2 authoring
and emission surface, not the read path.

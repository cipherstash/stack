---
'stash': patch
'@cipherstash/stack': patch
---

Docs: EQL v3 is now the sole documented approach. The `stash-encryption`,
`stash-drizzle`, and `stash-supabase` skills and the `@cipherstash/stack`
README teach only the v3 typed surface (`Encryption`, the `types.*` concrete
domains, the `@cipherstash/stack-drizzle` package root, `encryptedSupabase`);
EQL v2 shrinks to read-compatibility notes. Two places keep more detail because
stored EQL v2 data is still reachable there:

- **DynamoDB reads.** `encryptedDynamoDB` writes EQL v3 only, but `decryptModel`
  / `bulkDecryptModels` can read previously stored v2 items when passed the
  corresponding v3 table and `{ storedEqlVersion: 2 }`, so the
  `stash-dynamodb` skill documents that explicit compatibility path (#657).
- **The encrypt rollout lifecycle.** `stash encrypt *` and `@cipherstash/migrate`
  classify a column from its Postgres domain type: a `public.eql_v3_*` domain is
  recognised as v3, and anything else — including a legacy `eql_v2_encrypted`
  column — does not classify. The documented lifecycle is the v3 one
  (backfill → switch the application to the encrypted column → drop the
  plaintext); legacy v2 columns are read-only, covered under a version callout
  (#648).

Also corrects the legacy `@cipherstash/drizzle` README's pointer to the removed
`@cipherstash/stack/drizzle` subpath (now the separate `@cipherstash/stack-drizzle`
package).

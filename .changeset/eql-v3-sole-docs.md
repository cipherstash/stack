---
'stash': patch
'@cipherstash/stack': patch
---

Docs: EQL v3 is now the sole documented approach. The `stash-encryption`,
`stash-drizzle`, and `stash-supabase` skills and the `@cipherstash/stack`
README teach only the v3 typed surface (`Encryption`, the `types.*` concrete
domains, the `@cipherstash/stack-drizzle` package root, `encryptedSupabase`);
EQL v2 shrinks to one short Legacy section per document. Two places keep more
than a Legacy section, because EQL v2 is still reachable there:

- **DynamoDB reads.** `encryptedDynamoDB` writes EQL v3 only, but `decryptModel`
  / `bulkDecryptModels` still accept an EQL v2 table so previously stored v2
  items stay readable, so the `stash-dynamodb` skill keeps the v2 schema shape
  documented for that read path (#657).
- **The encrypt rollout lifecycle.** `stash encrypt *` and `@cipherstash/migrate`
  detect a column's generation from its Postgres domain type, with EQL v3 as the
  recognised and default generation; a legacy `eql_v2_encrypted` column does not
  classify and falls through to the v2 lifecycle, which ends in
  `stash encrypt cutover` rather than the v3 `stash encrypt drop`. That
  difference is kept under a version callout (#648).

Also corrects the legacy `@cipherstash/drizzle` README's pointer to the removed
`@cipherstash/stack/drizzle` subpath (now the separate `@cipherstash/stack-drizzle`
package).

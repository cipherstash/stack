---
'stash': patch
'@cipherstash/stack': patch
---

Docs: EQL v3 is now the sole documented approach. The `stash-encryption`,
`stash-drizzle`, and `stash-supabase` skills and the `@cipherstash/stack`
README teach only the v3 typed surface (`EncryptionV3`, `types.*` concrete
domains, `@cipherstash/stack-drizzle/v3`, `encryptedSupabaseV3`); EQL v2
shrinks to one short Legacy section per document. Two explicit exceptions are
called out: DynamoDB still requires the v2 schema surface (#657), and the
encrypt rollout tooling (`stash encrypt backfill`/`cutover`,
`@cipherstash/migrate`) currently targets v2 columns (#648) — its guidance is
kept under a version callout. Also corrects the legacy `@cipherstash/drizzle`
README's pointer to the removed `@cipherstash/stack/drizzle` subpath (now the
separate `@cipherstash/stack-drizzle` package).

---
'@cipherstash/stack': minor
'@cipherstash/stack-drizzle': minor
'@cipherstash/stack-supabase': minor
---

Split the Drizzle and Supabase integrations into their own packages.

The adapters now ship as first-party packages that depend on `@cipherstash/stack`,
following the `@cipherstash/prisma-next` precedent:

- **`@cipherstash/stack-drizzle`** — Drizzle ORM integration. EQL v2 on the package
  root (`@cipherstash/stack-drizzle`: `encryptedType`, `extractEncryptionSchema`,
  `createEncryptionOperators`) and EQL v3 on `@cipherstash/stack-drizzle/v3`
  (`types` factories, `createEncryptionOperatorsV3`, `extractEncryptionSchemaV3`, …).
- **`@cipherstash/stack-supabase`** — Supabase integration: `encryptedSupabase` (v2)
  and `encryptedSupabaseV3` (v3, connect-time introspection).

**Breaking (`@cipherstash/stack`):** the `./drizzle`, `./supabase`, and
`./eql/v3/drizzle` subpath exports are removed. Migrate imports:

- `@cipherstash/stack/drizzle` → `@cipherstash/stack-drizzle`
- `@cipherstash/stack/eql/v3/drizzle` → `@cipherstash/stack-drizzle/v3`
- `@cipherstash/stack/supabase` → `@cipherstash/stack-supabase`

Add the relevant package to your dependencies alongside `@cipherstash/stack`. A new
`@cipherstash/stack/adapter-kit` subpath exposes the narrow core internals the
first-party adapters consume; it is the core↔adapter seam, not general-purpose API.

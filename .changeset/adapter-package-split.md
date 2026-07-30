---
'@cipherstash/stack': minor
'@cipherstash/stack-drizzle': minor
'@cipherstash/stack-supabase': minor
---

Split the Drizzle and Supabase integrations into their own packages.

The adapters now ship as first-party packages that depend on `@cipherstash/stack`,
following the `@cipherstash/stack-prisma` precedent:

- **`@cipherstash/stack-drizzle`** — EQL v3 Drizzle integration on the package
  root (`types` factories, `createEncryptionOperators`,
  `extractEncryptionSchema`, …).
- **`@cipherstash/stack-supabase`** — EQL v3 Supabase integration through the
  connect-time-introspecting `encryptedSupabase` factory.

**Breaking (`@cipherstash/stack`):** the `./drizzle`, `./supabase`, and
`./eql/v3/drizzle` subpath exports are removed. Migrate imports:

- `@cipherstash/stack/drizzle` → `@cipherstash/stack-drizzle`
- `@cipherstash/stack/eql/v3/drizzle` → `@cipherstash/stack-drizzle`
- `@cipherstash/stack/supabase` → `@cipherstash/stack-supabase`

Add the relevant package to your dependencies alongside `@cipherstash/stack`. A new
`@cipherstash/stack/adapter-kit` subpath exposes the narrow core internals the
first-party adapters consume; it is the core↔adapter seam, not general-purpose API.

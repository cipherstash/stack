# @cipherstash/stack-supabase

Supabase integration for [CipherStash Stack](https://www.npmjs.com/package/@cipherstash/stack) —
transparent, searchable field-level encryption on top of a Supabase (PostgREST) client.

Depends on `@cipherstash/stack`; install both:

```bash
npm install @cipherstash/stack @cipherstash/stack-supabase @supabase/supabase-js
```

## EQL v3

`encryptedSupabase` introspects the database at connect time (native
`public.eql_v3_*` column domains) — no schema argument, `select('*')` support,
equality/range filters, and encrypted `order()` on OPE columns.

EQL 3.0.2 requires typed query-domain operands for encrypted free-text and JSON
operators. PostgREST cannot express those casts, so v3 `matches()`, encrypted
`contains()`, and `selectorEq()`/`selectorNe()` fail fast with this EQL release.
Use the Drizzle or Prisma Next adapter, or a carefully scoped direct SQL/RPC
path.

```ts
import { encryptedSupabase } from '@cipherstash/stack-supabase'

const es = await encryptedSupabase(supabaseUrl, supabaseKey)
await es.from('users').select('id, email').eq('email', 'a@b.com')
```

`encryptedSupabaseV3` remains as a `@deprecated`, type-identical alias of
`encryptedSupabase`, so existing imports keep working.

Introspection needs a direct Postgres connection (`DATABASE_URL`), so `pg` is an
optional peer and the factory cannot run in a Worker or the browser.

## EQL v2 (removed)

The legacy EQL v2 authoring wrapper — `encryptedSupabase({ encryptionClient,
supabaseClient }).from(tableName, schema)` — has been removed; this package now
authors and queries EQL v3 only. Migrate existing v2 columns to an `eql_v3_*`
domain, or pin the last release that shipped the v2 wrapper.

See the `stash-supabase` agent skill and https://cipherstash.com/docs for the full guide.

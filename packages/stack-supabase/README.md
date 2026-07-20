# @cipherstash/stack-supabase

Supabase integration for [CipherStash Stack](https://www.npmjs.com/package/@cipherstash/stack) —
transparent, searchable field-level encryption on top of a Supabase (PostgREST) client.

Depends on `@cipherstash/stack`; install both:

```bash
npm install @cipherstash/stack @cipherstash/stack-supabase @supabase/supabase-js
```

## EQL v3 (recommended)

`encryptedSupabaseV3` introspects the database at connect time (native
`public.eql_v3_*` column domains) — no schema argument, `select('*')` support,
equality/range filters, and encrypted `order()` on OPE columns.

EQL 3.0.2 requires typed query-domain operands for encrypted free-text and JSON
operators. PostgREST cannot express those casts, so v3 `matches()`, encrypted
`contains()`, and `selectorEq()`/`selectorNe()` fail fast with this EQL release.
Use the Drizzle or Prisma Next adapter, or a carefully scoped direct SQL/RPC
path.

```ts
import { encryptedSupabaseV3 } from '@cipherstash/stack-supabase'

const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey)
await es.from('users').select('id, email').eq('email', 'a@b.com')
```

Introspection needs a direct Postgres connection (`DATABASE_URL`), so `pg` is an
optional peer and the factory cannot run in a Worker or the browser.

## EQL v2 (legacy)

`encryptedSupabase` wraps a supabase-js client with a v2 schema; still shipped for
existing v2 deployments.

See the `stash-supabase` agent skill and https://cipherstash.com/docs for the full guide.

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
`contains()` free-text search, and encrypted `order()` on OPE columns.

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

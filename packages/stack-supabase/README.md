<div align="center">
  <h1>@cipherstash/stack-supabase</h1>

  <p><b>Searchable, application-level encryption for <a href="https://supabase.com">Supabase</a>, from <a href="https://github.com/cipherstash/stack">CipherStash Stack</a>.</b></p>

  <a href="https://www.npmjs.com/package/@cipherstash/stack-supabase"><img alt="npm version" src="https://img.shields.io/npm/v/@cipherstash/stack-supabase.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://www.npmjs.com/package/@cipherstash/stack-supabase"><img alt="npm downloads" src="https://img.shields.io/npm/dm/@cipherstash/stack-supabase.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://cipherstash.com/docs/stack/cipherstash/encryption/supabase?utm_source=github&utm_medium=stack_supabase_readme"><img alt="Docs" src="https://img.shields.io/badge/Docs-333333.svg?style=for-the-badge&logo=readthedocs&labelColor=333"></a>
  <a href="https://discord.gg/5qwXUFb6PB"><img alt="Discord" src="https://img.shields.io/badge/Join%20the%20community-blueviolet.svg?style=for-the-badge&logo=Discord&labelColor=000000"></a>
  <a href="https://github.com/cipherstash/stack/blob/main/LICENSE.md"><img alt="License" src="https://img.shields.io/npm/l/@cipherstash/stack-supabase.svg?style=for-the-badge&labelColor=000000"></a>
</div>

## Why

Anyone with database access — a leaked `service_role` key, a misconfigured RLS policy, a SQL
injection, a stolen backup — normally sees everything. CipherStash encrypts each value with its
own key before it leaves your app, so what reaches Supabase is ciphertext; you can only decrypt
what you're explicitly authorized to, and every decryption is audited.

The trick is queries still work: searchable encrypted terms let equality and range filters run
against native Postgres indexes without decrypting the table. RLS stays exactly where it is —
this complements authorization, it doesn't replace it.
[Security architecture →][security-architecture]

## Encrypted columns. Real Supabase queries.

The `email` and `amount` columns below are stored as ciphertext with a unique key per row — and
the same Supabase.js calls keep working, because the filters run on the ciphertext:

```ts
import { encryptedSupabase } from '@cipherstash/stack-supabase'

const es = await encryptedSupabase(supabaseUrl, supabaseKey)

// Insert — encrypted transparently on the way in
await es.from('users').insert({ email: 'alice@example.com', amount: 30 })

// Query — filters encrypted on the way in, results decrypted on the way out
const { data } = await es
  .from('users')
  .select('id, email, amount')
  .eq('email', 'alice@example.com') // encrypted equality — runs on ciphertext
  .gte('amount', 10)                // encrypted range
```

You can also wrap an existing client: `await encryptedSupabase(supabaseClient, options)`.

| Query type | Filters | Notes |
|---|---|---|
| **Equality** | `.eq`, `.neq`, `.in`, `.match({ … })` | on equality-capable domains |
| **Range** | `.gt` / `.gte` / `.lt` / `.lte` | on `*Ord` domains |
| **Ordering** | `.order()` | on OPE-backed encrypted ordering columns (and plaintext columns) |
| **Compound** | `.or(…)` | over the filters above |

Each column's query capabilities are fixed by its `eql_v3_*` type, so an unsupported operation is
rejected loudly instead of silently scanning.

> **PostgREST limitation (EQL 3.0.4).** Encrypted free-text `matches()`, encrypted JSON
> `contains()`, and `selectorEq()`/`selectorNe()` need typed query-domain casts that PostgREST
> cannot express, so they fail fast with this EQL release — the requirement began in EQL 3.0.2
> and remains in 3.0.4. Use the
> [Drizzle][stack-drizzle] or [Prisma][stack-prisma] adapter, or a carefully scoped SQL/RPC
> path, for those query shapes. Plaintext `like`/`ilike` on encrypted columns is rejected by
> design.

## Quick start

About five minutes, starting on the **free developer tier** ([sign up][signup]). The setup wizard
handles authentication, the EQL install, and your schema:

```bash
npx stash init
```

Or install manually (this package depends on `@cipherstash/stack`; install all three):

```bash
npm install @cipherstash/stack @cipherstash/stack-supabase @supabase/supabase-js
```

Full guide: [Supabase quickstart →][supabase-docs]

## How the wrapper works

`encryptedSupabase` **introspects your database at connect time**: it discovers the native
`public.eql_v3_*` column domains, so there is no schema argument and no client-side column
config to maintain — `select('*')` just works, inserts and updates encrypt automatically, and
reads decrypt automatically.

Introspection needs a direct Postgres connection (`DATABASE_URL`), so `pg` is an optional peer
dependency and the factory cannot run in an edge Worker or the browser — construct it in your
server-side code.

It runs alongside Supabase Auth and RLS, and supports
[identity-locking encryption][identity] — binding a row's data key to the signed-in user's
JWT claim — via the same lock-context API as the rest of the Stack.

> `encryptedSupabaseV3` remains as a `@deprecated`, type-identical alias of `encryptedSupabase`,
> so existing imports keep working.

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark) and (max-width: 600px)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-stacked-dark.svg">
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-dark.svg">
    <source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-stacked-light.svg">
    <img alt="CipherStash architecture: encryption and decryption happen in your TypeScript app; only ciphertext (EQL JSON) is stored in your PostgreSQL database. ZeroKMS issues a unique key per value, derived in your app. Plaintext and keys never reach CipherStash, and every decryption is logged for audit." width="880" src="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-light.svg">
  </picture>
</p>

Every value is encrypted into an [EQL][eql] payload: the ciphertext plus the *searchable terms*
its column type declares — an HMAC term for equality, an order-preserving term for range and
sorting. The EQL SQL bundle defines the Postgres domains and operators, so an encrypted `.eq()`
resolves to a comparison of equality terms and engages a functional index. Keys come from
[ZeroKMS][zerokms] — one per value — so a leaked key or a dumped table never exposes more than
it should, and the EQL install needs no superuser (it works on cloud-hosted Supabase as-is).

## Docs

- [Supabase integration guide →][supabase-docs]
- [Searchable encryption concepts →][searchable-encryption]
- [Security architecture →][security-architecture]
- The bundled `stash-supabase` agent skill, installed into your repo by `stash init`

[signup]: https://cipherstash.com/signup?utm_source=github&utm_medium=stack_supabase_readme
[supabase-docs]: https://cipherstash.com/docs/stack/cipherstash/encryption/supabase?utm_source=github&utm_medium=stack_supabase_readme
[searchable-encryption]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_supabase_readme
[security-architecture]: https://cipherstash.com/docs/stack/reference/security-architecture?utm_source=github&utm_medium=stack_supabase_readme
[identity]: https://cipherstash.com/docs/stack/cipherstash/encryption/identity?utm_source=github&utm_medium=stack_supabase_readme
[zerokms]: https://cipherstash.com/docs/stack/cipherstash/kms?utm_source=github&utm_medium=stack_supabase_readme
[eql]: https://github.com/cipherstash/encrypt-query-language
[stack-drizzle]: https://www.npmjs.com/package/@cipherstash/stack-drizzle
[stack-prisma]: https://www.npmjs.com/package/@cipherstash/stack-prisma

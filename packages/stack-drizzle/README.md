# @cipherstash/stack-drizzle

**Searchable, application-level encryption for [Drizzle ORM][drizzle-orm] and PostgreSQL**,
from [CipherStash Stack][stack-repo].

## Why

Anyone with database access — a DBA, a leaked service account, a SQL injection — normally sees
everything. CipherStash encrypts each value with its own key, derived at query time from the
caller's identity. So a dump, an injection, or a compromised box yields ciphertext; you can
only decrypt what you're explicitly authorized to, and every decryption is audited.

The trick is queries still work: we build searchable encrypted indexes using deterministic
encryption, ORE, and bloom filters, so equality, range, and fuzzy-text queries run against
native Postgres indexes in milliseconds without decrypting the table.

The trade-off is explicit and bounded: the indexes leak equality and order relationships,
nothing else — it's not FHE, and we don't pretend it is.
[Security architecture →][security-architecture]

## Encrypted columns. Real Drizzle queries.

The `email` and `age` columns below are stored as ciphertext with a unique key per row — and the
queries still work, because they run on the ciphertext. No decrypt-and-scan, no query rewriting
layer, no proxy in the query path.

```ts
export const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: types.TextSearch('email'), // → eql_v3_text_search — the type is the config
  age: types.IntegerOrd('age'),     // → eql_v3_integer_ord
})

const rows = await db
  .select()
  .from(users)
  .where(await ops.and(
    ops.contains(users.email, 'alice'), // free-text match, on ciphertext
    ops.between(users.age, 18, 65),     // range, on ciphertext
  ))
  .orderBy(ops.asc(users.age))          // ordered by encrypted value
```

The operators mirror Drizzle's and encrypt their operands transparently:

| Query type | Operators | Docs |
|---|---|---|
| **Equality** | `ops.eq`, `ops.ne`, `ops.inArray` | [Equality queries →][query-equality] |
| **Range & ordering** | `ops.gt`/`gte`/`lt`/`lte`, `ops.between`, `ops.asc`/`desc` | [Range & ordering →][query-range] |
| **Free-text match** | `ops.matches`, `ops.contains` | [Text search →][query-match] |
| **Encrypted JSON** | `ops.contains` (containment), `ops.selector(col, path)` | [JSON →][query-json] |

Each column's query capabilities are fixed by its type, so an unsupported operation is rejected
loudly instead of silently scanning.

## Quick start

About five minutes, starting on the **free developer tier** ([sign up][signup]). The setup wizard
handles authentication, the EQL install, and your schema:

```bash
npx stash init
```

Or install manually (this package depends on `@cipherstash/stack`; install both), then run
`stash eql install` once — or generate a migration with `stash eql migration --drizzle`:

```bash
npm install @cipherstash/stack @cipherstash/stack-drizzle drizzle-orm
```

Full guide: [Drizzle quickstart →][drizzle-docs]

## Full example (EQL v3, the `/v3` subpath)

Each encrypted column is a concrete `public.eql_v3_*` Postgres domain whose query capabilities
are fixed by the `types.*` factory you choose — no per-column config object:

```ts
import { pgTable, integer } from 'drizzle-orm/pg-core'
import { EncryptionV3 } from '@cipherstash/stack/v3'
import {
  types,
  extractEncryptionSchemaV3,
  createEncryptionOperatorsV3,
} from '@cipherstash/stack-drizzle/v3'

const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: types.TextSearch('email'), // equality + order/range + free-text
  age: types.IntegerOrd('age'),     // equality + order/range
})

const schema = extractEncryptionSchemaV3(users)
const client = await EncryptionV3({ schemas: [schema] })
const ops = createEncryptionOperatorsV3(client)

// Insert — encrypt models first (bulk helpers batch key operations
// through ZeroKMS instead of one round trip per row)
const enc = await client.bulkEncryptModels(
  [{ email: 'alice@example.com', age: 30 }],
  schema,
)
if (!enc.failure) await db.insert(users).values(enc.data)

// Query — operators auto-encrypt their plaintext operands
const rows = await db
  .select()
  .from(users)
  .where(await ops.eq(users.email, 'alice@example.com'))

// Decrypt after select
const dec = await client.bulkDecryptModels(rows, schema)
```

For a `types.Json` column, `ops.selector(column, path)` supports encrypted comparisons and
ordering at a scalar JSONPath leaf. For example,
`.orderBy(await ops.selector(users.profile, '$.age').asc())` lowers to
`ORDER BY eql_v3.ord_term(...)` over the selected encrypted entry.

### Indexing encrypted columns

Encrypted predicates only use an index if one exists over the matching `eql_v3.*`
term-extractor expression — otherwise every encrypted query sequential-scans.
`encryptedIndexes` derives the recommended indexes for every encrypted column in a table;
spread it into `pgTable`'s third-argument callback and `drizzle-kit generate` picks the
indexes up like any others:

```ts
import { integer, pgTable } from 'drizzle-orm/pg-core'
import { encryptedIndexes, types } from '@cipherstash/stack-drizzle/v3'

export const users = pgTable(
  'users',
  {
    id: integer('id').primaryKey(),
    email: types.TextEq('email'),
    bio: types.TextSearch('bio'),
  },
  (t) => [...encryptedIndexes(t)],
)
```

Each column gets indexes matching its domain's capabilities, named
`<table>_<column>_<capability>` (equality btree, ordering btree, free-text GIN, JSON
containment GIN); storage-only and non-encrypted columns get none. After the migration
applies, run `ANALYZE <table>` — expression indexes have no statistics until then. For custom
names, subsets, or field-level selector indexes on encrypted JSON, declare individual
expression indexes instead; the bundled `stash-indexing` agent skill has the full recipes.

## How it works

Every value is encrypted into an [EQL][eql] payload: the ciphertext plus the *searchable
terms* its column type declares — an HMAC term for equality, an order-preserving term for
range and sorting, a bloom filter for text match, a structured-encryption vector for JSON.
The EQL SQL bundle defines the Postgres domains, operators, and term-extractor functions, so
`WHERE email = $1` resolves to a comparison of equality terms and engages a functional index
over the extractor. Keys come from [ZeroKMS][zerokms] — one per value — so bulk operations,
key revocation, and [identity-bound decryption][identity] (lock contexts) work without the
database ever holding a secret. Runs on plain PostgreSQL, Supabase, and RDS/Aurora; the SQL
install needs no superuser.

## EQL v2 (package root) — legacy

The v2 integration predates the typed v3 domains and is kept for existing projects. New
projects should use v3 above.

```ts
import { encryptedType, extractEncryptionSchema, createEncryptionOperators } from '@cipherstash/stack-drizzle'
import { Encryption } from '@cipherstash/stack'
```

`encryptedType` defines an `eql_v2_encrypted` column; `createEncryptionOperators` returns
query operators (`eq`, `like`, `gt`, `inArray`, …) that transparently encrypt search values.

## Docs

- [Drizzle integration guide →][drizzle-docs]
- [Searchable encryption concepts →][searchable-encryption]
- [Security architecture →][security-architecture]
- The bundled `stash-drizzle` and `stash-indexing` agent skills, installed into your repo by `stash init`

> Not to be confused with `@cipherstash/drizzle`, the older `@cipherstash/protect`-based
> package — deprecated and no longer maintained; this package replaces it.

[drizzle-orm]: https://orm.drizzle.team
[stack-repo]: https://github.com/cipherstash/stack
[eql]: https://github.com/cipherstash/encrypt-query-language
[signup]: https://cipherstash.com/signup?utm_source=github&utm_medium=stack_drizzle_readme
[zerokms]: https://cipherstash.com/docs/stack/cipherstash/kms?utm_source=github&utm_medium=stack_drizzle_readme
[security-architecture]: https://cipherstash.com/docs/stack/reference/security-architecture?utm_source=github&utm_medium=stack_drizzle_readme
[drizzle-docs]: https://cipherstash.com/docs/stack/cipherstash/encryption/drizzle?utm_source=github&utm_medium=stack_drizzle_readme
[searchable-encryption]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_drizzle_readme
[identity]: https://cipherstash.com/docs/stack/cipherstash/encryption/identity?utm_source=github&utm_medium=stack_drizzle_readme
[query-equality]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_drizzle_readme#equality
[query-range]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_drizzle_readme#range-and-ordering
[query-match]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_drizzle_readme#free-text-search
[query-json]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_drizzle_readme#json

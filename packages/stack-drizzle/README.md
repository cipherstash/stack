# @cipherstash/stack-drizzle

Drizzle ORM integration for [CipherStash Stack](https://www.npmjs.com/package/@cipherstash/stack) —
searchable, application-layer field-level encryption for PostgreSQL.

Depends on `@cipherstash/stack`; install both:

```bash
npm install @cipherstash/stack @cipherstash/stack-drizzle drizzle-orm
```

## Usage (EQL v3)

Each encrypted column is a concrete `public.eql_v3_*` Postgres domain whose query
capabilities are fixed by the `types.*` factory you choose — no per-column config
object. Install the domains once with `stash eql install --eql-version 3`.

```ts
import { pgTable, integer } from 'drizzle-orm/pg-core'
import { EncryptionV3 } from '@cipherstash/stack/v3'
import {
  types as encryptedTypes,
  extractEncryptionSchema,
  createEncryptionOperators,
} from '@cipherstash/stack-drizzle'

const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: encryptedTypes.TextSearch('email'), // equality + order/range + free-text
  age: encryptedTypes.IntegerOrd('age'),     // equality + order/range
})

const schema = extractEncryptionSchema(users)
const client = await EncryptionV3({ schemas: [schema] })
const ops = createEncryptionOperators(client)

// Insert — encrypt models first
const enc = await client.bulkEncryptModels(
  [{ email: 'alice@example.com', age: 30 }],
  schema,
)
if (!enc.failure) await db.insert(users).values(enc.data)

// Query — operators auto-encrypt their plaintext operands
const rows = await db
  .select()
  .from(users)
  .where(await ops.and(
    ops.contains(users.email, 'alice'), // free-text containment over ciphertext
    ops.between(users.age, 18, 65),
  ))
  .orderBy(ops.asc(users.age))

// Decrypt after select
const dec = await client.bulkDecryptModels(rows, schema)
```

For a `types.Json` column, `ops.selector(column, path)` supports encrypted
comparisons and ordering at a scalar JSONPath leaf. For example,
`.orderBy(await ops.selector(users.profile, '$.age').asc())` lowers to
`ORDER BY eql_v3.ord_term(...)` over the selected encrypted entry.

## Docs

Full guide: https://cipherstash.com/docs/integrations/drizzle — see also the
bundled `stash-drizzle` agent skill.

> Not to be confused with `@cipherstash/drizzle`, the older `@cipherstash/protect`-based package — deprecated and no longer maintained; this package replaces it.

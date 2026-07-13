---
name: stash-drizzle
description: Integrate CipherStash encryption with Drizzle ORM using @cipherstash/stack-drizzle. Covers the encryptedType column type, encrypted query operators (eq, like, ilike, gt/gte/lt/lte, between, inArray, asc/desc), schema extraction, batched and/or conditions, EQL migration generation, the EQL v3 integration (@cipherstash/stack-drizzle/v3), and the complete Drizzle integration workflow. Use when adding encryption to a Drizzle ORM project, defining encrypted Drizzle schemas, or querying encrypted columns with Drizzle.
---

# CipherStash Stack - Drizzle ORM Integration

Guide for integrating CipherStash field-level encryption with Drizzle ORM using `@cipherstash/stack-drizzle`. Provides a custom column type for encrypted fields and query operators that transparently encrypt search values.

## When to Use This Skill

- Adding field-level encryption to a Drizzle ORM project
- Defining encrypted columns in Drizzle table schemas
- Querying encrypted data with type-safe operators
- Sorting and filtering on encrypted columns
- Generating EQL database migrations
- Building Express/Hono/Next.js APIs with encrypted Drizzle queries
- Using EQL v3 typed-schema columns in Drizzle (see "EQL v3 Integration" below)

## Installation

```bash
npm install @cipherstash/stack @cipherstash/stack-drizzle drizzle-orm
```

The Drizzle integration ships as its own first-party package,
`@cipherstash/stack-drizzle`, which depends on `@cipherstash/stack`. Install both.
It is distinct from the older, separate `@cipherstash/drizzle` package (which is
`@cipherstash/protect`-based, with different symbol names).

## Database Setup

### Install EQL Extension

The EQL (Encrypt Query Language) PostgreSQL extension enables searchable encryption functions. Generate a migration:

```bash
npx generate-eql-migration
# Options:
#   -n, --name <name>   Migration name (default: "install-eql")
#   -o, --out <dir>     Output directory (default: "drizzle")
```

Then apply it:

```bash
npx drizzle-kit migrate
```

### Column Storage

Encrypted columns use the `eql_v2_encrypted` PostgreSQL type (installed by EQL). If not using EQL directly, use JSONB:

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email eql_v2_encrypted,    -- with EQL extension
  name jsonb NOT NULL,       -- or use jsonb
  age INTEGER                -- non-encrypted columns are normal types
);
```

## Schema Definition

Use `encryptedType<T>()` to define encrypted columns in Drizzle table schemas:

```typescript
import { pgTable, integer, timestamp, varchar } from "drizzle-orm/pg-core"
import { encryptedType } from "@cipherstash/stack-drizzle"

const usersTable = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),

  // Encrypted string with search capabilities
  email: encryptedType<string>("email", {
    equality: true,        // enables: eq, ne, inArray
    freeTextSearch: true,  // enables: like, ilike
    orderAndRange: true,   // enables: gt, gte, lt, lte, between, asc, desc
  }),

  // Encrypted number
  age: encryptedType<number>("age", {
    dataType: "number",
    equality: true,
    orderAndRange: true,
  }),

  // Encrypted JSON object with searchable JSONB queries
  profile: encryptedType<{ name: string; bio: string }>("profile", {
    dataType: "json",
    searchableJson: true,
  }),

  // Non-encrypted columns
  role: varchar("role", { length: 50 }),
  createdAt: timestamp("created_at").defaultNow(),
})
```

### `encryptedType<TData>(name, config?)`

| Config Option | Type | Description |
|---|---|---|
| `dataType` | `"string"` \| `"number"` \| `"json"` \| `"boolean"` \| `"bigint"` \| `"date"` | Plaintext data type (default: `"string"`) |
| `equality` | `boolean` \| `TokenFilter[]` | Enable equality index |
| `freeTextSearch` | `boolean` \| `MatchIndexOpts` | Enable free-text search index |
| `orderAndRange` | `boolean` | Enable ORE index for sorting and range queries |
| `searchableJson` | `boolean` | Enable JSONB path queries (requires `dataType: "json"`) |

The generic type parameter `<TData>` sets the TypeScript type for the decrypted value.

## Initialization

### 1. Extract Schema from Drizzle Table

```typescript
import { extractEncryptionSchema, createEncryptionOperators } from "@cipherstash/stack-drizzle"
import { Encryption } from "@cipherstash/stack"

// Convert Drizzle table definition to CipherStash schema
const usersSchema = extractEncryptionSchema(usersTable)
```

### 2. Initialize Encryption Client

```typescript
const encryptionClient = await Encryption({
  schemas: [usersSchema],
})
```

### 3. Create Query Operators

```typescript
const encryptionOps = createEncryptionOperators(encryptionClient)
```

### 4. Create Drizzle Instance

```typescript
import { drizzle } from "drizzle-orm/postgres-js"
import postgres from "postgres"

const db = drizzle({ client: postgres(process.env.DATABASE_URL!) })
```

## Insert Encrypted Data

Encrypt models before inserting:

```typescript
// Single insert
const encrypted = await encryptionClient.encryptModel(
  { email: "alice@example.com", age: 30, role: "admin" },
  usersSchema,
)
if (!encrypted.failure) {
  await db.insert(usersTable).values(encrypted.data)
}

// Bulk insert
const encrypted = await encryptionClient.bulkEncryptModels(
  [
    { email: "alice@example.com", age: 30, role: "admin" },
    { email: "bob@example.com", age: 25, role: "user" },
  ],
  usersSchema,
)
if (!encrypted.failure) {
  await db.insert(usersTable).values(encrypted.data)
}
```

## Query Encrypted Data

### Equality

```typescript
// Exact match - await the operator
const results = await db
  .select()
  .from(usersTable)
  .where(await encryptionOps.eq(usersTable.email, "alice@example.com"))
```

### Text Search

```typescript
// Case-insensitive search
const results = await db
  .select()
  .from(usersTable)
  .where(await encryptionOps.ilike(usersTable.email, "%alice%"))

// Case-sensitive search
const results = await db
  .select()
  .from(usersTable)
  .where(await encryptionOps.like(usersTable.name, "%Smith%"))
```

### Range Queries

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(await encryptionOps.gte(usersTable.age, 18))

const results = await db
  .select()
  .from(usersTable)
  .where(await encryptionOps.between(usersTable.age, 18, 65))
```

### Array Operators

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(await encryptionOps.inArray(usersTable.email, [
    "alice@example.com",
    "bob@example.com",
  ]))
```

### Sorting

```typescript
// Sort by encrypted column (sync - no await needed)
const results = await db
  .select()
  .from(usersTable)
  .orderBy(encryptionOps.asc(usersTable.age))

const results = await db
  .select()
  .from(usersTable)
  .orderBy(encryptionOps.desc(usersTable.age))
```

**Note:** Sorting on encrypted columns requires operator family support in the database. On databases without operator families (e.g. Supabase, or when installed with `--exclude-operator-family`), `ORDER BY` on encrypted columns is not currently supported. Sort application-side after decrypting instead. Operator family support for Supabase is being developed with the Supabase and CipherStash teams.

## JSONB Queries

Query encrypted JSON columns using JSONB operators. These require `searchableJson: true` and `dataType: "json"` in the column's `encryptedType` config.

### Check path existence

```typescript
// Check if a JSONB path exists in an encrypted column
const results = await db
  .select()
  .from(usersTable)
  .where(await encryptionOps.jsonbPathExists(usersTable.profile, "$.bio"))
```

### Extract value at path

```typescript
// Extract the first matching value at a JSONB path
const result = await encryptionOps.jsonbPathQueryFirst(usersTable.profile, "$.name")
```

### Get value with `->` operator

```typescript
// Get a value using the JSONB -> operator
const result = await encryptionOps.jsonbGet(usersTable.profile, "$.name")
```

> **Note:** `jsonbPathExists` returns a boolean and can be used in `WHERE` clauses. `jsonbPathQueryFirst` and `jsonbGet` return encrypted values — use them in `SELECT` expressions.

### Combine JSONB with other operators

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(
    await encryptionOps.and(
      encryptionOps.jsonbPathExists(usersTable.profile, "$.name"),
      encryptionOps.eq(usersTable.email, "jane@example.com"),
    ),
  )
```

## Batched Conditions (and / or)

Use `encryptionOps.and()` and `encryptionOps.or()` to batch multiple encrypted conditions into a single ZeroKMS call. This is more efficient than awaiting each operator individually.

```typescript
// Batched AND - all encryptions happen in one call
const results = await db
  .select()
  .from(usersTable)
  .where(
    await encryptionOps.and(
      encryptionOps.gte(usersTable.age, 18),     // no await needed
      encryptionOps.lte(usersTable.age, 65),     // lazy operators
      encryptionOps.ilike(usersTable.email, "%example.com"),
      eq(usersTable.role, "admin"),           // mix with regular Drizzle ops
    ),
  )

// Batched OR
const results = await db
  .select()
  .from(usersTable)
  .where(
    await encryptionOps.or(
      encryptionOps.eq(usersTable.email, "alice@example.com"),
      encryptionOps.eq(usersTable.email, "bob@example.com"),
    ),
  )
```

**Key pattern:** Pass lazy operators (no `await`) to `and()`/`or()`, then `await` the outer call. This batches all encryption into a single operation.

## Decrypt Results

```typescript
// Single model
const decrypted = await encryptionClient.decryptModel(results[0])
if (!decrypted.failure) {
  console.log(decrypted.data.email) // "alice@example.com"
}

// Bulk decrypt
const decrypted = await encryptionClient.bulkDecryptModels(results)
if (!decrypted.failure) {
  for (const user of decrypted.data) {
    console.log(user.email)
  }
}
```

## Migrating an Existing Column to Encrypted

The hard case: a Drizzle table that already exists in production with live data in a plaintext column you want to encrypt. You can't just change the column type — that would drop the data and break NOT NULL constraints.

CipherStash splits this into two named steps with a hard production-deploy gate between them: an **encryption rollout** (schema-add + dual-write code) and an **encryption cutover** (backfill + rename + drop). (If using CipherStash Proxy, the rollout also includes `stash db push` to register the encryption config with EQL.) The `stash-encryption` skill is the canonical reference for the lifecycle; this section walks the Drizzle-specific shape.

> **Runner note.** `stash init` adds `stash` to the project as a dev dependency, so `stash <command>` runs through whichever package manager the project uses (Bun, pnpm, Yarn, or npm) — examples below show this bare form. Before init has run, prefix with your package manager's one-shot runner: `bunx`, `pnpm dlx`, `yarn dlx`, or `npx`. The CLI's behaviour is identical across all of them.

> **Where am I?** Run `stash status` first (substitute the runner per the note above). It shows you which Drizzle tables/columns are mid-rollout, which are post-deploy, and what the next move is. Re-run after every transition.

### Starting state

You have:

```typescript
// src/db/schema.ts
export const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: text('email').notNull(),  // plaintext, populated, NOT NULL
})
```

And an `INSERT INTO users (email) VALUES (...)` somewhere in your app code.

### Step 1 — Encryption rollout (one PR, one deploy)

Everything below lands in one PR. The deploy of that PR is the gate.

#### Schema-add: declare the encrypted twin

Add an `email_encrypted` column **alongside** `email`. Crucially, the encrypted column is **nullable** at creation — never `.notNull()`, because rows that already exist will have NULL in this column until backfill catches them.

```typescript
// src/db/schema.ts
import { encryptedType } from '@cipherstash/stack-drizzle'

export const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: text('email').notNull(),                              // unchanged
  email_encrypted: encryptedType<string>('email_encrypted', {  // new — nullable
    freeTextSearch: true,
    equality: true,
  }),
})
```

Update the encryption client to harvest the encrypted columns from the table:

```typescript
// src/encryption/index.ts
import { Encryption } from '@cipherstash/stack'
import { extractEncryptionSchema } from '@cipherstash/stack-drizzle'
import { users } from '../db/schema'

const usersEncryptionSchema = extractEncryptionSchema(users)

export const encryptionClient = await Encryption({ schemas: [usersEncryptionSchema] })
```

Generate the migration with `drizzle-kit generate`. The generated SQL should be a single `ALTER TABLE ... ADD COLUMN email_encrypted eql_v2_encrypted;`. Apply with `drizzle-kit migrate`.

> **Using CipherStash Proxy?**
> 
> If your app queries encrypted data through CipherStash Proxy, register the new encryption config with EQL:
> 
> ```bash
> stash db push
> ```
> 
> If this is the project's first encrypted column, `db push` writes directly to the active EQL config (nothing to rename). If an active config already exists, `db push` writes the new config as `pending` — that's expected. The pending row will be promoted to active by `stash encrypt cutover` in the cutover step.
> 
> SDK-only users can skip this step.

#### Dual-writing: write to both columns from app code

Find **every** code path that writes to `users.email` and update it to encrypt and also write to `email_encrypted`:

```typescript
// Before
await db.insert(users).values({ email: input.email })

// After
const encrypted = await encryptionClient.encryptModel({ email_encrypted: input.email }, usersEncryptionSchema)
if (encrypted.failure) throw new Error(encrypted.failure.message)

await db.insert(users).values({
  email: input.email,                                  // plaintext — keep writing
  email_encrypted: encrypted.data.email_encrypted,     // encrypted twin — new
})
```

Same shape for UPDATE: if your app updates `email`, it must also re-encrypt and update `email_encrypted` in the same statement.

**The dual-write rule.** Every persistence path that mutates this row writes both columns, in the same transaction, on every code branch. Insert sites, update sites, upserts, ON CONFLICT clauses, seeders, fixtures, CSV importers, admin actions, background jobs, third-party webhook handlers — all of them. A single missed branch means rows inserted in production after deploy land in plaintext only, and backfill won't catch them. Grep for every site that touches `users.email` before declaring this step done.

After this phase, existing rows still have `email_encrypted = NULL`. App reads still come from `email`. Nothing has broken.

### ⛔ Deploy gate

Stop. Ship this PR to production. The deployed environment must be running the dual-write code before any cutover-step work is safe.

When the deploy is live:

```bash
stash status        # verify the rollout is recorded
stash plan          # detects dual-writes are live; drafts the cutover plan
```

`stash impl` will refuse to run a cutover-step plan if `cs_migrations` has no `dual_writing` event for `users.email`. That refusal is the safety net for cases where someone runs cutover work locally before the code is actually live.

### Step 2 — Encryption cutover

Once dual-writes are live in production and `cs_migrations` records `dual_writing`:

#### Backfill: encrypt the historical rows

```bash
stash encrypt backfill --table users --column email
# (Interactive: answer 'yes' to the dual-write confirmation prompt.)
# (CI: pass --confirm-dual-writes-deployed instead.)
```

Resumable, idempotent, chunked. The CLI walks the table in keyset-pagination order, encrypts each chunk via the encryption client, and writes the ciphertext into `email_encrypted` inside transactions that also checkpoint to `cs_migrations`. SIGINT-safe.

If something goes wrong (e.g. you discover the dual-write code wasn't actually live when backfill ran), re-run with `--force` to re-encrypt every row regardless of current state.

> **SDK-only note:** `stash encrypt cutover` currently requires a pending EQL configuration set by `stash db push`. If you're using the SDK without Proxy, you'll hit a "No pending EQL configuration" error from cutover. **Workaround:** run `stash db push` once before `stash encrypt cutover`. [Issue #447](https://github.com/cipherstash/stack/issues/447) tracks decoupling this requirement.

#### Cutover: rename swap and activate

First, update the Drizzle schema to the post-cutover shape — switch `email` to use `encryptedType` and remove the `email_encrypted` column.

> **Using CipherStash Proxy?**
> 
> If using Proxy, re-push the encryption config so EQL has a pending row that points at `email` (no `_encrypted` suffix):
> 
> ```bash
> stash db push
> # → writes the new config as `pending`. Active config (still pointing at
> #   `email_encrypted`) keeps serving while we complete the cutover.
> ```

Now run the cutover:

```bash
stash encrypt cutover --table users --column email
```

Inside one transaction it: (1) renames `email` → `email_plaintext` and `email_encrypted` → `email`, (2) promotes the pending EQL config to `active` (and the prior active to `inactive`), (3) records a `cut_over` event in `cs_migrations`.

The Drizzle schema you just edited now matches the physical DB shape — `email` is the encrypted column. Keep the temporary `email_plaintext: text('email_plaintext')` declaration in the schema file until the drop step:

```typescript
// src/db/schema.ts (post-cutover)
export const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: encryptedType<string>('email', {
    freeTextSearch: true,
    equality: true,
  }),
  email_plaintext: text('email_plaintext'),  // temporary; dropped next
})
```

App code that does `SELECT email FROM users` now returns ciphertext that must be decrypted via the encryption client. **This is the moment that breaks read paths if they aren't decrypting.**

Update read paths to decrypt:

```typescript
// Before
const rows = await db.select().from(users).where(eq(users.id, id))
const email = rows[0].email

// After
const rows = await db.select().from(users).where(eq(users.id, id))
const decrypted = await encryptionClient.decryptModel(rows[0])
if (decrypted.failure) throw new Error(decrypted.failure.message)
const email = decrypted.data.email
```

For queries that filter on `email`, switch to the encrypted operators from `createEncryptionOperators` — `eq`, `like`, `gte`, etc. (See `## Query Encrypted Data` above.)

#### Drop: remove the plaintext column

Once read paths are updated and you're confident reads are decrypting correctly, generate the drop migration:

```bash
stash encrypt drop --table users --column email
```

The CLI emits a Drizzle migration file with `ALTER TABLE users DROP COLUMN email_plaintext;`. Review and apply with `drizzle-kit migrate`. Update the schema to remove `email_plaintext`:

```typescript
// src/db/schema.ts (final)
export const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: encryptedType<string>('email', {
    freeTextSearch: true,
    equality: true,
  }),
})
```

Also remove the dual-write code from app paths — `email_plaintext` is gone; only `email` (encrypted) is written now.

### Inspecting progress at any time

```bash
stash status         # quest log: where each rollout is, what to do next
stash encrypt status # raw per-column phase, EQL state, backfill progress
stash encrypt plan   # diffs your migrations.json intent vs observed state
```

All three are read-only.

## Complete Operator Reference

### Encrypted Operators (async)

| Operator | Usage | Required Index |
|---|---|---|
| `eq(col, value)` | Equality | `equality: true` or `orderAndRange: true` |
| `ne(col, value)` | Not equal | `equality: true` or `orderAndRange: true` |
| `gt(col, value)` | Greater than | `orderAndRange: true` |
| `gte(col, value)` | Greater than or equal | `orderAndRange: true` |
| `lt(col, value)` | Less than | `orderAndRange: true` |
| `lte(col, value)` | Less than or equal | `orderAndRange: true` |
| `between(col, min, max)` | Between (inclusive) | `orderAndRange: true` |
| `notBetween(col, min, max)` | Not between | `orderAndRange: true` |
| `like(col, pattern)` | LIKE pattern match | `freeTextSearch: true` |
| `ilike(col, pattern)` | ILIKE case-insensitive | `freeTextSearch: true` |
| `notIlike(col, pattern)` | NOT ILIKE | `freeTextSearch: true` |
| `inArray(col, values)` | IN array | `equality: true` |
| `notInArray(col, values)` | NOT IN array | `equality: true` |
| `jsonbPathQueryFirst(col, selector)` | Extract first value at JSONB path | `searchableJson: true` |
| `jsonbGet(col, selector)` | Get value using JSONB `->` operator | `searchableJson: true` |
| `jsonbPathExists(col, selector)` | Check if JSONB path exists | `searchableJson: true` |

### Sort Operators (sync)

| Operator | Usage | Required Index |
|---|---|---|
| `asc(col)` | Ascending sort | `orderAndRange: true` |
| `desc(col)` | Descending sort | `orderAndRange: true` |

### Logical Operators (async, batched)

| Operator | Usage | Description |
|---|---|---|
| `and(...conditions)` | Combine with AND | Batches encryption |
| `or(...conditions)` | Combine with OR | Batches encryption |

Both `and()` and `or()` accept `undefined` conditions, which are filtered out. This is useful for conditional query building:

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(
    await encryptionOps.and(
      maybeCond ? encryptionOps.eq(usersTable.email, value) : undefined,
      encryptionOps.gte(usersTable.age, 18),
    ),
  )
```

### Passthrough Operators (sync, no encryption)

`exists`, `notExists`, `isNull`, `isNotNull`, `not`, `arrayContains`, `arrayContained`, `arrayOverlaps`

These are re-exported from Drizzle and work identically.

## Non-Encrypted Column Fallback

All operators automatically detect whether a column is encrypted. If the column is not encrypted (regular Drizzle column), the operator falls back to the standard Drizzle operator:

```typescript
// This works for both encrypted and non-encrypted columns
await encryptionOps.eq(usersTable.email, "alice@example.com") // encrypted
await encryptionOps.eq(usersTable.role, "admin")              // falls back to drizzle eq()
```

## Complete Example: Express API

```typescript
import "dotenv/config"
import express from "express"
import { eq } from "drizzle-orm"
import { drizzle } from "drizzle-orm/postgres-js"
import postgres from "postgres"
import { pgTable, integer, timestamp, varchar } from "drizzle-orm/pg-core"
import { encryptedType, extractEncryptionSchema, createEncryptionOperators, EncryptionOperatorError, EncryptionConfigError } from "@cipherstash/stack-drizzle"
import { Encryption } from "@cipherstash/stack"

// Schema
const usersTable = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  email: encryptedType<string>("email", { equality: true, freeTextSearch: true }),
  age: encryptedType<number>("age", { dataType: "number", orderAndRange: true }),
  role: varchar("role", { length: 50 }),
  createdAt: timestamp("created_at").defaultNow(),
})

// Init
const usersSchema = extractEncryptionSchema(usersTable)
const encryptionClient = await Encryption({ schemas: [usersSchema] })
const encryptionOps = createEncryptionOperators(encryptionClient)
const db = drizzle({ client: postgres(process.env.DATABASE_URL!) })

const app = express()
app.use(express.json())

// Create user
app.post("/users", async (req, res) => {
  const encrypted = await encryptionClient.encryptModel(req.body, usersSchema)
  if (encrypted.failure) return res.status(500).json({ error: encrypted.failure.message })

  const [user] = await db.insert(usersTable).values(encrypted.data).returning()
  res.json(user)
})

// Search users
app.get("/users", async (req, res) => {
  const conditions = []

  if (req.query.email) {
    conditions.push(encryptionOps.ilike(usersTable.email, `%${req.query.email}%`))
  }
  if (req.query.minAge) {
    conditions.push(encryptionOps.gte(usersTable.age, Number(req.query.minAge)))
  }
  if (req.query.role) {
    conditions.push(eq(usersTable.role, req.query.role as string))
  }

  let query = db.select().from(usersTable)
  if (conditions.length > 0) {
    query = query.where(await encryptionOps.and(...conditions)) as typeof query
  }

  const results = await query
  const decrypted = await encryptionClient.bulkDecryptModels(results)
  if (decrypted.failure) return res.status(500).json({ error: decrypted.failure.message })

  res.json(decrypted.data)
})

app.listen(3000)
```

## Error Handling

Individual operators (e.g., `eq()`, `gte()`, `like()`) throw errors when invoked with invalid configuration or missing indexes:

- **`EncryptionOperatorError`** — thrown for operator-level issues (e.g., invalid arguments, unsupported operations).
- **`EncryptionConfigError`** — thrown for configuration issues (e.g., using `like` on a column without `freeTextSearch: true`).

```typescript
import { createEncryptionOperators, EncryptionOperatorError, EncryptionConfigError } from "@cipherstash/stack-drizzle"

class EncryptionOperatorError extends Error {
  context?: {
    tableName?: string
    columnName?: string
    operator?: string
  }
}

class EncryptionConfigError extends Error {
  context?: {
    tableName?: string
    columnName?: string
    operator?: string
  }
}
```

Encryption client operations return `Result` objects with `data` or `failure`.

## EQL v3 Integration (`@cipherstash/stack-drizzle/v3`)

Everything above covers the v2 integration (`@cipherstash/stack-drizzle`). The **EQL v3** typed schema has its own Drizzle integration on the `@cipherstash/stack-drizzle/v3` subpath. In v3 every encrypted column is a concrete Postgres domain (`public.eql_v3_text_search`, `public.eql_v3_integer_ord`, ...) whose query capabilities are fixed by the type — there is no `equality: true` / `freeTextSearch: true` config object. See the `stash-encryption` skill's "EQL v3 Typed Schema" section for the full `types` catalog and capability suffixes (`Eq`, `Ord`/`OrdOre`, `Match`, `Search`).

Exports: `types` (Drizzle-native column factories mirroring the `@cipherstash/stack/eql/v3` namespace), `makeEqlV3Column`, `getEqlV3Column`, `isEqlV3Column`, `extractEncryptionSchemaV3`, `createEncryptionOperatorsV3`, `EncryptionOperatorError`, and the codec helpers `v3ToDriver` / `v3FromDriver` / `EqlV3CodecError`.

### Schema, Client, and Operators

```typescript
import { pgTable, integer } from "drizzle-orm/pg-core"
import { EncryptionV3 } from "@cipherstash/stack/v3"
import {
  types,
  extractEncryptionSchemaV3,
  createEncryptionOperatorsV3,
} from "@cipherstash/stack-drizzle/v3"

const users = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  email: types.TextSearch("email"),   // equality + order/range + free-text
  age: types.IntegerOrd("age"),       // equality + order/range
})

const usersSchema = extractEncryptionSchemaV3(users)
const client = await EncryptionV3({ schemas: [usersSchema] })
const ops = createEncryptionOperatorsV3(client)
```

Each `types.*` factory emits its domain as the column's SQL type, so `drizzle-kit generate` produces `ADD COLUMN email public.eql_v3_text_search` etc. Install the EQL v3 SQL first with `stash eql install --eql-version 3` (direct install only for v3 — the v2 `generate-eql-migration` Drizzle path is not supported yet).

`makeEqlV3Column(builder)` wraps a column builder from `@cipherstash/stack/eql/v3` (e.g. `makeEqlV3Column(v3types.TextEq("email"))`) — `types.TextEq("email")` from the drizzle subpath is shorthand for the same thing.

### Insert, Query, Decrypt

The Drizzle column stores the encrypted EQL envelope, so encrypt models before insert and decrypt after select — passing the extracted schema table:

```typescript
// Insert
const enc = await client.bulkEncryptModels(
  [{ email: "alice@example.com", age: 30 }],
  usersSchema,
)
if (!enc.failure) await db.insert(users).values(enc.data)

// Query — operators auto-encrypt their plaintext operands
const rows = await db.select().from(users)
  .where(await ops.and(
    ops.contains(users.email, "alice"),   // free-text containment
    ops.between(users.age, 18, 65),
  ))
  .orderBy(ops.asc(users.age))

// Decrypt — v3 decryptModel/bulkDecryptModels take the schema table
const dec = await client.bulkDecryptModels(rows, usersSchema)
```

### Operators

| Operator | Required capability (domain suffix) |
|---|---|
| `eq`, `ne`, `inArray`, `notInArray` | equality (`Eq`, `Ord`, `OrdOre`, `TextSearch`) |
| `gt`, `gte`, `lt`, `lte`, `between`, `notBetween`, `asc`, `desc` | order/range (`Ord`, `OrdOre`, `TextSearch`) |
| `contains` | free-text (`TextMatch`, `TextSearch`) **or** encrypted-JSONB containment (`Json`) |
| `and`, `or` | combinators — accept lazy (un-awaited) operators and `undefined`, resolve concurrently |
| `isNull`, `isNotNull`, `not`, `exists`, `notExists` | Drizzle passthroughs, no encryption |

Differences from the v2 operators to know about:

- **`like` / `ilike` do not exist — by design.** v3 free-text search is tokenised containment, not SQL pattern matching; `contains(col, needle)` is the free-text operator. Don't pass `%` wildcards.
- **`contains` on a `types.Json` column** answers encrypted-JSONB containment instead of free-text: `contains(col, { roles: ['admin'] })` matches every row whose document contains that sub-object (jsonb `@>` semantics; array containment is position-independent). It emits the `@>` operator with a `query_jsonb` needle — a `Json` column carries no `eq` / ordering, so those operators throw on it.
- **No plaintext-column fallback.** Every v3 operator requires an encrypted v3 column and throws `EncryptionOperatorError` otherwise. Use regular Drizzle operators for non-encrypted columns.
- A `null` operand throws — use `isNull()` / `isNotNull()` for NULL checks.
- `inArray` / `notInArray` reject an empty list, and encrypt the whole list in a single `encryptQuery` batch crossing.
- `contains` rejects a needle shorter than the match tokenizer's token length (it would otherwise silently match every row).
- Operators gate on the column's capabilities and throw `EncryptionOperatorError` (with `context.columnName` / `tableName` / `operator`) when the domain can't answer the operator. This `EncryptionOperatorError` is exported from `@cipherstash/stack-drizzle/v3` and is deliberately separate from the v2 class of the same name; there is no `EncryptionConfigError` on the v3 path.
- Every operator takes an optional trailing `{ lockContext, audit }` argument; `createEncryptionOperatorsV3(client, { lockContext, audit })` sets defaults applied to every operand encryption.

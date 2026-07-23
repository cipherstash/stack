---
name: stash-drizzle
description: Integrate CipherStash encryption with Drizzle ORM using @cipherstash/stack-drizzle/v3 (EQL v3). Covers the types.* encrypted column factories (concrete Postgres domains), auto-encrypting query operators (eq, ne, gt/gte/lt/lte, between, inArray, matches, contains, JSON selector, asc/desc), schema extraction, the EncryptionV3 typed client, database setup with stash eql install, and migrating existing plaintext columns to encrypted. Use when adding encryption to a Drizzle ORM project, defining encrypted Drizzle schemas, or querying encrypted columns with Drizzle.
---

# CipherStash Stack - Drizzle ORM Integration

Guide for integrating CipherStash field-level encryption with Drizzle ORM using `@cipherstash/stack-drizzle/v3` (EQL v3). Provides Drizzle-native encrypted column factories and query operators that transparently encrypt search values — Drizzle never sees plaintext in a query.

In EQL v3 every encrypted column is a **concrete Postgres domain** (`public.eql_v3_text_search`, `public.eql_v3_integer_ord`, ...) whose query capabilities are fixed by the type you pick — there is no capability config object. See the `stash-encryption` skill's "Schema Definition" section (the `types` catalog) for the full catalog and capability suffixes (`Eq`, `Ord`/`OrdOre`, `Match`, `Search`, `Json`).

## When to Use This Skill

- Adding field-level encryption to a Drizzle ORM project
- Defining encrypted columns in Drizzle table schemas with the v3 `types.*` factories
- Querying encrypted data with type-safe, auto-encrypting operators
- Sorting, filtering, and encrypted-JSONB querying on encrypted columns
- Migrating an existing plaintext column to encrypted
- Building Express/Hono/Next.js APIs with encrypted Drizzle queries

## Installation

```bash
npm install @cipherstash/stack @cipherstash/stack-drizzle drizzle-orm
```

> **Version note:** `npx stash init` is the preferred install path — it pins
> every `@cipherstash/*` package to the versions matching your CLI release.
> If you install manually as above, verify what actually resolved
> (`node -p "require('@cipherstash/stack/package.json').version"`): bare
> dist-tag installs can lag behind a release, and `stash init` will warn on
> the version skew.

The Drizzle integration ships as its own first-party package,
`@cipherstash/stack-drizzle`, which depends on `@cipherstash/stack`. Install both.
The v3 surface documented here lives on the `@cipherstash/stack-drizzle/v3` subpath.
It is distinct from the older, separate `@cipherstash/drizzle` package (which is
`@cipherstash/protect`-based, with different symbol names) — that package is
**deprecated and no longer published**; do not install it. This package replaces it.

## Database Setup

> **Runner note.** `stash init` adds `stash` to the project as a dev dependency, so `stash <command>` runs through whichever package manager the project uses (Bun, pnpm, Yarn, or npm) — examples in this skill show this bare form. Before init has run, prefix with your package manager's one-shot runner: `bunx`, `pnpm dlx`, `yarn dlx`, or `npx`. The CLI's behaviour is identical across all of them.

### Install the EQL v3 SQL

EQL (Encrypt Query Language) provides the PostgreSQL functions and domains that make encrypted columns searchable. Two ways to install version 3:

**Direct install** — run the SQL straight against the database (quick, good for dev):

```bash
stash eql install --eql-version 3
```

**Migration (preferred for real projects)** — generate a Drizzle custom migration that carries the EQL v3 install SQL, so it lands in your migration history and ships to every environment through `drizzle-kit migrate`:

```bash
stash eql migration --drizzle              # writes a custom migration into drizzle/
stash eql migration --drizzle --supabase   # also grants eql_v3 to anon/authenticated/service_role
```

The generated migration also installs the `cs_migrations` tracking schema, so a single `drizzle-kit migrate` covers everything `stash encrypt …` needs — no out-of-band `stash eql install`. EQL v3 ships one SQL bundle for every target including Supabase; `--supabase` only adds the PostgREST/RLS role grants (harmless when you connect directly as `postgres`). Requires `drizzle-kit` installed and configured.

**Changing an existing plaintext column to an encrypted one.** `drizzle-kit generate` emits an in-place `ALTER TABLE … ALTER COLUMN … SET DATA TYPE eql_v3_<name>`, which Postgres rejects — there is no cast from `text`/`numeric` to an EQL domain. (On drizzle-kit 0.31.0 and later the emitted type is also mangled to `"undefined"."eql_v3_<name>"`, since a `customType` has no `typeSchema`.) The `stash eql migration --drizzle` sweep repairs the invalid statement — the `stash-cli` skill covers what it rewrites and the rule that matters: the repair is data-destroying, so it is safe **only on an empty table**. For a table with live data, do **not** apply the swept migration; follow the staged flow in **Migrating an Existing Column to Encrypted** below instead.

### Column Storage

Each encrypted column is a concrete Postgres domain named `public.eql_v3_<name>`:

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  email public.eql_v3_text_search,   -- equality + order/range + free-text
  age public.eql_v3_integer_ord,     -- equality + order/range
  profile public.eql_v3_json_search,        -- encrypted-JSONB queries
  role VARCHAR(50)                   -- non-encrypted columns are normal types
);
```

You don't usually hand-write this: the `types.*` factories below emit the domain as the column's SQL type, so `drizzle-kit generate` produces the `ADD COLUMN "email" "eql_v3_text_search"` DDL for you. The generated type is **unqualified** (`eql_v3_text_search`, not `public.eql_v3_text_search`): drizzle-kit wraps a custom type's whole name in one pair of quotes, which would turn a schema-qualified name into the invalid identifier `"public.eql_v3_text_search"`. The bare name resolves via the search path because the domains live in `public` — so keep `public` on the search path (the default), and don't hand-edit the generated type back to a qualified name.

Drizzle emits the encrypted query operators for you, but **no index DDL** — add the `eql_v3.*` functional-index `CREATE INDEX` statements in a drizzle-kit migration (custom SQL). Recipes per domain are in the `stash-indexing` skill.

## Schema Definition

Use the `types` namespace from `@cipherstash/stack-drizzle/v3` to define encrypted columns. Each factory maps 1:1 to a Postgres domain, and the column's query capabilities are fixed by the type:

```typescript
import { pgTable, integer, timestamp, varchar } from "drizzle-orm/pg-core"
import { types } from "@cipherstash/stack-drizzle/v3"

const usersTable = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),

  email: types.TextSearch("email"),      // equality + order/range + free-text
  age: types.IntegerOrd("age"),          // equality + order/range
  notes: types.Text("notes"),            // storage only — encrypt/decrypt, no queries
  profile: types.Json("profile"),        // encrypted-JSONB containment + selector

  // Non-encrypted columns
  role: varchar("role", { length: 50 }),
  createdAt: timestamp("created_at").defaultNow(),
})
```

Capability suffixes at a glance (full catalog: `stash-encryption` skill, "Schema Definition" — the `types` namespace):

| Factory shape | Domain | Enables |
|---|---|---|
| `types.Text`, `types.Integer`, ... (no suffix) | `eql_v3_text`, ... | Storage only |
| `types.TextEq`, `types.IntegerEq`, ... | `eql_v3_text_eq`, ... | `eq`, `ne`, `inArray`, `notInArray` |
| `types.IntegerOrd`, `types.TimestampOrd`, ... | `eql_v3_integer_ord`, ... | equality + `gt`/`gte`/`lt`/`lte`/`between`/`asc`/`desc` |
| `types.IntegerOrdOre`, ... | `eql_v3_integer_ord_ore`, ... | as `Ord`, with block-ORE ordering (superuser-only install — see Sorting) |
| `types.TextMatch` | `eql_v3_text_match` | `matches` (fuzzy free-text) only |
| `types.TextSearch` | `eql_v3_text_search` | equality + order/range + `matches` |
| `types.Json` | `eql_v3_json_search` | `contains` + `selector` (encrypted JSONB) |

Value families: `Integer`/`Smallint`/`Numeric`/`Real`/`Double` (`number`), `Bigint` (`bigint`), `Date`/`Timestamp` (`Date`), `Text` (`string`), `Boolean` (`boolean`, storage only), `Json` (a JSON document — object or array, not a top-level scalar).

`makeEqlV3Column(builder)` wraps a column builder from `@cipherstash/stack/eql/v3` (e.g. `makeEqlV3Column(v3types.TextEq("email"))`) — `types.TextEq("email")` from the Drizzle subpath is shorthand for the same thing.

## Initialization

### 1. Extract Schema from Drizzle Table

```typescript
import { extractEncryptionSchemaV3, createEncryptionOperatorsV3 } from "@cipherstash/stack-drizzle/v3"
import { EncryptionV3 } from "@cipherstash/stack/v3"

// Convert the Drizzle table definition to a CipherStash v3 schema
const usersSchema = extractEncryptionSchemaV3(usersTable)
```

### 2. Initialize the Encryption Client

```typescript
const encryptionClient = await EncryptionV3({
  schemas: [usersSchema],
})
```

`EncryptionV3` returns a strongly-typed client: plaintext types are pinned to each column's domain, and query methods only accept queryable columns.

### 3. Create Query Operators

```typescript
const ops = createEncryptionOperatorsV3(encryptionClient)
```

`createEncryptionOperatorsV3(client, { lockContext, audit })` optionally sets defaults applied to every operand encryption; the async encrypting operators (`eq`, `ne`, `inArray`, `notInArray`, `gt`/`gte`/`lt`/`lte`, `between`/`notBetween`, `matches`, `contains`, and all methods returned by `selector(...)`) also take an optional trailing `{ lockContext, audit }` argument per call. Top-level `asc`/`desc` and the passthrough operators (`isNull`, `isNotNull`, `not`, `and`, `or`, `exists`, `notExists`) encrypt nothing and take no such argument.

### 4. Create Drizzle Instance

```typescript
import { drizzle } from "drizzle-orm/postgres-js"
import postgres from "postgres"

const db = drizzle({ client: postgres(process.env.DATABASE_URL!) })
```

## Insert Encrypted Data

Rows are pre-encrypted with the client before `db.insert` — Drizzle only ever handles the encrypted EQL envelope:

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

Operators auto-encrypt their plaintext operands into EQL v3 query terms — you pass plaintext, the emitted SQL compares encrypted values. Comparison operators are async (they encrypt), so `await` them (or hand them lazily to `ops.and`/`ops.or`, below).

### Equality

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(await ops.eq(usersTable.email, "alice@example.com"))
```

### Free-Text Search (`matches`)

`matches(col, needle)` is fuzzy bloom-token matching on a `TextMatch`/`TextSearch` column — **not** SQL pattern matching. There are no `like`/`ilike` operators on the v3 surface, by design; don't pass `%` wildcards.

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(await ops.matches(usersTable.email, "alice"))
```

Semantics to know:

- **Fuzzy and one-sided.** The needle's downcased token set is bloom-tested as a subset of the column's — order- and multiplicity-insensitive. A match may be a false positive; a non-match never is. Re-check candidates after decryption if you need exactness.
- **Case-insensitive**, and matches substrings of 3 characters or more.
- **Short needles are rejected.** A needle shorter than the tokenizer's token length (3 by default) produces no tokens and would silently match every row, so the operator throws `EncryptionOperatorError` instead.

### Range Queries

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(await ops.gte(usersTable.age, 18))

const results = await db
  .select()
  .from(usersTable)
  .where(await ops.between(usersTable.age, 18, 65))
```

### Array Membership

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(await ops.inArray(usersTable.email, [
    "alice@example.com",
    "bob@example.com",
  ]))
```

`inArray`/`notInArray` reject an empty list and encrypt the whole list in a single batch crossing.

### Sorting

```typescript
// Sort by encrypted column (sync — no await needed)
const results = await db
  .select()
  .from(usersTable)
  .orderBy(ops.asc(usersTable.age))

const results = await db
  .select()
  .from(usersTable)
  .orderBy(ops.desc(usersTable.age))
```

`ops.asc`/`ops.desc` emit `ORDER BY eql_v3.ord_term(col)` (`ord_term_ore(col)` for the `*OrdOre` domains). The ORE-flavoured domains require a superuser install and are unavailable on managed Postgres (Supabase, RDS, etc.) — prefer the plain `Ord` domains there; ordering works everywhere EQL v3 installs.

### Encrypted-JSONB Containment (`contains`)

`contains(col, subDoc)` on a `types.Json` column is **exact** encrypted containment (jsonb `@>` semantics, no false positives). The needle is a ciphertext-free `query_json` term. Array containment is position-independent — `{ roles: ["admin"] }` matches any document whose `roles` array includes `"admin"`:

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(await ops.contains(usersTable.profile, { roles: ["admin"] }))
```

An empty-object needle (`{}`) is rejected — `doc @> '{}'` holds for every document, so it would silently match every row. Omit the predicate if you want all rows.

`types.Json` carries no equality or ordering: `eq`/`gt`/`asc` on a `Json` column throw.

### JSONPath Selector-with-Constraint (`selector`)

`ops.selector(col, path)` returns comparison methods bound to the encrypted value at a JSONPath inside a `types.Json` column. Its unique power over `contains` is **ordering at a path**:

```typescript
// col->'$.age' > 25
const results = await db
  .select()
  .from(usersTable)
  .where(await ops.selector(usersTable.profile, "$.age").gt(25))

// col->'$.user' = 'zoe@example.com'
const results = await db
  .select()
  .from(usersTable)
  .where(await ops.selector(usersTable.profile, "$.user").eq("zoe@example.com"))

// ORDER BY eql_v3.ord_term of the encrypted leaf at $.age
const ordered = await db
  .select()
  .from(usersTable)
  .orderBy(await ops.selector(usersTable.profile, "$.age").asc())
```

Available methods: `.eq`, `.ne`, `.gt`, `.gte`, `.lt`, `.lte`, `.asc`, `.desc`. Rules:

- **Paths are dot-notation object keys only** (`"$.a.b"`). Array-index and wildcard syntax (`$.items[0]`) is rejected.
- **Leaves are JSON scalars only**: `string`, `number`, or `boolean`. An object or array leaf is rejected — use `contains` for sub-object matching. A `boolean` leaf is rejected under the ordering methods (booleans have no ordering). Serialize `Date`/`bigint` to the representation actually stored in the JSON document.
- **A scalar needle does not match an array at the path.** `selector(col, "$.tags").eq("a")` will not match `{ tags: ["a"] }` — use `contains(col, { tags: ["a"] })` for that.
- **Absent-path semantics:** `eq` and the ordering methods exclude rows whose document lacks the path; `ne` **includes** them ("not equal to X" covers "has no X").
- **ORDER BY absent paths are SQL NULL.** PostgreSQL's normal NULL placement applies (`ASC` puts them last; `DESC` puts them first unless the query overrides NULL placement).
- **No ciphertext in selector predicates.** Equality uses a value-selector containment needle (and can use the functional GIN index); ordering uses a selector hash plus a ciphertext-free scalar query term.

### Batched Conditions (and / or)

Use `ops.and()` and `ops.or()` to combine encrypted conditions. Pass the operators **lazily** (no `await`) so they resolve concurrently, then `await` the outer call:

```typescript
const results = await db
  .select()
  .from(usersTable)
  .where(
    await ops.and(
      ops.gte(usersTable.age, 18),              // no await — lazy
      ops.lte(usersTable.age, 65),
      ops.matches(usersTable.email, "example"),
      eq(usersTable.role, "admin"),             // mix with regular Drizzle ops
    ),
  )

const results = await db
  .select()
  .from(usersTable)
  .where(
    await ops.or(
      ops.eq(usersTable.email, "alice@example.com"),
      ops.eq(usersTable.email, "bob@example.com"),
    ),
  )
```

Both accept `undefined` conditions, which are filtered out — useful for conditional query building:

```typescript
await ops.and(
  maybeEmail ? ops.eq(usersTable.email, maybeEmail) : undefined,
  ops.gte(usersTable.age, 18),
)
```

### NULLs and Non-Encrypted Columns

- A `null` operand throws — use `ops.isNull(col)` / `ops.isNotNull(col)` for NULL checks.
- **No plaintext-column fallback.** Every v3 operator requires an encrypted v3 column and throws `EncryptionOperatorError` otherwise. Use regular Drizzle operators (`eq`, `gte`, ...) for non-encrypted columns — mixing the two inside `ops.and`/`ops.or` is fine.

## Decrypt Results

Selected rows hold encrypted envelopes; decrypt with the client. The v3 `decryptModel`/`bulkDecryptModels` take the schema table as the second argument:

```typescript
// Single model
const decrypted = await encryptionClient.decryptModel(results[0], usersSchema)
if (!decrypted.failure) {
  console.log(decrypted.data.email) // "alice@example.com"
}

// Bulk decrypt
const decrypted = await encryptionClient.bulkDecryptModels(results, usersSchema)
if (!decrypted.failure) {
  for (const user of decrypted.data) {
    console.log(user.email)
  }
}
```

`Date` columns are reconstructed to real `Date` instances on decrypt; `bigint` columns round-trip as native `bigint`. Non-schema fields pass through unchanged.

## Migrating an Existing Column to Encrypted

The hard case: a Drizzle table that already exists in production with live data in a plaintext column you want to encrypt. You can't just change the column type — that would drop the data and break NOT NULL constraints.

CipherStash splits this into two named steps with a hard production-deploy gate between them: an **encryption rollout** (schema-add + dual-write code) and a **cutover step** (backfill + switch reads + drop — under EQL v2 the switch is a rename, under v3 it is an application-side change). (If using CipherStash Proxy, the rollout also includes `stash db push` to register the encryption config with EQL.) The `stash-encryption` skill is the canonical reference for the lifecycle; this section walks the Drizzle-specific shape.

> **EQL version note.** The CLI rollout tooling (`stash encrypt *`, and the underlying `@cipherstash/migrate`) works with **both EQL versions** and auto-detects a column's version from its Postgres domain type — there is no flag. The lifecycles differ at the end: **v3** (the default, and what the schema below uses) is `schema-add → dual-write → deploy gate → backfill → switch the app to the encrypted column by name → drop`, with **no cut-over rename**; **v2** finishes with `stash encrypt cutover` (a rename swap plus an `eql_v2_configuration` promotion) before the drop. Running `stash encrypt cutover` on a **backfilled** v3 column reports "not applicable" and exits 0 (it exits 1 if the backfill hasn't finished).

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
import { types } from '@cipherstash/stack-drizzle/v3'

export const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email: text('email').notNull(),                    // unchanged
  email_encrypted: types.TextSearch('email_encrypted'),  // new — nullable
})
```

Update the encryption client to harvest the encrypted columns from the table:

```typescript
// src/encryption/index.ts
import { EncryptionV3 } from '@cipherstash/stack/v3'
import { extractEncryptionSchemaV3 } from '@cipherstash/stack-drizzle/v3'
import { users } from '../db/schema'

const usersEncryptionSchema = extractEncryptionSchemaV3(users)

export const encryptionClient = await EncryptionV3({ schemas: [usersEncryptionSchema] })
```

Generate the migration with `drizzle-kit generate`. The generated SQL should be a single `ALTER TABLE ... ADD COLUMN email_encrypted public.eql_v3_text_search;`. Apply with `drizzle-kit migrate`. (This requires the EQL v3 SQL to be installed first — see Database Setup.)

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

> **SDK-only note (EQL v2 only):** `stash encrypt cutover` requires a pending EQL configuration set by `stash db push`. If you're using the SDK without Proxy, you'll hit a "No pending EQL configuration" error from cutover. **Workaround:** run `stash db push` once before `stash encrypt cutover`. EQL v3 columns never hit this — cut-over doesn't apply to them.

#### Switch reads to the encrypted column

**EQL v3 (the schema above): there is no cut-over.** The encrypted column keeps
its own name — you switch the application to it by name, verify reads, then drop
the plaintext column. Point your queries at `email_encrypted`, deploy, and
confirm reads decrypt correctly; then skip ahead to the drop step. Running
`stash encrypt cutover` on a **backfilled** v3 column reports "not applicable" and exits 0 (it exits 1 if the backfill hasn't finished).

The rest of this subsection is the **EQL v2** path (a `eql_v2_encrypted` twin),
kept for existing v2 deployments.

First, update the Drizzle schema to the post-cutover shape — switch `email` to the encrypted type and remove the `email_encrypted` column.

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
  email: types.TextSearch('email'),
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
const decrypted = await encryptionClient.decryptModel(rows[0], usersEncryptionSchema)
if (decrypted.failure) throw new Error(decrypted.failure.message)
const email = decrypted.data.email
```

For queries that filter on `email`, switch to the encrypted operators from `createEncryptionOperatorsV3` — `eq`, `matches`, `gte`, etc. (See `## Query Encrypted Data` above.)

#### Drop: remove the plaintext column

Once read paths are updated and you're confident reads are decrypting correctly, generate the drop migration:

```bash
stash encrypt drop --table users --column email
```

The CLI emits a Drizzle migration file with the drop. **Which column it drops depends on the EQL version**, which the CLI auto-detects:

- **v3** — drops the original plaintext column, `ALTER TABLE users DROP COLUMN email;`. There was no rename, so no `email_plaintext` exists. Requires the column to be in the `backfilled` phase, plus a live coverage check.
- **v2** — drops the post-rename leftover, `ALTER TABLE users DROP COLUMN email_plaintext;`. Requires the `cut-over` phase.

Review and apply with `drizzle-kit migrate`, then update the schema to its final shape — the encrypted column is the only one left:

```typescript
// src/db/schema.ts (final, EQL v3)
export const users = pgTable('users', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  email_encrypted: types.TextSearch('email_encrypted'),
})
```

Also remove the dual-write code from app paths — the plaintext column is gone; only the encrypted column is written now.

### Inspecting progress at any time

```bash
stash status         # quest log: where each rollout is, what to do next
stash encrypt status # raw per-column phase, EQL state, backfill progress
stash encrypt plan   # diffs your migrations.json intent vs observed state
```

All three are read-only.

## Complete Operator Reference

All comparison/containment operators auto-encrypt their operands and are async; `asc`/`desc` and the passthroughs are sync.

### Encrypted Operators (async)

| Operator | Usage | Required column capability (domain suffix) |
|---|---|---|
| `eq(col, value)` | Equality | equality (`Eq`, `Ord`, `OrdOre`, `TextSearch`) |
| `ne(col, value)` | Not equal | equality |
| `gt` / `gte` / `lt` / `lte` `(col, value)` | Comparison | order/range (`Ord`, `OrdOre`, `TextSearch`) |
| `between(col, min, max)` | Inclusive range | order/range |
| `notBetween(col, min, max)` | Negated range | order/range |
| `inArray(col, values)` / `notInArray(col, values)` | Membership (single-batch encryption; empty list rejected) | equality |
| `matches(col, needle)` | Fuzzy free-text token match (short needles rejected) | free-text (`TextMatch`, `TextSearch`) |
| `contains(col, subDoc)` | Exact encrypted-JSONB containment (`{}` rejected) | `Json` |
| `selector(col, path).eq/ne/gt/gte/lt/lte(value)` | JSONPath selector-with-constraint (dot-notation paths, scalar leaves) | `Json` |
| `selector(col, path).asc()/desc()` | ORDER BY a scalar JSONPath leaf (missing paths are SQL NULL) | `Json` |

### Sort Operators (sync)

| Operator | Usage | Required capability |
|---|---|---|
| `asc(col)` | `ORDER BY eql_v3.ord_term(col)` ascending | order/range |
| `desc(col)` | `ORDER BY eql_v3.ord_term(col)` descending | order/range |

(`ord_term_ore` for `*OrdOre` domains — superuser-only, unavailable on managed Postgres.)

### Logical Operators (async, concurrent)

| Operator | Description |
|---|---|
| `and(...conditions)` | Conjunction — accepts lazy (un-awaited) operators and `undefined`, resolves concurrently |
| `or(...conditions)` | Disjunction — same |

### Passthrough Operators (sync, no encryption)

`isNull`, `isNotNull`, `not`, `exists`, `notExists` — re-exported from Drizzle and work identically.

### Other v3 Exports

`types`, `makeEqlV3Column`, `getEqlV3Column`, `isEqlV3Column`, `extractEncryptionSchemaV3`, `createEncryptionOperatorsV3`, `EncryptionOperatorError`, and the codec helpers `v3ToDriver` / `v3FromDriver` / `EqlV3CodecError` — all from `@cipherstash/stack-drizzle/v3`.

## Error Handling

Operators throw `EncryptionOperatorError` (exported from `@cipherstash/stack-drizzle/v3`) whenever the query cannot be answered safely:

- the column is not an encrypted v3 column (there is no plaintext fallback);
- the column's domain lacks the operator's capability (e.g. ordering a `TextEq` column, `eq` on a `Json` column);
- the operand is `null` (use `isNull`/`isNotNull`), an empty list (`inArray`), an empty object (`contains`), or a too-short needle (`matches`);
- a `selector` path is malformed / uses array syntax, or its leaf value is a non-scalar;
- operand encryption itself fails.

```typescript
import { EncryptionOperatorError } from "@cipherstash/stack-drizzle/v3"

class EncryptionOperatorError extends Error {
  context?: {
    tableName?: string
    columnName?: string
    operator?: string
  }
}
```

There is no `EncryptionConfigError` on the v3 path — capability problems surface as `EncryptionOperatorError` with the offending column/table/operator in `context`.

Encryption client operations (`encryptModel`, `bulkDecryptModels`, ...) don't throw — they return `Result` objects with `data` or `failure`. Check `.failure` before using `.data`.

## Legacy: EQL v2

The original v2 integration — `encryptedType` config-flag columns, `extractEncryptionSchema`, and `createEncryptionOperators` (with `like`/`ilike`) from the `@cipherstash/stack-drizzle` package root, over the `eql_v2_encrypted` column type installed via `stash eql install --drizzle` (the deprecated standalone `@cipherstash/drizzle` package shipped its own `generate-eql-migration` bin for the same purpose) — still exists for existing deployments and is documented at https://cipherstash.com/docs. New projects must use the `/v3` surface documented above — `stash init --drizzle` generates an EQL **v3** migration via `stash eql migration --drizzle`. Reaching the v2 install path now requires opting in explicitly with `stash eql install --drizzle --eql-version 2`.

---
name: stash-supabase
description: Integrate CipherStash encryption with Supabase using @cipherstash/stack/supabase. Covers the encryptedSupabase wrapper, transparent encryption/decryption on insert/update/select, encrypted query filters (eq, like, ilike, gt/gte/lt/lte, in, or, match), identity-aware encryption, and the complete query builder API. Use when adding encryption to a Supabase project, querying encrypted columns, or building secure Supabase applications.
---

# CipherStash Stack - Supabase Integration

Guide for integrating CipherStash field-level encryption with Supabase using the `encryptedSupabase` wrapper. The wrapper provides transparent encryption on mutations and decryption on selects, with full support for querying encrypted columns.

## When to Use This Skill

- Adding field-level encryption to a Supabase project
- Querying encrypted data with Supabase's query builder (eq, like, gt, in, or, etc.)
- Inserting, updating, or upserting encrypted data
- Using identity-aware encryption (lock contexts) with Supabase
- Building applications where sensitive columns need encryption at rest and in transit

## Installation

```bash
npm install @cipherstash/stack @supabase/supabase-js
```

## Database Schema

Encrypted columns must be stored as JSONB in your Supabase database:

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email jsonb NOT NULL,        -- encrypted column
  name jsonb NOT NULL,         -- encrypted column
  age jsonb,                   -- encrypted column (numeric)
  role VARCHAR(50),            -- regular column (not encrypted)
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

For searchable encryption (equality, range, text search), install the EQL extension:

```sql
CREATE EXTENSION IF NOT EXISTS eql_v2;
```

## Setup

### 1. Define Encrypted Schema

```typescript
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"

const users = encryptedTable("users", {
  email: encryptedColumn("email")
    .equality()         // eq, neq, in
    .freeTextSearch(),  // like, ilike

  name: encryptedColumn("name")
    .equality()
    .freeTextSearch(),

  age: encryptedColumn("age")
    .dataType("number")
    .equality()
    .orderAndRange(),   // gt, gte, lt, lte
})
```

### 2. Initialize Clients

```typescript
import { createClient } from "@supabase/supabase-js"
import { Encryption } from "@cipherstash/stack"
import { encryptedSupabase } from "@cipherstash/stack/supabase"

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!,
)

const encryptionClient = await Encryption({ schemas: [users] })

const eSupabase = encryptedSupabase({
  encryptionClient,
  supabaseClient: supabase,
})
```

### 3. Use the Wrapper

All queries go through `eSupabase.from(tableName, schema)`:

```typescript
const { data, error } = await eSupabase
  .from("users", users)
  .select("id, email, name")
  .eq("email", "alice@example.com")
```

## Insert (Encrypted Automatically)

```typescript
// Single insert
const { data, error } = await eSupabase
  .from("users", users)
  .insert({
    email: "alice@example.com",  // encrypted automatically
    name: "Alice Smith",         // encrypted automatically
    age: 30,                     // encrypted automatically
    role: "admin",               // not in schema, passed through
  })
  .select("id")

// Bulk insert
const { data, error } = await eSupabase
  .from("users", users)
  .insert([
    { email: "alice@example.com", name: "Alice", age: 30, role: "admin" },
    { email: "bob@example.com", name: "Bob", age: 25, role: "user" },
  ])
  .select("id")
```

## Update (Encrypted Automatically)

```typescript
const { data, error } = await eSupabase
  .from("users", users)
  .update({ name: "Alice Johnson" })  // encrypted automatically
  .eq("id", 1)
  .select("id, name")
```

## Upsert

```typescript
const { data, error } = await eSupabase
  .from("users", users)
  .upsert(
    { id: 1, email: "alice@example.com", name: "Alice", role: "admin" },
    { onConflict: "id" },
  )
  .select("id, email, name")
```

## Select (Decrypted Automatically)

```typescript
// List query - returns decrypted array
const { data, error } = await eSupabase
  .from("users", users)
  .select("id, email, name, role")
// data: [{ id: 1, email: "alice@example.com", name: "Alice Smith", role: "admin" }]

// Single result
const { data, error } = await eSupabase
  .from("users", users)
  .select("id, email, name")
  .eq("id", 1)
  .single()
// data: { id: 1, email: "alice@example.com", name: "Alice Smith" }

// Maybe single (returns null if no match)
const { data, error } = await eSupabase
  .from("users", users)
  .select("id, email")
  .eq("email", "nobody@example.com")
  .maybeSingle()
// data: null
```

**Important:** You must list columns explicitly in `select()` — using `select('*')` will throw an error. The wrapper automatically adds `::jsonb` casts to encrypted columns so PostgreSQL parses them correctly.

`select()` also accepts an optional second parameter: `select(columns, { head?: boolean, count?: 'exact' | 'planned' | 'estimated' })`.

## Query Filters

All filter values for encrypted columns are automatically encrypted before the query executes. Multiple filters are batch-encrypted in a single ZeroKMS call for efficiency.

### Equality Filters

```typescript
// Exact match (requires .equality() on column)
.eq("email", "alice@example.com")

// Not equal
.neq("email", "alice@example.com")

// IN array (requires .equality())
.in("email", ["alice@example.com", "bob@example.com"])

// NULL check (no encryption needed)
.is("email", null)
```

### Text Search Filters

```typescript
// LIKE - case sensitive (requires .freeTextSearch())
.like("name", "%alice%")

// ILIKE - case insensitive (requires .freeTextSearch())
.ilike("name", "%alice%")
```

### Range/Comparison Filters

```typescript
// Greater than (requires .orderAndRange())
.gt("age", 21)

// Greater than or equal
.gte("age", 18)

// Less than
.lt("age", 65)

// Less than or equal
.lte("age", 100)
```

### Match (Multi-Column Equality)

```typescript
.match({ email: "alice@example.com", name: "Alice" })
```

### OR Conditions

```typescript
// String format
.or("email.eq.alice@example.com,email.eq.bob@example.com")

// Structured format (more type-safe)
.or([
  { column: "email", op: "eq", value: "alice@example.com" },
  { column: "email", op: "eq", value: "bob@example.com" },
])
```

Both forms encrypt values for encrypted columns automatically.

### NOT Filter

```typescript
.not("email", "eq", "alice@example.com")
```

### Raw Filter

```typescript
.filter("email", "eq", "alice@example.com")
```

## Delete

```typescript
const { data, error } = await eSupabase
  .from("users", users)
  .delete()
  .eq("id", 1)
```

## Transforms

These are passed through to Supabase directly:

```typescript
.order("name", { ascending: true })
.limit(10)
.range(0, 9)
.csv()
.abortSignal(signal)
.throwOnError()
.returns<U>()
```

### Ordering by Encrypted Columns

**`ORDER BY` on encrypted columns is not currently supported** on databases without operator family support (including Supabase).

Without operator families installed in PostgreSQL, the database cannot sort on `eql_v2_encrypted` columns. This affects all clients — the Supabase JS SDK, Drizzle, raw SQL, and any other ORM.

**Workaround:** Sort application-side after decrypting the results.

Operator family support is currently being developed in collaboration with the Supabase and CipherStash teams and will be available in a future release.

`.order()` on non-encrypted columns works normally.

## Identity-Aware Encryption

Chain `.withLockContext()` to tie encryption to a specific user's JWT:

```typescript
import { LockContext } from "@cipherstash/stack/identity"

const lc = new LockContext()
const identified = await lc.identify(userJwt)
if (identified.failure) throw new Error(identified.failure.message)
const lockContext = identified.data

const { data, error } = await eSupabase
  .from("users", users)
  .insert({ email: "alice@example.com", name: "Alice" })
  .withLockContext(lockContext)
  .select("id")
```

## Audit Logging

Chain `.audit()` to attach metadata for ZeroKMS audit logging:

```typescript
const { data, error } = await eSupabase
  .from("users", users)
  .select("id, email, name")
  .eq("email", "alice@example.com")
  .audit({ metadata: { action: "user-lookup", requestId: "abc-123" } })
```

## Complete Example

```typescript
import { createClient } from "@supabase/supabase-js"
import { Encryption } from "@cipherstash/stack"
import { encryptedSupabase } from "@cipherstash/stack/supabase"
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"

// Schema
const users = encryptedTable("users", {
  email: encryptedColumn("email").equality().freeTextSearch(),
  name: encryptedColumn("name").equality().freeTextSearch(),
  age: encryptedColumn("age").dataType("number").equality().orderAndRange(),
})

// Clients
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!)
const encryptionClient = await Encryption({ schemas: [users] })
const eSupabase = encryptedSupabase({ encryptionClient, supabaseClient: supabase })

// Insert
await eSupabase
  .from("users", users)
  .insert([
    { email: "alice@example.com", name: "Alice", age: 30 },
    { email: "bob@example.com", name: "Bob", age: 25 },
  ])

// Query with multiple filters
const { data } = await eSupabase
  .from("users", users)
  .select("id, email, name, age")
  .gte("age", 18)
  .lte("age", 35)
  .ilike("name", "%ali%")

// data is fully decrypted:
// [{ id: 1, email: "alice@example.com", name: "Alice", age: 30 }]
```

## Response Type

```typescript
type EncryptedSupabaseResponse<T> = {
  data: T | null                     // Decrypted rows
  error: EncryptedSupabaseError | null
  count: number | null
  status: number
  statusText: string
}
```

Errors can come from Supabase (API errors) or from encryption operations. Check `error.encryptionError` for encryption-specific failures.

The full `EncryptedSupabaseError` type:

```typescript
type EncryptedSupabaseError = {
  message: string
  details?: string       // Supabase error details
  hint?: string          // Supabase error hint
  code?: string          // Supabase/PostgreSQL error code
  encryptionError?: EncryptionError  // CipherStash encryption-specific error
}
```

## Filter to Index Mapping

| Filter Method | Required Index | Query Type |
|---|---|---|
| `eq`, `neq`, `in` | `.equality()` | `'equality'` |
| `like`, `ilike` | `.freeTextSearch()` | `'freeTextSearch'` |
| `gt`, `gte`, `lt`, `lte` | `.orderAndRange()` | `'orderAndRange'` |
| `is` | None | No encryption (NULL/boolean check) |

## Exported Types

`@cipherstash/stack/supabase` also exports the following types:

- `EncryptedSupabaseConfig`
- `EncryptedSupabaseInstance`
- `EncryptedQueryBuilder`
- `PendingOrCondition`
- `SupabaseClientLike`

## Migrating an Existing Column to Encrypted

The hard case: a Supabase table that already exists with live data in a plaintext column you want to encrypt. You can't just change the column type — that would drop the data.

CipherStash splits this into two named steps with a hard production-deploy gate between them: an **encryption rollout** (schema-add + dual-write code + `db push`) and an **encryption cutover** (backfill + rename + drop). The `stash-encryption` skill is the canonical reference for the lifecycle; this section walks the Supabase-specific shape.

> **Runner note.** `stash init` adds `stash` to the project as a dev dependency, so `stash <command>` runs through whichever package manager the project uses (Bun, pnpm, Yarn, or npm) — examples below show this bare form. Before init has run, prefix with your package manager's one-shot runner: `bunx`, `pnpm dlx`, `yarn dlx`, or `npx`. The CLI's behaviour is identical across all of them.

> **Where am I?** Run `stash status` first (substitute the runner per the note above). It shows you which tables/columns are mid-rollout, which are post-deploy, and what the next move is. Re-run after every transition.

### Starting state

You have:

```sql
-- supabase/migrations/<timestamp>_initial.sql (already applied)
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,             -- plaintext, populated, NOT NULL
  created_at timestamptz DEFAULT now()
);
```

…and an `await supabase.from('users').insert({ email })` somewhere in your app code.

### Step 1 — Encryption rollout (one PR, one deploy)

Everything below lands in one PR. The deploy of that PR is the gate.

#### Schema-add: declare the encrypted twin

Generate a Supabase migration:

```bash
supabase migration new add_users_email_encrypted
```

Edit the generated file to add an `email_encrypted` column **alongside** `email`. The encrypted column must be **nullable** at creation — never `NOT NULL`, because rows that already exist will have NULL in this column until backfill catches them.

```sql
-- supabase/migrations/<timestamp>_add_users_email_encrypted.sql
ALTER TABLE users
  ADD COLUMN email_encrypted eql_v2_encrypted;  -- nullable
```

Apply with `supabase db reset` locally or `supabase migration up` against the remote project.

Update the encryption schema to declare the new encrypted column:

```typescript
// src/encryption/schema.ts
import { encryptedTable, encryptedColumn } from '@cipherstash/stack/schema'

export const users = encryptedTable('users', {
  email_encrypted: encryptedColumn('email_encrypted')
    .freeTextSearch()
    .equality(),
})

// src/encryption/index.ts
import { Encryption } from '@cipherstash/stack'
import { users } from './schema'

export const encryptionClient = await Encryption({ schemas: [users] })
```

Register the new encryption config with EQL:

```bash
stash db push
```

If this is the project's first encrypted column, `db push` writes directly to the active EQL config. If an active config already exists, it writes the new config as `pending` — that's expected. Cutover (later) will promote it.

#### Dual-writing: write to both columns from app code

Find **every** code path that writes to `users.email` and update it to encrypt and also write to `email_encrypted`. The cleanest pattern is to keep the raw `supabase` client for the plaintext write and use the `encryptedSupabase` wrapper for the encrypted write — wrapped in a single function so callers can't forget one half:

```typescript
// src/db/users.ts
import { supabase, encrypted } from './clients'
import { users } from '../encryption/schema'

export async function insertUser(email: string) {
  // The encryptedSupabase wrapper handles the encryption call for you;
  // the plaintext write is a separate `supabase` call so the rollout
  // does not change read behaviour for `email` yet.
  const ciphertext = await encrypted.encryptValue(email, {
    table: users,
    column: 'email_encrypted',
  })
  if (ciphertext.failure) throw new Error(ciphertext.failure.message)

  return supabase.from('users').insert({
    email,                                  // plaintext — keep writing
    email_encrypted: ciphertext.data,       // encrypted twin — new
  })
}
```

Same shape for UPDATE: every site that updates `email` must also re-encrypt and update `email_encrypted` in the same statement.

**The dual-write rule.** Every persistence path that mutates this row writes both columns, in the same transaction, on every code branch. Insert sites, update sites, upserts, ON CONFLICT clauses, seeders, fixtures, edge functions, RPC functions, admin actions, background jobs, third-party webhooks — all of them. A single missed branch means rows inserted in production after deploy land in plaintext only, and backfill won't catch them. Grep for every site that touches `users.email` before declaring this step done.

After this phase, existing rows still have `email_encrypted = NULL`. Reads still come from `email`. Nothing has broken.

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

#### Cutover: rename swap and activate

First, update the encryption schema to the post-cutover shape — the encrypted column will live under the original column name:

```typescript
// src/encryption/schema.ts (post-cutover)
export const users = encryptedTable('users', {
  email: encryptedColumn('email').freeTextSearch().equality(),
})
```

Re-push the encryption config so EQL has a pending row that points at `email` (no `_encrypted` suffix):

```bash
stash db push
# → writes the new config as `pending`. Active config (still pointing at
#   `email_encrypted`) keeps serving while we complete the cutover.
```

Now run the cutover:

```bash
stash encrypt cutover --table users --column email
```

Inside one transaction it: (1) renames `email` → `email_plaintext` and `email_encrypted` → `email`, (2) promotes the pending EQL config to `active` (and the prior active to `inactive`), (3) records a `cut_over` event in `cs_migrations`.

App code that does `select('email')` now returns ciphertext that must be decrypted via the `encryptedSupabase` wrapper. **This is the moment that breaks read paths if they aren't going through the wrapper.**

Update read paths to use `encryptedSupabase`:

```typescript
// Before
const { data } = await supabase.from('users').select('email').eq('id', id).single()

// After — encryptedSupabase decrypts transparently
const { data } = await encrypted.from('users').select('email').eq('id', id).single()
```

For queries that filter on `email`, the `encryptedSupabase` wrapper handles the encrypted operators internally — the call site is the same shape as before (`.eq()`, `.like()`, `.ilike()`, `.gte()`, etc.), but the values are encrypted before reaching the database. See `## Query Filters` above.

#### Drop: remove the plaintext column

Once read paths are routing through `encryptedSupabase` and you're confident reads are decrypting correctly:

```bash
stash encrypt drop --table users --column email
```

The CLI emits a Supabase migration file with `ALTER TABLE users DROP COLUMN email_plaintext;`. Review and apply with `supabase migration up` (or `supabase db reset` locally). Then remove the dual-write code from app paths — `email_plaintext` is gone; only `email` (encrypted) is written now via `encryptedSupabase`.

### Inspecting progress at any time

```bash
stash status         # quest log: where each rollout is, what to do next
stash encrypt status # raw per-column phase, EQL state, backfill progress
stash encrypt plan   # diffs your migrations.json intent vs observed state
```

All three are read-only.

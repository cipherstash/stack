---
name: stash-supabase
description: Integrate CipherStash encryption with Supabase using @cipherstash/stack/supabase. Covers encryptedSupabaseV3 (EQL v3, the current surface) — connect-time schema introspection, native public.eql_v3_* column domains, transparent encryption/decryption on insert/update/select, encrypted query filters (eq, contains, gt/gte/lt/lte, in, or, match, order), identity-aware encryption, and the complete query builder API. Includes a legacy section for the v2 encryptedSupabase wrapper. Use when adding encryption to a Supabase project, querying encrypted columns, or building secure Supabase applications.
---

# CipherStash Stack — Supabase Integration

Integrate CipherStash field-level encryption with Supabase. The wrapper encrypts
transparently on mutations and decrypts on selects, with full support for
querying encrypted columns.

**Use `encryptedSupabaseV3` (EQL v3) for new work.** It stores each column in its
own native `public.eql_v3_*` Postgres domain, introspects the database at connect
time (so you usually pass no schema), and supports `select('*')` and encrypted
`order()`. The older v2 `encryptedSupabase` wrapper is still shipped and covered
under [Legacy: EQL v2](#legacy-eql-v2-encryptedsupabase) at the end.

## When to Use This Skill

- Adding field-level encryption to a Supabase project
- Querying encrypted data with Supabase's query builder (eq, contains, gt, in, or, order, …)
- Inserting, updating, or upserting encrypted data
- Using identity-aware encryption (lock contexts) with Supabase
- Migrating an existing plaintext column to encrypted

## Installation

```bash
npm install @cipherstash/stack @supabase/supabase-js
```

## Install EQL v3 on Supabase

Searchable encryption needs EQL. **EQL is not a PostgreSQL extension — do not
`CREATE EXTENSION`.** It is a set of schemas (`eql_v3`, `eql_v3_internal`) plus
the `public.eql_v3_*` column domains, installed by the CLI:

```bash
stash eql install --eql-version 3 --supabase
```

Since eql-3.0.0 there is **one** v3 SQL artifact for every target — there is no
separate Supabase variant. The bundle's only superuser-requiring statements (the
ORE operator class/family) skip themselves when the install role lacks the
privilege, and the bundle then disables the ORE-opclass-backed domains it cannot
support. `--supabase` adds one thing: the role grants for `anon` /
`authenticated` / `service_role` on the two schemas the bundle creates — `eql_v3`
(the operator-backing functions) and `eql_v3_internal` (SEM internals). Without
the grants, encrypted queries fail loudly with a permission error (e.g.
`permission denied for schema eql_v3_internal`).

> **v3 installs via the direct path only.** `--migration` (and `--drizzle`,
> `--latest`, `--migrations-dir`) are rejected under `--eql-version 3`. There is
> no `supabase/migrations/` file for EQL v3, so **`supabase db reset` drops it** —
> the reset replays only the files in that directory. Re-run the install after
> every reset. (This differs from the v2 path, where `--migration` is available
> and preferred.)

No **Exposed schemas** change is needed: the column domains and their operators
live in `public`, so bare `col = term` filters resolve under Supabase's default
PostgREST configuration. Do not expose `eql_v3_internal`.

## Database Schema (native `public.eql_v3_*` domains)

Each encrypted column is declared with the native domain for its type and
capabilities. The domains use SQL-standard type names (`integer`, `smallint`,
`real`, `double`, `boolean`, `timestamp`):

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email public.eql_v3_text_search,      -- eq + range + free-text (contains)
  amount public.eql_v3_integer_ord,     -- eq + range
  joined_at public.eql_v3_timestamp_ord,-- eq + range, decrypts to Date
  role VARCHAR(50),                     -- regular column (not encrypted)
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

The domain is `DOMAIN … AS jsonb` with a CHECK, so an encrypted column is nullable
by default — leave it that way during a rollout (the app writes ciphertext *after*
the column exists). Pick the domain by capability: `*_eq` (equality only), `*_ord`
(equality + OPE range/order), `text_search` (equality + range + free-text
`contains`), `text_match` (free-text `contains` only). See the `stash-encryption`
skill for the full domain catalogue.

## Quick Start

`encryptedSupabaseV3` **introspects the database at connect time**: it detects EQL
v3 columns by their Postgres domain, derives each column's encryption config from
the domain, and builds the encryption client internally. You do not pass a schema.

```typescript
import { encryptedSupabaseV3 } from "@cipherstash/stack/supabase"

// Introspects via options.databaseUrl or DATABASE_URL, then wraps a Supabase client.
const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey)
// or wrap an existing client: await encryptedSupabaseV3(supabaseClient, options)

await es.from("users").insert({ email: "a@b.com", amount: 30 })
await es.from("users").select("id, email, amount").eq("email", "a@b.com")
await es.from("users").select("id, amount").gte("amount", 10).lte("amount", 100)
```

`from(tableName)` takes only the table name — **no schema argument**. Column
capabilities come from the introspected domains. Introspection needs a direct
Postgres connection (`options.databaseUrl`, defaulting to `DATABASE_URL`), so the
factory cannot run in a Worker or the browser.

### Optional declared schemas (compile-time types)

Declaring tables is **optional** — introspection already knows every column's
domain. Passing `schemas` (a record whose keys equal each table's name) only adds
compile-time types and verifies the declared tables against the database at
construction:

```typescript
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"
import { encryptedSupabaseV3 } from "@cipherstash/stack/supabase"

const users = encryptedTable("users", {
  email:  types.TextSearch("email"),        // public.eql_v3_text_search
  amount: types.IntegerOrd("amount"),       // public.eql_v3_integer_ord
  joined: types.TimestampOrd("joined_at"),  // public.eql_v3_timestamp_ord — decrypts to Date
})

const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey, { schemas: { users } })

const { data } = await es.from("users").select("id, email, joined").eq("email", "a@b.com")
```

A declared table gets a **typed builder**: rows infer each column's plaintext type
(`types.IntegerOrd` → `number`, `types.TimestampOrd` → `Date`), storage-only
columns are excluded from every filter method, `contains()` is narrowed to
match-indexed columns, and `order()` to plaintext and OPE-backed ordering columns.
Undeclared tables behave exactly as with no `schemas`. Every v3 column is fully
described by its `types.*` factory — there are no capability or tuning chains on v3
columns. A JS property may map to a different DB column name
(`joined: types.TimestampOrd("joined_at")`); filters, selects, and results are
translated automatically.

The `types.*` member name maps to the flat `public.eql_v3_<name>` domain: strip
the `eql_v3_` prefix and PascalCase each `_`-separated segment (`types.TextEq` →
`public.eql_v3_text_eq`, `types.IntegerOrd` → `public.eql_v3_integer_ord`).

## Insert (Encrypted Automatically)

```typescript
// Single insert
await es.from("users").insert({
  email: "alice@example.com",  // encrypted automatically
  amount: 30,                  // encrypted automatically
  role: "admin",               // not an encrypted domain — passed through
}).select("id")

// Bulk insert
await es.from("users").insert([
  { email: "alice@example.com", amount: 30, role: "admin" },
  { email: "bob@example.com",   amount: 25, role: "user" },
]).select("id")
```

## Update (Encrypted Automatically)

```typescript
await es.from("users").update({ amount: 31 }).eq("id", 1).select("id, amount")
```

## Upsert

```typescript
await es.from("users")
  .upsert({ id: 1, email: "alice@example.com", amount: 30 }, { onConflict: "id" })
  .select("id, email, amount")
```

## Select (Decrypted Automatically)

```typescript
// select('*') works on v3 — it expands to the introspected column list
const { data } = await es.from("users").select("*")

// Explicit columns
const { data } = await es.from("users").select("id, email, amount, role")

// Single / maybe-single
await es.from("users").select("id, email").eq("id", 1).single()
await es.from("users").select("id, email").eq("email", "nobody@example.com").maybeSingle()
```

Rows come back fully decrypted. `select()` also accepts an optional second
parameter: `select(columns, { head?: boolean, count?: 'exact' | 'planned' | 'estimated' })`.

## Query Filters

All filter values for encrypted columns are automatically encrypted before the
query executes. Multiple filters are batch-encrypted in a single ZeroKMS call.

### Equality

```typescript
.eq("email", "alice@example.com")     // requires an eq-capable domain (*_eq, *_ord, text_search)
.neq("email", "alice@example.com")
.in("email", ["alice@example.com", "bob@example.com"])
.is("email", null)                    // NULL check — no encryption
```

### Free-text search — `contains()` (not `like`/`ilike`)

```typescript
.contains("email", "example")   // requires a match-indexed domain (text_search, text_match)
```

The v3 domains define **no LIKE operator**. Free-text search is bloom-filter token
containment (PostgREST `cs` / SQL `@>`), where `%` is tokenized like any other
character — so a `like` pattern is a category error. **Calling `like`/`ilike` on an
encrypted column throws an error pointing at `contains()`**; on plaintext columns
both pass through unchanged.

`contains()` matches **substrings**: the search term blooms to its own trigrams,
and a row matches when the stored value's bloom contains all of them, so any
substring of at least 3 characters (the tokenizer's `token_length`) matches. Terms
shorter than 3 characters bloom to nothing and are rejected with an error rather
than matching every row.

### Range / Comparison

```typescript
.gt("amount", 21)     // requires an *_ord domain
.gte("amount", 18)
.lt("amount", 65)
.lte("amount", 100)
```

### Match (multi-column equality)

```typescript
.match({ email: "alice@example.com", amount: 30 })
```

### OR conditions

```typescript
// String format
.or("email.eq.alice@example.com,email.eq.bob@example.com")

// Structured format (more type-safe)
.or([
  { column: "email", op: "eq", value: "alice@example.com" },
  { column: "email", op: "eq", value: "bob@example.com" },
])
```

`.or()` understands PostgREST's `column.not.<op>.<value>` negation and encrypts
values for encrypted columns in both forms.

### NOT / Raw filter

```typescript
.not("email", "eq", "alice@example.com")
.filter("email", "eq", "alice@example.com")
```

A raw `.filter(column, operator, …)` on an encrypted column derives its query type
from the operator, so `.filter("bio", "cs", …)` on a `text_match` column works and
an unsupported operator throws (rather than silently encrypting the wrong term).

### Ordering by encrypted columns

`order()` works on **OPE-backed v3 ordering columns**. PostgREST cannot emit the
canonical `ORDER BY eql_v3.ord_term(col)`, but it can emit the jsonb path
`col->op`, which selects the same order-preserving OPE term — so the builder
rewrites an encrypted ordering column to `col->op` and the sort reproduces the
plaintext order.

```typescript
.order("amount", { ascending: true })   // *_ord / text_ord / text_search — OK
```

Supported on every `*_ord` domain plus `text_ord` and `text_search` (all carry an
`ope` term). **Rejected with a clear error** on ORE-only ordering columns
(`*_ord_ore` — their `ob` term needs the superuser-only ORE operator class,
unreachable through a jsonb path, and such a column cannot hold data on Supabase
anyway) and on columns with no ordering term. Order by a plaintext column normally.

> This is a v3 improvement: EQL v2 could not order encrypted columns on Supabase
> at all (no operator families). v3 uses OPE, which needs no custom operator class.

### Failure modes worth knowing

**Wrong index on a column → it errors.** Filtering `.gt()` on an `*_eq` domain
throws `… does not support orderAndRange queries`, surfaced as an encryption error.
That is the good case — the adapter does not silently degrade.

**Storage-only domains are not filterable** (e.g. `types.Boolean`, `types.Text`):
a filter (including `.match()`) on one is a type error on a declared table and
always a clear runtime error. `.is(column, null)` remains available.

**Null filter values are rejected** with a pointer to `.is(column, null)` — a null
cannot be encrypted into an operand.

## Delete

```typescript
await es.from("users").delete().eq("id", 1)
```

## Transforms

Passed through to Supabase directly:

```typescript
.limit(10)
.range(0, 9)
.csv()
.abortSignal(signal)
.throwOnError()
.returns<U>()
```

(`.order()` on encrypted columns is handled specially — see
[Ordering](#ordering-by-encrypted-columns).)

## Identity-Aware Encryption

Bind a data key to a claim from the end user's JWT, so only that user can decrypt.
Two parts: **authenticate the client as the user** with `OidcFederationStrategy`,
then chain **`.withLockContext()`** on the query.

```typescript
import { OidcFederationStrategy } from "@cipherstash/stack"
import { LockContext } from "@cipherstash/stack/identity"

// 1. Authenticate as the end user. `getJwt` returns the current Supabase access
//    token and is re-invoked on every (re-)federation.
const strategy = OidcFederationStrategy.create(
  process.env.CS_WORKSPACE_CRN!,
  () => getSupabaseAccessToken(),
)
if (strategy.failure) {
  throw new Error(`[auth] ${strategy.failure.type}: ${strategy.failure.error.message}`)
}

// Pass the strategy to the factory. (encryptedSupabaseV3 builds the encryption
// client internally, so supply it via options.config.authStrategy.)
const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey, {
  config: { authStrategy: strategy.data },
})

// 2. Bind the data key to the user's `sub` claim. No identify() call.
const lockContext = new LockContext()   // defaults to the "sub" claim

await es.from("users")
  .insert({ email: "alice@example.com" })
  .withLockContext(lockContext)
  .select("id")
```

The **same** lock context must be supplied when reading the row back — the claim
is baked into the data key's tag, so decrypting without it fails.

> **Don't call `LockContext.identify()`.** Per-operation CTS tokens were removed in
> `protect-ffi` 0.25. `identify()` still exists for backwards compatibility, but
> the token it fetches is no longer used by encryption. Construct the `LockContext`
> directly and authenticate the client with `OidcFederationStrategy`.

> **The Supabase builder wants a `LockContext` instance.** Core operations also
> accept a plain `{ identityClaim: ["sub"] }`, but `.withLockContext()` on the
> query builder is typed as `LockContext` only. Pass
> `new LockContext({ context: { identityClaim: ["sub", "org_id"] } })` for a custom
> claim set.

## Audit Logging

Chain `.audit()` to attach metadata for ZeroKMS audit logging:

```typescript
await es.from("users")
  .select("id, email")
  .eq("email", "alice@example.com")
  .audit({ metadata: { action: "user-lookup", requestId: "abc-123" } })
```

## Interim: filter operands are full storage envelopes

EQL ships term-only query domains (`eql_v3.query_<name>`, which accept envelopes
with no ciphertext) and the encryption client can mint those narrowed terms, but
PostgREST has no syntax to cast a filter value — an uncast operand can only reach
the `jsonb` operator overload, which coerces it into the storage domain, whose
CHECK requires ciphertext. So the adapter still encrypts each filter value with the
full storage path. The call shape is unchanged.

> **Security caveat:** query terms are meant to be index-terms-only, but a
> full-envelope operand carries a real decryptable ciphertext `c` plus **all** of
> the column's index terms, and PostgREST filters travel in GET query strings — so
> these envelopes can land in URL logs, intermediate proxies, and Supabase request
> logs. The remaining gap is PostgREST operand casting; an adapter-side fix is
> tracked.

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

Errors can come from Supabase (API errors) or from encryption operations.

> **Don't branch on `error.encryptionError` — it is currently always `undefined`.**
> The builder's catch block hardcodes `encryptionError: undefined` when
> constructing the error, so the populated value is discarded even for a genuine
> encryption failure. Until that is fixed, distinguish encryption failures by
> `status === 500 && statusText === 'Encryption Error'`, or use `.throwOnError()`
> and catch `EncryptionFailedError`.

## Complete Example (v3)

```typescript
import { encryptedSupabaseV3 } from "@cipherstash/stack/supabase"
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"

// Optional: declare tables for compile-time types
const users = encryptedTable("users", {
  email:  types.TextSearch("email"),
  amount: types.IntegerOrd("amount"),
})

// Connect (introspects the DB via DATABASE_URL)
const es = await encryptedSupabaseV3(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!,
  { schemas: { users } },
)

// Insert
await es.from("users").insert([
  { email: "alice@example.com", amount: 30 },
  { email: "bob@example.com",   amount: 25 },
])

// Query with multiple filters
const { data } = await es.from("users")
  .select("id, email, amount")
  .gte("amount", 18)
  .lte("amount", 35)
  .contains("email", "ali")

// data is fully decrypted:
// [{ id: 1, email: "alice@example.com", amount: 30 }]
```

## Exported Types

`@cipherstash/stack/supabase` exports:

- **v3:** `EncryptedSupabaseV3Options`, `EncryptedSupabaseV3Instance`,
  `TypedEncryptedSupabaseV3Instance`, `EncryptedQueryBuilderV3`,
  `EncryptedQueryBuilderV3Untyped`, `V3FilterableKeys`,
  `V3FreeTextSearchableKeys`, `V3Schemas`
- **v2 (legacy):** `EncryptedSupabaseConfig`, `EncryptedSupabaseInstance`,
  `EncryptedQueryBuilder`, `PendingOrCondition`, `SupabaseClientLike`
- **shared:** `EncryptedSupabaseResponse`, `EncryptedSupabaseError`

## Migrating an Existing Column to Encrypted

The hard case: a Supabase table that already exists with live data in a plaintext
column you want to encrypt. You can't just change the column type — that would drop
the data. CipherStash splits this into two named steps with a hard
production-deploy gate between them: an **encryption rollout** (schema-add +
dual-write code) and an **encryption cutover** (backfill + rename + drop). The
`stash-encryption` skill is the canonical reference for the lifecycle; this section
walks the Supabase-specific shape for EQL v3.

> **v3 has no EQL configuration table**, so there is no `stash db push` /
> `stash db activate` in this flow (those are v2 + CipherStash Proxy only). The
> encrypted column shape lives entirely in its Postgres domain.

> **Runner note.** `stash init` adds `stash` as a dev dependency, so `stash <cmd>`
> runs through the project's package manager. Before init, prefix with `bunx`,
> `pnpm dlx`, `yarn dlx`, or `npx`.

> **Where am I?** Run `stash status` first. It shows which columns are
> mid-rollout, which are post-deploy, and the next move. Re-run after every
> transition.

### Starting state

```sql
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,             -- plaintext, populated, NOT NULL
  created_at timestamptz DEFAULT now()
);
```

…and an `await supabase.from('users').insert({ email })` somewhere in app code.

### Step 1 — Encryption rollout (one PR, one deploy)

Add an `email_encrypted` column **alongside** `email`, in its native v3 domain.
It must be **nullable** at creation — existing rows are NULL here until backfill.
(EQL v3 has no `supabase/migrations/` file, so apply the domain install and this
column with a direct connection; re-run the EQL install after any `supabase db
reset`.)

```sql
ALTER TABLE users
  ADD COLUMN email_encrypted public.eql_v3_text_search;  -- nullable
```

Connect the encrypted client by introspection (no schema needed):

```typescript
// src/db/clients.ts
import { encryptedSupabaseV3 } from '@cipherstash/stack/supabase'
export const es = await encryptedSupabaseV3(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!)
```

**Dual-write** every path that writes `users.email`, in the same transaction, on
every branch — insert sites, updates, upserts, ON CONFLICT, seeders, edge
functions, RPC, admin actions, background jobs, webhooks. A single missed branch
means rows inserted after deploy land in plaintext only and backfill won't catch
them.

```typescript
// Keep writing plaintext `email`; also write the encrypted twin via the wrapper.
await es.from('users').insert({ email_encrypted: email })   // encrypts email_encrypted
await supabase.from('users').update({ email }).eq(...)      // plaintext, unchanged reads
```

After this phase existing rows still have `email_encrypted = NULL`; reads still
come from `email`. Nothing has broken.

### ⛔ Deploy gate

Ship this PR to production. `stash impl` refuses to run a cutover-step plan until
`cs_migrations` records a `dual_writing` event for `users.email` — the safety net
against running cutover before the dual-write code is actually live.

```bash
stash status        # verify the rollout is recorded
stash plan          # detects dual-writes are live; drafts the cutover plan
```

### Step 2 — Encryption cutover

```bash
# Backfill historical rows (resumable, idempotent, chunked, SIGINT-safe)
stash encrypt backfill --table users --column email
# (Interactive: answer 'yes'. CI: pass --confirm-dual-writes-deployed.)

# Rename swap + record cut_over, in one transaction:
#   email -> email_plaintext, email_encrypted -> email
stash encrypt cutover --table users --column email
```

After cutover, `select('email')` returns ciphertext — read paths **must** go
through the wrapper (`es.from('users').select('email')` decrypts transparently).
Filters keep the same call shape (`.eq()`, `.contains()`, `.gte()`), with values
encrypted before reaching the database.

```bash
# Once reads route through the wrapper and decrypt correctly:
stash encrypt drop --table users --column email    # drops email_plaintext
```

### Inspecting progress at any time (read-only)

```bash
stash status         # where each rollout is, what to do next
stash encrypt status # raw per-column phase, backfill progress
stash encrypt plan   # diffs migrations.json intent vs observed state
```

## Legacy: EQL v2 (`encryptedSupabase`)

The v2 wrapper is still shipped and unchanged. Prefer v3 for new work; use v2 only
for existing v2 deployments. Key differences from v3:

- **Storage type:** one composite `public.eql_v2_encrypted` column (declared as
  `jsonb`), not per-domain `public.eql_v3_*` domains.
- **Schema is required:** every call is `eSupabase.from(table, schema)` with an
  `encryptedTable`/`encryptedColumn` schema built from capability chains
  (`.equality()`, `.freeTextSearch()`, `.orderAndRange()`). v3 introspects instead.
- **`select('*')` is not supported** (no column list to expand) — list columns
  explicitly.
- **Free-text search is `like`/`ilike`** (`eql_v2.like`, `~~`), not `contains()`.
- **`order()` on an encrypted column is unsupported** on Supabase (no operator
  families) — sort application-side after decrypting.
- **Install with `--migration`:** `stash eql install --supabase --migration` writes
  `supabase/migrations/00000000000000_cipherstash_eql.sql` (survives
  `supabase db reset`, unlike the v3 direct install).

```typescript
import { Encryption } from "@cipherstash/stack"
import { encryptedSupabase } from "@cipherstash/stack/supabase"
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"

const users = encryptedTable("users", {
  email: encryptedColumn("email").equality().freeTextSearch(),
  age:   encryptedColumn("age").dataType("number").equality().orderAndRange(),
})

const eSupabase = encryptedSupabase({
  encryptionClient: await Encryption({ schemas: [users] }),
  supabaseClient: supabase,
})

await eSupabase.from("users", users).select("id, email").ilike("email", "%ali%")
```

v2 filter → index mapping: `eq`/`neq`/`in` → `.equality()`; `like`/`ilike` →
`.freeTextSearch()`; `gt`/`gte`/`lt`/`lte` → `.orderAndRange()`; `is` → none.
The two v2 failure modes (wrong index errors; a column missing from the schema
silently compares plaintext) still apply — **v3's introspection removes the second
one**, which is one reason to prefer it.

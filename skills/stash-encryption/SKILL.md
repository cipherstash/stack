---
name: stash-encryption
description: Implement field-level encryption with @cipherstash/stack. Covers schema definition, encrypt/decrypt operations, searchable encryption (equality, free-text, range, JSON), bulk operations, model operations, identity-aware encryption with LockContext, multi-tenant keysets, and the full TypeScript type system. Use when adding encryption to a project, defining encrypted schemas, or working with the CipherStash Encryption API.
---

# CipherStash Stack - Encryption

Comprehensive guide for implementing field-level encryption with `@cipherstash/stack`. Every value is encrypted with its own unique key via ZeroKMS (backed by AWS KMS). Encryption happens client-side before data leaves the application.

## When to Use This Skill

- Adding field-level encryption to a TypeScript/Node.js project
- Defining encrypted table schemas
- Encrypting and decrypting individual values or entire models
- Implementing searchable encryption (equality, free-text, range, JSON queries)
- Bulk encrypting/decrypting large datasets
- Implementing identity-aware encryption with JWT-based lock contexts
- Setting up multi-tenant encryption with keysets
- Migrating from `@cipherstash/protect` to `@cipherstash/stack`

## Installation

```bash
npm install @cipherstash/stack
```

> [!IMPORTANT]
> **Exclude `@cipherstash/stack` from bundling — required for any project with a bundler (Next.js, webpack, esbuild, vite SSR, etc.).** The package wraps a native FFI module (`@cipherstash/protect-ffi`) that cannot be bundled. Importing the encryption client from server code without this exclusion will fail at runtime with errors about missing native modules. Configure as soon as you install the package; do not skip this step.

Concrete configuration for the most common bundlers:

**Next.js** (`next.config.{js,ts,mjs}`):

```ts
const nextConfig = {
  serverExternalPackages: ['@cipherstash/stack', '@cipherstash/protect-ffi'],
}
export default nextConfig
```

(Older Next.js — pre-15 — uses `experimental.serverComponentsExternalPackages` with the same value.)

**webpack** (next/nuxt/remix/etc. that compose webpack directly):

```js
config.externals.push('@cipherstash/stack', '@cipherstash/protect-ffi')
```

**esbuild**:

```js
{ external: ['@cipherstash/stack', '@cipherstash/protect-ffi'] }
```

**Vite SSR**:

```ts
ssr: { external: ['@cipherstash/stack', '@cipherstash/protect-ffi'] }
```

If you skip this step, you'll see runtime errors like `Cannot find module '@cipherstash/protect-ffi-darwin-arm64'` or `dlopen failed` once the bundler tries to inline the native binding.

## Configuration

### Environment Variables

Set these in `.env` or your hosting platform:

```bash
CS_WORKSPACE_CRN=crn:ap-southeast-2.aws:your-workspace-id
CS_CLIENT_ID=your-client-id
CS_CLIENT_KEY=your-client-key
CS_CLIENT_ACCESS_KEY=your-access-key
```

Sign up at [cipherstash.com/signup](https://cipherstash.com/signup) to generate credentials.

### Programmatic Config

```typescript
const client = await Encryption({
  schemas: [users],
  config: {
    workspaceCrn: "crn:ap-southeast-2.aws:your-workspace-id",
    clientId: "your-client-id",
    clientKey: "your-client-key",
    accessKey: "your-access-key",
    keyset: { name: "my-keyset" }, // optional: multi-tenant isolation
  },
})
```

If `config` is omitted, the client reads `CS_*` environment variables automatically.

### Logging

Logging is enabled by default at the `error` level. Configure the log level with the `STASH_STACK_LOG` environment variable:

```bash
STASH_STACK_LOG=error  # debug | info | error (default: error)
```

| Value   | What is logged         |
| ------- | ---------------------- |
| `error` | Errors only (default)  |
| `info`  | Info and errors        |
| `debug` | Debug, info, and errors |

When `STASH_STACK_LOG` is not set, the SDK defaults to `error` (errors only).

The SDK never logs plaintext data.

## Subpath Exports

| Import Path | Provides |
|---|---|
| `@cipherstash/stack` | `Encryption` function, `Secrets` class, `encryptedTable`, `encryptedColumn`, `encryptedField` (convenience re-exports) |
| `@cipherstash/stack/schema` | `encryptedTable`, `encryptedColumn`, `encryptedField`, schema types |
| `@cipherstash/stack/identity` | `LockContext` class and identity types |
| `@cipherstash/stack/secrets` | `Secrets` class and secrets types |
| `@cipherstash/stack/drizzle` | `encryptedType`, `extractEncryptionSchema`, `createEncryptionOperators` for Drizzle ORM |
| `@cipherstash/stack/supabase` | `encryptedSupabase` wrapper for Supabase |
| `@cipherstash/stack/dynamodb` | `encryptedDynamoDB` helper for DynamoDB |
| `@cipherstash/stack/encryption` | `EncryptionClient` class, `Encryption` function |
| `@cipherstash/stack/errors` | `EncryptionErrorTypes`, `StackError`, error subtypes, `getErrorMessage` |
| `@cipherstash/stack/client` | Client-safe exports: schema builders, schema types, `EncryptionClient` type (no native FFI) |
| `@cipherstash/stack/types` | All TypeScript types |

## Schema Definition

Define which tables and columns to encrypt using `encryptedTable` and `encryptedColumn`:

```typescript
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"

const users = encryptedTable("users", {
  email: encryptedColumn("email")
    .equality()         // exact-match queries
    .freeTextSearch()   // full-text / fuzzy search
    .orderAndRange(),   // sorting and range queries

  age: encryptedColumn("age")
    .dataType("number")
    .equality()
    .orderAndRange(),

  address: encryptedColumn("address"), // encrypt-only, no search indexes
})

const documents = encryptedTable("documents", {
  metadata: encryptedColumn("metadata")
    .searchableJson(), // encrypted JSONB queries (JSONPath + containment)
})
```

### Index Types

| Method | Purpose | Query Type |
|---|---|---|
| `.equality(tokenFilters?)` | Exact match lookups. Accepts an optional array of token filters (e.g., `[{ kind: 'downcase' }]`) for case-insensitive matching. | `'equality'` |
| `.freeTextSearch(opts?)` | Full-text / fuzzy search | `'freeTextSearch'` |
| `.orderAndRange()` | Sorting, comparison, range queries | `'orderAndRange'` |
| `.searchableJson()` | Encrypted JSONB path and containment queries (auto-sets `dataType` to `'json'`) | `'searchableJson'` |
| `.dataType(cast)` | Set plaintext data type | N/A |

**Supported data types:** `'string'` (default), `'text'`, `'number'`, `'boolean'`, `'date'`, `'bigint'`, `'json'`

Methods are chainable - call as many as you need on a single column.

### Free-Text Search Options

```typescript
encryptedColumn("bio").freeTextSearch({
  tokenizer: { kind: "ngram", token_length: 3 },  // or { kind: "standard" }
  token_filters: [{ kind: "downcase" }],
  k: 6,
  m: 2048,
  include_original: true,
})
```

### Type Inference

```typescript
import type { InferPlaintext, InferEncrypted } from "@cipherstash/stack/schema"

type UserPlaintext = InferPlaintext<typeof users>
// { email: string; age: string; address: string }

type UserEncrypted = InferEncrypted<typeof users>
// { email: Encrypted; age: Encrypted; address: Encrypted }
```

## Client Initialization

```typescript
import { Encryption } from "@cipherstash/stack"

const client = await Encryption({ schemas: [users, documents] })
```

The `Encryption()` function returns `Promise<EncryptionClient>` and throws on error (e.g., bad credentials, missing config, invalid keyset UUID). At least one schema is required.

```typescript
// Error handling
try {
  const client = await Encryption({ schemas: [users] })
} catch (error) {
  console.error("Init failed:", error.message)
}
```

## Encrypt and Decrypt Single Values

```typescript
// Encrypt
const encrypted = await client.encrypt("hello@example.com", {
  column: users.email,
  table: users,
})

if (encrypted.failure) {
  console.error(encrypted.failure.message)
} else {
  console.log(encrypted.data) // Encrypted payload (opaque object)
}

// Decrypt
const decrypted = await client.decrypt(encrypted.data)

if (!decrypted.failure) {
  console.log(decrypted.data) // "hello@example.com"
}
```

All plaintext values must be non-null. Null handling is managed at the model level by `encryptModel` and `decryptModel`.

## Model Operations

Encrypt or decrypt an entire object. Only fields matching your schema are encrypted; other fields pass through unchanged.

The return type is **schema-aware**: fields matching the table schema are typed as `Encrypted`, while other fields retain their original types. For best results, let TypeScript infer the type parameters from the arguments rather than providing an explicit `<User>`.

```typescript
type User = { id: string; email: string; createdAt: Date }

const user = {
  id: "user_123",
  email: "alice@example.com",  // defined in schema -> encrypted
  createdAt: new Date(),       // not in schema -> unchanged
}

// Encrypt model — let TypeScript infer the return type from the schema
const encResult = await client.encryptModel(user, users)
if (!encResult.failure) {
  // encResult.data.email is typed as Encrypted
  // encResult.data.id is typed as string
  // encResult.data.createdAt is typed as Date
}

// Decrypt model
const decResult = await client.decryptModel(encResult.data)
if (!decResult.failure) {
  console.log(decResult.data.email) // "alice@example.com"
}
```

The `Decrypted<T>` type maps encrypted fields back to their plaintext types.

Passing an explicit type parameter (e.g., `client.encryptModel<User>(...)`) still works for backward compatibility — the return type degrades to `User` in that case.

## Bulk Operations

All bulk methods make a single call to ZeroKMS regardless of record count, while still using a unique key per value.

### Bulk Encrypt / Decrypt (Raw Values)

```typescript
const plaintexts = [
  { id: "u1", plaintext: "alice@example.com" },
  { id: "u2", plaintext: "bob@example.com" },
  { id: "u3", plaintext: "charlie@example.com" },
]

const encrypted = await client.bulkEncrypt(plaintexts, {
  column: users.email,
  table: users,
})
// encrypted.data = [{ id: "u1", data: EncryptedPayload }, ...]

const decrypted = await client.bulkDecrypt(encrypted.data)
// Per-item error handling:
for (const item of decrypted.data) {
  if ("data" in item) {
    console.log(`${item.id}: ${item.data}`)
  } else {
    console.error(`${item.id} failed: ${item.error}`)
  }
}
```

### Bulk Encrypt / Decrypt Models

```typescript
const userModels = [
  { id: "1", email: "alice@example.com" },
  { id: "2", email: "bob@example.com" },
]

const encrypted = await client.bulkEncryptModels(userModels, users)
const decrypted = await client.bulkDecryptModels(encrypted.data)
```

## Searchable Encryption

Encrypt query terms so you can search encrypted data in PostgreSQL.

### Single Query Encryption

```typescript
// Equality query
const eqQuery = await client.encryptQuery("alice@example.com", {
  column: users.email,
  table: users,
  queryType: "equality",
})

// Free-text search
const matchQuery = await client.encryptQuery("alice", {
  column: users.email,
  table: users,
  queryType: "freeTextSearch",
})

// Order and range
const rangeQuery = await client.encryptQuery(25, {
  column: users.age,
  table: users,
  queryType: "orderAndRange",
})

// JSON path query (steVecSelector)
const pathQuery = await client.encryptQuery("$.user.email", {
  column: documents.metadata,
  table: documents,
  queryType: "steVecSelector",
})

// JSON containment query (steVecTerm)
const containsQuery = await client.encryptQuery({ role: "admin" }, {
  column: documents.metadata,
  table: documents,
  queryType: "steVecTerm",
})
```

If `queryType` is omitted, it's auto-inferred from the column's configured indexes (priority: unique > match > ore > ste_vec).

### Query Result Formatting (`returnType`)

By default `encryptQuery` returns an `Encrypted` object (the raw EQL JSON payload). Use `returnType` to change the output format:

| `returnType` | Output | Use case |
|---|---|---|
| `'eql'` (default) | `Encrypted` object | Parameterized queries, ORMs accepting JSON |
| `'composite-literal'` | `string` | Supabase `.eq()`, string-based APIs |
| `'escaped-composite-literal'` | `string` | Embedding inside another string or JSON value |

```typescript
// Get a composite literal string for use with Supabase
const term = await client.encryptQuery("alice@example.com", {
  column: users.email,
  table: users,
  queryType: "equality",
  returnType: "composite-literal",
})
// term.data is a string
```

Each term in a batch can have its own `returnType`.

### Searchable JSON

For columns using `.searchableJson()`, the query type is auto-inferred from the plaintext:

```typescript
// String -> JSONPath selector query
const pathQuery = await client.encryptQuery("$.user.email", {
  column: documents.metadata,
  table: documents,
})

// Object/Array -> containment query
const containsQuery = await client.encryptQuery({ role: "admin" }, {
  column: documents.metadata,
  table: documents,
})
```

### Batch Query Encryption

Encrypt multiple query terms in one ZeroKMS call:

```typescript
const terms = [
  { value: "alice@example.com", column: users.email, table: users, queryType: "equality" as const },
  { value: "bob", column: users.email, table: users, queryType: "freeTextSearch" as const },
]

const results = await client.encryptQuery(terms)
// results.data = [EncryptedPayload, EncryptedPayload]
```

All values in the array must be non-null.

## Identity-Aware Encryption (Lock Contexts)

Lock encryption to a specific user by requiring a valid JWT for decryption.

```typescript
import { LockContext } from "@cipherstash/stack/identity"

// 1. Create a lock context (defaults to the "sub" claim)
const lc = new LockContext()
// Or with custom claims: new LockContext({ context: { identityClaim: ["sub", "org_id"] } })
// Or with a pre-fetched CTS token: new LockContext({ ctsToken: { accessToken: "...", expiry: 123456 } })

// 2. Identify the user with their JWT
const identifyResult = await lc.identify(userJwt)
if (identifyResult.failure) {
  throw new Error(identifyResult.failure.message)
}
const lockContext = identifyResult.data

// 3. Encrypt with lock context
const encrypted = await client
  .encrypt("sensitive data", { column: users.email, table: users })
  .withLockContext(lockContext)

// 4. Decrypt with the same lock context
const decrypted = await client
  .decrypt(encrypted.data)
  .withLockContext(lockContext)
```

Lock contexts work with ALL operations: `encrypt`, `decrypt`, `encryptModel`, `decryptModel`, `bulkEncrypt`, `bulkDecrypt`, `bulkEncryptModels`, `bulkDecryptModels`, `encryptQuery`.

### CTS Token Service

The lock context exchanges the JWT for a CTS (CipherStash Token Service) token. Set the endpoint:

```bash
CS_CTS_ENDPOINT=https://ap-southeast-2.aws.auth.viturhosted.net
```

## Multi-Tenant Encryption (Keysets)

Isolate encryption keys per tenant:

```typescript
// By name
const client = await Encryption({
  schemas: [users],
  config: { keyset: { name: "Company A" } },
})

// By UUID
const client = await Encryption({
  schemas: [users],
  config: { keyset: { id: "123e4567-e89b-12d3-a456-426614174000" } },
})
```

Each keyset provides full cryptographic isolation between tenants.

## Operation Chaining

All operations return thenable objects that support chaining:

```typescript
const result = await client
  .encrypt(plaintext, { column: users.email, table: users })
  .withLockContext(lockContext)         // optional: identity-aware
  .audit({ metadata: { action: "create" } }) // optional: audit trail
```

## Error Handling

All async methods return a `Result` object - a discriminated union with either `data` (success) or `failure` (error), never both.

```typescript
const result = await client.encrypt("hello", { column: users.email, table: users })

if (result.failure) {
  console.error(result.failure.type, result.failure.message)
  // type is one of: "ClientInitError" | "EncryptionError" | "DecryptionError"
  //                  | "LockContextError" | "CtsTokenError"
} else {
  console.log(result.data)
}
```

### Error Types

| Type | When |
|---|---|
| `ClientInitError` | Client initialization fails (bad credentials, missing config) |
| `EncryptionError` | An encrypt operation fails (has optional `code` field) |
| `DecryptionError` | A decrypt operation fails |
| `LockContextError` | Lock context creation or usage fails |
| `CtsTokenError` | Identity token exchange fails |

`StackError` is a discriminated union of all the error types above, enabling exhaustive `switch` handling. `EncryptionErrorTypes` provides runtime constants for each error type string. Use `getErrorMessage(error: unknown): string` to safely extract a message from any thrown value.

```typescript
import { EncryptionErrorTypes, type StackError, getErrorMessage } from "@cipherstash/stack/errors"

function handleError(error: StackError) {
  switch (error.type) {
    case EncryptionErrorTypes.ClientInitError:
      console.error("Init failed:", error.message)
      break
    case EncryptionErrorTypes.EncryptionError:
      console.error("Encrypt failed:", error.message, error.code)
      break
    case EncryptionErrorTypes.DecryptionError:
      console.error("Decrypt failed:", error.message)
      break
    case EncryptionErrorTypes.LockContextError:
      console.error("Lock context failed:", error.message)
      break
    case EncryptionErrorTypes.CtsTokenError:
      console.error("CTS token failed:", error.message)
      break
    default:
      // TypeScript ensures exhaustiveness
      const _exhaustive: never = error
  }
}

// Safe error message extraction from unknown errors
try {
  await client.encrypt("data", { column: users.email, table: users })
} catch (e) {
  console.error(getErrorMessage(e))
}
```

### Validation Rules

- NaN and Infinity are rejected for numeric values
- `freeTextSearch` index only supports string values
- At least one `encryptedTable` schema must be provided
- Keyset UUIDs must be valid format

## Ordering Encrypted Data

**`ORDER BY` on encrypted columns requires operator family support in the database.**

On databases without operator families (e.g. Supabase, or when EQL is installed with `--exclude-operator-family`), sorting on encrypted columns is not currently supported — regardless of the client or ORM used. This applies to Drizzle, the Supabase JS SDK, raw SQL, and any other database client.

**Workaround:** Sort application-side after decrypting the results.

Operator family support for Supabase is being developed in collaboration with the Supabase and CipherStash teams and will be available in a future release.

## PostgreSQL Storage

Encrypted data is stored as EQL (Encrypt Query Language) JSON payloads. Install the EQL extension in PostgreSQL:

```sql
CREATE EXTENSION IF NOT EXISTS eql_v2;

CREATE TABLE users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email eql_v2_encrypted
);
```

Or store as JSONB if not using the EQL extension directly:

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email jsonb NOT NULL
);
```

## Column Migration Lifecycle

Adding a fresh encrypted column to a table you don't yet write to is the easy case — declare it in the schema, run the migration, start writing. The harder case is taking an **existing plaintext column with live data** and turning it into an encrypted one without dropping a write or returning the wrong value mid-cutover. CipherStash models that as a six-phase lifecycle:

```
schema-added → dual-writing → backfilling → backfilled → cut-over → dropped
```

| Phase (`phase` col) | Event (`event` col) | What's true | What changes here |
|---|---|---|---|
| `schema-added` | `schema_added` | The encrypted twin column (`<col>_encrypted`) exists in the DB and is registered in `eql_v2_configuration`. The plaintext column is unchanged; the application still writes only plaintext. | A schema migration adds the column. |
| `dual-writing` | `dual_writing` | Application code now writes both `<col>` (plaintext, unchanged) **and** `<col>_encrypted` (encrypted via the encryption client) on every insert/update. Reads still come from the plaintext column. | Persistence-layer code change. The CLI cannot detect this transition; the user (or agent) declares it via the prompt / `--confirm-dual-writes-deployed` flag on the first backfill run. |
| `backfilling` | `backfill_started`, `backfill_checkpoint` | A backfill job is encrypting the existing plaintext rows into `<col>_encrypted`, in chunks, resumably. New rows continue to land in both columns from dual-writing. Each committed chunk inserts a `backfill_checkpoint` event with the cursor value and rows processed. | The backfill engine in `@cipherstash/migrate` (driven by `stash encrypt backfill`). |
| `backfilled` | `backfilled` | Every row has a non-null `<col>_encrypted` value. Plaintext column still authoritative for reads. | Backfill completes, records the transition. |
| `cut-over` | `cut_over` | A single transaction renames `<col>` → `<col>_plaintext` and `<col>_encrypted` → `<col>` (`eql_v2.rename_encrypted_columns()`). Application reads of `<col>` now return decrypted ciphertext transparently — no app code change required for reads. | One DB transaction. |
| `dropped` | `dropped` | `<col>_plaintext` is removed via a regular schema migration. The application stops writing to it (dual-writing logic is removed). | App-code change to remove dual-writes + a schema migration. |

A failure at any phase is recorded as an `error` event without changing the effective phase, so a retry resumes from where it failed.

### State storage

Three sources of truth, kept separate on purpose:

- **`.cipherstash/migrations.json`** (repo) — *intent*. Which columns the developer wants to encrypt and at which phase, code-reviewable.
- **`eql_v2_configuration`** (DB, EQL-managed) — *EQL intent*. Which columns are encrypted and with which indexes; drives the CipherStash Proxy.
- **`cipherstash.cs_migrations`** (DB, CipherStash-managed) — *runtime state*. Append-only event log: phase transitions, backfill cursors, error rows. The current phase for a column is the `phase` value on the latest row (greatest `id`) for `(table_name, column_name)`.

`stash encrypt status` shows all three side-by-side and flags drift (e.g. EQL says registered, the physical `<col>_encrypted` column is missing).

#### `cipherstash.cs_migrations` schema

Installed by `stash db install` (or, when the project uses Drizzle/Supabase, bundled into the EQL install migration so `drizzle-kit migrate` / `supabase db reset` rolls it out alongside EQL). The DDL is:

```sql
CREATE TABLE cipherstash.cs_migrations (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  table_name     text NOT NULL,
  column_name    text NOT NULL,
  event          text NOT NULL,   -- discrete event, snake_case
  phase          text NOT NULL,   -- effective phase AFTER this event, kebab-case
  cursor_value   text,            -- last processed PK on backfill_checkpoint / backfilled
  rows_processed bigint,          -- cumulative rows encrypted (backfill events only)
  rows_total     bigint,          -- target rows for this backfill (backfill events only)
  details        jsonb,           -- per-event metadata: { chunkSize, resumed, message, force, ... }
  created_at     timestamptz NOT NULL DEFAULT now()
);
```

> Note the column naming: `event` is snake_case (e.g. `cut_over`, `backfill_checkpoint`); `phase` is kebab-case (e.g. `cut-over`, `backfilling`). There is no `status` or `state` column — when you need to read the current state, select the latest `phase` for the `(table_name, column_name)` pair.

The valid `event` values are `schema_added`, `dual_writing`, `backfill_started`, `backfill_checkpoint`, `backfilled`, `cut_over`, `dropped`, `error`. The valid `phase` values are `schema-added`, `dual-writing`, `backfilling`, `backfilled`, `cut-over`, `dropped`.

Inspect runtime state directly when needed:

```sql
-- current phase per column
SELECT DISTINCT ON (table_name, column_name)
  table_name, column_name, event, phase, rows_processed, rows_total, created_at
FROM cipherstash.cs_migrations
ORDER BY table_name, column_name, id DESC;

-- full history for one column
SELECT id, event, phase, cursor_value, rows_processed, details, created_at
FROM cipherstash.cs_migrations
WHERE table_name = 'users' AND column_name = 'email'
ORDER BY id;
```

Programmatic access lives in `@cipherstash/migrate` — `appendEvent`, `progress`, and `latestByColumn` wrap the same queries with typed return values. Prefer those over hand-rolled SQL when scripting transitions; they're the same primitives the CLI uses.

### CLI surface

The `stash encrypt` command group drives each phase. See the `stash-cli` skill for full flag reference. Typical sequence for a single column:

```bash
# Phase 1 — schema-added
# Add the encrypted twin column via your normal migration tooling
# (drizzle-kit / supabase migrations / etc.). Then register the new
# encryption config with EQL:
stash db push
# First push (no active config yet) → writes directly to active.
# Subsequent push (active already exists) → writes pending; cutover
# in phase 4 will promote it.

# Phase 2 + 3 — dual-writing then backfilling, in one command
# (First, edit the application code to write both columns and ship that deploy.
#  Then run backfill — it will prompt to confirm dual-writes are live, append
#  the `dual_writing` event, and run the chunked encryption loop.)
stash encrypt backfill --table users --column email
# In CI / non-interactive contexts, swap the prompt for the explicit flag:
stash encrypt backfill --table users --column email --confirm-dual-writes-deployed
# Resumable; checkpoints to cs_migrations after every chunk. SIGINT-safe.

# Recovery — if dual-writes weren't actually live when backfill first ran,
# rows inserted during the backfill landed in plaintext only and the encrypted
# twin is stale. Re-run with --force to re-encrypt every row regardless.
stash encrypt backfill --table users --column email --force

# Phase 4 — cut-over
# First, edit the schema to drop the `_encrypted` suffix (the column will now
# be named `email`, declared with encryptedType / encryptedColumn). Re-push:
stash db push
# → writes the renamed-shape config as `pending`. The active config (still
#   pointing at `email_encrypted`) keeps serving until cutover finishes.

# Now run the cutover. In one transaction: rename the physical columns,
# promote pending → active, record cs_migrations event.
stash encrypt cutover --table users --column email

# Phase 5 — dropped
stash encrypt drop --table users --column email
# Emits a migration file removing <col>_plaintext. Apply with your normal tooling.
```

### Library use

Long-running backfills can also embed the engine directly without the CLI:

```typescript
import { runBackfill } from '@cipherstash/migrate'
import { Encryption } from '@cipherstash/stack'

const encryptionClient = await Encryption({ schemas: [usersTable] })

await runBackfill({
  db,                              // pg client/pool, postgres-js or drizzle conn
  encryptionClient,
  tableSchema: usersTable,         // the EncryptedTable from your schemas
  tableName: 'users',
  schemaColumnKey: 'email',        // key in the EncryptedTable schema
  plaintextColumn: 'email',
  encryptedColumn: 'email_encrypted',
  pkColumn: 'id',
  chunkSize: 1000,
  signal: abortCtrl.signal,
})
```

Useful when the backfill needs to run in a worker, on a schedule, or alongside an existing job runner.

### Invariants the lifecycle preserves

- **Reads never return the wrong value.** Until cut-over, reads come from the plaintext column. After cut-over, the same `SELECT email` returns the decrypted ciphertext via Proxy or the encryption client. There is no in-between.
- **Writes never drop.** Dual-writing keeps both columns in sync until the cut-over moment. After cut-over, writes go to the encrypted column.
- **Re-runs are safe.** Backfill is idempotent (`<col> IS NOT NULL AND <col>_encrypted IS NULL` guards every chunk). `cs_migrations` is append-only.
- **Rollback is possible up to cut-over.** Until the rename happens, the plaintext column is authoritative; aborting just leaves the encrypted twin partially populated. After cut-over, rollback is a manual restore — the migration plan should treat cut-over as the one-way door.

## Migration from @cipherstash/protect

| `@cipherstash/protect` | `@cipherstash/stack` | Import Path |
|---|---|---|
| `protect(config)` | `Encryption(config)` | `@cipherstash/stack` |
| `csTable(name, cols)` | `encryptedTable(name, cols)` | `@cipherstash/stack/schema` |
| `csColumn(name)` | `encryptedColumn(name)` | `@cipherstash/stack/schema` |
| `LockContext` from `/identify` | `LockContext` from `/identity` | `@cipherstash/stack/identity` |

All method signatures on the encryption client remain the same. The `Result` pattern is unchanged.

## Complete API Reference

### EncryptionClient Methods

| Method | Signature | Returns |
|---|---|---|
| `encrypt` | `(plaintext, { column, table })` | `EncryptOperation` |
| `decrypt` | `(encryptedData)` | `DecryptOperation` |
| `encryptQuery` | `(plaintext, { column, table, queryType?, returnType? })` | `EncryptQueryOperation` |
| `encryptQuery` | `(terms: readonly ScalarQueryTerm[])` | `BatchEncryptQueryOperation` |
| `encryptModel` | `(model, table)` | `EncryptModelOperation<EncryptedFromSchema<T, S>>` |
| `decryptModel` | `(encryptedModel)` | `DecryptModelOperation<T>` — resolves to `Decrypted<T>` |
| `bulkEncrypt` | `(plaintexts, { column, table })` | `BulkEncryptOperation` |
| `bulkDecrypt` | `(encryptedPayloads)` | `BulkDecryptOperation` |
| `bulkEncryptModels` | `(models, table)` | `BulkEncryptModelsOperation<EncryptedFromSchema<T, S>>` |
| `bulkDecryptModels` | `(encryptedModels)` | `BulkDecryptModelsOperation<T>` — resolves to `Decrypted<T>[]` |

All operations are thenable (awaitable) and support `.withLockContext()` and `.audit()` chaining.

### Schema Builders

```typescript
encryptedTable(tableName: string, columns: Record<string, EncryptedColumn | EncryptedField | nested>)
encryptedColumn(columnName: string) // chainable: .equality(), .freeTextSearch(), .orderAndRange(), .searchableJson(), .dataType()
encryptedField(valueName: string)   // for nested encrypted fields (not searchable), chainable: .dataType()
```

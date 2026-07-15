# @cipherstash/stack

The all-in-one TypeScript SDK for the CipherStash data security stack.

[![npm version](https://img.shields.io/npm/v/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000)](https://www.npmjs.com/package/@cipherstash/stack)
[![License: MIT](https://img.shields.io/npm/l/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000)](https://github.com/cipherstash/stack/blob/main/LICENSE.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-first-blue?style=for-the-badge&labelColor=000000)](https://www.typescriptlang.org/)

---

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Features](#features)
- [Schema Definition](#schema-definition)
- [Encryption and Decryption](#encryption-and-decryption)
- [Searchable Encryption](#searchable-encryption)
- [Authentication](#authentication)
- [Identity-Aware Encryption](#identity-aware-encryption-lock-contexts)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Error Handling](#error-handling)
- [API Reference](#api-reference)
- [Subpath Exports](#subpath-exports)
- [Legacy: EQL v2](#legacy-eql-v2)
- [Requirements](#requirements)
- [License](#license)

---

## Install

```bash
npm install @cipherstash/stack
```

Or with your preferred package manager:

```bash
yarn add @cipherstash/stack
pnpm add @cipherstash/stack
```

## Quick Start

### 1. Initialize and authenticate your project

```bash
npx stash init
```

The wizard will authenticate you, walk you through choosing a database connection method, build an encryption schema, and install the required dependencies.

### 2. Encrypt and decrypt

Define a table with concrete EQL v3 column types, build the typed client, and encrypt:

```typescript
import { EncryptionV3 } from "@cipherstash/stack/v3"
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"

// Define a schema — the column type fixes its query capabilities
const users = encryptedTable("users", {
  email: types.TextSearch("email"), // equality + order/range + free-text search
})

// Create a typed client
const client = await EncryptionV3({ schemas: [users] })

// Encrypt a value
const encrypted = await client.encrypt("hello@example.com", {
  column: users.email,
  table: users,
})

// Every operation returns `{ data } | { failure }`. Narrow on `.failure` and
// return/throw before reading `.data` — the failure branch has no `data`.
if (encrypted.failure) {
  throw new Error(`Encryption failed: ${encrypted.failure.message}`)
}
console.log("Encrypted payload:", encrypted.data)

// Decrypt the value
const decrypted = await client.decrypt(encrypted.data)
if (decrypted.failure) {
  throw new Error(`Decryption failed: ${decrypted.failure.message}`)
}
console.log("Plaintext:", decrypted.data) // "hello@example.com"
```

The client is typed from your schemas: passing the wrong plaintext type for a column (`client.encrypt(42, { column: users.email, ... })`) is a compile error.

## Features

- **Field-level encryption** - Every value encrypted with its own unique key via [ZeroKMS](https://cipherstash.com/products/zerokms), backed by AWS KMS.
- **Searchable encryption** - Exact match, free-text search, order/range queries, and encrypted JSON queries in PostgreSQL, driven by concrete EQL v3 column types.
- **Type-safe by construction** - Each encrypted column is a concrete Postgres domain; its query capabilities are fixed by the type you pick and enforced at compile time by the typed client.
- **Bulk operations** - Encrypt or decrypt thousands of values in a single ZeroKMS call (`bulkEncrypt`, `bulkDecrypt`, `bulkEncryptModels`, `bulkDecryptModels`).
- **Identity-aware encryption** - Tie encryption to a user's JWT via `OidcFederationStrategy` and `.withLockContext()`, so only that user can decrypt.
- **CLI (`stash`)** - Initialize projects and set up encryption from the terminal.
- **TypeScript-first** - Strongly typed schemas, results, and model operations with full generics support.

## Schema Definition

Define which tables and columns to encrypt using `encryptedTable` and the `types` namespace from `@cipherstash/stack/eql/v3`. Each factory in `types` maps 1:1 to a **concrete Postgres domain** named `public.eql_v3_<name>` — the naming rule is: strip the `eql_v3_` prefix and PascalCase each underscore-separated segment. So `types.TextSearch` builds a `public.eql_v3_text_search` column, `types.IntegerOrd` builds `public.eql_v3_integer_ord`.

There are **no chainable capability methods** — the concrete type fully describes what a column can do.

```typescript
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"

const users = encryptedTable("users", {
  email: types.TextSearch("email"),    // equality + order/range + free-text search
  age: types.IntegerOrd("age"),        // equality + order/range
  balance: types.Bigint("balance"),    // storage only — encrypt/decrypt, no queries
  metadata: types.Json("metadata"),    // encrypted JSON: containment + JSONPath selectors
})
```

The returned table is also a column accessor (`users.email`). The JS property name and the DB column name may differ: `createdOn: types.Timestamp("created_at")` reads and writes the `createdOn` property on models but targets the `created_at` column in the database.

### Capability Suffixes

The suffix on the type name encodes the query capability:

| Suffix | Capabilities | Query types |
|---|---|---|
| _(none)_ | Storage only — encrypt/decrypt, no queries | — |
| `Eq` | Equality | `'equality'` |
| `Ord` | Equality + ordering/range (OPE-backed) | `'equality'`, `'orderAndRange'` |
| `OrdOre` | Equality + ordering/range (block-ORE-backed — the ORE operator class is superuser-only and unavailable on managed Postgres such as Supabase) | `'equality'`, `'orderAndRange'` |
| `Match` (text only) | Free-text search only | `'freeTextSearch'` |
| `Search` (text only, as `TextSearch`) | Equality + ordering/range + free-text | all three |
| `Json` | Encrypted JSON containment + JSONPath selector queries | `'searchableJson'` |

Prefer the plain `Ord` domains unless you know your database supports the ORE operator class.

### Domain Families and Plaintext Types

| Family | Factories | Plaintext (TypeScript) type |
|---|---|---|
| `Integer`, `Smallint`, `Numeric`, `Real`, `Double` | base, `Eq`, `Ord`, `OrdOre` | `number` |
| `Bigint` | base, `Eq`, `Ord`, `OrdOre` | `bigint` (native JS bigint, full i64 range) |
| `Date` | base, `Eq`, `Ord`, `OrdOre` | `Date` (calendar date; time-of-day truncated) |
| `Timestamp` | base, `Eq`, `Ord`, `OrdOre` | `Date` (time-of-day preserved) |
| `Text` | base, `Eq`, `Match`, `Ord`, `OrdOre`, `Search` | `string` |
| `Boolean` | base only | `boolean` |
| `Json` | `Json` only | a JSON *document* (object, array, or null — not a top-level scalar) |

### Database Setup

Install the EQL v3 SQL into your database with the stash CLI:

```bash
npx stash eql install --eql-version 3
# On Supabase, add --supabase to grant the anon/authenticated/service_role
# roles access to the eql_v3 schemas — without it, encrypted queries fail with
# "permission denied for schema eql_v3_internal":
npx stash eql install --eql-version 3 --supabase
```

In migrations, declare each encrypted column as its domain type:

```sql
CREATE TABLE users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email public.eql_v3_text_search,
  age public.eql_v3_integer_ord,
  balance public.eql_v3_bigint,
  metadata public.eql_v3_json
);
```

## Encryption and Decryption

### Single Values

```typescript
// Encrypt — plaintext is pinned to the column's domain type
const encrypted = await client.encrypt("secret@example.com", {
  column: users.email,
  table: users,
})

// Decrypt (narrow on `.failure` before reading `.data`)
if (encrypted.failure) throw new Error(encrypted.failure.message)
const decrypted = await client.decrypt(encrypted.data)
```

### Model Operations

Encrypt or decrypt an entire object. Only fields matching your schema are encrypted; other fields pass through unchanged. Schema fields are validated against their inferred plaintext type at compile time.

`decryptModel` takes the **table as a second argument** and returns the precise plaintext model: `Date` columns are reconstructed to real `Date` instances, and `bigint` columns round-trip as native `bigint`.

```typescript
const user = {
  id: "user_123",                // not in schema -> passes through
  email: "alice@example.com",    // TextSearch    -> encrypted as string
  age: 30,                       // IntegerOrd    -> encrypted as number
  balance: 100_000n,             // Bigint        -> encrypted as bigint
}

const encryptedResult = await client.encryptModel(user, users)
// encryptedResult.data.email -> Encrypted
// encryptedResult.data.id    -> string

if (encryptedResult.failure) throw new Error(encryptedResult.failure.message)
const decryptedResult = await client.decryptModel(encryptedResult.data, users)
// decryptedResult.data.email   -> string
// decryptedResult.data.balance -> bigint
```

### Bulk Operations

All bulk methods make a single call to ZeroKMS regardless of the number of records, while still using a unique key per value.

#### Bulk Encrypt / Decrypt Models

```typescript
const userModels = [
  { id: "1", email: "alice@example.com", age: 30, balance: 100_000n },
  { id: "2", email: "bob@example.com", age: 41, balance: 250_000n },
]

const encrypted = await client.bulkEncryptModels(userModels, users)
if (encrypted.failure) throw new Error(encrypted.failure.message)
const decrypted = await client.bulkDecryptModels(encrypted.data, users)
```

#### Bulk Encrypt / Decrypt (raw values)

`bulkEncrypt` / `bulkDecrypt` are untyped passthroughs for raw value arrays:

```typescript
const plaintexts = [
  { id: "u1", plaintext: "alice@example.com" },
  { id: "u2", plaintext: "bob@example.com" },
]

const encrypted = await client.bulkEncrypt(plaintexts, {
  column: users.email,
  table: users,
})

// encrypted.data = [{ id: "u1", data: EncryptedPayload }, ...]

if (encrypted.failure) throw new Error(encrypted.failure.message)
const decrypted = await client.bulkDecrypt(encrypted.data)
if (decrypted.failure) throw new Error(decrypted.failure.message)

// Each item has either { data: "plaintext" } or { error: "message" }
for (const item of decrypted.data) {
  if ("data" in item) {
    console.log(`${item.id}: ${item.data}`)
  } else {
    console.error(`${item.id} failed: ${item.error}`)
  }
}
```

## Searchable Encryption

Encrypt a query term so you can search encrypted data in PostgreSQL. The typed client only accepts queryable columns, and `queryType` is constrained to the column's capabilities — equality and range queries run through the domain's own SQL operators.

```typescript
// Equality
const eqQuery = await client.encryptQuery("alice@example.com", {
  column: users.email,
  table: users,
  queryType: "equality",
})

// Free-text search — queryType is REQUIRED for a match term (see gotcha below)
const matchQuery = await client.encryptQuery("ali", {
  column: users.email,
  table: users,
  queryType: "freeTextSearch",
})

// Order and range
const rangeQuery = await client.encryptQuery(30, {
  column: users.age,
  table: users,
  queryType: "orderAndRange",
})
```

> **Gotcha — `TextSearch` defaults to equality.** A `TextSearch` column carries all three indexes, and `encryptQuery` with **no explicit `queryType` builds an equality term, not a free-text match**. A substring like `"joh"` then matches nothing. Always pass `queryType: 'freeTextSearch'` for substring/token search.

Free-text search is fuzzy bloom-filter token matching, surfaced as `matches` in the Drizzle and Supabase adapters — it is order- and multiplicity-insensitive and one-sided (a match may be a false positive, a non-match never is). It is not SQL `LIKE`; don't pass `%` wildcards.

### Encrypted JSON

A `types.Json` column encrypts a whole JSON document (an object, array, or null — not a top-level scalar) to a `public.eql_v3_json` value. Two query patterns are supported:

**Exact containment** (jsonb `@>` semantics, no false positives). Pass a sub-object or sub-array needle; array containment is a subset test regardless of element position — `{ roles: ["admin"] }` matches any document whose `roles` array includes `"admin"`:

```typescript
const events = encryptedTable("events", { metadata: types.Json("metadata") })

const containsQuery = await client.encryptQuery(
  { roles: ["admin"] },
  { column: events.metadata, table: events }, // queryType inferred: 'searchableJson'
)
```

**JSONPath selectors** — equality and ordering at a path (`$.a`, `$.a.b` dot-notation object paths):

- **Drizzle**: `ops.selector(events.metadata, "$.age")` returns comparison methods bound to the path — `eq`, `ne`, `gt`, `gte`, `lt`, `lte` (e.g. `await ops.selector(events.metadata, "$.age").gt(21)`). Its unique power over containment is *ordering* at a path; equality at a path is equivalently `contains(col, { age: 21 })`.
- **Supabase**: `selectorEq(col, path, value)` and `selectorNe(col, path, value)`.

Two semantics to know:

- **`ne` includes absent paths.** A "not equal at path" query also matches rows where the path does not exist at all.
- **Array-leaf caveat:** a scalar needle does not match an array at the path. `selectorEq("payload", "$.roles", "admin")` does *not* match `{ roles: ["admin", "analyst"] }` — use containment for membership tests.

`types.Json` carries no equality or ordering on the document itself, so applying `eq` / `gt` / `asc` directly to a `Json` column throws.

### Batch Query Encryption

Encrypt multiple query terms in one call:

```typescript
const terms = [
  { value: "alice@example.com", column: users.email, table: users, queryType: "equality" as const },
  { value: "bob", column: users.email, table: users, queryType: "freeTextSearch" as const },
]

const results = await client.encryptQuery(terms)
```

### Ordering Encrypted Data

`ORDER BY` works on encrypted ordering columns via the domain's order term:

- **Drizzle**: `ops.asc(col)` / `ops.desc(col)` emit `ORDER BY eql_v3.ord_term(col)` (or `eql_v3.ord_term_ore` for ORE domains).
- **Supabase**: `.order()` works on OPE-backed ordering columns — every plain `*Ord` domain plus `TextSearch`.

The one limitation is the ORE-backed `*OrdOre` domains: their ordering term needs the superuser-only ORE operator class, which is unavailable on managed Postgres (e.g. Supabase) — the Supabase adapter rejects `order()` on those columns with a clear error. Prefer the plain `*Ord` (OPE) domains for anything you need to sort in a managed environment.

### Drizzle Integration

The `@cipherstash/stack-drizzle/v3` subpath (of the separate `@cipherstash/stack-drizzle` package) provides Drizzle-native column factories, schema extraction, and auto-encrypting, capability-checked query operators.

Declare a Drizzle table using the `types` factories — each factory emits its domain as the column's SQL type, so `drizzle-kit generate` produces `ADD COLUMN email public.eql_v3_text_search` etc.:

```ts
import { pgTable, integer } from "drizzle-orm/pg-core"
import { drizzle } from "drizzle-orm/postgres-js"
import {
  types,
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
} from "@cipherstash/stack-drizzle/v3"
import { EncryptionV3 } from "@cipherstash/stack/v3"

// Capabilities come from the concrete type — no flags to configure.
const users = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  email: types.TextEq("email"),      // equality: eq / ne / inArray
  age: types.IntegerOrd("age"),      // order + range: gt/gte/lt/lte, between, asc/desc
  bio: types.TextMatch("bio"),       // free-text search: matches
  balance: types.Bigint("balance"),  // storage only (no query capability)
})
```

Derive the v3 schema from the table, build the typed client, and create the operators:

```ts
const usersSchema = extractEncryptionSchemaV3(users)
const client = await EncryptionV3({ schemas: [usersSchema] })
const ops = createEncryptionOperatorsV3(client)

const db = drizzle({ client: sqlClient })
```

The operators auto-encrypt their operands and validate them against the column's concrete type. Applying an operator the type doesn't support throws `EncryptionOperatorError`:

```ts
// Equality — email is TextEq
const exact = await db.select().from(users)
  .where(await ops.eq(users.email, "alice@example.com"))

// Range + ordering — age is IntegerOrd
const adults = await db.select().from(users)
  .where(await ops.gte(users.age, 18))
  .orderBy(ops.asc(users.age))

const midBand = await db.select().from(users)
  .where(await ops.between(users.age, 25, 40))

// Set membership — built on equality
const listed = await db.select().from(users)
  .where(await ops.inArray(users.email, ["alice@example.com", "bob@example.com"]))

// Free-text token match — bio is TextMatch
const coffee = await db.select().from(users)
  .where(await ops.matches(users.bio, "coffee"))
```

Rows are **pre-encrypted** with `client.bulkEncryptModels(...)` before they reach `db.insert(...).values(...)` — Drizzle never sees plaintext. `Bigint` columns take a native JS `bigint`:

```ts
const rows = await client.bulkEncryptModels(
  [
    { email: "alice@example.com", age: 30, bio: "climbing and coffee", balance: 100_000n },
    { email: "bob@example.com", age: 41, bio: "cycling and coffee", balance: 250_000n },
  ],
  usersSchema,
)
if (rows.failure) throw new Error(rows.failure.message)

await db.insert(users).values(rows.data)
```

Notes:

- **Free-text search is `ops.matches`** (fuzzy bloom token matching on `TextMatch` / `TextSearch` columns), not SQL `like` / `ilike` — those operators do not exist on the v3 surface. `ops.contains` is a *different* operator: exact encrypted-JSON containment on `types.Json` columns.
- **The concrete type defines the legal operators.** `TextEq` supports `eq` / `ne` / `inArray` / `notInArray`; `*Ord` types add `gt` / `gte` / `lt` / `lte` / `between` / `notBetween` and `asc` / `desc`; `TextMatch` and `TextSearch` add `matches`; `Json` supports `contains` and `selector(col, '$.path').{eq,ne,gt,gte,lt,lte}`; a bare `Text` / `Integer` / `Bigint` column is storage-only. Using an unsupported operator throws `EncryptionOperatorError`.
- Combine conditions with `ops.and` / `ops.or`, and do NULL checks with `ops.isNull` / `ops.isNotNull` (the where-clause operators are `async` and must be `await`ed; `ops.asc` / `ops.desc` are synchronous).

### Supabase Integration

`encryptedSupabaseV3` from the separate `@cipherstash/stack-supabase` package wraps a Supabase client and **introspects the database at connect time** — it detects EQL v3 columns by their Postgres domain and builds the encryption client internally:

```typescript
import { encryptedSupabaseV3 } from "@cipherstash/stack-supabase"

const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey)

await es.from("users").insert({ email: "a@b.com", age: 30 })
await es.from("users").select("id, email").eq("email", "a@b.com")
await es.from("users").select("id, age").gte("age", 18).order("age")
```

Encrypted free-text search is `matches()` (fuzzy bloom token search — `contains()` stays native, exact containment for plaintext columns), encrypted-JSON path queries are `selectorEq()` / `selectorNe()`, and `order()` works on OPE-backed ordering columns. Pass optional declared `schemas` for compile-time row types. See the `stash-supabase` skill or the [docs](https://cipherstash.com/docs) for the full guide.

## Authentication

The client authenticates to ZeroKMS through `config.authStrategy`. Leave it
unset for the default **auto** strategy: in local development, authenticate
once with `npx stash auth login` (preferred — no credentials in your
environment); in CI/production, set the `CS_*` environment variables. Two
explicit strategies cover the other cases:

- **`AccessKeyStrategy`** — service-to-service / CI. Authenticates a *service*
  with a CipherStash access key.
- **`OidcFederationStrategy`** — authenticates the client **as the end user**
  by federating a third-party OIDC JWT (Clerk, Supabase, Auth0, Okta, ...)
  into a CipherStash service token:

```typescript
import { OidcFederationStrategy } from "@cipherstash/stack"
import { EncryptionV3 } from "@cipherstash/stack/v3"

// The callback is re-invoked on every (re-)federation and must return the
// CURRENT third-party OIDC JWT.
const strategy = OidcFederationStrategy.create(
  process.env.CS_WORKSPACE_CRN!,
  () => getUserJwt(),
)
if (strategy.failure) throw new Error(strategy.failure.error.message)

const client = await EncryptionV3({
  schemas: [users],
  config: { authStrategy: strategy.data },
})
```

Authentication stands on its own — an OIDC-authenticated client encrypts and
decrypts normally. Binding *data* to the authenticated user is a separate,
optional step: the lock context, below.

## Identity-Aware Encryption (Lock Contexts)

Bind a data key to a claim from the end user's JWT, so only that user can
decrypt. Chain `.withLockContext({ identityClaim })` on any operation:

```typescript
// Requires a client authenticated with OidcFederationStrategy (above) — the
// claim's value resolves from the federated JWT.
const IDENTITY = { identityClaim: ["sub"] }

const encrypted = await client
  .encrypt("sensitive data", { column: users.email, table: users })
  .withLockContext(IDENTITY)
if (encrypted.failure) throw new Error(encrypted.failure.message)

const decrypted = await client
  .decrypt(encrypted.data)
  .withLockContext(IDENTITY)
```

Lock contexts **require** an `OidcFederationStrategy`-authenticated client
(the auto and access-key strategies authenticate no end user, so there is no
JWT to resolve claims from); plain authentication never requires a lock
context.

`identityClaim` is an array of JWT claim *names* (`["sub"]`), not values, and the
same claim must be supplied to encrypt and decrypt. Lock contexts work with all
operations: `encrypt`, `decrypt`, `encryptModel`, `decryptModel`,
`bulkEncryptModels`, `bulkDecryptModels`, `bulkEncrypt`, `bulkDecrypt`,
`encryptQuery`. `.withLockContext()` also accepts a `LockContext` instance.
On the typed client, `decryptModel` / `bulkDecryptModels` take the lock
context as an optional third argument instead of chaining.

> **Deprecated: `LockContext.identify()`.** Per-operation CTS tokens were removed
> in `protect-ffi` 0.25; the token `identify()` fetches is no longer used by
> encryption. Authenticate with `OidcFederationStrategy` and pass the claim
> directly, as above.

## CLI Reference

The CLI is available via `npx stash` after install.

### `npx stash auth`

Authenticate with CipherStash.

```bash
npx stash auth login
```

This runs the device code flow: it opens your browser, you confirm the code, and a token is saved to `~/.cipherstash/auth.json`. No environment variables or credentials files are needed for local development.

### `npx stash init`

Initialize CipherStash for your project with an interactive wizard.

```bash
npx stash init
npx stash init --supabase
```

The wizard will:
1. Authenticate with CipherStash (device code flow)
2. Introspect your database and install the EQL v3 SQL
3. Choose your database connection method (Drizzle ORM, Supabase JS, Prisma, or Raw SQL)
4. Build an encryption schema interactively or use a placeholder, then generate the encryption client file
5. Install `stash` as a dev dependency for database tooling

`init` installs EQL for you — no separate `eql install` step is needed afterward.

| Flag | Description |
|------|-------------|
| `--supabase` / `--drizzle` / `--prisma-next` | Target a specific integration's setup flow |
| `--proxy` / `--no-proxy` | Opt in/out of the CipherStash Proxy path |
| `--region <slug>` | Workspace region (env `STASH_REGION`); **required for non-interactive init when not already logged in** |

## Configuration

### Local Development

No environment variables or credentials are needed for local development. Run `npx stash auth login` to authenticate via the device code flow (or `npx stash init` for the agent-assisted end-to-end setup), and the SDK and CLI will use the token saved to `~/.cipherstash/auth.json`.

### Going to Production

For production, CI/CD, and deployed environments, you'll need to set up machine credentials via environment variables:

| Variable | Description |
|-----|-------|
| `CS_WORKSPACE_CRN` | The workspace identifier (CRN format) |
| `CS_CLIENT_ID` | The client identifier |
| `CS_CLIENT_KEY` | Client key material used with ZeroKMS for encryption |
| `CS_CLIENT_ACCESS_KEY` | API key for authenticating with the CipherStash API |

See the [Going to Production](https://cipherstash.com/docs/stack/deploy/going-to-production) guide for full details on creating machine clients, setting up access keys, and configuring CI/CD pipelines.

### Programmatic Config

Pass config directly when initializing the client:

```typescript
import { EncryptionV3 } from "@cipherstash/stack/v3"
import { users } from "./schema"

const client = await EncryptionV3({
  schemas: [users],
  config: {
    workspaceCrn: "crn:ap-southeast-2.aws:your-workspace-id",
    clientId: "your-client-id",
    clientKey: "your-client-key",
    accessKey: "your-access-key",
    keyset: { name: "my-keyset" }, // or { id: "uuid" }
  },
})
```

### Multi-Tenant Encryption (Keysets)

Isolate encryption keys per tenant using keysets:

```typescript
const client = await EncryptionV3({
  schemas: [users],
  config: {
    keyset: { id: "123e4567-e89b-12d3-a456-426614174000" },
  },
})

// or by name
const client2 = await EncryptionV3({
  schemas: [users],
  config: {
    keyset: { name: "Company A" },
  },
})
```

### Logging

The SDK uses structured logging across all interfaces (Encryption, Supabase, DynamoDB). Each operation emits a single wide event with context such as the operation type, table, column, lock context status, and duration.

Configure the log level with the `STASH_STACK_LOG` environment variable:

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

## Error Handling

All async methods return a `Result` object with either a `data` key (success) or a `failure` key (error). This is a discriminated union - you never get both.

```typescript
const result = await client.encrypt("hello", { column: users.email, table: users })

if (result.failure) {
  // result.failure.type: string (e.g. "EncryptionError")
  // result.failure.message: string
  console.error(result.failure.type, result.failure.message)
} else {
  // result.data: Encrypted payload
  console.log(result.data)
}
```

### Error Types

| Type | When |
|---|---|
| `ClientInitError` | Client initialization fails (bad credentials, missing config) |
| `EncryptionError` | An encrypt operation fails |
| `DecryptionError` | A decrypt operation fails |
| `LockContextError` | Lock context creation or usage fails |
| `CtsTokenError` | Identity token exchange fails |

## API Reference

### `EncryptionV3(config)` - Initialize the typed client

```typescript
function EncryptionV3(config: {
  schemas: AnyV3Table[]
  config?: ClientConfig
}): Promise<TypedEncryptionClient>
```

The wire format is pinned to EQL v3 — you don't set it yourself. `typedClient(client, ...schemas)` (same subpath) wraps an already-built `EncryptionClient` in the typed surface.

### `TypedEncryptionClient` Methods

Method signatures are derived from your schemas: plaintext arguments are pinned to each column's domain type, query methods only accept queryable columns, and `queryType` is constrained to the column's capabilities.

| Method | Signature | Returns |
|----|------|-----|
| `encrypt` | `(plaintext, { column, table })` | `EncryptOperation` (thenable) |
| `decrypt` | `(encryptedData)` | `DecryptOperation` (thenable) |
| `encryptQuery` | `(plaintext, { column, table, queryType?, returnType? })` | `EncryptQueryOperation` (thenable) |

`returnType` controls the encrypted query term's shape: `'eql'` (default, the EQL JSON payload for the ORM adapters), `'composite-literal'` (a Postgres composite string for `.eq()`/string-based APIs), or `'escaped-composite-literal'` (the same, escaped for embedding). Most users take the default; the adapters set it as needed.
| `encryptQuery` | `(terms: ScalarQueryTerm[])` | `BatchEncryptQueryOperation` (thenable) |
| `encryptModel` | `(model, table)` | `EncryptModelOperation` (thenable) |
| `decryptModel` | `(encryptedModel, table, lockContext?)` | `Promise<Result<...>>` |
| `bulkEncryptModels` | `(models, table)` | `BulkEncryptModelsOperation` (thenable) |
| `bulkDecryptModels` | `(encryptedModels, table, lockContext?)` | `Promise<Result<...>>` |
| `bulkEncrypt` | `(plaintexts, { column, table })` | `BulkEncryptOperation` (thenable) |
| `bulkDecrypt` | `(encryptedPayloads)` | `BulkDecryptOperation` (thenable) |
| `getEncryptConfig` | `()` | The resolved encrypt config |

The thenable operations support `.withLockContext(lockContext)` for identity-aware encryption. `decryptModel` / `bulkDecryptModels` return a plain `Promise` instead — pass the lock context as the optional third argument. `decrypt` of a single value cannot be strongly typed (a lone ciphertext carries no column identity), and `encryptQuery` rejects storage-only columns at compile time.

### `LockContext` (legacy)

Identity-aware encryption is done with `OidcFederationStrategy` +
`.withLockContext({ identityClaim })` (see [Identity-Aware Encryption](#identity-aware-encryption-lock-contexts)).
`LockContext` / `identify()` remain for backwards compatibility only — the
per-operation CTS token `identify()` fetches was removed in `protect-ffi` 0.25
and is no longer used by encryption.

### Schema Builders

```typescript
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"

encryptedTable(tableName, columns)  // columns: Record<string, types.*(dbColumnName)>
types.TextSearch("email")           // one factory per public.eql_v3_* domain
```

Type inference helpers live on the same subpath:

```typescript
import type { InferPlaintext, InferEncrypted } from "@cipherstash/stack/eql/v3"

type UserPlaintext = InferPlaintext<typeof users>
// { email: string; age: number; balance: bigint; metadata: JsonDocument }

type UserEncrypted = InferEncrypted<typeof users>
// { email: Encrypted; age: Encrypted; ... }
```

## Subpath Exports

| Import Path | Provides |
|-------|-----|
| `@cipherstash/stack/v3` | `EncryptionV3` typed client factory, `typedClient`, plus re-exports of the EQL v3 authoring DSL |
| `@cipherstash/stack/eql/v3` | EQL v3 authoring DSL: `encryptedTable`, the `types` namespace, `buildEncryptConfig`, inference types (`InferPlaintext`, `InferEncrypted`, ...) |
| `@cipherstash/stack` | `Encryption` function (legacy v2 entry point), auth strategies |
| `@cipherstash/stack/schema` | Legacy v2 schema builders (see [Legacy: EQL v2](#legacy-eql-v2)) |
| `@cipherstash/stack/identity` | `LockContext` class and identity types |
| `@cipherstash/stack/client` | Client-safe exports (schema builders and types only - no native FFI) |
| `@cipherstash/stack/types` | All TypeScript types (`Encrypted`, `Decrypted`, `ClientConfig`, `EncryptionClientConfig`, query types, etc.) |

The Drizzle and Supabase integrations are **separate first-party packages** that
depend on `@cipherstash/stack` (they are no longer subpaths of it):

| Package | Provides |
|-------|-----|
| `@cipherstash/stack-drizzle/v3` | EQL v3 Drizzle integration: `types` column factories, `createEncryptionOperatorsV3`, `extractEncryptionSchemaV3`, `makeEqlV3Column`, `EncryptionOperatorError` |
| `@cipherstash/stack-supabase` | Supabase integration: `encryptedSupabaseV3` (and the legacy v2 `encryptedSupabase`) |
| `@cipherstash/stack-drizzle` | Legacy EQL v2 Drizzle integration (root subpath): `encryptedType`, `extractEncryptionSchema`, `createEncryptionOperators` |

## Legacy: EQL v2

Before the concrete-domain types above, encrypted columns were declared with
chainable capability builders and stored in a single `eql_v2_encrypted`
composite column type. That surface remains fully supported for existing
deployments, but new work should use EQL v3:

- **Client and schema**: `Encryption` from `@cipherstash/stack` with
  `encryptedColumn("email").equality().freeTextSearch().orderAndRange()` and
  `.searchableJson()` from `@cipherstash/stack/schema`. v2 and v3 tables cannot
  be mixed in one client.
- **Query formatting**: v2 query terms can be rendered as strings with
  `returnType: 'composite-literal'` / `'escaped-composite-literal'` for
  string-based APIs.
- **Integrations**: the v2 Drizzle surface is the root of
  `@cipherstash/stack-drizzle` (`encryptedType`, `extractEncryptionSchema`,
  `createEncryptionOperators`); the v2 Supabase surface is `encryptedSupabase`.
- **DynamoDB still requires v2**: `encryptedDynamoDB` from
  `@cipherstash/stack/dynamodb` works with the v2 API only — v3 support is
  tracked in [#657](https://github.com/cipherstash/stack/issues/657).

Full v2 documentation lives at [cipherstash.com/docs](https://cipherstash.com/docs).

### Migrating from @cipherstash/protect

`@cipherstash/protect` users land on the legacy v2 surface first — the mapping
below is 1:1, and method signatures on the encryption client (`encrypt`,
`decrypt`, `encryptModel`, etc.) and the `Result` pattern (`data` / `failure`)
are unchanged. From there, adopt EQL v3 for new tables:

| `@cipherstash/protect` | `@cipherstash/stack` (legacy v2) | Import Path |
|------------|-----------|-------|
| `protect(config)` | `Encryption(config)` | `@cipherstash/stack` |
| `csTable(name, cols)` | `encryptedTable(name, cols)` | `@cipherstash/stack/schema` |
| `csColumn(name)` | `encryptedColumn(name)` | `@cipherstash/stack/schema` |
| `import { LockContext } from "@cipherstash/protect/identify"` | `import { LockContext } from "@cipherstash/stack/identity"` | `@cipherstash/stack/identity` |
| N/A | CLI | `npx stash` |

## Requirements

- **Node.js** >= 22
- The default entry includes a native FFI module (`@cipherstash/protect-ffi`). On a Node server, externalize it from bundling (e.g. Next.js `serverExternalPackages`).
- For bundled or non-Node runtimes (Deno, Bun, Cloudflare Workers, Supabase Edge Functions), import `@cipherstash/stack/wasm-inline` instead — it inlines the WASM build, so no externalization is needed. See the [bundling guide](https://cipherstash.com/docs/stack/deploy/bundling).

## License

MIT - see [LICENSE.md](https://github.com/cipherstash/stack/blob/main/LICENSE.md).

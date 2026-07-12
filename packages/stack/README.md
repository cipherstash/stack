# @cipherstash/stack

The all-in-one TypeScript SDK for the CipherStash data security stack.

[![npm version](https://img.shields.io/npm/v/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000)](https://www.npmjs.com/package/@cipherstash/stack)
[![License: MIT](https://img.shields.io/npm/l/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000)](https://github.com/cipherstash/stack/blob/main/LICENSE.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-first-blue?style=for-the-badge&labelColor=000000)](https://www.typescriptlang.org/)

--

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Features](#features)
- [Schema Definition](#schema-definition)
- [Encryption and Decryption](#encryption-and-decryption)
- [Searchable Encryption](#searchable-encryption)
- [Identity-Aware Encryption](#identity-aware-encryption)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Error Handling](#error-handling)
- [API Reference](#api-reference)
- [Subpath Exports](#subpath-exports)
- [Migration from @cipherstash/protect](#migration-from-cipherstashprotect)
- [Requirements](#requirements)
- [License](#license)

--

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

```typescript
import { Encryption } from "@cipherstash/stack"
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"

// Define a schema
const users = encryptedTable("users", {
  email: encryptedColumn("email").equality().freeTextSearch(),
})

// Create a client
const client = await Encryption({ schemas: [users] })

// Encrypt a value
const encrypted = await client.encrypt("hello@example.com", {
  column: users.email,
  table: users,
})

if (encrypted.failure) {
  console.error("Encryption failed:", encrypted.failure.message)
} else {
  console.log("Encrypted payload:", encrypted.data)
}

// Decrypt the value
const decrypted = await client.decrypt(encrypted.data)

if (decrypted.failure) {
  console.error("Decryption failed:", decrypted.failure.message)
} else {
  console.log("Plaintext:", decrypted.data) // "hello@example.com"
}
```

## Features

- **Field-level encryption** - Every value encrypted with its own unique key via [ZeroKMS](https://cipherstash.com/products/zerokms), backed by AWS KMS.
- **Searchable encryption** - Exact match, free-text search, order/range queries, and encrypted JSONB queries in PostgreSQL.
- **Bulk operations** - Encrypt or decrypt thousands of values in a single ZeroKMS call (`bulkEncrypt`, `bulkDecrypt`, `bulkEncryptModels`, `bulkDecryptModels`).
- **Identity-aware encryption** - Tie encryption to a user's JWT via `LockContext`, so only that user can decrypt.
- **CLI (`stash`)** - Initialize projects and set up encryption from the terminal.
- **TypeScript-first** - Strongly typed schemas, results, and model operations with full generics support.

## Schema Definition

Define which tables and columns to encrypt using `encryptedTable` and `encryptedColumn` from `@cipherstash/stack/schema`.

```typescript
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"

const users = encryptedTable("users", {
  email: encryptedColumn("email")
    .equality()         // exact-match queries
    .freeTextSearch()   // full-text search queries
    .orderAndRange(),   // sorting and range queries
})

const documents = encryptedTable("documents", {
  metadata: encryptedColumn("metadata")
    .searchableJson(),  // encrypted JSONB queries (JSONPath + containment)
})
```

### Index Types

| Method | Purpose | Query Type |
|----|-----|------|
| `.equality()` | Exact match lookups | `'equality'` |
| `.freeTextSearch()` | Full-text / fuzzy search | `'freeTextSearch'` |
| `.orderAndRange()` | Sorting, comparison, range queries | `'orderAndRange'` |
| `.searchableJson()` | Encrypted JSONB path and containment queries | `'searchableJson'` |
| `.dataType(cast)` | Set the plaintext data type (`'string'`, `'number'`, `'boolean'`, `'date'`, `'bigint'`, `'json'`) | N/A |

Methods are chainable - call as many as you need on a single column.

## Encryption and Decryption

### Single Values

```typescript
// Encrypt
const encrypted = await client.encrypt("secret@example.com", {
  column: users.email,
  table: users,
})

// Decrypt
const decrypted = await client.decrypt(encrypted.data)
```

### Model Operations

Encrypt or decrypt an entire object. Only fields matching your schema are encrypted; other fields pass through unchanged.

The return type is **schema-aware**: fields matching the table schema are typed as `Encrypted`, while other fields retain their original types. For best results, let TypeScript infer the type parameters from the arguments:

```typescript
type User = { id: string; email: string; createdAt: Date }

const user = {
  id: "user_123",
  email: "alice@example.com",  // defined in schema -> encrypted
  createdAt: new Date(),       // not in schema -> unchanged
}

// Let TypeScript infer the return type from the schema
const encryptedResult = await client.encryptModel(user, users)
// encryptedResult.data.email    -> Encrypted
// encryptedResult.data.id       -> string
// encryptedResult.data.createdAt -> Date

// Decrypt a model
const decryptedResult = await client.decryptModel(encryptedResult.data)
```

### Bulk Operations

All bulk methods make a single call to ZeroKMS regardless of the number of records, while still using a unique key per value.

#### Bulk Encrypt / Decrypt (raw values)

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

// Each item has either { data: "plaintext" } or { error: "message" }
for (const item of decrypted.data) {
  if ("data" in item) {
    console.log(`${item.id}: ${item.data}`)
  } else {
    console.error(`${item.id} failed: ${item.error}`)
  }
}
```

#### Bulk Encrypt / Decrypt Models

```typescript
const userModels = [
  { id: "1", email: "alice@example.com" },
  { id: "2", email: "bob@example.com" },
]

const encrypted = await client.bulkEncryptModels(userModels, users)
const decrypted = await client.bulkDecryptModels(encrypted.data)
```

## Searchable Encryption

Encrypt a query term so you can search encrypted data in PostgreSQL.

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
const rangeQuery = await client.encryptQuery("alice@example.com", {
  column: users.email,
  table: users,
  queryType: "orderAndRange",
})
```

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

Encrypt multiple query terms in one call:

```typescript
const terms = [
  { value: "alice@example.com", column: users.email, table: users, queryType: "equality" as const },
  { value: "bob",               column: users.email, table: users, queryType: "freeTextSearch" as const },
]

const results = await client.encryptQuery(terms)
```

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

// term.data is a string — use directly with .eq()
await supabase.from("users").select().eq("email", term.data)
```

Each term in a batch can have its own `returnType`.

### Ordering Encrypted Data

**`ORDER BY` on encrypted columns requires operator family support in the database.**

On databases without operator families (e.g. Supabase, or when EQL is installed with `--exclude-operator-family`), sorting on encrypted columns is not currently supported — regardless of the client or ORM used. Sort application-side after decrypting the results as a workaround.

Operator family support for Supabase is being developed in collaboration with the Supabase and CipherStash teams and will be available in a future release.

### PostgreSQL / Drizzle Integration Pattern

Encrypted data is stored as an [EQL](https://github.com/cipherstash/encrypt-query-language) JSON payload. Install the EQL extension in PostgreSQL to enable searchable queries, then store encrypted data in `eql_v2_encrypted` columns.

The `@cipherstash/stack/drizzle` module provides `encryptedType` for defining encrypted columns and `createEncryptionOperators` for querying them:

```typescript
import { pgTable, integer, timestamp } from "drizzle-orm/pg-core"
import { encryptedType, extractEncryptionSchema, createEncryptionOperators } from "@cipherstash/stack/drizzle"
import { Encryption } from "@cipherstash/stack"

// Define schema with encrypted columns
const usersTable = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  email: encryptedType<string>("email", {
    equality: true,
    freeTextSearch: true,
    orderAndRange: true,
  }),
  profile: encryptedType<{ name: string; bio: string }>("profile", {
    dataType: "json",
    searchableJson: true,
  }),
})

// Initialize
const usersSchema = extractEncryptionSchema(usersTable)
const client = await Encryption({ schemas: [usersSchema] })
const ops = createEncryptionOperators(client)

// Query with auto-encrypting operators
const results = await db.select().from(usersTable)
  .where(await ops.eq(usersTable.email, "alice@example.com"))

// JSONB queries on encrypted JSON columns
const jsonResults = await db.select().from(usersTable)
  .where(await ops.jsonbPathExists(usersTable.profile, "$.bio"))
```

#### Drizzle `encryptedType` Config Options

| Option | Type | Description |
|---|---|---|
| `dataType` | `"string"` \| `"number"` \| `"json"` | Plaintext data type (default: `"string"`) |
| `equality` | `boolean` \| `TokenFilter[]` | Enable equality index |
| `freeTextSearch` | `boolean` \| `MatchIndexOpts` | Enable free-text search index |
| `orderAndRange` | `boolean` | Enable ORE index for sorting/range queries |
| `searchableJson` | `boolean` | Enable JSONB path queries (requires `dataType: "json"`) |

#### Drizzle JSONB Operators

For columns with `searchableJson: true`, three JSONB operators are available:

| Operator | Description |
|---|---|
| `jsonbPathExists(col, selector)` | Check if a JSONB path exists (boolean, use in `WHERE`) |
| `jsonbPathQueryFirst(col, selector)` | Extract first value at a JSONB path |
| `jsonbGet(col, selector)` | Get value using the JSONB `->` operator |

These operators encrypt the JSON path selector using the `steVecSelector` query type and cast it to `eql_v2_encrypted` for use with the EQL PostgreSQL functions.

### EQL v3 Concrete-Type Columns (Drizzle)

The `@cipherstash/stack/eql/v3/drizzle` module targets EQL v3, where each encrypted column is a **concrete Postgres domain type** (`eql_v3.text_eq`, `eql_v3.integer_ord`, …). Instead of toggling capability flags, you pick a concrete type from the `types` namespace and its query capabilities are fixed by that choice. The v2 `@cipherstash/stack/drizzle` module above is unchanged — this is an additive export.

Declare a Drizzle table using the `types` factories. The suffix encodes the capability: `*Eq` (equality), `*Ord` (order + range, which also covers equality), `*Match` / `TextSearch` (free-text search), and the bare name (e.g. `Text`, `Bigint`) is storage-only.

```ts
import { pgTable, integer } from "drizzle-orm/pg-core"
import { drizzle } from "drizzle-orm/postgres-js"
import {
  types,
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
} from "@cipherstash/stack/eql/v3/drizzle"
import { EncryptionV3 } from "@cipherstash/stack/v3"

// Capabilities come from the concrete type — no flags to configure.
const users = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  email: types.TextEq("email"),      // equality: eq / ne / inArray
  age: types.IntegerOrd("age"),      // order + range: gt/gte/lt/lte, between, asc/desc
  bio: types.TextMatch("bio"),       // free-text search: contains
  balance: types.Bigint("balance"),  // storage only (no query capability)
})
```

Derive the v3 schema from the table, build the typed client, and create the capability-checked operators:

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

// Free-text token containment — bio is TextMatch
const coffee = await db.select().from(users)
  .where(await ops.contains(users.bio, "coffee"))
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

- **Free-text search uses `ops.contains`** (token containment on a `match` index), not SQL `like` / `ilike`. It matches whole indexed tokens, so `contains(users.bio, "coffee")` finds rows whose `bio` contains the token `coffee`.
- **The concrete type defines the legal operators.** `TextEq` supports `eq` / `ne` / `inArray` / `notInArray`; `*Ord` types add `gt` / `gte` / `lt` / `lte` / `between` / `notBetween` and `asc` / `desc`; `*Match` and `TextSearch` add `contains`; a bare `Text` / `Integer` / `Bigint` column is storage-only. Using an unsupported operator throws `EncryptionOperatorError`.
- Combine conditions with `ops.and` / `ops.or`, and do NULL checks with `ops.isNull` / `ops.isNotNull` (the where-clause operators are `async` and must be `await`ed; `ops.asc` / `ops.desc` are synchronous).

## Identity-Aware Encryption

Lock encryption to a specific user by requiring a valid JWT for decryption.

```typescript
import { LockContext } from "@cipherstash/stack/identity"

// 1. Create a lock context (defaults to the "sub" claim)
const lc = new LockContext()

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

Lock contexts work with all operations: `encrypt`, `decrypt`, `encryptModel`, `decryptModel`, `bulkEncryptModels`, `bulkDecryptModels`, `bulkEncrypt`, `bulkDecrypt`.

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
2. Bind your device to the default Keyset
3. Choose your database connection method (Drizzle ORM, Supabase JS, Prisma, or Raw SQL)
4. Build an encryption schema interactively or use a placeholder, then generate the encryption client file
5. Install `stash` as a dev dependency for database tooling

After init, run `npx stash db setup` to configure your database.

| Flag | Description |
|------|-------------|
| `--supabase` | Use Supabase-specific setup flow |

## Configuration

### Local Development

No environment variables or credentials are needed for local development. Run `npx @cipherstash/stack auth login` to authenticate via the device code flow, and the SDK and CLI will use the token saved to `~/.cipherstash/auth.json`.

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
import { Encryption } from "@cipherstash/stack"
import { users } from "./schema"

const client = await Encryption({
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
const client = await Encryption({
  schemas: [users],
  config: {
    keyset: { id: "123e4567-e89b-12d3-a456-426614174000" },
  },
})

// or by name
const client2 = await Encryption({
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

### `Encryption(config)` - Initialize the client

```typescript
function Encryption(config: EncryptionClientConfig): Promise<EncryptionClient>
```

### `EncryptionClient` Methods

| Method | Signature | Returns |
|----|------|-----|
| `encrypt` | `(plaintext, { column, table })` | `EncryptOperation` (thenable) |
| `decrypt` | `(encryptedData)` | `DecryptOperation` (thenable) |
| `encryptQuery` | `(plaintext, { column, table, queryType?, returnType? })` | `EncryptQueryOperation` (thenable) |
| `encryptQuery` | `(terms: ScalarQueryTerm[])` | `BatchEncryptQueryOperation` (thenable) |
| `encryptModel` | `(model, table)` | `EncryptModelOperation<EncryptedFromSchema<T, S>>` (thenable) |
| `decryptModel` | `(encryptedModel)` | `DecryptModelOperation<T>` (thenable) |
| `bulkEncrypt` | `(plaintexts, { column, table })` | `BulkEncryptOperation` (thenable) |
| `bulkDecrypt` | `(encryptedPayloads)` | `BulkDecryptOperation` (thenable) |
| `bulkEncryptModels` | `(models, table)` | `BulkEncryptModelsOperation<EncryptedFromSchema<T, S>>` (thenable) |
| `bulkDecryptModels` | `(encryptedModels)` | `BulkDecryptModelsOperation<T>` (thenable) |

All operations are thenable (awaitable) and support `.withLockContext(lockContext)` for identity-aware encryption.

### `LockContext`

```typescript
import { LockContext } from "@cipherstash/stack/identity"

const lc = new LockContext(options?)
const result = await lc.identify(jwtToken)
```

### Schema Builders

```typescript
import { encryptedTable, encryptedColumn, csValue } from "@cipherstash/stack/schema"

encryptedTable(tableName, columns)
encryptedColumn(columnName)        // returns EncryptedColumn
csValue(valueName)                 // returns ProtectValue (for nested values)
```

## Subpath Exports

| Import Path | Provides |
|-------|-----|
| `@cipherstash/stack` | `Encryption` function (main entry point) |
| `@cipherstash/stack/schema` | `encryptedTable`, `encryptedColumn`, `csValue`, schema types |
| `@cipherstash/stack/identity` | `LockContext` class and identity types |
| `@cipherstash/stack/client` | Client-safe exports (schema builders and types only - no native FFI) |
| `@cipherstash/stack/types` | All TypeScript types (`Encrypted`, `Decrypted`, `ClientConfig`, `EncryptionClientConfig`, query types, etc.) |
| `@cipherstash/stack/v3` | `EncryptionV3` typed client plus the EQL v3 authoring DSL (`encryptedTable`, `types`, v3 type helpers) |
| `@cipherstash/stack/eql/v3/drizzle` | EQL v3 Drizzle integration: `types` column factories, `createEncryptionOperatorsV3`, `extractEncryptionSchemaV3`, `makeEqlV3Column`, `EncryptionOperatorError` |

## Migration from @cipherstash/protect

If you are migrating from `@cipherstash/protect`, the following table maps the old API to the new one:

| `@cipherstash/protect` | `@cipherstash/stack` | Import Path |
|------------|-----------|-------|
| `protect(config)` | `Encryption(config)` | `@cipherstash/stack` |
| `csTable(name, cols)` | `encryptedTable(name, cols)` | `@cipherstash/stack/schema` |
| `csColumn(name)` | `encryptedColumn(name)` | `@cipherstash/stack/schema` |
| `import { LockContext } from "@cipherstash/protect/identify"` | `import { LockContext } from "@cipherstash/stack/identity"` | `@cipherstash/stack/identity` |
| N/A | CLI | `npx stash` |

All method signatures on the encryption client (`encrypt`, `decrypt`, `encryptModel`, etc.) remain the same. The `Result` pattern (`data` / `failure`) is unchanged.

## Requirements

- **Node.js** >= 18
- The package includes a native FFI module (`@cipherstash/protect-ffi`) written in Rust and embedded via [Neon](https://github.com/neon-bindings/neon). You must opt out of bundling this package in tools like Webpack, esbuild, or Next.js (`serverExternalPackages`).

## License

MIT - see [LICENSE.md](https://github.com/cipherstash/stack/blob/main/LICENSE.md).

---
name: stash-encryption
description: Implement field-level encryption with @cipherstash/stack. Covers schema definition, encrypt/decrypt operations, searchable encryption (equality, free-text, range, JSON), bulk operations, model operations, identity-aware encryption with LockContext, multi-tenant keysets, the EQL v3 typed schema (concrete Postgres domain columns and the strongly-typed EncryptionV3 client), and the full TypeScript type system. Use when adding encryption to a project, defining encrypted schemas, or working with the CipherStash Encryption API.
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
- Using the EQL v3 typed schema (`@cipherstash/stack/eql/v3`) — concrete Postgres domain columns with a strongly-typed client (see "EQL v3 Typed Schema" below)
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
| `@cipherstash/stack` | `Encryption` function, `encryptedTable`, `encryptedColumn`, `encryptedField` (convenience re-exports) |
| `@cipherstash/stack/schema` | `encryptedTable`, `encryptedColumn`, `encryptedField`, schema types |
| `@cipherstash/stack/identity` | `LockContext` class and identity types |
| `@cipherstash/stack-drizzle` | `encryptedType`, `extractEncryptionSchema`, `createEncryptionOperators` for Drizzle ORM |
| `@cipherstash/stack-supabase` | `encryptedSupabase` wrapper for Supabase |
| `@cipherstash/stack/dynamodb` | `encryptedDynamoDB` helper for DynamoDB |
| `@cipherstash/stack/encryption` | `EncryptionClient` class, `Encryption` function |
| `@cipherstash/stack/errors` | `EncryptionErrorTypes`, `StackError`, error subtypes, `getErrorMessage` |
| `@cipherstash/stack/client` | Client-safe exports: schema builders, schema types, `EncryptionClient` type (no native FFI) |
| `@cipherstash/stack/types` | All TypeScript types |
| `@cipherstash/stack/eql/v3` | EQL v3 typed schema: `encryptedTable`, `types` namespace, `buildEncryptConfig`, inference types (see "EQL v3 Typed Schema" below) |
| `@cipherstash/stack/v3` | `EncryptionV3` factory, `typedClient`, `TypedEncryptionClient` — plus re-exports of everything in `@cipherstash/stack/eql/v3` |
| `@cipherstash/stack-drizzle/v3` | Drizzle ORM integration for EQL v3 schemas (see the `stash-drizzle` skill) |

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

## Authentication

The client authenticates to ZeroKMS through `config.authStrategy`. Leave it unset for the default **auto** strategy — credentials from the `CS_*` environment variables, falling back to the local dev profile created by `npx stash auth login`. Two explicit strategies cover the other cases:

- **`AccessKeyStrategy`** — service-to-service / CI. Authenticates a *service* with a CipherStash access key.
- **`OidcFederationStrategy`** — authenticates the client **as the end user** by federating a third-party OIDC JWT (Clerk, Supabase, Auth0, Okta, ...) into a CipherStash service token:

```typescript
import { Encryption, OidcFederationStrategy } from "@cipherstash/stack"

// `getJwt` is re-invoked on every (re-)federation and must return the
// *current* third-party OIDC JWT.
const strategy = OidcFederationStrategy.create(
  process.env.CS_WORKSPACE_CRN!,
  () => getUserJwt(),
)
if (strategy.failure) {
  throw new Error(`[auth] ${strategy.failure.type}: ${strategy.failure.error.message}`)
}

const client = await Encryption({
  schemas: [users],
  config: { authStrategy: strategy.data },
})
```

`OidcFederationStrategy.create()` returns a `Result` — **unwrap it**. Passing the envelope straight to `authStrategy` gives the FFI an object with no `getToken()` at all.

> **Known type error (runtime is fine).** The example above works at runtime, but `authStrategy: strategy.data` does not currently typecheck. `@cipherstash/auth` 0.41 strategies declare `getToken(): Promise<Result<TokenResult, AuthFailure>>`, while `@cipherstash/protect-ffi`'s exported `AuthStrategy` type still says `getToken(): Promise<{ token: string }>`. protect-ffi accepts **both** shapes at runtime (0.28+), on the Node and WASM paths alike — only its TypeScript declaration was left behind. Until it's widened, add `as unknown as AuthStrategy` or `// @ts-expect-error`. Tracked in [issue #602](https://github.com/cipherstash/stack/issues/602).

Authentication stands on its own — an OIDC-authenticated client encrypts and decrypts normally. Binding *data* to the authenticated user is a separate, optional step: the lock context, below.

## Identity-Aware Encryption (Lock Contexts)

Bind a data key to a claim from the end user's JWT, so only that user can decrypt. Chain `.withLockContext({ identityClaim })` on any operation:

```typescript
// Requires a client authenticated with OidcFederationStrategy (see
// "Authentication" above) — the claim's value resolves from the federated JWT.
const IDENTITY = { identityClaim: ["sub"] }

const encrypted = await client
  .encrypt("sensitive data", { column: users.email, table: users })
  .withLockContext(IDENTITY)
if (encrypted.failure) {
  throw new Error(`[encryption] ${encrypted.failure.type}: ${encrypted.failure.message}`)
}

// Decrypt with the SAME claim. Anything else cannot reproduce the key.
const decrypted = await client
  .decrypt(encrypted.data)
  .withLockContext(IDENTITY)
if (decrypted.failure) {
  throw new Error(`[encryption] ${decrypted.failure.type}: ${decrypted.failure.message}`)
}
```

Lock contexts **require** an `OidcFederationStrategy`-authenticated client: the claim's value resolves from the JWT the strategy federated. The auto and access-key strategies authenticate no end user, so there is no JWT to resolve claims from — `AccessKeyStrategy` in particular authenticates a *service* and cannot be used with a lock context. Plain authentication never requires a lock context.

Every operation returns a `Result`. Narrow on `.failure` before touching `.data`: the `Failure` branch has no `data` property, so skipping the check is a type error, not merely a runtime risk.

`identityClaim` is an array of JWT claim *names*, not values: `["sub"]` (the default) or `["sub", "org_id"]`. ZeroKMS resolves each claim's value from the JWT the strategy federated. **The same claim must be supplied to encrypt and decrypt** — it is baked into the data key's tag, so decrypting without it fails with `Failed to retrieve key`.

Lock contexts work with every operation: `encrypt`, `decrypt`, `encryptModel`, `decryptModel`, `bulkEncrypt`, `bulkDecrypt`, `bulkEncryptModels`, `bulkDecryptModels`, `encryptQuery`.

### Deprecated: `LockContext.identify()`

Older code fetched a per-operation CTS token:

```typescript
const lc = new LockContext()
const identified = await lc.identify(userJwt)   // deprecated
await client.encrypt(...).withLockContext(identified.data)
```

**Per-operation CTS tokens were removed in `protect-ffi` 0.25.** `LockContext`, `identify()` and `getLockContext()` still exist for backwards compatibility, but the token `identify()` fetches is no longer used by encryption — and `CS_CTS_ENDPOINT` is only read on that dead path. Authenticate with `OidcFederationStrategy` instead and pass the claim directly. `.withLockContext()` accepts either a `LockContext` instance or a plain `{ identityClaim }`.

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

## EQL v3 Typed Schema

EQL v3 is a newer schema surface where every encrypted column is a **concrete Postgres domain** (`public.eql_v3_<name>`) and its query capabilities are fixed by the column type you pick. There is **no chainable capability tuner** — no `.equality()`, `.freeTextSearch()`, or `.orderAndRange()` — every domain is fully described by its type. The v2 surface documented above (`encryptedColumn` from `@cipherstash/stack/schema`) continues to work unchanged; v3 lives on its own subpaths.

### Quick Start

```typescript
import { Encryption } from "@cipherstash/stack"
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"

const users = encryptedTable("users", {
  email: types.TextSearch("email"),
})

const client = await Encryption({ schemas: [users] })

const encryptResult = await client.encrypt("secret@example.com", {
  column: users.email,
  table: users,
})
if (encryptResult.failure) {
  // handle encryptResult.failure.message
}

const decryptResult = await client.decrypt(encryptResult.data)
```

`Encryption({ schemas })` auto-detects v3 tables and sets the EQL v3 wire format. **v2 and v3 tables cannot be mixed in one client** — a mixed schema set throws at init. Create separate clients if you need both.

The v3 `encryptedTable` intentionally shares its name with the v2 builder — the import path picks the model. The returned table is also a column accessor (`users.email`). The JS property name and the DB column name may differ: `createdOn: types.Timestamp("created_at")` reads/writes the `createdOn` property on models but targets the `created_at` column in the database.

### The `types` Namespace

Each factory in `types` maps 1:1 to a Postgres domain named `public.eql_v3_<name>`. The naming rule: strip the `eql_v3_` prefix and PascalCase each underscore-separated segment. So `types.TextSearch` builds a `public.eql_v3_text_search` column, `types.IntegerOrd` builds `public.eql_v3_integer_ord`, and `types.Timestamp` builds `public.eql_v3_timestamp`.

**Capability suffixes:**

| Suffix | Capabilities | Query types |
|---|---|---|
| _(none)_ | Storage only — encrypt/decrypt, no queries | — |
| `Eq` | Equality | `'equality'` |
| `Ord` / `OrdOre` | Equality + ordering/range | `'equality'`, `'orderAndRange'` |
| `Match` (text only) | Free-text containment only | `'freeTextSearch'` |
| `Search` (text only) | Equality + ordering/range + free-text | all three |
| `Json` (no suffix) | Encrypted-JSONB containment queries (JSONPath selector: not yet, see #623) | `'searchableJson'` |

**Domain families and plaintext types:**

| Family | Factories | Plaintext (TypeScript) type |
|---|---|---|
| `Integer`, `Smallint`, `Numeric`, `Real`, `Double` | base, `Eq`, `Ord`, `OrdOre` | `number` |
| `Bigint` | base, `Eq`, `Ord`, `OrdOre` | `bigint` (native JS bigint; full i64 range, out-of-range values rejected client-side before the FFI) |
| `Date` | base, `Eq`, `Ord`, `OrdOre` | `Date` (calendar date; time-of-day is truncated) |
| `Timestamp` | base, `Eq`, `Ord`, `OrdOre` | `Date` (time-of-day preserved) |
| `Text` | base, `Eq`, `Match`, `Ord`, `OrdOre`, `Search` | `string` |
| `Boolean` | base only | `boolean` |
| `Json` | `Json` only | a JSON *document* (`JsonDocument`: object, array, or null — NOT a top-level scalar; nested values are any `JsonValue`) |

Examples: `types.Text("notes")` (storage only), `types.TextEq("username")`, `types.BigintOrd("balance")`, `types.TimestampOrdOre("created_at")`, `types.Boolean("active")`, `types.Json("metadata")`.

The match index on `Match`/`Search` columns is always emitted with the default configuration — there is no per-column tuning in v3.

### Free-Text Queries on `types.TextSearch`

A `TextSearch` column carries all three indexes, and `encryptQuery` with **no explicit `queryType` builds an equality term, not a free-text match** (index inference priority: unique > match > ore). A substring like `"joh"` then matches nothing. Pass `queryType: 'freeTextSearch'` explicitly for substring/token search:

```typescript
// equality (default): exact value only
await client.encryptQuery("john@example.com", { column: users.email, table: users })

// free-text match: substring/token search
await client.encryptQuery("joh", {
  column: users.email,
  table: users,
  queryType: "freeTextSearch",
})
```

### Encrypted-JSONB Queries on `types.Json`

A `types.Json("metadata")` column encrypts a whole JSON document (a
`JsonDocument`: object, array, or null — not a top-level scalar) to a
`public.eql_v3_json` value.

**Containment** is the supported query today. Pass a sub-object or sub-array to
`encryptQuery` with `queryType: 'searchableJson'`; it matches documents that
contain the needle (jsonb `@>` semantics). Array containment is a subset test
regardless of element position — `{ roles: ['admin'] }` matches any document
whose `roles` array includes `admin`.

```typescript
const events = encryptedTable("events", { metadata: types.Json("metadata") })

// containment: object needle
await client.encryptQuery({ roles: ["admin"] }, { column: events.metadata, table: events })
```

Through the Drizzle v3 integration this is `ops.contains(col, subObject)` — see
the `stash-drizzle` skill. `types.Json` carries no equality or ordering, so
`eq` / `gt` / `asc` on it throw.

> **Not yet implemented:** JSONPath selector-with-constraint queries
> (`metadata->'plan' = $1`, `metadata->'age' > $1`) — a distinct third pattern
> the `eql_v3_json` domain supports at the SQL level (`->` / `->>`). Neither the
> query operator nor the selector-string needle typing is wired up yet; tracked
> in [#623](https://github.com/cipherstash/stack/issues/623).

### Strongly-Typed Client: `EncryptionV3`

`EncryptionV3` from `@cipherstash/stack/v3` returns a `TypedEncryptionClient` whose method signatures are derived from your schemas — wrong-typed plaintext is rejected at compile time, and query methods only accept queryable columns with `queryType` constrained to the column's capabilities:

```typescript
import { EncryptionV3, encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", {
  email: types.TextSearch("email"),
  lastLogin: types.TimestampOrd("last_login"),
  balance: types.BigintEq("balance"),
})

const client = await EncryptionV3({ schemas: [users] })

// Plaintext is pinned to the column's domain type:
await client.encrypt("alice@example.com", { table: users, column: users.email })  // string ✓
await client.encrypt(new Date(), { table: users, column: users.lastLogin })       // Date ✓
// client.encrypt(42, { table: users, column: users.email })  // ✗ compile error

const enc = await client.encryptModel(
  { id: "u1", email: "alice@example.com", lastLogin: new Date(), balance: 100n },
  users,
)
if (!enc.failure) {
  const dec = await client.decryptModel(enc.data, users)
  if (!dec.failure) {
    dec.data.email     // string
    dec.data.lastLogin // Date — reconstructed on decrypt
    dec.data.balance   // bigint
    dec.data.id        // string — non-schema fields pass through
  }
}
```

Typed-client notes:

- The wire format is pinned to EQL v3 (`eqlVersion: 3`); you don't set it yourself.
- Methods: `encrypt`, `encryptQuery`, `encryptModel`, `bulkEncryptModels`, `decrypt`, `decryptModel`, `bulkDecryptModels`, plus `bulkEncrypt`/`bulkDecrypt` passthroughs and `getEncryptConfig`.
- `decryptModel` / `bulkDecryptModels` take the **table as a second argument** and return a plain `Promise<Result<...>>` (not a chainable operation) — pass a lock context as the optional third argument instead of chaining `.withLockContext()`. `Date` columns are reconstructed to real `Date` instances on decrypt; `bigint` columns round-trip as native `bigint`.
- `decrypt` of a single value cannot be strongly typed — a lone ciphertext carries no column identity.
- `encryptQuery` rejects storage-only columns outright at compile time.
- `typedClient(client, ...schemas)` (also exported from `@cipherstash/stack/v3`) wraps an already-built `EncryptionClient` in the typed surface.

### Database Setup

Install the EQL v3 SQL with the stash CLI:

```bash
stash eql install --eql-version 3
```

EQL v3 ships one SQL bundle for every target, including Supabase — no separate Supabase or no-operator-family variants. v3 currently installs via the direct path only (`--drizzle`, `--migration`, `--migrations-dir`, and `--latest` are not supported for v3 yet).

In migrations, declare each encrypted column as its domain type:

```sql
CREATE TABLE users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email public.eql_v3_text_search,
  last_login public.eql_v3_timestamp_ord,
  balance public.eql_v3_bigint_eq
);
```

### Type Inference

```typescript
import type { InferPlaintext, InferEncrypted } from "@cipherstash/stack/eql/v3"

type UserPlaintext = InferPlaintext<typeof users>
// { email: string; lastLogin: Date; balance: bigint }

type UserEncrypted = InferEncrypted<typeof users>
// { email: Encrypted; lastLogin: Encrypted; balance: Encrypted }
```

`V3ModelInput`, `V3EncryptedModel`, and `V3DecryptedModel` (same subpath) are the model-shape helpers the typed client uses: schema-column keys are pinned to the column's plaintext type (nullable fields stay nullable), non-schema keys pass through unchanged.

### Drizzle ORM

`@cipherstash/stack-drizzle/v3` provides Drizzle-native v3 column factories, schema extraction, and auto-encrypting query operators. See the `stash-drizzle` skill for the full guide.

## Rolling Encryption Out to Production

Adding a fresh encrypted column to a table you don't yet write to is the easy case — declare it in the schema, run the migration, start writing. The harder case is taking an **existing plaintext column with live data** and turning it into an encrypted one without dropping a write or returning the wrong value mid-cutover.

CipherStash splits that into two named steps with a hard production-deploy gate between them:

```
ENCRYPTION ROLLOUT  →  ⛔ deploy gate  →  ENCRYPTION CUTOVER
─────────────────────                     ──────────────────────
schema-add                                backfill historical rows
dual-write code                           switch reads to encrypted
```
then drop the plaintext column when reads are decrypting.

The gate is the rule that backfill is only safe once the dual-write code is **running in the production environment that owns the database** — not on the developer's laptop, not in CI. Any row inserted during the backfill window must be written to both columns by the application; otherwise it lands in plaintext only and creates silent migration drift.

> **Runner note.** `stash init` adds `stash` to the project as a dev dependency, so `stash <command>` runs through whichever package manager the project uses (Bun, pnpm, Yarn, or npm) — examples below show this bare form. Before init has run, prefix with your package manager's one-shot runner: `bunx`, `pnpm dlx`, `yarn dlx`, or `npx`. The CLI's behaviour is identical across all of them; only the prefix changes. The `stash-cli` skill has the full mapping.

### Where am I?

Always start with `stash status` (`stash status` / `pnpm dlx stash status` / etc., per the runner note above). It is disk-only, idempotent, and tells you which encryption rollouts are in flight, what's been deployed, and what the next move is per column. Re-run it after every transition. Never act blind.

### Step 1 — Encryption rollout

Everything that lands in the repo and ships in **one** PR:

| Action | What changes |
|---|---|
| Schema-add | Migration adds `<col>_encrypted` (nullable `jsonb`) alongside the existing plaintext column. Plaintext column unchanged; application still writes only plaintext. |
| Dual-write code | Application now writes both `<col>` and `<col>_encrypted` on every persistence path that mutates the row, in the same transaction, on every code branch. Reads still come from the plaintext column. |

> **If you use CipherStash Proxy:** After the schema-add, run `stash db push` to register the new column in `eql_v2_configuration`. With no active config yet it writes directly to `active`; with an existing active config it writes `pending` (cutover will promote it). Required for Proxy-based queries.

**The dual-write definition matters.** "Writes both columns" is not enough. The rule is: every persistence path that mutates this row writes both columns, in the same transaction, on every code branch. A single missed branch — a CSV import, an admin action, a background job, a third-party webhook handler — means rows inserted in production after deploy land in plaintext only, and backfill won't catch them. Grep for every site that writes the plaintext column before declaring rollout complete.

### ⛔ Deploy gate

Stop. The rollout PR ships to production. The deployed environment must be running this code before any cutover-step work is safe.

When the deploy is live, run `stash status`. Look for the active quest's "Next move" hint to confirm dual-writes are recorded. Then run `stash plan` again — the CLI detects that dual-writes are live and writes a separate cutover plan.

`stash impl` will refuse to run a cutover-step plan if `cs_migrations` has no `dual_writing` event for the targeted columns. That refusal is intentional; it's the safety net for cases where someone runs cutover work locally before the code is actually live.

### Step 2 — Encryption cutover

Once dual-writes are recorded as live in `cs_migrations`:

| Action | What changes |
|---|---|
| `stash encrypt backfill` | Walks the table in keyset-pagination order, encrypts each chunk, writes a single transactional `UPDATE` per chunk plus a `cs_migrations` checkpoint. SIGINT-safe; idempotent re-runs converge. |
| Schema rename | Update the schema file: drop the `_encrypted` suffix; switch the original column declaration onto the encrypted type. |
| `stash encrypt cutover` | One transaction: renames `<col>` → `<col>_plaintext`, `<col>_encrypted` → `<col>`, and promotes `pending` → `active`. Application reads of `<col>` now return decrypted ciphertext transparently. |
| Wire reads through the encryption client | Read paths must decrypt before returning the value to callers (`decryptModel(row, table)` for Drizzle; `encryptedSupabase` wrapper for Supabase; `decrypt`/`bulkDecryptModels` otherwise). Without this step, reads return raw `eql_v2_encrypted` payloads to end users. |
| Remove dual-write code | The plaintext column is now `<col>_plaintext` and is no longer authoritative. Delete the dual-write logic. |
| `stash encrypt drop` | Emits a migration that removes `<col>_plaintext`. Apply with the project's normal migration tooling. |

> **If you use CipherStash Proxy:** After the schema rename, run `stash db push` to register the renamed shape as `pending`. This is required for Proxy-based queries; SDK users skip this step.

### State storage

Three sources of truth, kept separate on purpose:

- **`.cipherstash/migrations.json`** (repo) — *intent*. Which columns the developer wants to encrypt and at which phase, code-reviewable.
- **`eql_v2_configuration`** (DB, EQL-managed) — *EQL intent*. Which columns are encrypted and with which indexes; drives the CipherStash Proxy.
- **`cipherstash.cs_migrations`** (DB, CipherStash-managed) — *runtime state*. Append-only event log: phase transitions, backfill cursors, error rows. Latest row per `(table, column)` is the current state.

`stash encrypt status` shows all three side-by-side and flags drift (e.g. EQL says registered, the physical `<col>_encrypted` column is missing). `stash status` (the quest log) rolls them up into the per-column "what's the next move" view used during a rollout.

> **Note on internal phase names.** The runtime event log uses `schema-added → dual-writing → backfilling → backfilled → cut-over → dropped` as machine-readable phase names. They appear in `cs_migrations` rows and `stash encrypt status` output. Treat them as internal mechanism detail — the user-facing story is "encryption rollout, then cutover, with a deploy gate in between."

### CLI sequence for a single column

> **Known limitation:** `stash encrypt cutover` currently requires a pending EQL configuration registered via `stash db push`. SDK-only users may hit a "No pending EQL configuration" error. **Workaround:** Run `stash db push` once before `stash encrypt cutover`, even if you don't use CipherStash Proxy. Decoupling cutover from EQL config for SDK users is tracked in issue [#447](https://github.com/cipherstash/stack/issues/447) follow-up work.

```bash
# Run this often — it's the canonical "where am I?" command.
stash status

# ---- ENCRYPTION ROLLOUT (one PR, one deploy) ----
# 1. Add the encrypted twin column via your normal migration tooling
#    (drizzle-kit / supabase migrations / etc.).
# 2. Edit application code so every persistence path writes both
#    `<col>` and `<col>_encrypted` in the same transaction, on every
#    code branch.
# 3. Ship the PR to production.

# ---- ⛔ DEPLOY GATE ----
# Verify dual-writes are live, then redraft the plan for cutover work:
stash status
stash plan

# ---- ENCRYPTION CUTOVER ----
stash encrypt backfill --table users --column email
# Prompts to confirm dual-writes are live (or pass
# --confirm-dual-writes-deployed in CI). Resumable; SIGINT-safe.

# Recovery — if dual-writes weren't actually live when backfill ran,
# re-run with --force to encrypt every plaintext row regardless.
stash encrypt backfill --table users --column email --force

# Edit the schema to drop the `_encrypted` suffix, then register the
# pending EQL config — cutover requires it (see Known limitation above),
# so SDK-only deployments must run `stash db push` once here too:
stash db push
stash encrypt cutover --table users --column email
# In one transaction: rename physical columns, promote pending → active.

# Wire the read paths through the encryption client. Remove dual-write
# code. Then drop the plaintext column:
stash encrypt drop --table users --column email
```

#### If you use CipherStash Proxy

Register and promote encryption config at each phase:

```bash
# Run this often — it's the canonical "where am I?" command.
stash status

# ---- ENCRYPTION ROLLOUT (one PR, one deploy) ----
# 1. Add the encrypted twin column via your normal migration tooling
#    (drizzle-kit / supabase migrations / etc.).
# 2. Register the new encryption config with EQL:
stash db push
#    First push (no active config yet) → writes directly to active.
#    Subsequent push (active already exists) → writes pending; cutover
#    will promote it.
# 3. Edit application code so every persistence path writes both
#    `<col>` and `<col>_encrypted` in the same transaction, on every
#    code branch.
# 4. Ship the PR to production.

# ---- ⛔ DEPLOY GATE ----
# Verify dual-writes are live, then redraft the plan for cutover work:
stash status
stash plan

# ---- ENCRYPTION CUTOVER ----
stash encrypt backfill --table users --column email
# Prompts to confirm dual-writes are live (or pass
# --confirm-dual-writes-deployed in CI). Resumable; SIGINT-safe.

# Recovery — if dual-writes weren't actually live when backfill ran,
# re-run with --force to encrypt every plaintext row regardless.
stash encrypt backfill --table users --column email --force

# Edit the schema to drop the `_encrypted` suffix, then re-push:
stash db push
#  → writes the renamed-shape config as `pending`. The active config
#    keeps serving until cutover finishes.

stash encrypt cutover --table users --column email
# In one transaction: rename physical columns, promote pending → active.

# Wire the read paths through the encryption client. Remove dual-write
# code. Then drop the plaintext column:
stash encrypt drop --table users --column email
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

### Invariants the rollout preserves

- **Reads never return the wrong value.** Until cutover, reads come from the plaintext column. After cutover, the same `SELECT email` returns the decrypted ciphertext via Proxy or the encryption client. There is no in-between.
- **Writes never drop.** Dual-writing keeps both columns in sync until the cutover moment. After cutover, writes go to the encrypted column.
- **The deploy gate is a one-way door for production.** Backfill against rows the dual-write code never saw produces silent drift. The CLI refuses to run cutover-step plans without a `dual_writing` event recorded; do not paper over that refusal.
- **Re-runs are safe.** Backfill is idempotent (`<col> IS NOT NULL AND <col>_encrypted IS NULL` guards every chunk). `cs_migrations` is append-only.
- **Rollback is possible up to cutover.** Until the rename happens, the plaintext column is authoritative; aborting just leaves the encrypted twin partially populated. After cutover, rollback is a manual restore — treat cutover as the one-way door for data.

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

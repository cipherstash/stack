---
name: stash-encryption
description: Implement field-level encryption with @cipherstash/stack using the EQL v3 typed schema. Covers the types.* column catalog (concrete Postgres domains with fixed query capabilities), the strongly-typed EncryptionV3 client, encrypt/decrypt and model operations, searchable encryption (equality, free-text, range), encrypted JSON (containment and JSONPath selectors), bulk operations, identity-aware encryption with lock contexts, multi-tenant keysets, and the rollout/cutover lifecycle. Use when adding encryption to a project, defining encrypted schemas, or working with the CipherStash Encryption API.
---

# CipherStash Stack - Encryption

Comprehensive guide for implementing field-level encryption with `@cipherstash/stack`. Every value is encrypted with its own unique key via ZeroKMS (backed by AWS KMS). Encryption happens client-side before data leaves the application.

Encrypted columns are **EQL v3 concrete Postgres domains** (`public.eql_v3_text_search`, `public.eql_v3_integer_ord`, ...): each column's query capabilities are fixed by the domain type you pick in the schema, and the `EncryptionV3` client derives precise TypeScript types from that schema — wrong-typed plaintext is a compile error, not a runtime surprise.

> An older schema surface (EQL v2, with chainable capability builders) still exists for existing deployments — see "Legacy: EQL v2" at the end. Everything else in this skill is the v3 surface. New projects should use v3.

## When to Use This Skill

- Adding field-level encryption to a TypeScript/Node.js project
- Defining encrypted table schemas with the `types.*` domain catalog
- Encrypting and decrypting individual values or entire models
- Implementing searchable encryption (equality, free-text, range, encrypted JSON)
- Bulk encrypting/decrypting large datasets
- Implementing identity-aware encryption with JWT-based lock contexts
- Setting up multi-tenant encryption with keysets
- Rolling encryption out to a production table with live plaintext data

## Quick Start

```typescript
import { EncryptionV3, encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", {
  email: types.TextSearch("email"),
})

const client = await EncryptionV3({ schemas: [users] })

const encrypted = await client.encrypt("secret@example.com", {
  table: users,
  column: users.email,
})
if (encrypted.failure) {
  throw new Error(encrypted.failure.message)
}

const decrypted = await client.decrypt(encrypted.data)
```

## Installation

```bash
npm install @cipherstash/stack
```

> **Version note:** `npx stash init` is the preferred install path — it pins
> every `@cipherstash/*` package to the versions matching your CLI release.
> If you install manually as above, verify what actually resolved
> (`node -p "require('@cipherstash/stack/package.json').version"`): bare
> dist-tag installs can lag behind a release, and `stash init` will warn on
> the version skew.

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

### Local Development (preferred: `stash auth login`)

No environment variables are needed for local development:

```bash
npx stash init        # agent-assisted setup: auth + schema + database, end to end
# or, if the project is already set up:
npx stash auth login  # device code flow; token saved to ~/.cipherstash/auth.json
```

`npx stash init` is the assisted flow — it authenticates, builds the encryption
schema with you, generates the client file, and wires the database. For an
already-initialized project, `npx stash auth login` alone authenticates the
machine; the SDK and CLI pick up the saved profile automatically. Sign up at
[cipherstash.com/signup](https://cipherstash.com/signup) first.

Agents can drive the login too: `npx stash auth login --json --region <slug>`
emits the verification URL as data — run it in the background, relay the URL
to the human, and the flow completes when they approve in a browser. The
event contract and the operational loop are in the `stash-cli` skill's
Authentication section.

### CI and Production (environment variables)

Deployed environments and CI use machine credentials via environment variables
(set in your hosting platform or pipeline secrets — not committed `.env`):

```bash
CS_WORKSPACE_CRN=crn:ap-southeast-2.aws:your-workspace-id
CS_CLIENT_ID=your-client-id
CS_CLIENT_KEY=your-client-key
CS_CLIENT_ACCESS_KEY=your-access-key
```

Mint all four from your device session with `npx stash env --name <name>` —
no dashboard copy-paste. It creates a fresh ZeroKMS client plus a
**member-role** access key (shown exactly once; the CLI cannot mint admin
keys) and prints the block above, ready to pipe into your platform's secret
store. `CS_CLIENT_KEY` and `CS_CLIENT_ACCESS_KEY` are secrets — never commit
them. Also the path for runtimes that can't read `~/.cipherstash` — e.g.
`@cipherstash/stack/wasm-inline` on Supabase Edge Functions (containerised
even in local dev) or Cloudflare Workers. See the `stash-cli` skill for flags
(`--write`, `--json`).

When both are present, the `CS_*` variables take precedence over the saved
profile.

### Programmatic Config

```typescript
const client = await EncryptionV3({
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

If `config` is omitted, the client resolves credentials automatically: `CS_*` environment variables when set (CI/production), otherwise the local `stash auth login` profile (development).

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
| `@cipherstash/stack/v3` | `EncryptionV3` factory, `typedClient`, `TypedEncryptionClient` — plus re-exports of everything in `@cipherstash/stack/eql/v3`. The one-stop import for v3. |
| `@cipherstash/stack/eql/v3` | `encryptedTable`, the `types` namespace, `buildEncryptConfig`, inference types (`InferPlaintext`, `InferEncrypted`, `V3ModelInput`, ...) |
| `@cipherstash/stack` | `OidcFederationStrategy`, `AccessKeyStrategy`, the untyped `Encryption` function (also accepts v3 schemas), legacy v2 re-exports |
| `@cipherstash/stack/identity` | `LockContext` class and identity types |
| `@cipherstash/stack/errors` | `EncryptionErrorTypes`, `StackError`, error subtypes, `getErrorMessage` |
| `@cipherstash/stack/types` | All TypeScript types |
| `@cipherstash/stack-drizzle/v3` | Drizzle ORM integration for EQL v3 schemas (see the `stash-drizzle` skill) |
| `@cipherstash/stack-supabase` | `encryptedSupabaseV3` wrapper for Supabase (see the `stash-supabase` skill) |
| `@cipherstash/stack/dynamodb` | `encryptedDynamoDB` — **still requires the legacy v2 schema surface**; see "Legacy: EQL v2" below |
| `@cipherstash/stack/schema`, `@cipherstash/stack/client`, `@cipherstash/stack/encryption` | Legacy v2 schema builders and client surface — see "Legacy: EQL v2" below |

## Schema Definition

Define which tables and columns to encrypt with `encryptedTable` and the `types` namespace. Every encrypted column is a **concrete Postgres domain** whose query capabilities are **fixed by the type** — there is no chainable capability tuner; every domain is fully described by its `types.*` factory.

```typescript
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"
// (also re-exported from "@cipherstash/stack/v3")

const users = encryptedTable("users", {
  email: types.TextSearch("email"),       // equality + order/range + free-text
  username: types.TextEq("username"),     // equality only
  balance: types.BigintOrd("balance"),    // equality + order/range
  lastLogin: types.TimestampOrd("last_login"),
  active: types.Boolean("active"),        // storage only — encrypt/decrypt, no queries
  notes: types.Text("notes"),             // storage only
})

const events = encryptedTable("events", {
  metadata: types.Json("metadata"),       // encrypted JSONB: containment + selectors
})
```

The returned table is also a column accessor (`users.email`). The JS property name and the DB column name may differ: `lastLogin: types.TimestampOrd("last_login")` reads/writes the `lastLogin` property on models but targets the `last_login` column in the database.

### The `types` Namespace

Each factory in `types` maps 1:1 to a Postgres domain named `public.eql_v3_<name>`. The naming rule: strip the `eql_v3_` prefix and PascalCase each underscore-separated segment. So `types.TextSearch` builds a `public.eql_v3_text_search` column, `types.IntegerOrd` builds `public.eql_v3_integer_ord`, and `types.Timestamp` builds `public.eql_v3_timestamp`.

**Capability suffixes:**

| Suffix | Capabilities | Query types |
|---|---|---|
| _(none)_ | Storage only — encrypt/decrypt, no queries | — |
| `Eq` | Equality | `'equality'` |
| `Ord` | Equality + ordering/range (OPE-backed) | `'equality'`, `'orderAndRange'` |
| `OrdOre` | Equality + ordering/range (block-ORE flavour — see caveat below) | `'equality'`, `'orderAndRange'` |
| `Match` (text only) | Free-text containment only | `'freeTextSearch'` |
| `Search` (text only) | Equality + ordering/range + free-text | all three |
| `Json` (no suffix) | Encrypted-JSONB containment + JSONPath selector queries | `'searchableJson'` |

> **`Ord` vs `OrdOre`:** prefer `Ord`. The `OrdOre` domains are backed by an ORE operator class whose installation requires **superuser** — unavailable on managed Postgres (including Supabase), where the install bundle skips the ORE opclass and disables the `_ord_ore` domains it cannot support. The two ordering flavours produce different, non-cross-comparable terms (`Ord`/`Search` extract via `eql_v3.ord_term`; `OrdOre` via `eql_v3.ord_term_ore`).

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

The match index on `Match`/`Search` columns is always emitted with the default configuration (trigram tokenizer, downcased) — there is no per-column tuning in v3. Search needles must be at least 3 characters; shorter needles tokenize to nothing and are rejected.

### Type Inference

```typescript
import type { InferPlaintext, InferEncrypted } from "@cipherstash/stack/eql/v3"

type UserPlaintext = InferPlaintext<typeof users>
// { email: string; lastLogin: Date; balance: bigint; ... }

type UserEncrypted = InferEncrypted<typeof users>
// { email: Encrypted; lastLogin: Encrypted; balance: Encrypted; ... }
```

`V3ModelInput`, `V3EncryptedModel`, and `V3DecryptedModel` (same subpath) are the model-shape helpers the typed client uses: schema-column keys are pinned to the column's plaintext type (nullable fields stay nullable), non-schema keys pass through unchanged.

### Database Setup

Install the EQL v3 SQL with the stash CLI (v3 is the default):

```bash
stash eql install --eql-version 3

# Supabase targets: add --supabase to apply role grants
stash eql install --eql-version 3 --supabase
```

EQL v3 ships **one SQL bundle for every target, including Supabase** — no separate Supabase or no-operator-family variants. For Supabase, though, still pass the `--supabase` flag: it applies the `anon`/`authenticated`/`service_role` grants on the `eql_v3` and `eql_v3_internal` schemas. Without it, encrypted queries fail with `permission denied for schema eql_v3_internal`. v3 installs via the direct path only (`--drizzle`, `--migration`, `--migrations-dir`, and `--latest` are v2-only flags and are not supported for v3).

In migrations, declare each encrypted column as its domain type:

```sql
CREATE TABLE users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email public.eql_v3_text_search,
  last_login public.eql_v3_timestamp_ord,
  balance public.eql_v3_bigint_ord
);
```

## Client Initialization: `EncryptionV3`

`EncryptionV3` from `@cipherstash/stack/v3` returns a `TypedEncryptionClient` whose method signatures are derived from your schemas — wrong-typed plaintext is rejected at compile time, and query methods only accept queryable columns with `queryType` constrained to the column's capabilities:

```typescript
import { EncryptionV3, encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", {
  email: types.TextSearch("email"),
  lastLogin: types.TimestampOrd("last_login"),
  balance: types.BigintEq("balance"),
})

const client = await EncryptionV3({ schemas: [users] })
```

- The wire format is pinned to EQL v3 (`eqlVersion: 3`); you don't set it yourself.
- `EncryptionV3()` throws on init error (bad credentials, missing config, invalid keyset UUID). At least one schema is required.
- `typedClient(client, ...schemas)` (also exported from `@cipherstash/stack/v3`) wraps an already-built untyped `EncryptionClient` in the typed surface.
- The untyped `Encryption({ schemas })` from `@cipherstash/stack` also accepts v3 tables (it auto-detects them and sets the v3 wire format), but you lose the per-column typing — prefer `EncryptionV3`. **v2 and v3 tables cannot be mixed in one client** — a mixed schema set throws at init. Create separate clients if you need both.

```typescript
// Error handling
try {
  const client = await EncryptionV3({ schemas: [users] })
} catch (error) {
  console.error("Init failed:", error.message)
}
```

## Encrypt and Decrypt Single Values

Plaintext is pinned to the column's domain type:

```typescript
await client.encrypt("alice@example.com", { table: users, column: users.email })  // string ✓
await client.encrypt(new Date(), { table: users, column: users.lastLogin })       // Date ✓
// client.encrypt(42, { table: users, column: users.email })  // ✗ compile error

const encrypted = await client.encrypt("hello@example.com", {
  table: users,
  column: users.email,
})

if (encrypted.failure) {
  throw new Error(encrypted.failure.message)
}
console.log(encrypted.data) // Encrypted payload (opaque object)

// Decrypt
const decrypted = await client.decrypt(encrypted.data)

if (!decrypted.failure) {
  console.log(decrypted.data) // "hello@example.com"
}
```

`decrypt` of a single value cannot be strongly typed — a lone ciphertext carries no column identity. All plaintext values passed to `encrypt` must be non-null; null handling is managed at the model level by `encryptModel` and `decryptModel`.

## Model Operations

Encrypt or decrypt an entire object. Only fields matching your schema are encrypted; other fields pass through unchanged, and schema fields are validated against their inferred plaintext type at compile time.

```typescript
const enc = await client.encryptModel(
  { id: "u1", email: "alice@example.com", lastLogin: new Date(), balance: 100n },
  users,
)
if (!enc.failure) {
  // enc.data.email is Encrypted; enc.data.id stays string

  const dec = await client.decryptModel(enc.data, users)
  if (!dec.failure) {
    dec.data.email     // string
    dec.data.lastLogin // Date — reconstructed on decrypt
    dec.data.balance   // bigint
    dec.data.id        // string — non-schema fields pass through
  }
}
```

Typed-client model notes:

- `decryptModel` / `bulkDecryptModels` take the **table as a second argument** and return a plain `Promise<Result<...>>` (not a chainable operation) — pass a lock context as the optional third argument instead of chaining `.withLockContext()`.
- `Date` columns are reconstructed to real `Date` instances on decrypt; `bigint` columns round-trip as native `bigint`.
- Nullable schema fields stay nullable through the round trip.

## Bulk Operations

All bulk methods make a single call to ZeroKMS regardless of record count, while still using a unique key per value.

### Bulk Encrypt / Decrypt Models

```typescript
const userModels = [
  { id: "1", email: "alice@example.com", lastLogin: new Date(), balance: 1n },
  { id: "2", email: "bob@example.com", lastLogin: new Date(), balance: 2n },
]

const encrypted = await client.bulkEncryptModels(userModels, users)
if (encrypted.failure) throw new Error(encrypted.failure.message)

const decrypted = await client.bulkDecryptModels(encrypted.data, users)
```

### Bulk Encrypt / Decrypt (Raw Values)

`bulkEncrypt` / `bulkDecrypt` are parity passthroughs (not v3-strengthened):

```typescript
const plaintexts = [
  { id: "u1", plaintext: "alice@example.com" },
  { id: "u2", plaintext: "bob@example.com" },
]

const encrypted = await client.bulkEncrypt(plaintexts, {
  column: users.email,
  table: users,
})
if (encrypted.failure) throw new Error(encrypted.failure.message)
// encrypted.data = [{ id: "u1", data: EncryptedPayload }, ...]

const decrypted = await client.bulkDecrypt(encrypted.data)
if (decrypted.failure) throw new Error(decrypted.failure.message)
// Per-item error handling:
for (const item of decrypted.data) {
  if ("data" in item) {
    console.log(`${item.id}: ${item.data}`)
  } else {
    console.error(`${item.id} failed: ${item.error}`)
  }
}
```

## Searchable Encryption

Encrypt query terms with `encryptQuery` so you can search encrypted data in PostgreSQL. On the typed client, `encryptQuery` only accepts queryable columns (storage-only columns are rejected at compile time) and constrains `queryType` to the column's capabilities.

```typescript
// Equality query
const eqQuery = await client.encryptQuery("alice@example.com", {
  column: users.email,
  table: users,
  queryType: "equality",
})

// Free-text search (substring/token match)
const matchQuery = await client.encryptQuery("alice", {
  column: users.email,
  table: users,
  queryType: "freeTextSearch",
})

// Order and range
const rangeQuery = await client.encryptQuery(new Date("2026-01-01"), {
  column: users.lastLogin,
  table: users,
  queryType: "orderAndRange",
})
```

### Query-Type Inference Gotcha on `types.TextSearch`

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

### Free-Text Search Semantics

Encrypted free-text search is **fuzzy bloom-filter token matching**, not SQL pattern matching:

- The needle blooms to its own trigrams; a row matches when the stored value's bloom contains all of them. Case-insensitive; order- and multiplicity-insensitive.
- **One-sided:** a match may be a false positive; a non-match never is.
- Needles must be at least 3 characters (the default trigram length) — shorter needles bloom to nothing and are rejected rather than silently matching every row.
- In the Drizzle and Supabase v3 integrations the operator is **`matches`** — the adapters expose free-text search as `matches`, not `like`/`ilike` (the Supabase adapter keeps a deprecated `like`/`ilike` shim that delegates to `matches` with a warning). Don't pass `%` wildcards.

### Query Result Formatting (`returnType`)

By default `encryptQuery` returns an `Encrypted` object (the raw EQL JSON payload). Use `returnType` to change the output format:

| `returnType` | Output | Use case |
|---|---|---|
| `'eql'` (default) | `Encrypted` object | Parameterized queries, ORMs accepting JSON |
| `'composite-literal'` | `string` | Supabase `.eq()`, string-based APIs |
| `'escaped-composite-literal'` | `string` | Embedding inside another string or JSON value |

```typescript
const term = await client.encryptQuery("alice@example.com", {
  column: users.email,
  table: users,
  queryType: "equality",
  returnType: "composite-literal",
})
// term.data is a string
```

Each term in a batch can have its own `returnType`.

### Batch Query Encryption

Encrypt multiple query terms in one ZeroKMS call (the per-term columns are heterogeneous, so the batch form takes untyped `ScalarQueryTerm`s):

```typescript
const terms = [
  { value: "alice@example.com", column: users.email, table: users, queryType: "equality" as const },
  { value: "bob", column: users.email, table: users, queryType: "freeTextSearch" as const },
]

const results = await client.encryptQuery(terms)
// results.data = [EncryptedPayload, EncryptedPayload]
```

All values in the array must be non-null.

### On the Wire: Operators and Ordering

Scalar filters compare through each domain's `eql_v3.*` operators (`col = term`, `col > term`, ...), and `ORDER BY` on an encrypted column goes through the ordering extractors — `eql_v3.ord_term(col)` for OPE-backed (`Ord`/`Search`) domains, `eql_v3.ord_term_ore(col)` for `OrdOre`. The Drizzle v3 integration emits all of this for you (including `asc`/`desc`, which emit `ORDER BY eql_v3.ord_term(col)`). Over Supabase/PostgREST, the adapter's `order()` works on OPE-backed ordering columns (plain `*_ord`, `text_ord`, `text_search`) by sorting on the column's `col->op` term; `OrdOre`-flavour (`*_ord_ore`) domains and columns with no ordering term are rejected. See the `stash-drizzle` and `stash-supabase` skills.

## Encrypted JSON (`types.Json`)

A `types.Json("metadata")` column encrypts a whole JSON document to a `public.eql_v3_json_search` value. The plaintext is a **`JsonDocument`: an object, an array, or `null` — NOT a bare top-level scalar** (protect-ffi rejects a top-level string/number/boolean; a scalar belongs in a scalar domain like `types.TextEq` or `types.IntegerEq`). Nested scalars are fully supported.

`types.Json` carries no equality or ordering capability — `eq` / `gt` / `asc` on it throw. It supports two query patterns: containment and JSONPath selectors.

### Containment (exact, `@>`)

Pass a sub-object or sub-array to `encryptQuery` with `queryType: 'searchableJson'`; it matches documents that contain the needle with jsonb `@>` semantics — **exact** containment, no false positives. Array containment is a subset test regardless of element position: `{ roles: ['admin'] }` matches any document whose `roles` array includes `admin`.

```typescript
const events = encryptedTable("events", { metadata: types.Json("metadata") })

// containment: object needle
await client.encryptQuery({ roles: ["admin"] }, { column: events.metadata, table: events })
```

The Drizzle and Supabase adapters reject an empty-object needle (jsonb `{} ⊆ anything` — it would silently match every row); core `client.encryptQuery` does not enforce this, so guard against empty needles yourself when composing raw SQL.

### JSONPath Selectors (value-at-a-path)

Selector queries constrain the value **at a path** inside the document — `metadata->'$.user.role' = 'admin'`. Their unique power over containment is **ordering at a path** (`gt`/`gte`/`lt`/`lte`), available through the Drizzle and Prisma Next integrations. Paths are dot-notation object paths (`'$.a.b'`); array/wildcard steps are rejected.

Semantics to know:

- **`eq`** at a path excludes rows whose document lacks the path (absent is not equal).
- **`ne`** at a path **includes** rows whose document lacks the path, and — in both adapters — rows whose column is SQL NULL ("not equal to value" covers "has no value"; Drizzle adds `OR <col> IS NULL`, Supabase an `is.null` branch).
- **Array-leaf caveat:** a scalar needle does not match an array at the path — ste_vec encodes array elements under their own selectors, so `{a: [40, 30]}` is NOT matched by a selector-eq of `30` at `$.a`. To match an array-valued path, pass the full array through containment.
- **Query operands are ciphertext-free in Drizzle and Prisma Next.** Equality uses a value-selector containment needle; ordering uses a selector hash plus a scalar query term. Supabase still sends a full storage envelope because PostgREST cannot cast a filter operand to `eql_v3.query_json` ([cipherstash/stack#654](https://github.com/cipherstash/stack/issues/654)).

### Adapter Matrix

| Capability | Drizzle v3 | Prisma Next | Supabase v3 |
|---|---|---|---|
| Containment (`@>`) | `ops.contains(col, subdoc)` | `eqlJsonContains(subdoc)` | `contains(col, subdoc)` |
| Selector equality | `ops.selector(col, path).eq/ne(value)` | `eqlJsonPathEq/Neq(path, value)` | `selectorEq/selectorNe(col, path, value)` |
| Selector ordering | `ops.selector(col, path).gt/gte/lt/lte(value)` | `eqlJsonPathGt/Gte/Lt/Lte(path, value)` | Not available — needs [cipherstash/encrypt-query-language#407](https://github.com/cipherstash/encrypt-query-language/issues/407) |

> **EQL 3.0.2 upgrade:** the `public.eql_v3_json_search` storage domain and
> SteVec wire format are not compatible with earlier encrypted JSON rows.
> Re-encrypt those rows during the upgrade. Legacy EQL v2
> `searchableJson()` columns are no longer supported by protect-ffi 0.30;
> migrate them to v3 `types.Json`. If you use raw `encryptQuery` query types,
> explicit `steVecTerm` now produces a scalar JSON ordering term rather than a
> containment needle. Prefer `searchableJson` for containment, or
> `steVecValueSelector` for exact equality at a path.

See the `stash-drizzle` and `stash-supabase` skills for the full integration guides.

## Authentication

The client authenticates to ZeroKMS through `config.authStrategy`. Leave it unset for the default **auto** strategy: in local development, authenticate once with `npx stash auth login` (preferred — no credentials in your environment; `npx stash init` is the agent-assisted flow that also sets up schema and database); in CI/production, set the `CS_*` environment variables. Two explicit strategies cover the other cases:

- **`AccessKeyStrategy`** — service-to-service / CI. Authenticates a *service* with a CipherStash access key.
- **`OidcFederationStrategy`** — authenticates the client **as the end user** by federating a third-party OIDC JWT (Clerk, Supabase, Auth0, Okta, ...) into a CipherStash service token:

```typescript
import { OidcFederationStrategy } from "@cipherstash/stack"
import { EncryptionV3, encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", { email: types.TextSearch("email") })

// `getJwt` is re-invoked on every (re-)federation and must return the
// *current* third-party OIDC JWT.
const strategy = OidcFederationStrategy.create(
  process.env.CS_WORKSPACE_CRN!,
  () => getUserJwt(),
)
if (strategy.failure) {
  throw new Error(`[auth] ${strategy.failure.type}: ${strategy.failure.error.message}`)
}

const client = await EncryptionV3({
  schemas: [users],
  config: { authStrategy: strategy.data },
})
```

`OidcFederationStrategy.create()` returns a `Result` — **unwrap it**. Passing the envelope straight to `authStrategy` gives the FFI an object with no `getToken()` at all.

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

Lock contexts work with every operation: `encrypt`, `decrypt`, `encryptModel`, `decryptModel`, `bulkEncrypt`, `bulkDecrypt`, `bulkEncryptModels`, `bulkDecryptModels`, `encryptQuery`. On the typed client, `decryptModel` and `bulkDecryptModels` take the lock context as their optional **third argument** (they return a plain `Promise<Result<...>>`, so there is no `.withLockContext()` to chain):

```typescript
const dec = await client.decryptModel(enc.data, users, IDENTITY)
```

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
const client = await EncryptionV3({
  schemas: [users],
  config: { keyset: { name: "Company A" } },
})

// By UUID
const client = await EncryptionV3({
  schemas: [users],
  config: { keyset: { id: "123e4567-e89b-12d3-a456-426614174000" } },
})
```

Each keyset provides full cryptographic isolation between tenants.

## Operation Chaining

Encrypt operations return thenable objects that support chaining:

```typescript
const result = await client
  .encrypt(plaintext, { column: users.email, table: users })
  .withLockContext(lockContext)         // optional: identity-aware
  .audit({ metadata: { action: "create" } }) // optional: audit trail
```

(The typed client's `decryptModel` / `bulkDecryptModels` are the exception: they return a plain `Promise<Result<...>>` and take the lock context as an argument — see "Model Operations".)

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
- `bigint` values outside the signed 64-bit range are rejected client-side before the FFI
- Free-text search only applies to string values (`Match`/`Search` text domains); needles shorter than the trigram length (3) are rejected
- A `types.Json` column rejects a bare top-level scalar — the document must be an object, array, or null
- At least one `encryptedTable` schema must be provided
- Keyset UUIDs must be valid format

## Rolling Encryption Out to Production

> **EQL version note.** The rollout tooling (`stash encrypt *`, `@cipherstash/migrate`) works with **both EQL versions** and auto-detects the column's version from its Postgres domain type — no flag. The lifecycles differ at the end: **v2** finishes with `stash encrypt cutover` (a rename swap plus a config promotion in `eql_v2_configuration`), then drops `<col>_plaintext`. **v3 has no cut-over and no configuration table** — after backfill you point the application at `<col>_encrypted` *by name*, verify reads, then `stash encrypt drop` generates the drop of the original plaintext `<col>`. Running `encrypt cutover` on a v3 column safely reports "not applicable" with the next step. `stash db push`/`db activate` remain v2-only (they manage `eql_v2_configuration`).

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
| Wire reads through the encryption client | Read paths must decrypt before returning the value to callers (`decryptModel(row, table)` for Drizzle; the Supabase wrapper for Supabase; `decrypt`/`bulkDecryptModels` otherwise). Without this step, reads return raw `eql_v2_encrypted` payloads to end users. |
| Remove dual-write code | The plaintext column is now `<col>_plaintext` and is no longer authoritative. Delete the dual-write logic. |
| `stash encrypt drop` | Emits a migration that removes `<col>_plaintext`. Apply with the project's normal migration tooling. |

> **If you use CipherStash Proxy:** After the schema rename, run `stash db push` to register the renamed shape as `pending`. This is required for Proxy-based queries; SDK users skip this step.

### State storage

Three sources of truth, kept separate on purpose:

- **`.cipherstash/migrations.json`** (repo) — *intent*. Which columns the developer wants to encrypt and at which phase, code-reviewable.
- **`eql_v2_configuration`** (DB, EQL-managed) — *EQL intent*. Which columns are encrypted and with which indexes; drives the CipherStash Proxy.
- **`cipherstash.cs_migrations`** (DB, CipherStash-managed) — *runtime state*. Append-only event log: phase transitions, backfill cursors, error rows. Latest row per `(table, column)` is the current state.

`stash encrypt status` shows all three side-by-side and flags drift (e.g. EQL says registered, the physical `<col>_encrypted` column is missing). `stash status` (the quest log) rolls them up into the per-column "what's the next move" view used during a rollout.

> **Note on internal phase names.** The runtime event log uses machine-readable phase names that depend on the column's EQL version: v3 (the default) runs `schema-added → dual-writing → backfilling → backfilled → dropped` (no cut-over — the app switches to the encrypted column by name), while v2 runs `schema-added → dual-writing → backfilling → backfilled → cut-over → dropped`. They appear in `cs_migrations` rows and `stash encrypt status` output. Treat them as internal mechanism detail — the user-facing story is "encryption rollout, then switch reads to encrypted, with a deploy gate in between."

### CLI sequence for a single column

> **Known limitation (v2):** `stash encrypt cutover` requires a pending EQL configuration registered via `stash db push`. SDK-only users may hit a "No pending EQL configuration" error. **Workaround:** Run `stash db push` once before `stash encrypt cutover`, even if you don't use CipherStash Proxy. Decoupling cutover from EQL config for SDK users is tracked separately. (EQL v3 columns never hit this — cutover doesn't apply to them.)

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

Useful when the backfill needs to run in a worker, on a schedule, or alongside an existing job runner. `runBackfill` is version-agnostic — for an EQL v3 column pass an `EncryptionV3` client (from `@cipherstash/stack/v3`) and it writes v3 envelopes straight into the concrete `eql_v3_*` domain column.

### Invariants the rollout preserves

- **Reads never return the wrong value.** Until cutover, reads come from the plaintext column. After cutover, the same `SELECT email` returns the decrypted ciphertext via Proxy or the encryption client. There is no in-between.
- **Writes never drop.** Dual-writing keeps both columns in sync until the cutover moment. After cutover, writes go to the encrypted column.
- **The deploy gate is a one-way door for production.** Backfill against rows the dual-write code never saw produces silent drift. The CLI refuses to run cutover-step plans without a `dual_writing` event recorded; do not paper over that refusal.
- **Re-runs are safe.** Backfill is idempotent (`<col> IS NOT NULL AND <col>_encrypted IS NULL` guards every chunk). `cs_migrations` is append-only.
- **Rollback is possible up to cutover.** Until the rename happens, the plaintext column is authoritative; aborting just leaves the encrypted twin partially populated. After cutover, rollback is a manual restore — treat cutover as the one-way door for data.

## Integrations

| Target | Package / entry point | Skill |
|---|---|---|
| Drizzle ORM | `@cipherstash/stack-drizzle/v3` — v3 column factories (each `types.*` factory emits its domain as the column's SQL type for `drizzle-kit generate`), schema extraction, auto-encrypting operators (`ops.eq`, `ops.matches`, `ops.contains`, `ops.selector`, `ops.asc`, ...) | `stash-drizzle` |
| Supabase | `encryptedSupabaseV3` from `@cipherstash/stack-supabase` — schema-aware query builder (`eq`, `matches`, `contains`, `selectorEq`/`selectorNe`, ...) that works through PostgREST, including as `anon` | `stash-supabase` |
| Prisma | `@cipherstash/prisma-next` — searchable field-level encryption for Postgres | — |
| DynamoDB | `encryptedDynamoDB` from `@cipherstash/stack/dynamodb` — **v2 schema surface only**, see the exception note under "Legacy: EQL v2" | `stash-dynamodb` |

## Complete API Reference

### TypedEncryptionClient Methods

| Method | Signature | Returns |
|---|---|---|
| `encrypt` | `(plaintext, { table, column })` — plaintext pinned to the column's domain type | `EncryptOperation` |
| `decrypt` | `(encryptedData)` — untyped (no column identity) | `DecryptOperation` |
| `encryptQuery` | `(plaintext, { table, column, queryType?, returnType? })` — queryable columns only; `queryType` constrained to the column's capabilities | `EncryptQueryOperation` |
| `encryptQuery` | `(terms: readonly ScalarQueryTerm[])` — batch form | `BatchEncryptQueryOperation` |
| `encryptModel` | `(model, table)` — schema fields validated against inferred plaintext types | `EncryptModelOperation<V3EncryptedModel<Table, T>>` |
| `decryptModel` | `(model, table, lockContext?)` | `Promise<Result<V3DecryptedModel<Table, T>, EncryptionError>>` |
| `bulkEncryptModels` | `(models, table)` | `BulkEncryptModelsOperation<V3EncryptedModel<Table, T>>` |
| `bulkDecryptModels` | `(models, table, lockContext?)` | `Promise<Result<V3DecryptedModel<Table, T>[], EncryptionError>>` |
| `bulkEncrypt` | `(plaintexts, { column, table })` — parity passthrough | `BulkEncryptOperation` |
| `bulkDecrypt` | `(encryptedPayloads)` — parity passthrough | `BulkDecryptOperation` |
| `getEncryptConfig` | `()` | The client's encrypt config |

The encrypt-side operations are thenable (awaitable) and support `.withLockContext()` and `.audit()` chaining; `decryptModel`/`bulkDecryptModels` return plain promises and take the lock context as an argument.

### Schema Builders

```typescript
encryptedTable(tableName: string, columns: Record<string, AnyEncryptedV3Column>)
types.<Family><Suffix>(dbColumnName: string)
// e.g. types.TextSearch("email"), types.BigintOrd("balance"), types.Json("metadata")
```

## Legacy: EQL v2

Before the v3 typed schema, encrypted columns were a single composite type (`eql_v2_encrypted`) and query capabilities were enabled per column with chainable builders:

```typescript
// Legacy v2 surface — for existing deployments only
import { Encryption } from "@cipherstash/stack"
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"

const users = encryptedTable("users", {
  email: encryptedColumn("email").equality().freeTextSearch().orderAndRange(),
})

const client = await Encryption({ schemas: [users] })
```

The scalar v2 API — `Encryption` plus the `@cipherstash/stack/schema` builders, the v2 Drizzle/Supabase integrations (`@cipherstash/stack-drizzle`, `encryptedSupabase`), and `stash eql install --eql-version 2` — still exists for existing deployments. Legacy v2 `searchableJson()` is the exception: protect-ffi 0.30 cannot emit the removed selector envelope, so migrate those columns to v3 `types.Json`. Full v2 documentation lives at [cipherstash.com/docs](https://cipherstash.com/docs). Remember: v2 and v3 tables cannot be mixed in one client. (If you are migrating code from the old `@cipherstash/protect` package, its `protect`/`csTable`/`csColumn` names map onto this v2 surface.)

> **Exception — DynamoDB.** The DynamoDB integration (`encryptedDynamoDB` from `@cipherstash/stack/dynamodb`) **still requires the v2 schema surface** — `encryptedTable`/`encryptedColumn`/`encryptedField` from `@cipherstash/stack/schema`. Do not use v3 `types.*` schemas with it. See the `stash-dynamodb` skill; v3 support is tracked in [cipherstash/stack#657](https://github.com/cipherstash/stack/issues/657).

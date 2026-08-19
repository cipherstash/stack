---
name: stash-encryption
description: Implement field-level encryption with @cipherstash/stack using the EQL v3 typed schema. Covers the types.* column catalog, the generic EncryptionClient, encrypt/decrypt and model operations, searchable encryption, encrypted JSON, bulk operations, identity-aware encryption, multi-tenant keysets, and the rollout/cutover lifecycle.
---

# CipherStash Stack - Encryption

Comprehensive guide for implementing field-level encryption with `@cipherstash/stack`. Every value is encrypted with its own unique key via ZeroKMS (backed by AWS KMS). Encryption happens client-side before data leaves the application.

Encrypted columns are **EQL v3 concrete Postgres domains** (`public.eql_v3_text_search`, `public.eql_v3_integer_ord`, ...): each column's query capabilities are fixed by the domain type you pick in the schema, and the `Encryption` client (typed for an all-v3 schema set) derives precise TypeScript types from that schema — wrong-typed plaintext is a compile error, not a runtime surprise.

> EQL v2 is a **read-compatibility path only**. The v2 schema builders and the `@cipherstash/stack/client` subpath have been removed; `decrypt` / `decryptModel` still read stored v2 payloads so existing deployments keep working — see "Legacy: EQL v2" at the end. Author every schema and every new write with the v3 surface this skill describes.

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
import { Encryption } from "@cipherstash/stack"
import { encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", {
  email: types.TextSearch("email"),
})

const client = await Encryption({ schemas: [users] })

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
| `@cipherstash/stack/v3` | `Encryption`, `EncryptionClient<S>`, and the EQL v3 authoring DSL. The one-stop import for schema authoring. |
| `@cipherstash/stack/eql/v3` | `encryptedTable`, the `types` namespace, `buildEncryptConfig`, inference types (`InferPlaintext`, `InferEncrypted`, `V3ModelInput`, ...) |
| `@cipherstash/stack` | `OidcFederationStrategy`, `AccessKeyStrategy`, and the v3-only `Encryption` factory |
| `@cipherstash/stack/identity` | `LockContext` class and identity types |
| `@cipherstash/stack/errors` | `EncryptionErrorTypes`, `StackError`, error subtypes, `getErrorMessage` |
| `@cipherstash/stack/types` | All TypeScript types |
| `@cipherstash/stack-drizzle` | Drizzle ORM integration for EQL v3 schemas — the package root, EQL v3 only (see the `stash-drizzle` skill) |
| `@cipherstash/stack-supabase` | `encryptedSupabase` wrapper for Supabase — EQL v3 only (see the `stash-supabase` skill) |
| `@cipherstash/stack/wasm-inline` | The **edge** entry — Deno, Bun, Cloudflare Workers, Supabase Edge Functions. Its own `Encryption` factory plus its own copy of the v3 authoring surface, `EncryptionErrorTypes`, and the WASM build of protect-ffi inlined into the bundle. No native binding, so no bundler externalisation needed. **EQL v3 only** — `Encryption()` here rejects a v2 schema, and its operations return plain Results with no `.audit()` or `.withLockContext()` chaining, so **values written here cannot be identity-bound** and it cannot read what the native entry wrote under a lock context. **ESM-only, and its schema types do not interchange with the other entries'** — see the `stash-edge` skill. |
| `@cipherstash/stack/dynamodb` | `encryptedDynamoDB` — encrypt/write is **EQL v3 only** (`types.*`); decrypt still reads existing v2 items via `{ storedEqlVersion: 2 }`, on both the native and `wasm-inline` entries. See the `stash-dynamodb` skill |
| `@cipherstash/stack/schema` | Low-level encrypt-config types and validation helpers; it is not a schema-authoring DSL |
| `@cipherstash/stack/encryption` | The `Encryption` factory and the chainable operation classes its methods return (`EncryptOperation`, `DecryptOperation`, `EncryptQueryOperation`, `BulkEncryptModelsOperation`, …). Import these only to *name* an operation's type; author schemas and build the client from `@cipherstash/stack/v3` |
| `@cipherstash/stack/adapter-kit` | The internal seam for the **first-party** adapter packages (`@cipherstash/stack-drizzle`, `@cipherstash/stack-supabase`). Not a general-purpose public API — anything an end user needs has a dedicated subpath above. Do not import it in application code |
| `@cipherstash/stack/diagnostics` | One export, `assertNativeBindingAvailable()`, for **tooling** that needs to prove the protect-ffi native binding is installed — this is what `stash doctor` calls. Importing it forces nothing; calling it forces the platform binary to load and throws the loader's own error, naming the missing `@cipherstash/protect-ffi-<platform>-<arch>` package, if it is absent. Not part of the encryption API and not needed in application code |

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

Each factory in `types` maps 1:1 to a Postgres domain named `public.eql_v3_<name>`. The naming rule: strip the `eql_v3_` prefix and PascalCase each underscore-separated segment. So `types.TextSearch` builds a `public.eql_v3_text_search` column, `types.IntegerOrd` builds `public.eql_v3_integer_ord`, and `types.Timestamp` builds `public.eql_v3_timestamp`. **One exception:** `types.Json` builds `public.eql_v3_json_search`, not `eql_v3_json` (and its query-operand domain is `eql_v3.query_json`, not `query_json_search`).

#### The capability matrix

Picking the wrong factory is **silent at authoring time**. There is no type error and no runtime warning — the predicate you wanted simply will not run, and you find out when a query errors or returns nothing. Look your type up here before writing the column.

| SDK factory | Postgres column domain | Predicates it supports | What to index | Managed Postgres |
|---|---|---|---|---|
| `types.Text(...)` | `public.eql_v3_text` | none — storage only | — | ✅ |
| `types.TextEq(...)` | `public.eql_v3_text_eq` | `=` `<>` `IN` | `eq_term` (HMAC btree) | ✅ |
| `types.TextMatch(...)` | `public.eql_v3_text_match` | `@@` free-text `matches` only | `match_term` (bloom GIN) | ✅ |
| `types.TextOrd(...)` | `public.eql_v3_text_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `eq_term` **+** `ord_term` (two indexes) | ✅ |
| `types.TextOrdOre(...)` | `public.eql_v3_text_ord_ore` | as `TextOrd` | `eq_term` **+** `ord_term_ore` — ORE opclass, **privileged install only** | ⛔ unusable — see below |
| `types.TextSearch(...)` | `public.eql_v3_text_search` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` **and** `@@` | `eq_term` + `ord_term` + `match_term` (three) | ✅ |
| `types.Integer(...)` | `public.eql_v3_integer` | none — storage only | — | ✅ |
| `types.IntegerEq(...)` | `public.eql_v3_integer_eq` | `=` `<>` `IN` | `eq_term` (HMAC btree) | ✅ |
| `types.IntegerOrd(...)` | `public.eql_v3_integer_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` (OPE btree) — one index serves all | ✅ |
| `types.IntegerOrdOre(...)` | `public.eql_v3_integer_ord_ore` | as `IntegerOrd` | `ord_term_ore` — ORE opclass, **privileged install only** | ⛔ unusable — see below |
| `types.Smallint(...)` | `public.eql_v3_smallint` | none — storage only | — | ✅ |
| `types.SmallintEq(...)` | `public.eql_v3_smallint_eq` | `=` `<>` `IN` | `eq_term` | ✅ |
| `types.SmallintOrd(...)` | `public.eql_v3_smallint_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` | ✅ |
| `types.SmallintOrdOre(...)` | `public.eql_v3_smallint_ord_ore` | as `SmallintOrd` | `ord_term_ore` — **privileged install only** | ⛔ unusable |
| `types.Bigint(...)` | `public.eql_v3_bigint` | none — storage only | — | ✅ |
| `types.BigintEq(...)` | `public.eql_v3_bigint_eq` | `=` `<>` `IN` | `eq_term` | ✅ |
| `types.BigintOrd(...)` | `public.eql_v3_bigint_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` | ✅ |
| `types.BigintOrdOre(...)` | `public.eql_v3_bigint_ord_ore` | as `BigintOrd` | `ord_term_ore` — **privileged install only** | ⛔ unusable |
| `types.Numeric(...)` | `public.eql_v3_numeric` | none — storage only | — | ✅ |
| `types.NumericEq(...)` | `public.eql_v3_numeric_eq` | `=` `<>` `IN` | `eq_term` | ✅ |
| `types.NumericOrd(...)` | `public.eql_v3_numeric_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` | ✅ |
| `types.NumericOrdOre(...)` | `public.eql_v3_numeric_ord_ore` | as `NumericOrd` | `ord_term_ore` — **privileged install only** | ⛔ unusable |
| `types.Real(...)` | `public.eql_v3_real` | none — storage only | — | ✅ |
| `types.RealEq(...)` | `public.eql_v3_real_eq` | `=` `<>` `IN` | `eq_term` | ✅ |
| `types.RealOrd(...)` | `public.eql_v3_real_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` | ✅ |
| `types.RealOrdOre(...)` | `public.eql_v3_real_ord_ore` | as `RealOrd` | `ord_term_ore` — **privileged install only** | ⛔ unusable |
| `types.Double(...)` | `public.eql_v3_double` | **none — storage only** | — | ✅ |
| `types.DoubleEq(...)` | `public.eql_v3_double_eq` | `=` `<>` `IN` | `eq_term` | ✅ |
| `types.DoubleOrd(...)` | `public.eql_v3_double_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` | ✅ |
| `types.DoubleOrdOre(...)` | `public.eql_v3_double_ord_ore` | as `DoubleOrd` | `ord_term_ore` — **privileged install only** | ⛔ unusable |
| `types.Date(...)` | `public.eql_v3_date` | none — storage only | — | ✅ |
| `types.DateEq(...)` | `public.eql_v3_date_eq` | `=` `<>` `IN` | `eq_term` | ✅ |
| `types.DateOrd(...)` | `public.eql_v3_date_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` | ✅ |
| `types.DateOrdOre(...)` | `public.eql_v3_date_ord_ore` | as `DateOrd` | `ord_term_ore` — **privileged install only** | ⛔ unusable |
| `types.Timestamp(...)` | `public.eql_v3_timestamp` | none — storage only | — | ✅ |
| `types.TimestampEq(...)` | `public.eql_v3_timestamp_eq` | `=` `<>` `IN` | `eq_term` | ✅ |
| `types.TimestampOrd(...)` | `public.eql_v3_timestamp_ord` | `=` `<>` `<` `<=` `>` `>=` `ORDER BY` | `ord_term` | ✅ |
| `types.TimestampOrdOre(...)` | `public.eql_v3_timestamp_ord_ore` | as `TimestampOrd` | `ord_term_ore` — **privileged install only** | ⛔ unusable |
| `types.Boolean(...)` | `public.eql_v3_boolean` | none — storage only | — | ✅ |
| `types.Json(...)` | `public.eql_v3_json_search` | `@>` containment + JSONPath selectors | `to_ste_vec_query` (GIN) | ✅ |

That is the whole surface — 40 factories, no others. Three things the table is trying to make unmissable:

1. **A bare factory name is storage-only.** `types.Double` encrypts and decrypts and answers *nothing*. If you want to compare it, you wanted `types.DoubleOrd`; if you want ORE blocks specifically, `types.DoubleOrdOre`. The same holds for every family.
2. **On the numeric and temporal families, one ordering index serves everything.** Their ordering term is injective (distinct plaintexts give distinct terms), so `=` rides it — there is deliberately **no `eq_term` overload** for those domains, and adding an equality index to a `_ord` numeric column indexes a function that does not exist. Text ordering terms are *not* injective, which is why `text_ord` / `text_ord_ore` / `text_search` carry `eq_term` **as well**.
3. **`Ord` and `OrdOre` are not interchangeable.** They mint different, non-cross-comparable terms (`eql_v3.ord_term` vs `eql_v3.ord_term_ore`), so you cannot switch one for the other without re-encrypting the column.

`ORDER BY` needs the extractor form (`ORDER BY eql_v3.ord_term(col)`); the ORM integrations emit it for you. The `CREATE INDEX` statements behind the "What to index" column are in the `stash-indexing` skill, and the raw-SQL predicate forms with their `eql_v3.query_*` operand casts are in `stash-postgres`.

#### Where these objects live

Three schemas, and knowing which is which resolves most "function does not exist" errors:

| Schema | Holds | Example |
|---|---|---|
| `public` | the **column storage domains** — what you declare a column as | `public.eql_v3_double_ord` |
| `eql_v3` | the **query-operand domains** and the operator/extractor functions | `eql_v3.query_double_ord`, `eql_v3.ord_term` |
| `eql_v3_internal` | the **index-term types** and their operators | `eql_v3_internal.ore_block_256` |

So a single encrypted comparison touches all three: a `public` column, cast against an `eql_v3` query domain, comparing `eql_v3_internal` term types. That is also why the Supabase role grants cover `eql_v3` **and** `eql_v3_internal` — granting only the first leaves `anon` / `authenticated` / `service_role` unable to execute the internal term operators the public ones inline to. The `eql_v3` schemas are dropped and recreated by every install; `public` is not, which is why your column domains survive a reinstall.

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

> **`Ord` vs `OrdOre` — prefer `Ord`.** The `OrdOre` domains are backed by an ORE operator class the installer creates with `CREATE OPERATOR CLASS`, which is superuser-gated in stock PostgreSQL. Platform support varies and is **not** a blanket managed-Postgres rule: AWS RDS and Aurora allow it (their admin role clears the gate despite `rolsuper = f`); cloud-hosted Supabase is the one confirmed platform that refuses it.
>
> Where the install role cannot create the class, the bundle skips it **and adds an always-raising `eql_ore_unavailable` CHECK to every `_ord_ore` domain**, so every write to such a column fails loudly rather than producing an index that silently never engages. On those databases an `OrdOre` column is unusable, not merely unindexed — which is why the matrix marks it ⛔ rather than ⚠️.
>
> Don't guess which case you are in — ask: `stash eql preflight` predicts it before you install (the `ORE operator class` row), and `stash eql status` / `stash eql verify` report it afterwards. `Ord` is OPE-backed, binds PostgreSQL's native `bytea` btree operator class, and needs no privileges anywhere.
>
> The two flavours mint different, non-cross-comparable terms (`Ord`/`Search` extract via `eql_v3.ord_term`; `OrdOre` via `eql_v3.ord_term_ore`), so switching between them means re-encrypting the column.

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
stash eql install

# Supabase targets: add --supabase to apply role grants
stash eql install --supabase
```

EQL v3 ships one SQL bundle for every target. For Supabase, pass `--supabase` to apply grants on `eql_v3` and `eql_v3_internal`. For a Drizzle migration, use `stash eql migration --drizzle`; the old v2 install flags were removed.

In migrations, declare each encrypted column as its domain type:

```sql
CREATE TABLE users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email public.eql_v3_text_search,
  last_login public.eql_v3_timestamp_ord,
  balance public.eql_v3_bigint_ord
);
```

## Client Initialization: `Encryption`

`Encryption` from `@cipherstash/stack` accepts concrete EQL v3 tables and returns `EncryptionClient<S>`, whose method signatures are derived from those schemas. Wrong-typed plaintext is rejected at compile time, and query methods only accept queryable columns with `queryType` constrained to the column's capabilities:

```typescript
import { Encryption } from "@cipherstash/stack"
import { encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", {
  email: types.TextSearch("email"),
  lastLogin: types.TimestampOrd("last_login"),
  balance: types.BigintEq("balance"),
})

const client = await Encryption({ schemas: [users] })
```

- The wire format is always EQL v3; `config.eqlVersion` does not exist.
- `Encryption()` throws on init error (bad credentials, missing config, invalid keyset UUID). At least one schema is required.
- A loose object or legacy v2 table is rejected at runtime as well as by TypeScript.
- `schemas` takes any non-empty array of v3 tables — a shared `export const schemas: AnyV3Table[]`, a `ReadonlyArray`, one built at runtime. It does not have to be an array literal. Writing `Encryption({ schemas: [] })` is a compile error, but an array typed `AnyV3Table[]` that is empty at runtime compiles and throws on init instead.
- **To name the client's type, use `EncryptionClient<S>`** from `@cipherstash/stack/v3`:

```typescript
import { type AnyV3Table, Encryption, type EncryptionClient, encryptedTable, types } from "@cipherstash/stack/v3"

const users = encryptedTable("users", { email: types.TextSearch("email") })

// A named schema tuple keeps per-column typing.
let client: EncryptionClient<readonly [typeof users]>
client = await Encryption({ schemas: [users] })

// Code that is generic over its schemas keeps the typed surface too.
function withClient(c: EncryptionClient<readonly AnyV3Table[]>) { /* … */ }
```

```typescript
// Error handling
try {
  const client = await Encryption({ schemas: [users] })
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

`decrypt` of a single value cannot be strongly typed — TypeScript cannot know which column a runtime payload came from, so the result is the whole plaintext union. All plaintext values passed to `encrypt` must be non-null; null handling is managed at the model level by `encryptModel` and `decryptModel`.

> **`decrypt` / `bulkDecrypt` hand back date columns as strings, not `Date`.** Reconstruction is driven by the table's `cast_as`, and only the model path is given a table — so the same stored value comes back as a `Date` from `decryptModel(row, table)` and as its stored ISO string from `decrypt(payload)`. Nothing warns: the raw path's declared type is the plaintext union, which includes `string`. Comparing two ISO strings orders correctly, so this survives review and breaks later on `.getTime()` or date arithmetic. Use the model helpers when you want the column's declared plaintext type, or rebuild at the call site (`new Date(value)`). Same on the WASM entry, and same for the one-arg `decryptModel(row)` / `bulkDecryptModels(rows)` forms, which take no table.

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

- `decryptModel` / `bulkDecryptModels` take the **table as a second argument** and return a chainable `AuditableDecryptModelOperation` — await it for the `Result`, or chain `.audit({ metadata })` / `.withLockContext(lockContext)` first. A lock context may instead be passed as the optional third argument; use one form or the other, not both (chaining `.withLockContext()` onto a decrypt that already took a positional lock context throws).
- `Date` columns are reconstructed to real `Date` instances by `decryptModel(row, table)` / `bulkDecryptModels(rows, table)` — the table-taking forms, and only those (see the raw-path note above); `bigint` columns round-trip as native `bigint` on every path. A stored value that does **not** parse as a date (a legacy non-ISO string, say) is handed back unchanged rather than as an `Invalid Date`, even though the declared type is `Date` — guard with `instanceof Date` before calling `Date` methods on a column whose stored values you don't control.
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

These two work on raw value arrays rather than models. `bulkEncrypt` is typed like `encrypt` — `{ table, column }` pins every `plaintext` to that column's domain — while `bulkDecrypt` takes the payloads alone, so it resolves to the plaintext union and does **no `Date` reconstruction**: a `types.Timestamp` column read this way is the stored ISO string, where `bulkDecryptModels(rows, table)` gives you a `Date`:

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

**On the WASM entry (`@cipherstash/stack/wasm-inline`), the batch shape differs** — do not copy the shape above onto the edge. The `{ data } | { failure }` Result is the same, but there are no `{ id, plaintext }` envelopes: each entry carries its own table and column, and the payload is a plain index-aligned array.

> [!IMPORTANT]
> The `client` below is a **different client** from the one used everywhere else in this skill. The edge entry has its own `Encryption` factory — the native `Encryption` client's `bulkEncrypt` takes `(plaintexts, { table, column })` and will fail at runtime if given the per-item shape below. Construct the WASM client explicitly:

> [!IMPORTANT]
> **The schema is not shareable between entries either.** Note that `encryptedTable` and `types` are imported *from the WASM entry* below, not from `@cipherstash/stack/eql/v3`. The entries ship independent type bundles whose column classes carry private fields, so TypeScript compares them **nominally**: a schema authored on one entry is rejected by the other's client, in both directions (`Types have separate declarations of a private property 'columnName'`). It works at runtime, which makes `as any` the tempting fix — don't. Author the shared schema module against exactly one entry and build that entry's client from it. See the `stash-edge` skill.

```typescript
// Deno / Workers / Supabase Edge Functions — note the import path
import { Encryption, encryptedTable, types } from "@cipherstash/stack/wasm-inline"

const users = encryptedTable("users", { email: types.TextEq("email") })

const client = await Encryption({
  schemas: [users],
  config: {
    workspaceCrn: Deno.env.get("CS_WORKSPACE_CRN")!,
    accessKey: Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
    clientId: Deno.env.get("CS_CLIENT_ID")!,
    clientKey: Deno.env.get("CS_CLIENT_KEY")!,
  },
})
```

```typescript
const encrypted = await client.bulkEncrypt([
  { plaintext: "alice@example.com", table: users, column: users.email },
  { plaintext: "hello", table: users, column: users.bio },
])
if (encrypted.failure) throw new Error(encrypted.failure.message)
// encrypted.data = [EncryptedPayload, EncryptedPayload] — same order as the input

const decrypted = await client.bulkDecrypt(rows.map((r) => r.email))
if (decrypted.failure) throw new Error(decrypted.failure.message)
// one ZeroKMS round trip for the whole list, not one per row
```

`null` / `undefined` entries yield `null` at the same index without reaching ZeroKMS. Because each entry names its own column, one call can cover several columns across many rows. When items fail to decrypt, `failure.message` names every failing index.

**The model helpers are available on the WASM entry too**: `encryptModel(model, table)`, `decryptModel(model, table)`, `bulkEncryptModels(models, table)`, `bulkDecryptModels(models, table)`. They run the same schema walk as the native client — declared columns are encrypted (matched by **JS property name**; nested fields via the column's dotted path), everything else passes through, `null`/`undefined` fields are preserved without reaching ZeroKMS, and the caller's model is never mutated — and a call that touches at least one field is **one ZeroKMS round trip** no matter how many fields or models it covers (an empty batch, or one whose models carry no schema fields, is short-circuited and makes **zero** calls). `table` must be one the client was built with (`Encryption({ schemas })`), else the call fails, as on the native client. `types.Date` / `types.Timestamp` columns round-trip `Date` → `Date` (on the wire they travel as ISO strings); because matching is by JS property name, a row keyed by raw DB column names (e.g. a raw `SELECT` returning `created_on`) still decrypts, but its date fields come back as ISO strings — key your models by the schema's property names. Differences from the native typed client: every method returns a plain `Promise` of the `{ data } | { failure }` Result (no `.audit()` chaining), and there is **no lock-context argument** — a known gap ([#797](https://github.com/cipherstash/stack/issues/797)), not a different mechanism. `config.authStrategy` decides *who the client is*; it does not bind values to the user (a lock context gates retrieval of a value's data key by a claim — `stash-auth` is canonical). Values written on the edge therefore carry no identity condition, and the edge cannot read values the native entry wrote under a lock context. Decrypt failures name every failing field: `bulkDecryptModels` prefixes the model index (`[model 1] profile.ssn`), `decryptModel` names the field alone (`profile.ssn`).

```typescript
const row = await client.encryptModel({ id: 1, email: "alice@example.com" }, users)
if (row.failure) throw new Error(row.failure.message)
// row.data = { id: 1, email: <EQL envelope> } — only schema columns encrypted

const back = await client.bulkDecryptModels(encryptedRows, users)
if (back.failure) throw new Error(back.failure.message)
// back.data = plaintext models, index-aligned with the input
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

Scalar filters compare through each domain's `eql_v3.*` operators (`col = term`, `col > term`, ...), and `ORDER BY` on an encrypted column goes through the ordering extractors — `eql_v3.ord_term(col)` for OPE-backed (`Ord`/`Search`) domains, `eql_v3.ord_term_ore(col)` for `OrdOre`. The Drizzle v3 integration emits all of this for you (including `asc`/`desc`, which emit `ORDER BY eql_v3.ord_term(col)`). Over Supabase/PostgREST, the adapter's `order()` works on OPE-backed ordering columns (plain `*_ord`, `text_ord`, `text_search`) by sorting on the column's `col->op` term; `OrdOre`-flavour (`*_ord_ore`) domains and columns with no ordering term are rejected. See the `stash-drizzle` and `stash-supabase` skills. These same extractor expressions are also what you index — the functional-index recipes are in the `stash-indexing` skill. Writing the SQL by hand instead (no ORM, `pg` / `postgres-js`)? The predicate matrix, the `eql_v3.query_*` operand casts, and the per-driver parameter-binding rules are in the `stash-postgres` skill; running on Deno / Workers / Supabase Edge Functions, the `stash-edge` skill.

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

The client authenticates to ZeroKMS through `config.authStrategy` (`stash-auth` is the canonical skill for credentials, strategies, and failure codes). Leave it unset for the default **auto** strategy: in local development, authenticate once with `npx stash auth login` (preferred — no credentials in your environment; `npx stash init` is the agent-assisted flow that also sets up schema and database); in CI/production, set the `CS_*` environment variables. Two explicit strategies cover the other cases:

- **`AccessKeyStrategy`** — service-to-service / CI. Authenticates a *service* with a CipherStash access key.
- **`OidcFederationStrategy`** — authenticates the client **as the end user** by federating a third-party OIDC JWT (Clerk, Supabase, Auth0, Okta, ...) into a CipherStash service token:

```typescript
import { OidcFederationStrategy } from "@cipherstash/stack"
import { Encryption } from "@cipherstash/stack"
import { encryptedTable, types } from "@cipherstash/stack/v3"

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

const client = await Encryption({
  schemas: [users],
  config: { authStrategy: strategy.data },
})
```

`OidcFederationStrategy.create()` returns a `Result` — **unwrap it**. Passing the envelope straight to `authStrategy` gives the FFI an object with no `getToken()` at all.

Authentication stands on its own — an OIDC-authenticated client encrypts and decrypts normally. Binding *data* to the authenticated user is a separate, optional step: the lock context, below.

## Identity-Aware Encryption (Lock Contexts)

Bind a data key to a claim from the end user's JWT, so only that user can decrypt — the claim is bound to the key at encrypt time, and ZeroKMS releases the key only to a caller presenting the same claim (`stash-auth` is the canonical skill for this model). Chain `.withLockContext({ identityClaim })` on any operation:

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

Lock contexts work with every operation: `encrypt`, `decrypt`, `encryptModel`, `decryptModel`, `bulkEncrypt`, `bulkDecrypt`, `bulkEncryptModels`, `bulkDecryptModels`, `encryptQuery`. On the typed client, `decryptModel` and `bulkDecryptModels` additionally accept the lock context as an optional **third argument**, which is the form shown here — `.withLockContext()` chains on them too, but use one or the other, not both:

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

Each keyset provides full cryptographic isolation between tenants. Encrypt
and query always use the client's bound keyset (one `Encryption()` client
per tenant); decrypt follows each payload's own keyset, subject to grants.
Omitting `config.keyset` resolves to the *client's* default keyset. The
`stash-zerokms` skill is canonical for keysets, clients, grants, and the
failure modes.

## Operation Chaining

Encrypt operations return thenable objects that support chaining:

```typescript
const result = await client
  .encrypt(plaintext, { column: users.email, table: users })
  .withLockContext(lockContext)         // optional: identity-aware
  .audit({ metadata: { action: "create" } }) // optional: audit trail
```

(The typed client's `decryptModel` / `bulkDecryptModels` may also take the lock context as a positional argument instead of chaining — see "Model Operations".)

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

> **EQL version note.** Rollout mutation tooling is EQL v3 only. It requires a `public.eql_v3_*` destination domain; legacy v2 columns remain readable and visible in status/history diagnostics but cannot be installed, backfilled, cut over, or dropped through `stash`.

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
| Switch schema/query references | Leave `<col>_encrypted` under its own name and point the schema and queries at it. EQL v3 has no rename cut-over. |
| Wire reads through the encryption client | Read paths must decrypt before returning the value to callers (`decryptModel(row, table)` for Drizzle; the Supabase wrapper for Supabase; `decrypt`/`bulkDecryptModels` otherwise). Without this step, reads return raw EQL payloads to end users (a `public.eql_v3_*` jsonb document on v3; an `eql_v2_encrypted` composite on a legacy v2 column). |
| Remove dual-write code | Delete dual-write logic once reads are served from the encrypted column. |
| `stash encrypt drop` | Emits a migration that drops the original plaintext `<col>`. The generated SQL locks the table, re-checks coverage at apply time, and raises instead of dropping if plaintext-only rows remain. |

**Create functional indexes between backfill and the read switch.** Build the `eql_v3.*` extractor indexes for every queried capability and run `ANALYZE`.

### State storage

Two current sources of truth, kept separate on purpose:

- **`.cipherstash/migrations.json`** (repo) — *intent*. Which columns the developer wants to encrypt and at which phase, code-reviewable.
- **`cipherstash.cs_migrations`** (DB, CipherStash-managed) — *runtime state*. Append-only event log: phase transitions, backfill cursors, error rows. Latest row per `(table, column)` is the current state.

`stash encrypt status` shows all three side-by-side and flags drift (e.g. EQL says registered, the physical `<col>_encrypted` column is missing). `stash status` (the quest log) rolls them up into the per-column "what's the next move" view used during a rollout.

> **Note on internal phase names.** Current runs use `schema-added → dual-writing → backfilling → backfilled → dropped`. Readers still accept legacy `cut-over` rows so old history remains displayable.

### CLI sequence for a single column

#### EQL v3 (the default)

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

# Create the `eql_v3.*` extractor indexes for every queried capability
# and ANALYZE the table, via your normal migration tooling. Do this
# after backfill and before reads move over. Recipes: `stash-indexing`.

# Point the application at the encrypted column BY NAME —
# `email_encrypted`. There is no rename command. Wire the read paths through
# the encryption client so they
# decrypt, deploy, and verify reads return plaintext.

# Then remove the dual-write code and drop the plaintext column.
# The generated migration re-checks coverage under a lock at apply
# time and refuses to drop if any plaintext-only row remains:
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

Useful when the backfill needs to run in a worker, on a schedule, or alongside an existing job runner. `runBackfill` is version-agnostic — for an EQL v3 column pass an `Encryption` client built from a v3 schema set and it writes v3 envelopes straight into the concrete `eql_v3_*` domain column.

### Invariants the rollout preserves

- **Reads never return the wrong value.** Before the application switch, reads come from the plaintext column. After the switch, queries target the encrypted column by name and decrypt through the integration/client.
- **Writes never drop.** Dual-writing keeps both columns in sync until the application switches to the encrypted column.
- **The deploy gate is a one-way door for production.** Backfill against rows the dual-write code never saw produces silent drift. The CLI refuses to run cutover-step plans without a `dual_writing` event recorded; do not paper over that refusal.
- **Re-runs are safe.** Backfill is idempotent (`<col> IS NOT NULL AND <col>_encrypted IS NULL` guards every chunk). `cs_migrations` is append-only.
- **Rollback is possible until plaintext is dropped.** Before the final drop, aborting leaves the original plaintext column intact; after the drop, recovery requires a restore.

## Integrations

| Target | Package / entry point | Skill |
|---|---|---|
| Drizzle ORM | `@cipherstash/stack-drizzle` — v3 column factories (each `types.*` factory emits its domain as the column's SQL type for `drizzle-kit generate`), schema extraction, auto-encrypting operators (`ops.eq`, `ops.matches`, `ops.contains`, `ops.selector`, `ops.asc`, ...) | `stash-drizzle` |
| Supabase | `encryptedSupabase` from `@cipherstash/stack-supabase` — schema-aware query builder (`eq`, `matches`, `contains`, `selectorEq`/`selectorNe`, ...) that works through PostgREST, including as `anon` | `stash-supabase` |
| Prisma | `@cipherstash/stack-prisma` — searchable field-level encryption for Postgres | — |
| DynamoDB | `encryptedDynamoDB` from `@cipherstash/stack/dynamodb` — encrypt is **EQL v3 only**; decrypt still reads existing v2 items | `stash-dynamodb` |

## Complete API Reference

### EncryptionClient Methods

| Method | Signature | Returns |
|---|---|---|
| `encrypt` | `(plaintext, { table, column })` — plaintext pinned to the column's domain type | `EncryptOperation` |
| `decrypt` | `(encryptedData)` — untyped (the column is not known statically); no `Date` reconstruction | `DecryptOperation` |
| `encryptQuery` | `(plaintext, { table, column, queryType?, returnType? })` — queryable columns only; `queryType` constrained to the column's capabilities | `EncryptQueryOperation` |
| `encryptQuery` | `(terms: readonly ScalarQueryTerm[])` — batch form | `BatchEncryptQueryOperation` |
| `encryptModel` | `(model, table)` — schema fields validated against inferred plaintext types | `EncryptModelOperation<V3EncryptedModel<Table, T>>` |
| `decryptModel` | `(model, table, lockContext?)` | `AuditableDecryptModelOperation<V3DecryptedModel<Table, T>>` |
| `bulkEncryptModels` | `(models, table)` | `BulkEncryptModelsOperation<V3EncryptedModel<Table, T>>` |
| `bulkDecryptModels` | `(models, table, lockContext?)` | `AuditableDecryptModelOperation<V3DecryptedModel<Table, T>[]>` |
| `bulkEncrypt` | `(plaintexts, { column, table })` — raw values, each `plaintext` pinned to the column's domain type | `BulkEncryptOperation` |
| `bulkDecrypt` | `(encryptedPayloads)` — parity passthrough; no `Date` reconstruction | `BulkDecryptOperation` |
| `getEncryptConfig` | `()` | The client's encrypt config (the protect-ffi view: `cast_as` + index kinds, **no domain names**) |
| `getSchemas` | `()` | The tables passed to `Encryption({ schemas })`, by reference |

All of these operations are thenable (awaitable) and support `.withLockContext()` and `.audit()` chaining — including `decryptModel`/`bulkDecryptModels`, which also accept the lock context as a third argument. Use one or the other: chaining `.withLockContext()` onto a decrypt that already took a positional lock context throws.

`getSchemas()` is the domain-bearing view of the schema, and the reason it exists alongside `getEncryptConfig()`. The encrypt config is what the FFI consumes: a column builds to `{ cast_as, indexes }`, and the concrete domain name is dropped — so `cast_as: 'number'` with an `ope` index is ambiguous across `eql_v3_integer_ord`, `smallint_ord`, `real_ord`, `double_ord` and `numeric_ord`. Anything reasoning about the *declared* domain reads the tables instead. `stash eql validate` is the built-in consumer; the same accessor lets your own tooling do it:

```typescript
for (const table of client.getSchemas()) {
  for (const column of Object.values(table.columnBuilders)) {
    console.log(table.tableName, column.getName(), column.getEqlType())
    // users email public.eql_v3_text_search
  }
}
```

Per column: `getName()` is the **DB** column name (not the JS property), `getEqlType()` the concrete domain, `getQueryCapabilities()` the `{ equality, orderAndRange, freeTextSearch, searchableJson? }` flags, and `isQueryable()` whether it carries any query term at all.

### Schema Builders

```typescript
encryptedTable(tableName: string, columns: Record<string, AnyEncryptedV3Column>)
types.<Family><Suffix>(dbColumnName: string)
// e.g. types.TextSearch("email"), types.BigintOrd("balance"), types.Json("metadata")
```

## Legacy: EQL v2

EQL v2 is a read-compatibility path, not a public authoring mode. The native
client's `decrypt`, `decryptModel`, `bulkDecrypt`, and `bulkDecryptModels`
recognise stored v2 payloads automatically; no v2 schema or `eqlVersion` flag is
required. The v2 builders and the `@cipherstash/stack/client` subpath have been
removed. Author every schema and every new write with EQL v3.

**v2 is a read path now, not an authoring or rollout surface.** `decrypt` / `decryptModel` still read stored v2 payloads, but `stash` no longer installs EQL v2 or drives its Proxy configuration, backfill, rename, or drop lifecycle. For dump recovery, obtain the EQL 2.3.1 SQL from the upstream encrypt-query-language release. Migrate maintained deployments to v3 `types.*` domains.

> **DynamoDB.** The DynamoDB integration (`encryptedDynamoDB` from `@cipherstash/stack/dynamodb`) **encrypts EQL v3 only** — author tables with `types.*` from `@cipherstash/stack/eql/v3`. Legacy reads use the same v3 table descriptor plus an explicit `{ storedEqlVersion: 2 }` read option, so previously stored v2 items remain readable. See the `stash-dynamodb` skill.

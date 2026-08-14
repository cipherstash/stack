---
name: stash-prisma
description: Integrate CipherStash searchable field-level encryption with Prisma Next using @cipherstash/stack-prisma (EQL v3). Covers the full 31-constructor catalog of domain-named encrypted column types in schema.prisma (per plaintext type × capability tier — Text/TextEq/TextOrd/TextMatch/TextSearch, Integer/Smallint/BigInt/Numeric/Real/Double × Eq/Ord, Date/Timestamp × Eq/Ord, Boolean, Json), the one-call cipherstashFromStack wiring, the runtime value envelopes (EncryptedString/Number/BigInt/Date/Boolean/Json) and decryptAll, the eql* query operators (eqlEq, eqlMatch, eqlGt, eqlBetween, eqlIn, eqlJsonContains, eqlAsc/eqlDesc, eqlJsonPathAsc/eqlJsonPathDesc), EQL bundle installation via prisma-next migrate, and authentication. Use when adding encryption to a Prisma Next project, choosing a column type, or querying encrypted columns.
---

# CipherStash Stack — Prisma Next Integration

Guide for searchable field-level encryption in a **Prisma Next** app with
`@cipherstash/stack-prisma` (EQL v3), powered by `@cipherstash/stack`. You declare
encrypted columns directly in `schema.prisma`; Prisma Next's migration system
installs the EQL bundle in the same sweep that creates your tables — there is no
separate `stash eql install` step.

> `@cipherstash/stack-prisma` is **EQL v3 only** — there is no EQL v2 surface.
> Everything below is v3.

In EQL v3 every encrypted column is a **concrete Postgres domain**
(`public.eql_v3_text_search`, `public.eql_v3_double_ord`, …) whose query
capabilities are fixed by the column type you choose — there is no capability
config object. See the `stash-encryption` skill for the domain catalog and
capability semantics; this skill covers the Prisma-Next-specific surface.

## When to Use This Skill

- Adding field-level encryption to a Prisma Next project
- Declaring encrypted columns in `schema.prisma`
- Querying encrypted columns with the `eql*` operators
- Wiring the runtime with `cipherstashFromStack`

## Installation

```bash
npm install @cipherstash/stack @cipherstash/stack-prisma
```

Or run `npx stash init --prisma`, which detects Prisma Next, installs both
packages pinned to the CLI release, and authenticates. It does **not** scaffold
the wiring files — Prisma Next derives its schema from `contract.json`, so there
is no encryption-client file to generate; init prints the next steps (declare
encrypted columns, emit the contract, run the migration) instead.

## The three wiring points

### 1. Declare encrypted columns in `schema.prisma`

The column types are **domain-named** — the name encodes the query capability
(matching the `@cipherstash/stack` `types.*` catalog), not a generic primitive:

```prisma
model User {
  id            String @id
  email         cipherstash.TextSearch()  // eq + range + free-text + ORDER BY
  salary        cipherstash.DoubleOrd()   // eq + range + ORDER BY
  accountId     cipherstash.BigIntOrd()   // eq + range + ORDER BY
  birthday      cipherstash.DateOrd()     // eq + range + ORDER BY
  emailVerified cipherstash.Boolean()     // storage-only (no operators)
  preferences   cipherstash.Json()        // containment (@>)
}
```

The example shows six types; the **full catalog is 31 constructors** — one
per exposed `public.eql_v3_*` domain, derived mechanically from the domain
registry. Pick by **plaintext TypeScript type first**, then by the queries
you need:

| Plaintext (TS type) | Storage-only | Equality | Order + range | Free-text | Everything |
|---|---|---|---|---|---|
| `string` | `Text()` | `TextEq()` | `TextOrd()` | `TextMatch()` | `TextSearch()` |
| `number` (int4) | `Integer()` | `IntegerEq()` | `IntegerOrd()` | — | — |
| `number` (int2) | `Smallint()` | `SmallintEq()` | `SmallintOrd()` | — | — |
| `bigint` (int8) | `BigInt()` | `BigIntEq()` | `BigIntOrd()` | — | — |
| `number` (numeric) | `Numeric()` | `NumericEq()` | `NumericOrd()` | — | — |
| `number` (float4) | `Real()` | `RealEq()` | `RealOrd()` | — | — |
| `number` (float8) | `Double()` | `DoubleEq()` | `DoubleOrd()` | — | — |
| `Date` (date) | `Date()` | `DateEq()` | `DateOrd()` | — | — |
| `Date` (timestamp) | `Timestamp()` | `TimestampEq()` | `TimestampOrd()` | — | — |
| `boolean` | `Boolean()` | — | — | — | — |
| JSON document | `Json()` — searchable JSON: containment + JSONPath equality/range/ORDER BY | | | | |

Reading the table:

- Each constructor maps 1:1 to the domain named after it:
  `IntegerOrd()` → `eql_v3_integer_ord`, `Text()` → `eql_v3_text`, and so on
  (`Json()` → `eql_v3_json_search`).
- **Every `*Ord` domain includes equality** (equality + range + ORDER BY);
  every `*Eq` domain is equality only; the bare family name is storage-only
  (encrypt/decrypt, no operators). `TextMatch` is free-text **only** — no
  equality. `TextSearch` carries all three text capabilities.
- **The plaintext type matters as much as the capability.** Money stored as
  integer cents wants `IntegerOrd()` (JS `number`) — not `DoubleOrd()`
  (float semantics) and not `BigIntOrd()`, whose plaintext is a JS `bigint`
  and rejects `number` values.
- The `*OrdOre` variants exist in the database bundle but are deliberately
  not exposed as constructors (their btree opclass is superuser-gated — see
  `stash-indexing`).

The type is fixed at the column — there is no capability tuner. A value you
only store and decrypt can use a storage-only domain; a value you filter or
sort needs the matching `*Eq` / `*Ord` / text-search domain.

### 2. Register the extension pack in `prisma-next.config.ts`

Since Prisma Next 0.17 an application depends on exactly one database facade
(`@prisma/orm-postgres`; the retired `@prisma-next/*` scope no longer
publishes), and the facade's `defineConfig` wires the family, target, adapter,
driver, and PSL provider internally:

```typescript
import cipherstash from '@cipherstash/stack-prisma/control'
import { defineConfig } from '@prisma/orm-postgres/config'

export default defineConfig({
  contract: './prisma/schema.prisma',
  output: 'src/prisma',
  extensions: [cipherstash],
  db: { connection: process.env['DATABASE_URL']! },
})
```

The config key is `extensions` (0.17 renamed `extensionPacks`; the old key
fails loudly).

### 3. Wire the runtime with `cipherstashFromStack` in `src/db.ts`

```typescript
import 'dotenv/config'
import { cipherstashFromStack } from '@cipherstash/stack-prisma/v3'
import postgres from '@prisma/orm-postgres/runtime'
import type { Contract } from './prisma/contract.d'
import contractJson from './prisma/contract.json' with { type: 'json' }

const cipherstash = await cipherstashFromStack({ contractJson })

export const db = postgres<Contract>({
  contractJson,
  extensions: cipherstash.extensions,
  middleware: cipherstash.middleware,
})
```

`cipherstashFromStack({ contractJson })` derives the v3 encryption schemas from
the contract (one `public.eql_v3_*` domain per column), constructs the
`@cipherstash/stack` `Encryption` client from your `CS_*` env vars or local
profile, builds the SDK adapter, and returns ready-to-spread `extensions` and
`middleware`.

## Install the EQL bundle (part of your migration, not a separate step)

The extension pack contributes its own contract space at
`migrations/cipherstash/`, so the EQL bundle installs alongside your application
schema:

```bash
npx stash auth login                 # one-time, per developer
npx prisma-next contract emit
npx prisma-next migration plan --name initial
npx prisma-next migrate              # installs EQL bundle + your schema
```

The apply command is the top-level `prisma-next migrate` (add `--yes` to skip the
confirmation prompt in CI). There is no `prisma-next migration apply` subcommand.

Do **not** run `stash eql install` for a Prisma Next project — `prisma-next
migrate` owns EQL installation, and `stash init --prisma` skips the
standalone installer for exactly this reason. The CLI enforces this: `stash eql
install` detects a Prisma Next project and refuses (pointing you at `prisma-next
migrate`) unless you pass `--force`.

## Encrypting data that already exists (`stash encrypt`)

Declaring an encrypted column only covers new writes. To encrypt rows already in
a plaintext column, use the CLI's rollout lifecycle — `stash encrypt backfill`,
then switch reads, then `stash encrypt drop` (`stash-cli` and `stash-encryption`
are canonical for the sequence and its dual-write precondition).

Two things are Prisma-Next-specific:

- **No encryption client file is needed.** `stash.config.ts`'s `client` option
  points at a file this integration deliberately doesn't have. `stash encrypt
  backfill` — the only command that loads it — detects a Prisma Next project,
  reads the emitted `contract.json` (`src/prisma/`, `prisma/`, or the project
  root), and derives the schemas the same way the runtime does. So run
  `prisma-next contract emit` before `stash encrypt backfill`, and don't
  hand-author a bridge client file.
- **The tracking schema is created for you.** `cipherstash.cs_migrations` is
  normally created by `stash eql install`, which this integration never runs.
  `stash encrypt backfill` bootstraps it itself (idempotently), so the backfill
  user needs CREATE on the database the first time.

## Indexing encrypted columns

The adapter emits the encrypted query operators, but **no index DDL** — without
functional indexes over the `eql_v3.*` extractors, every encrypted predicate
sequential-scans. Since Prisma Next 0.17, `@@index` takes an `expression`
argument, so the indexes are declared in `schema.prisma` next to the columns
they serve and ride the same `prisma-next migration plan` / `prisma-next
migrate` flow as everything else. Never run index DDL out-of-band.

One index per capability the column's domain carries:

```prisma
model User {
  // ... fields, including the encrypted columns ...

  // cipherstash.TextEq / TextSearch: equality
  @@index(expression: "eql_v3.eq_term(email)", name: "users_email_eq", type: "btree")
  // cipherstash.*Ord / TextSearch: ordering + range (on numeric/date/timestamp
  // _ord domains this one index serves = too; TextOrd needs the eq_term index
  // above as well)
  @@index(expression: "eql_v3.ord_term(created_at)", name: "users_created_at_ord", type: "btree")
  // cipherstash.TextMatch / TextSearch: free-text match
  @@index(expression: "eql_v3.match_term(bio)", name: "users_bio_match", type: "gin")
  // cipherstash.Json: containment
  @@index(expression: "(eql_v3.to_ste_vec_query(profile)::jsonb) jsonb_path_ops", name: "users_profile_json", type: "gin")
}
```

Three rules the interpreter enforces: an `@@index` takes exactly one of a
fields list or an `expression`; an expression index **requires `name` or
`map`** (no default name can be derived from an expression); and an `options`
argument requires `type`. The expression string is the entire element list
between the parens of `CREATE INDEX`, inserted verbatim — which is why the
Json recipe carries its own parens and the `jsonb_path_ops` opclass. TS-authored
contracts have the same surface: `index({ expression, name, type })` alongside
the column factories.

`ANALYZE` is still part of the recipe — an expression index has no statistics
until it runs, and PSL cannot express it — so it rides a raw-SQL operation
(`rawSql` from `@prisma/orm-postgres/migration`) in the migration that
introduces the indexes:

```typescript
rawSql({
  id: 'analyze.users',
  label: 'Refresh statistics for the new expression indexes',
  operationClass: 'additive',
  target: {
    id: 'postgres',
    details: { schema: 'public', objectType: 'table', name: 'users' },
  },
  precheck: [],
  execute: [{ description: 'refresh statistics', sql: 'ANALYZE "public"."users"' }],
  postcheck: [],
})
```

(`rawSql` also remains the fallback for index DDL itself if you need something
PSL doesn't carry — `CREATE INDEX CONCURRENTLY`, for instance.)

Everything above works as a non-superuser role (Supabase included); only the
ORE-flavour (`_ord_ore`) ordering opclass is superuser-gated. For the full
model — which domains take which index, engagement rules, `EXPLAIN`
verification, rollout timing — see the `stash-indexing` skill. For encrypted
predicates written as raw SQL rather than through the `cipherstash:*`
operators — operand casts to `eql_v3.query_*`, per-driver parameter binding —
see the `stash-postgres` skill.

## Writing and reading encrypted values

At the value boundary you wrap plaintext in a **runtime envelope** (primitive-named,
distinct from the domain-named column type) and unwrap with `decryptAll` +
`.decrypt()`:

```typescript
import {
  decryptAll,
  EncryptedString, EncryptedNumber, EncryptedBigInt,
  EncryptedDate, EncryptedBoolean, EncryptedJson,
} from '@cipherstash/stack-prisma/runtime'

await db.orm.public.User.create({
  id: 'user-0',
  email: EncryptedString.from('alice@example.com'),
  salary: EncryptedNumber.from(100_000),      // DoubleOrd column
  accountId: EncryptedBigInt.from(100_000_000_001n),
  birthday: EncryptedDate.from(new Date('1990-01-01')),
  emailVerified: EncryptedBoolean.from(true),
  preferences: EncryptedJson.from({ theme: 'dark' }),
})

const rows = await db.orm.public.User.where((u) => u.email.eqlEq('alice@example.com')).all()
await decryptAll(rows)                          // batches one SDK round-trip per (table,column)
console.log(await rows[0]?.email.decrypt())     // 'alice@example.com'
```

Envelopes pair by **plaintext type**, not by column name — one envelope
covers every domain of its family: `EncryptedString` ↔ all `Text*` columns,
`EncryptedNumber` ↔ all `number` families (`Integer*`, `Smallint*`,
`Numeric*`, `Real*`, `Double*`), `EncryptedBigInt` ↔ `BigInt*`,
`EncryptedDate` ↔ `Date*` and `Timestamp*`, `EncryptedBoolean` ↔ `Boolean`,
`EncryptedJson` ↔ `Json`.

## Query operators (`eql*`)

Operators live on the encrypted column inside `.where((u) => …)` and encrypt the
search term for you — Prisma Next never sees plaintext in a query. EQL v3 uses the
EQL-derived `eql*` vocabulary:

| Operator | Meaning | Requires |
|---|---|---|
| `eqlEq(v)` / `eqlNeq(v)` | equality / inequality | any searchable domain |
| `eqlIn(vs)` / `eqlNotIn(vs)` | membership | any searchable domain |
| `eqlMatch(term)` | free-text token match (`eql_v3.matches`) | `TextSearch` |
| `eqlGt/eqlGte/eqlLt/eqlLte(v)` | range comparison | an `*Ord` domain |
| `eqlBetween(lo,hi)` / `eqlNotBetween(lo,hi)` | range window | an `*Ord` domain |
| `eqlAsc(col)` / `eqlDesc(col)` | ORDER BY (free functions, take the column) | an `*Ord` or `TextSearch` domain |
| `eqlJsonContains(obj)` | encrypted JSON containment (`@>`) | `EncryptedJson` |
| `eqlJsonPathEq/Neq(path,v)` | exact value equality/inequality at a JSONPath | `EncryptedJson` |
| `eqlJsonPathGt/Gte/Lt/Lte(path,v)` | string/number ordering at a JSONPath | `EncryptedJson` |
| `eqlJsonPathAsc(col,path)` / `eqlJsonPathDesc(col,path)` | ORDER BY a scalar JSONPath leaf (free functions) | `EncryptedJson` |

```typescript
// range
await db.orm.public.User.where((u) => u.salary.eqlGt(100_000)).all()
// free-text
await db.orm.public.User.where((u) => u.email.eqlMatch('example.com')).all()
// between
await db.orm.public.User.where((u) => u.birthday.eqlBetween(lo, hi)).all()
// bigint membership
await db.orm.public.User.where((u) => u.accountId.eqlIn([100_000_000_001n])).all()
// encrypted JSON containment
await db.orm.public.User.where((u) => u.preferences.eqlJsonContains({ theme: 'dark' })).all()
// exact JSONPath equality (value-selector containment; GIN-indexable)
await db.orm.public.User.where((u) => u.preferences.eqlJsonPathEq('$.theme', 'dark')).all()
// JSONPath ordering (ciphertext-free selector + scalar term)
await db.orm.public.User.where((u) => u.preferences.eqlJsonPathGte('$.score', 80)).all()
// ordering
import { eqlAsc } from '@cipherstash/stack-prisma/runtime'
await db.orm.public.User.orderBy((u) => eqlAsc(u.salary)).all()

// ordering by a JSONPath leaf; missing paths follow PostgreSQL NULL ordering
import { eqlJsonPathAsc } from '@cipherstash/stack-prisma/runtime'
await db.orm.public.User.orderBy((u) => eqlJsonPathAsc(u.preferences, '$.score')).all()
```

Applying an operator its domain doesn't support (e.g. `eqlGt` on a
storage-only `EncryptedBoolean`, or `eqlMatch` on a non-text domain) is a typed
error at build time, not a runtime surprise.

## Authentication

Same credential model as the rest of Stack:

- **Local dev:** `npx stash auth login` (device-code flow; token in `~/.cipherstash`).
- **CI / production:** the four `CS_*` env vars (`CS_WORKSPACE_CRN`, `CS_CLIENT_ID`,
  `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`), minted with `stash env`. The
  `stash-auth` skill is canonical for credentials and auth strategies;
  `stash-zerokms` for keysets and what the credentials can reach.

`cipherstashFromStack` resolves `CS_*` when present, else the local profile.

## Bundling

`@cipherstash/stack` wraps a native FFI module and must be excluded from bundling
(`serverExternalPackages`, esbuild `external`, etc.) — see the `stash-encryption`
skill's bundling section. The Prisma Next adapter is **native-only**:
`cipherstashFromStack` constructs the native `@cipherstash/stack` client, and
there is no `wasm-inline` variant of this adapter — the WASM entry is a
different client for non-Prisma edge paths (`stash-edge`), not a drop-in here.
Run Prisma Next apps on a Node runtime where the native module loads.

## Subpath exports

| Subpath | Purpose |
|---|---|
| `@cipherstash/stack-prisma/v3` | The v3 surface: `cipherstashFromStack`, the SDK adapter, envelopes/middleware |
| `@cipherstash/stack-prisma/control` | The extension pack for `extensions: [...]` |
| `@cipherstash/stack-prisma/runtime` | Envelope classes, `decryptAll`, `eql*` operators, `EncryptedString.from()`… |
| `@cipherstash/stack-prisma/stack` | One-call setup against `@cipherstash/stack`: `cipherstashFromStack` |
| `@cipherstash/stack-prisma/column-types` | camelCase factories (`textSearch`, `bigIntOrd`, …) for **TS-authored** contracts — emits byte-identical `contract.json` to the PSL constructors |

## Gotchas

- **EQL installs via `prisma-next migrate` (top-level, not `migration apply`), never `stash eql install`.**
- **Column type (schema, domain-named) ≠ runtime envelope (value, primitive-named).**
  `DoubleOrd` column ↔ `EncryptedNumber.from(...)` value.
- **Regenerate the contract** (`prisma-next contract emit`) after changing a
  column's encrypted type, so `cipherstashFromStack` and the migrations agree.
- **Never log or read `~/.cipherstash`** or `.env*` credential files (see `stash-cli`).

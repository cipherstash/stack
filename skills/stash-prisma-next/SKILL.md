---
name: stash-prisma-next
description: Integrate CipherStash searchable field-level encryption with Prisma Next using @cipherstash/prisma-next (EQL v3). Covers the domain-named encrypted column types in schema.prisma (TextSearch, DoubleOrd, BigIntOrd, DateOrd, Boolean, Json), the one-call cipherstashFromStack wiring, the runtime value envelopes (EncryptedString/Number/BigInt/Date/Boolean/Json) and decryptAll, the eql* query operators (eqlEq, eqlMatch, eqlGt, eqlBetween, eqlIn, eqlJsonContains, eqlAsc/eqlDesc, eqlJsonPathAsc/eqlJsonPathDesc), EQL bundle installation via prisma-next migrate, and authentication. Use when adding encryption to a Prisma Next project or querying encrypted columns.
---

# CipherStash Stack — Prisma Next Integration

Guide for searchable field-level encryption in a **Prisma Next** app with
`@cipherstash/prisma-next` (EQL v3), powered by `@cipherstash/stack`. You declare
encrypted columns directly in `schema.prisma`; Prisma Next's migration system
installs the EQL bundle in the same sweep that creates your tables — there is no
separate `stash eql install` step.

> `@cipherstash/prisma-next` is **EQL v3 only** — there is no EQL v2 surface.
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
npm install @cipherstash/stack @cipherstash/prisma-next
```

Or run `npx stash init --prisma-next`, which detects Prisma Next, installs both
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

| Column type | Domain | Query capability |
|---|---|---|
| `TextSearch()` | `eql_v3_text_search` | equality, range, free-text, ORDER BY |
| `DoubleOrd()` | `eql_v3_double_ord` | equality, range, ORDER BY |
| `BigIntOrd()` | `eql_v3_bigint_ord` | equality, range, ORDER BY |
| `DateOrd()` | `eql_v3_date_ord` | equality, range, ORDER BY |
| `Boolean()` | `eql_v3_boolean` | storage-only (no operators) |
| `Json()` | `eql_v3_json_search` | containment + JSONPath equality/range |

Choose the column type by the queries you need: a value you only store and
decrypt (never search) can use a storage-only domain; a value you filter or sort
on needs the matching `*Ord` / `TextSearch` domain. The type is fixed at the
column — there is no capability tuner.

### 2. Register the extension pack in `prisma-next.config.ts`

```typescript
import cipherstash from '@cipherstash/prisma-next/control'
import { defineConfig } from 'prisma-next'
import { prismaContract } from '@prisma-next/sql-contract-psl/provider'
import postgresPack from '@prisma-next/target-postgres/pack'
import { postgresCreateNamespace } from '@prisma-next/target-postgres/types'
// ... family, target, adapter

export default defineConfig({
  // ... your existing config
  extensionPacks: [cipherstash],
  contract: prismaContract('./prisma/schema.prisma', {
    output: 'src/prisma/contract.json',
    target: postgresPack,
    createNamespace: postgresCreateNamespace,
  }),
})
```

`createNamespace` is **required** since Prisma Next 0.15 — the SQL family no
longer materialises a placeholder namespace. Omitting it fails at runtime with
`createNamespace is not a function` when you run `prisma-next contract emit`.

### 3. Wire the runtime with `cipherstashFromStack` in `src/db.ts`

```typescript
import 'dotenv/config'
import { cipherstashFromStack } from '@cipherstash/prisma-next/v3'
import postgres from '@prisma-next/postgres/runtime'
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
`@cipherstash/stack` `EncryptionV3` client from your `CS_*` env vars or local
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
migrate` owns EQL installation, and `stash init --prisma-next` skips the
standalone installer for exactly this reason. The CLI enforces this: `stash eql
install` detects a Prisma Next project and refuses (pointing you at `prisma-next
migrate`) unless you pass `--force`.

## Indexing encrypted columns

The adapter emits the encrypted query operators, but **no index DDL** — without
functional indexes over the `eql_v3.*` extractors, every encrypted predicate
sequential-scans. Two facts shape where the DDL goes:

- **`schema.prisma` cannot express functional indexes** (`@@index` takes
  fields, not expressions), so the schema file is not an option.
- Prisma Next migrations execute **raw SQL operations**, so an index migration
  is just an operation whose statements are the `CREATE INDEX` recipes —
  authored in the same migration history that installs the EQL bundle, applied
  by the same `prisma-next migrate`. Never run index DDL out-of-band.

One index per capability the column's domain carries:

```sql
-- cipherstash.TextEq / TextSearch: equality
CREATE INDEX users_email_eq ON users USING btree (eql_v3.eq_term(email));
-- cipherstash.*Ord / TextSearch: ordering + range (serves = too on _ord domains)
CREATE INDEX users_created_at_ord ON users USING btree (eql_v3.ord_term(created_at));
-- cipherstash.TextMatch / TextSearch: free-text match
CREATE INDEX users_bio_match ON users USING gin (eql_v3.match_term(bio));
-- cipherstash.Json: containment
CREATE INDEX users_profile_json
  ON users USING gin (eql_v3.to_ste_vec_query(profile)::jsonb jsonb_path_ops);

ANALYZE users;
```

The `ANALYZE` is part of the recipe — an expression index has no statistics
until it runs. Works as a non-superuser role (Supabase included); only the
ORE-flavour (`_ord_ore`) ordering opclass is superuser-gated. For the full
model — which domains take which index, engagement rules, `EXPLAIN`
verification, rollout timing — see the `stash-indexing` skill.

## Writing and reading encrypted values

At the value boundary you wrap plaintext in a **runtime envelope** (primitive-named,
distinct from the domain-named column type) and unwrap with `decryptAll` +
`.decrypt()`:

```typescript
import {
  decryptAll,
  EncryptedString, EncryptedNumber, EncryptedBigInt,
  EncryptedDate, EncryptedBoolean, EncryptedJson,
} from '@cipherstash/prisma-next/runtime'

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

The envelope for a `double` column is `EncryptedNumber` (JS `number`); the schema
column type is `DoubleOrd`. Envelope ↔ column pairing: `EncryptedString`
↔ `TextSearch`, `EncryptedNumber` ↔ `DoubleOrd`,
`EncryptedBigInt` ↔ `BigIntOrd`, `EncryptedDate` ↔ `DateOrd`,
`EncryptedBoolean` ↔ `Boolean`, `EncryptedJson` ↔ `Json`.

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
import { eqlAsc } from '@cipherstash/prisma-next/runtime'
await db.orm.public.User.orderBy((u) => eqlAsc(u.salary)).all()

// ordering by a JSONPath leaf; missing paths follow PostgreSQL NULL ordering
import { eqlJsonPathAsc } from '@cipherstash/prisma-next/runtime'
await db.orm.public.User.orderBy((u) => eqlJsonPathAsc(u.preferences, '$.score')).all()
```

Applying an operator its domain doesn't support (e.g. `eqlGt` on a
storage-only `EncryptedBoolean`, or `eqlMatch` on a non-text domain) is a typed
error at build time, not a runtime surprise.

## Authentication

Same credential model as the rest of Stack:

- **Local dev:** `npx stash auth login` (device-code flow; token in `~/.cipherstash`).
- **CI / production:** the four `CS_*` env vars (`CS_WORKSPACE_CRN`, `CS_CLIENT_ID`,
  `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`). See the `stash-cli` and
  `stash-encryption` skills for how to obtain them from your device session.

`cipherstashFromStack` resolves `CS_*` when present, else the local profile.

## Bundling

`@cipherstash/stack` wraps a native FFI module and must be excluded from bundling
(`serverExternalPackages`, esbuild `external`, etc.) — see the `stash-encryption`
skill's bundling section. For edge/serverless runtimes without the native module,
use `@cipherstash/stack/wasm-inline`.

## Subpath exports

| Subpath | Purpose |
|---|---|
| `@cipherstash/prisma-next/v3` | The v3 surface: `cipherstashFromStack`, the SDK adapter, envelopes/middleware |
| `@cipherstash/prisma-next/control` | The extension pack for `extensionPacks: [...]` |
| `@cipherstash/prisma-next/runtime` | Envelope classes, `decryptAll`, `eql*` operators, `EncryptedString.from()`… |
| `@cipherstash/prisma-next/stack` | One-call setup against `@cipherstash/stack`: `cipherstashFromStack` |

## Gotchas

- **EQL installs via `prisma-next migrate` (top-level, not `migration apply`), never `stash eql install`.**
- **Column type (schema, domain-named) ≠ runtime envelope (value, primitive-named).**
  `DoubleOrd` column ↔ `EncryptedNumber.from(...)` value.
- **Regenerate the contract** (`prisma-next contract emit`) after changing a
  column's encrypted type, so `cipherstashFromStack` and the migrations agree.
- **Never log or read `~/.cipherstash`** or `.env*` credential files (see `stash-cli`).

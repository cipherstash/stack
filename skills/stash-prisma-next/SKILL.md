---
name: stash-prisma-next
description: Integrate CipherStash searchable field-level encryption with Prisma Next using @cipherstash/prisma-next (EQL v3). Covers the domain-named encrypted column types in schema.prisma (EncryptedTextSearch, EncryptedDoubleOrd, EncryptedBigIntOrd, EncryptedDateOrd, EncryptedBoolean, EncryptedJson), the one-call cipherstashFromStackV3 wiring, the runtime value envelopes (EncryptedString/Number/BigInt/Date/Boolean/Json) and decryptAll, the eql* query operators (eqlEq, eqlMatch, eqlGt, eqlBetween, eqlIn, eqlJsonContains, eqlAsc/eqlDesc), EQL bundle installation via prisma-next migration apply, and authentication. Use when adding encryption to a Prisma Next project or querying encrypted columns.
---

# CipherStash Stack — Prisma Next Integration

Guide for searchable field-level encryption in a **Prisma Next** app with
`@cipherstash/prisma-next` (EQL v3), powered by `@cipherstash/stack`. You declare
encrypted columns directly in `schema.prisma`; Prisma Next's migration system
installs the EQL bundle in the same sweep that creates your tables — there is no
separate `stash eql install` step.

> This is the **EQL v3** surface (the documented one). A legacy EQL v2 surface
> exists for existing deployments (`cipherstashFromStack` from
> `@cipherstash/prisma-next/stack`, `cipherstash*` operators); everything below
> is v3. New projects use v3.

In EQL v3 every encrypted column is a **concrete Postgres domain**
(`public.eql_v3_text_search`, `public.eql_v3_double_ord`, …) whose query
capabilities are fixed by the column type you choose — there is no capability
config object. See the `stash-encryption` skill for the domain catalog and
capability semantics; this skill covers the Prisma-Next-specific surface.

## When to Use This Skill

- Adding field-level encryption to a Prisma Next project
- Declaring encrypted columns in `schema.prisma`
- Querying encrypted columns with the `eql*` operators
- Wiring the runtime with `cipherstashFromStackV3`

## Installation

```bash
npm install @cipherstash/stack @cipherstash/prisma-next
```

Or run `npx stash init --prisma-next`, which detects Prisma Next, installs both
packages pinned to the CLI release, authenticates, and scaffolds the wiring.

## The three wiring points

### 1. Declare encrypted columns in `schema.prisma`

The column types are **domain-named** — the name encodes the query capability
(matching the `@cipherstash/stack` `types.*` catalog), not a generic primitive:

```prisma
model User {
  id            String @id
  email         cipherstash.EncryptedTextSearch()  // eq + range + free-text + ORDER BY
  salary        cipherstash.EncryptedDoubleOrd()   // eq + range + ORDER BY
  accountId     cipherstash.EncryptedBigIntOrd()   // eq + range + ORDER BY
  birthday      cipherstash.EncryptedDateOrd()     // eq + range + ORDER BY
  emailVerified cipherstash.EncryptedBoolean()     // storage-only (no operators)
  preferences   cipherstash.EncryptedJson()        // containment (@>)
}
```

| Column type | Domain | Query capability |
|---|---|---|
| `EncryptedTextSearch()` | `eql_v3_text_search` | equality, range, free-text, ORDER BY |
| `EncryptedDoubleOrd()` | `eql_v3_double_ord` | equality, range, ORDER BY |
| `EncryptedBigIntOrd()` | `eql_v3_bigint_ord` | equality, range, ORDER BY |
| `EncryptedDateOrd()` | `eql_v3_date_ord` | equality, range, ORDER BY |
| `EncryptedBoolean()` | `eql_v3_boolean` | storage-only (no operators) |
| `EncryptedJson()` | `eql_v3_json` | containment (`@>`) |

Choose the column type by the queries you need: a value you only store and
decrypt (never search) can use a storage-only domain; a value you filter or sort
on needs the matching `*Ord` / `TextSearch` domain. The type is fixed at the
column — there is no capability tuner.

### 2. Register the extension pack in `prisma-next.config.ts`

```typescript
import cipherstash from '@cipherstash/prisma-next/control'
import { defineConfig } from 'prisma-next'
// ... family, target, adapter, contract

export default defineConfig({
  // ... your existing config
  extensionPacks: [cipherstash],
})
```

### 3. Wire the runtime with `cipherstashFromStackV3` in `src/db.ts`

```typescript
import 'dotenv/config'
import { cipherstashFromStackV3 } from '@cipherstash/prisma-next/v3'
import postgres from '@prisma-next/postgres/runtime'
import type { Contract } from './prisma/contract.d'
import contractJson from './prisma/contract.json' with { type: 'json' }

const cipherstash = await cipherstashFromStackV3({ contractJson })

export const db = postgres<Contract>({
  contractJson,
  extensions: cipherstash.extensions,
  middleware: cipherstash.middleware,
})
```

`cipherstashFromStackV3({ contractJson })` derives the v3 encryption schemas from
the contract (one `public.eql_v3_*` domain per column), constructs the
`@cipherstash/stack` `EncryptionV3` client from your `CS_*` env vars or local
profile, builds the SDK adapter, and returns ready-to-spread `extensions` and
`middleware`. A v3 client is v3-only — a contract carrying v2 codec ids is
rejected at setup (use `cipherstashFromStack` from
`@cipherstash/prisma-next/stack` for a v2 contract).

## Install the EQL bundle (part of your migration, not a separate step)

The extension pack contributes its own contract space at
`migrations/cipherstash/`, so the EQL bundle installs alongside your application
schema:

```bash
npx stash auth login                 # one-time, per developer
npx prisma-next contract emit
npx prisma-next migration plan --name initial
npx prisma-next migration apply      # installs EQL bundle + your schema
```

Do **not** run `stash eql install` for a Prisma Next project — `prisma-next
migration apply` owns EQL installation, and `stash init --prisma-next` skips the
standalone installer for exactly this reason.

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
  salary: EncryptedNumber.from(100_000),      // EncryptedDoubleOrd column
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
column type is `EncryptedDoubleOrd`. Envelope ↔ column pairing: `EncryptedString`
↔ `EncryptedTextSearch`, `EncryptedNumber` ↔ `EncryptedDoubleOrd`,
`EncryptedBigInt` ↔ `EncryptedBigIntOrd`, `EncryptedDate` ↔ `EncryptedDateOrd`,
`EncryptedBoolean` ↔ `EncryptedBoolean`, `EncryptedJson` ↔ `EncryptedJson`.

## Query operators (`eql*`)

Operators live on the encrypted column inside `.where((u) => …)` and encrypt the
search term for you — Prisma Next never sees plaintext in a query. EQL v3 uses the
EQL-derived `eql*` vocabulary (the legacy v2 surface keeps `cipherstash*` names):

| Operator | Meaning | Requires |
|---|---|---|
| `eqlEq(v)` / `eqlNeq(v)` | equality / inequality | any searchable domain |
| `eqlIn(vs)` / `eqlNotIn(vs)` | membership | any searchable domain |
| `eqlMatch(term)` | free-text token match (`eql_v3.contains`) | `EncryptedTextSearch` |
| `eqlGt/eqlGte/eqlLt/eqlLte(v)` | range comparison | an `*Ord` domain |
| `eqlBetween(lo,hi)` / `eqlNotBetween(lo,hi)` | range window | an `*Ord` domain |
| `eqlAsc()` / `eqlDesc()` | ORDER BY | an `*Ord` or `TextSearch` domain |
| `eqlJsonContains(obj)` | encrypted JSON containment (`@>`) | `EncryptedJson` |

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
// ordering
import { eqlAsc } from '@cipherstash/prisma-next/runtime'
await db.orm.public.User.orderBy((u) => eqlAsc(u.salary)).all()
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

`cipherstashFromStackV3` resolves `CS_*` when present, else the local profile.

## Bundling

`@cipherstash/stack` wraps a native FFI module and must be excluded from bundling
(`serverExternalPackages`, esbuild `external`, etc.) — see the `stash-encryption`
skill's bundling section. For edge/serverless runtimes without the native module,
use `@cipherstash/stack/wasm-inline`.

## Subpath exports

| Subpath | Purpose |
|---|---|
| `@cipherstash/prisma-next/v3` | The v3 surface: `cipherstashFromStackV3`, the SDK adapter, envelopes/middleware |
| `@cipherstash/prisma-next/control` | The extension pack for `extensionPacks: [...]` |
| `@cipherstash/prisma-next/runtime` | Envelope classes, `decryptAll`, `eql*` operators, `EncryptedString.from()`… |
| `@cipherstash/prisma-next/stack` | Legacy EQL v2 one-call setup (`cipherstashFromStack`) |

## Gotchas

- **EQL installs via `prisma-next migration apply`, never `stash eql install`.**
- **Column type (schema, domain-named) ≠ runtime envelope (value, primitive-named).**
  `EncryptedDoubleOrd` column ↔ `EncryptedNumber.from(...)` value.
- **A v3 client rejects a v2 contract** at `cipherstashFromStackV3`. Regenerate the
  contract (`prisma-next contract emit`) after switching a column to a v3 type.
- **Never log or read `~/.cipherstash`** or `.env*` credential files (see `stash-cli`).

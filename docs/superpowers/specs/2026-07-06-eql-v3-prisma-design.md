# EQL v3 Prisma ORM support — design

Status: proposed (spike complete, findings below)
Date: 2026-07-06
Ticket: CIP-3302
Branch: `james/cip-3302-integrate-eql-v3-into-prisma-orm`

## 1. Goal

Add EQL v3 support for **vanilla Prisma ORM** (`@prisma/client`) to
`@cipherstash/stack`, at the same layer as the Supabase integration
(`src/supabase`) and the Drizzle v3 integration (`src/eql/v3/drizzle`, PR #565).

Success = a developer can declare encrypted columns for a Prisma model, feed
the same `@cipherstash/stack/eql/v3` schema to `EncryptionV3`, and run
equality / range / free-text queries through their Prisma client with
transparent encrypt-on-write / decrypt-on-read.

Not to be confused with `@cipherstash/prisma-next` (PR #515) — the in-house
ORM is a separate track; nothing here touches it.

## 2. Spike findings (2026-07-06)

Environment: Prisma **7.8.0** + `@prisma/adapter-pg` (driver adapters are
mandatory in v7; `datasource.url` in `schema.prisma` is a validation error),
PG 17 with the vendored `eql_v3` bundle
(`packages/stack/__tests__/fixtures/eql-v3/cipherstash-encrypt-v3.sql`).
Table: `spike_users (email eql_v3.text_eq, age eql_v3.integer_ord)`, Prisma
model declares both as `Json?`. Envelopes hand-crafted (domain CHECKs verify
key shape only; the `=` operator compares `hm` terms, so a same-`hm` /
different-`c` operand distinguishes domain-operator resolution from jsonb
structural equality).

| # | Path | Result |
|---|------|--------|
| 1 | `create` with `Json` field → domain column | ✅ works (plain `INSERT … VALUES ($1,$2)`, assignment cast jsonb→domain) |
| 2 | `createMany` (valid envelopes) | ✅ works |
| 3 | `create`/`createMany` with plain `null` on a `Json` field | ❌ Prisma writes **JSON `null`**, which fails the domain CHECK (`jsonb_typeof ≠ 'object'`). `Prisma.DbNull` writes SQL NULL and works. The extension must normalize `null → DbNull` for encrypted columns. |
| 4 | CHECK-violating payload | ✅ rejected by PG (defense in depth holds) |
| 5 | `findMany` read-back | ✅ envelope round-trips as a JS object |
| 6 | Typed `where` `equals` with full envelope | ❌ **domain operator bypassed.** Prisma emits `"col"::jsonb = $1` — the column-side cast smashes the domain to base jsonb, so comparison is structural. Same-`hm`/different-`c` does not match. (A byte-identical envelope *does* match structurally, but with real encryption the operand's ciphertext always differs — so in production this silently returns zero rows.) |
| 7 | Typed `where` `gt/gte/lt/lte` on `Json` | ❌ rejected by Prisma client validation — not part of the Json filter surface |
| 8 | `$queryRaw` with native domain operator: `email = $1::jsonb` | ✅ matches via `eql_v3.eq` (the PostgREST/Supabase lowering) |
| 9 | `$queryRaw` with extracted terms: `eql_v3.eq_term(email) = eql_v3.eq_term($1::jsonb::eql_v3.text_eq)` | ✅ matches (the Drizzle v3 lowering; note the operand needs the double cast, or use the two-arg `eql_v3.eq(col, $1::jsonb)` function form) |
| 10 | `updateMany` with `Json` field | ✅ works |

**Conclusions.**

1. **Column strategy: `Json` fields over domain-typed DB columns.** Reads and
   writes work transparently through the standard client; PG's assignment
   cast + domain CHECK validate on the way in. `Unsupported("eql_v3.…")`
   is rejected as primary strategy — it removes the field from the generated
   client entirely.
2. **Typed `where` is a dead end for encrypted search** — equality is
   silently wrong (6) and range doesn't exist (7). All encrypted filtering
   must lower to raw SQL. This also means the integration must **guard**
   against users passing encrypted columns to plain `where` (silent zero-row
   results are the worst failure mode).
3. Both raw lowering styles work on main's bundle. Use the **two-arg
   function forms** (`eql_v3.eq(col, $::jsonb)` etc.) with full-envelope
   operands; emitting Drizzle-v3-identical SQL is not achievable today
   because #565 targets a different bundle generation (see §2b).
4. Prisma 7's driver-adapter requirement shapes the docs/example app but not
   the integration design ($extends and $queryRaw are unchanged).

## 2b. Insights from the Drizzle v3 implementation (PR #565, reviewed 2026-07-06)

#565 landed a full implementation of the sibling integration. What transfers,
what doesn't, and what it changes here:

**Bundle-generation split — the biggest caution.** #565 is built on the
**protect-ffi 0.26** line: pre-rename domain names (`eql_v3.int4_ord`), and a
bundle that exposes **public** term constructors
(`eql_v3.hmac_256/ore_block_256/bloom_filter`) accepting term-only jsonb; on
that line `client.encryptQuery` produces v3 scalar terms. Main — this
module's base — is the **protect-ffi 0.27** line: SQL-standard domain names
(`eql_v3.integer_ord`), constructors in **`eql_v3_internal`** only, public
two-arg wrappers (`eql_v3.eq(col, $::jsonb)`) that **coerce the operand into
the domain** (so it must be a full envelope passing the CHECK), and scalar
`encryptQuery` throwing `EQL_V3_QUERY_UNSUPPORTED`. Consequences:

- #565's exact SQL (`eql_v3.hmac_256(…)`) and its term-operand path **do not
  work against main's bundle**. This module keeps the full-envelope operand
  (spike-verified via both the native domain operator and the
  `eq_term(col) = eq_term($::jsonb::domain)` form, which the two-arg
  `eql_v3.eq(col, $::jsonb)` wrapper is equivalent to).
- Code-sharing #565's `sql-dialect.ts` is off the table for now — it is
  drizzle-`SQL`-typed and pinned to the other bundle generation. Share the
  **shape** (the dialect table below), not the module; extracting a
  driver-neutral dialect is a follow-up once both integrations sit on one
  bundle generation.
- Sequencing flips: #565 must reconcile with main's 0.27/SQL-standard-name
  line before anything can be shared. This module should **not block on it**.

**What does transfer (adopt directly):**

1. **The dialect shape.** A small object keyed off `builder.build().indexes`
   (`unique`/`ore`/`match` — the authoritative index set, which #565 uses for
   gating instead of `getQueryCapabilities()`; align on that here too), with:
   equality (`unique` → hmac path), **equality-via-ORE fallback** for
   ord-only columns (`ord_term = ore-constructor`, `queryType:
   'orderAndRange'`), comparison, `between`/`notBetween`, match, and
   `orderBy`.
2. **Encrypted `ORDER BY` is in scope** for raw-SQL integrations: `ORDER BY
   eql_v3.ord_term(col)` (requires `ore`). #565 ships `asc`/`desc`; this
   module ships an `orderByEncrypted` fragment builder. (Supersedes the
   earlier out-of-scope entry.)
3. **`inArray`/`notInArray`** as OR-of-equality / AND-of-inequality terms,
   encrypting operands with **bounded concurrency** (#565 caps at 4) — adopt
   for `whereIn`/`whereNotIn` builders.
4. **No-silent-fallback errors.** v3 operators throw a named error
   (`EncryptionOperatorError`) carrying `{ columnName, tableName, operator }`
   when a column lacks the required index or isn't a v3 column at all — no
   fall-through to plain operators (v2 behaviour), because wrong-operator SQL
   fails the domain CHECK at runtime anyway. Matches and strengthens this
   design's typed-`where` guard; adopt the same error-context convention.
5. **Null codec confirmation.** #565's `toDriver` maps `null`/`undefined` →
   SQL NULL for exactly the domain-CHECK reason spike finding 3 hit. Here
   only `null → Prisma.DbNull` transfers: Prisma's `undefined` means "field
   not provided" and must be left untouched (coercing it would null out
   columns on update — a Drizzle-codec detail that does not carry over).
6. **Per-table schema cache** (WeakMap keyed by the ORM table object) for
   resolving a column's owning `encryptedTable` — mirror in `model-map.ts`.

## 3. Architecture

```
packages/stack/src/eql/v3/prisma/
  index.ts             // barrel: encryptedPrisma, whereEncrypted helpers, errors
  extension.ts         // $extends factory: encrypt-on-write / decrypt-on-read
  model-map.ts         // Prisma model name ↔ v3 encryptedTable registration
  where.ts             // capability-checked Prisma.sql fragment builders (incl. whereIn, orderByEncrypted)
  sql-dialect.ts       // Prisma.sql emission; mirrors #565's dialect SHAPE (code-sharing blocked by the bundle split, §2b)
  null-handling.ts     // null → Prisma.DbNull normalization for encrypted fields
```

Exported at `@cipherstash/stack/eql/v3/prisma` (package.json `exports` + tsup
entry). Depends inward on `@/eql/v3` (concrete types = single source of truth
for domain / `cast_as` / capabilities) and `@/encryption` only. No dependency
on the v2 modules or on `@prisma/client` itself (structural typing over the
client, mirroring `SupabaseClientLike`).

### 3.1 Write/read transparency: `$extends` query component

`encryptedPrisma({ encryptionClient, prismaClient, tables })` returns
`prismaClient.$extends({ query: { $allModels: { … } } })` where `tables` maps
Prisma model names to v3 `encryptedTable` schemas.

- **Writes** (`create`, `update`, `upsert`, `createMany`, `createManyAndReturn`,
  `updateMany`): plaintext values on registered encrypted fields are encrypted
  via `encryptModel` / `bulkEncryptModels`; `null` becomes `Prisma.DbNull`
  (finding 3; #565's codec confirms the domain-CHECK rationale, §2b).
  `undefined` is left untouched — in Prisma it means "field not provided",
  and coercing it to `DbNull` would null out columns on update.
- **Reads** (`findMany`, `findFirst`, `findUnique`, and the `*OrThrow`
  variants, plus the rows returned by mutating calls): envelopes on registered
  fields are decrypted via `bulkDecryptModels`, with `Date` reconstruction
  from `cast_as` and native `bigint` passthrough (parity with
  `src/encryption/v3.ts`).
- **Guard**: any registered encrypted field appearing inside `where` /
  `orderBy` / `distinct` of an intercepted call throws
  `PrismaEncryptedColumnError` — never silently returns wrong results
  (finding 6). Plaintext (unregistered) fields pass through untouched.
- Lock context + audit config passthrough, same surface as the Supabase
  builder (`withLockContext`, `audit`).

### 3.2 Encrypted filtering: `Prisma.sql` fragment builders

Typed `where` cannot express encrypted search, so filtering is explicit:

```ts
const { whereEq, whereGt, whereMatch } = encryptedWhere(client, users)

const rows = await eprisma.$queryRawEncrypted(
  users,
  Prisma.sql`SELECT * FROM users WHERE ${await whereEq(users.email, 'a@b.com')} AND plan = ${plan}`,
)
```

- Each builder is **capability-checked** against `builder.build().indexes`
  (`unique`/`ore`/`match` — the authoritative index set, per #565; see §2b).
  Storage-only columns and operator/capability mismatches throw a named error
  with `{ columnName, tableName, operator }` context — runtime guard now,
  type-level narrowing like `V3FilterableKeys` where feasible. Equality on an
  ord-only column falls back to ORE (`queryType: 'orderAndRange'`), mirroring
  #565.
- Operand encryption reuses the **interim full-envelope encoding** with the
  same single-swap-point discipline as the Supabase builder
  (`query-builder-v3.ts#encryptCollectedTerms`, CIP-3402). #565's
  `encryptQuery` term path does NOT transfer to main's protect-ffi 0.27 line
  (§2b) — revisit only when the term-only envelope ships, and note the
  lowering must switch away from the domain-coercing forms at the same time
  (a term-only operand fails the domain CHECK).
- SQL emission uses the two-arg function forms (`eql_v3.eq(col, $::jsonb)`,
  finding 9 equivalent) to avoid the double-cast wrinkle. `whereIn` = OR of
  equality fragments with bounded operand-encryption concurrency;
  `orderByEncrypted` = `eql_v3.ord_term(col)` (requires `ore`).
- Free-text: bloom containment via the two-arg `eql_v3.contains(col,
  $::jsonb)` (equivalently the native `@>` operator Supabase's `cs` uses),
  documented as token match, not SQL `LIKE` (same caveat as Drizzle/Supabase).
- `$queryRawEncrypted(table, sql)` wraps `$queryRaw` and decrypts the result
  rows against the table schema.

### 3.3 DDL / migration story

`prisma migrate` emits `jsonb` for `Json` fields; the DB column must be the
domain. Ship documented, copy-pasteable migration SQL
(`ALTER TABLE … ALTER COLUMN … TYPE eql_v3.text_eq USING …` or authoring the
column as the domain in the initial migration — Prisma migrations are plain
SQL files, so hand-edits are first-class) plus the `eql_v3` bundle install
(reuse `scripts/install-eql-v3.ts` / CLI installer). A codegen step that
patches migrations automatically is a follow-up, not v1.

## 4. Scope

### In scope
- The module above, for every shipped scalar domain (text/int/float/numeric/
  date/timestamp/bool families; bigint rides in with #557's release gate).
- Unit tests with a mocked Prisma client (mirror the mock-Supabase pattern),
  `.test-d.ts` type tests, capability-mismatch matrix, live-gated PG tests
  (`DATABASE_URL` + `CS_*`, reuse `__tests__/helpers/live-gate.ts`).
- Example app under `examples/` (note `examples/prisma` belongs to
  prisma-next; new directory, e.g. `examples/prisma-orm`), Prisma 7 +
  driver-adapter shaped.
- README + `docs/query-api-walkthrough.md` sections, changeset (minor).

### Out of scope
- JSON / `ste_vec` columns (no v3 JSON builder exists yet).
- Encrypted `ORDER BY` through the **typed** API (`orderBy: {…}`) — but the
  raw-SQL `orderByEncrypted` fragment builder IS in scope (§2b insight 2).
- Automatic migration patching (documented manual edit in v1).
- Prisma < 7 compatibility testing (the `::jsonb` column cast predates v7, so
  the typed-where conclusion holds for v6; the extension targets the
  client-extension API, GA since v4.16 — verify on v6 opportunistically).
- Any change to `@cipherstash/prisma-next` or the v2 integrations.

## 5. Sequencing

1. **Do not block on #565.** It is built on the protect-ffi 0.26 /
   pre-rename-domain line and must reconcile with main's 0.27 /
   SQL-standard-name line before its dialect or encrypt-query path can be
   shared (§2b). This module proceeds against main directly.
2. This module's core (extension + where builders) against the interim
   full-envelope operand, mirroring #565's dialect *shape* only.
3. CIP-3402 lands the term-only envelope → swap inside the one operand-
   encryption method AND switch the lowering off the domain-coercing forms
   in the same change (term-only operands fail the domain CHECK).
4. Follow-up once both integrations share a bundle generation: extract a
   driver-neutral term-SQL dialect.

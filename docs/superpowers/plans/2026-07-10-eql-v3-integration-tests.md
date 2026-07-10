# EQL v3 Integration Test Suite Plan (tests → type robustness → packaging → JSON)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every EQL v3 adapter a **comprehensive, real-crypto integration suite** that proves query correctness against a real database — for each domain type, generate a sample of plaintext, single-encrypt some rows and bulk-encrypt the rest, insert them through the adapter, then exercise every valid query operation over a range of values and assert against a plaintext oracle. Then, standing on that suite, restore the erased EQL v3 types, split the adapters into their own packages, and add v3 JSON support.

**Architecture:** One capability catalog, one plaintext oracle, one driver. Everything is **derived from `V3_MATRIX`**, never hand-listed: which operations must work, which must be rejected, which rows to seed. The catalog is `satisfies Record<EqlV3TypeName, DomainSpec>` keyed off the real `AnyEncryptedV3Column` union, so adding a domain to the SDK fails compilation until a catalog row exists. A single `IntegrationAdapter` interface abstracts Drizzle from Supabase, so each per-family test file is three lines and the two adapters cannot drift in what they claim to cover. Integration tests are **separate from unit tests** — own vitest config, own `test:integration` script, own CI workflow — and they **fail loudly** rather than skipping when credentials or a database are absent. EQL v3 is installed by the real `stash eql install --eql-version 3` CLI, so an installer regression fails CI instead of hiding behind a test-only code path.

**Tech Stack:** TypeScript, `vitest` (`vitest run --config vitest.integration.config.ts`), `@cipherstash/stack` (`/eql/v3` catalog, `/v3` typed client, `/supabase`, `/eql/v3/drizzle`), `@cipherstash/eql@3.0.0` (canonical wire types; `/sql` release manifest), `@cipherstash/protect-ffi@0.29`, `postgres` (direct DDL), `@supabase/postgrest-js`, `drizzle-orm`, `stash` CLI (`packages/cli`), Docker (`ghcr.io/cipherstash/postgres-eql:17-2.3.1`, `supabase/postgres`, `postgrest/postgrest:v12.2.12`), `turbo`, `biome`.

## Global Constraints

1. **No `describe.skipIf` in integration suites.** A false gate is a silent whole-suite skip on a green job. Missing credentials, database, or PostgREST must throw with an actionable message. `AutoStrategy` lets a local `~/.cipherstash` profile stand in for `CS_*` env vars, so local dev stays frictionless.
2. **`pnpm test` must never run integration tests.** They live behind `test:integration` and their own workflows.
3. **Coverage is compile-enforced.** `V3_MATRIX` must keep its `satisfies Record<EqlV3TypeName, DomainSpec>`, and the test kit must be typechecked in CI, or a new domain silently goes untested.
4. **The oracle is the plaintext**, never a restatement of the query. Expected row sets are computed by filtering the seeded plaintext with `comparePlain`, not by asserting a literal.
5. **Never assert `localeCompare` ordering.** Strings compare by codepoint, dates by instant, bigints numerically.
6. **Connect direct to port 5432, never a pooler.** The `SET ROLE` / advisory-lock flakiness seen in `supabase-v3-grants-pg` is a PgBouncer transaction-mode artifact.

## Ground-truth notes (verified against `feat/eql-v3-text-search-schema`, 2026-07-10)

- **The Supabase v3 adapter has zero real-crypto coverage.** `packages/stack/__tests__/supabase-v3-pgrest-live.test.ts` runs against a real PostgREST but stubs ZeroKMS. Its equality term is `` `hm-${value}` `` (`__tests__/helpers/v3-envelope.ts:22`), so `.in('nickname', ['ada','nobody']) → ['ada']` is true by construction. The file header says as much: "What is faked is ZeroKMS — and only ZeroKMS."
- **`drizzle-v3/operators-live-pg.test.ts` is a genuine end-to-end suite** across all covered domains — real `EncryptionV3`, real Postgres, known rows, plaintext oracle (`plainValue`, `comparePlain`, `expectedKeysFor`, `sortedKeysFor`). It seeds **only** via `bulkEncryptModels`; the single-`encryptModel` insert path is never exercised.
- **The Supabase `insert()` branches on shape**: array → `bulkEncryptModels` (`query-builder.ts:452`), single object → `encryptModel` (`:474`). The live suite only ever inserts a single object, so the array path is untested.
- **The canonical EQL v3 types are imported nowhere.** `@cipherstash/eql@3.0.0` exports ~130 per-domain types (`IntegerOrd = { v, i, c, op: OpeCllw }` and its term-only twin `IntegerOrdQuery = { v, i, op }`), but no `.ts` source file imports them; only `@cipherstash/eql/sql` is consumed. Both adapters erase to `unknown`: `eql/v3/drizzle/operators.ts:51,55` type the client's `encrypt`/`bulkEncrypt` as returning `unknown`; `encryptOperands` returns `Promise<unknown[]>`; `supabase/query-builder-v3.ts:393,433,463` do the same, and the `Result` wrapper collapses to `{ data?: unknown }`.
- **v3 JSON is unimplemented, not merely untested.** The bundle ships `public.eql_v3_json` and `public.eql_v3_jsonb_entry` (51 `CREATE DOMAIN`s, 56 `eql_v3.{ste_vec,jsonb_path,selector,contained_by}` functions), but the SDK models 41 domains and `eql/v3/columns.ts` admits only `bigint | boolean | date | number | string | timestamp` as `cast_as`. There is no `'json'` kind, so a v3 JSON column cannot be declared. **The gap is in the core v3 schema; both adapters inherit it.** `eql/v3/drizzle/codec.ts:38` already carries defensive SteVec decode logic (`sv[0].c`) for documents nothing can currently create.
- **`@cipherstash/stack/drizzle` is not `@cipherstash/drizzle`.** They are a fork: `@cipherstash/drizzle@3.0.3` peer-depends on the predecessor SDK `@cipherstash/protect@12` and exports `createProtectOperators` (2,038 lines); stack's in-tree copy exports `createEncryptionOperators` (1,945 lines); ~645 lines have diverged. There is no dependency between them — hence no cycle today, only duplication. Docs reference the stack subpath 13× and the package 2×.
- **Ordering is safe on OPE.** EQL 3.0.0 pins `_ord` domains to `op` (CLLW-OPE), which orders via a native `bytea` btree, so `ORDER BY eql_v3.ord_term(col)` works on every provider without superuser.
- **`_ord_ore` columns cannot hold data on managed Postgres — and that is correct.** Measured against `supabase/postgres:17.4.1.048`, EQL 3.0.0, as the non-superuser `postgres` role: the nine ORE domains are created, but their CHECK calls `eql_v3_internal.ore_domain_unavailable()`, so the first `INSERT` raises with a hint naming `_eq` / `_ord` / `_ord_ope` as alternatives. The same insert succeeds on plain Postgres as a superuser. The bundle guards correctly; there is no silent wrongness. (An earlier draft of this plan claimed ORDER BY silently mis-sorts. It does at the *type* level — `ore_block_256` is a composite type, so with no opclass Postgres falls back to record comparison — but no value can reach a table to be ordered. `cipherstash/encrypt-query-language#395` records the correction.) A matrix that must pass on both databases cannot cover ORE, because the seed insert fails on one; ORE gets a superuser-only suite.
- **Supabase CAN order encrypted `_ord` columns.** A bare `ORDER BY col` sorts the ciphertext envelope through jsonb's default opclass (measured: `r00,r04,r08,r01,…` for plaintext `r00..r09`). But `eql_v3.ord_term` returns the `op` term, OPE is order-preserving, and PostgREST can emit the jsonb path `order=col->>op`, which reproduces plaintext order in both directions for `integer_ord` and `text_search`. The adapter now does exactly that, and rejects only ORE-backed and ordering-less columns.
- **The CLI installs fine as a non-superuser.** `stash eql install --eql-version 3 --supabase --direct --database-url …` runs non-interactively as `postgres` on `supabase/postgres` and grants `anon` USAGE on **both** `eql_v3` and `eql_v3_internal`. No `SUPABASE_ADMIN_URL` is needed. (`--supabase` without `--direct`/`--migration` prompts, so pass `--direct`.)
- **`postgres-eql:17-2.3.1` ships EQL v2, not v3.** Every DB variant must install v3 at setup.
- **`./supabase` and `./drizzle` are published stack subpaths** (`npm view @cipherstash/stack exports`); `./eql/v3/drizzle` is not.
- **Moving an adapter out of stack requires promoting internals.** `src/supabase` imports six non-public modules (`@/encryption/helpers`, `@/encryption/operations/base-operation`, `@/eql/v3/columns`, `@/eql/v3/domain-registry`, `@/types`, `@/utils/logger`); `src/eql/v3/drizzle` imports three (`@/types`, `@/schema/match-defaults`, `@/encryption/operations/base-operation`). Note `@/types` is the internal `src/types.ts`, distinct from the published `./types` → `types-public`.

## Sequencing

Tests first, so every later refactor lands against a suite that actually proves query correctness.

| PR | Contents |
|----|----------|
| **PR1** (this plan, Tasks 1–5) | Integration harness + Supabase v3 and Drizzle v3 real-crypto matrices. **No source moves.** |
| **PR2** | Type robustness: import `@cipherstash/eql` per-domain types; stop erasing `Result` and the query-type encoding. |
| **PR3** | Adapter package split: `@cipherstash/stack-drizzle`, `@cipherstash/stack-supabase`. Tests move with the code. |
| **PR4** | v3 JSON support: `types.Json()` + ste_vec, plus its family file in the existing matrix. v3 only. |
| *(independent, any time after PR1)* | Prisma-next live real-crypto suite; best-effort v2 coverage on the same harness. |

**Why the split is PR3 and not PR1.** It means promoting nine internal stack modules to public API and removing two published subpaths. That is a larger, riskier change than the test work, and it is exactly the refactor that wants an integration suite standing behind it. Doing it first would also churn every test import twice. Tests therefore land in `packages/stack/integration/` and relocate in PR3; because the shared kit is a workspace package from day one, that move is a path change, not a rewrite.

## File Structure

```
packages/test-kit/                      # NEW — private, unpublished, no build step
  package.json                          #   "private": true; exports "." -> ./src/index.ts
  src/
    catalog.ts                          #   MOVED from stack/__tests__/v3-matrix/catalog.ts
    families.ts                         #   FamilyName, domainsForFamily()
    oracle.ts                           #   plainValue, comparePlain, expectedKeysFor, sortedKeysFor
    rows.ts                             #   planTable(), planRows() — data gen + single/bulk split
    ops.ts                              #   QueryOpKind, positiveOps(), negativeOps()
    adapter.ts                          #   IntegrationAdapter interface
    run-family-suite.ts                 #   the driver
    env.ts                              #   requireIntegrationEnv(), requireEncryptionClientV3()
    install.ts                          #   shells out to `stash eql install --eql-version 3`
    index.ts

vitest.shared.ts                        # NEW — resolve.alias block, spread into every vitest config

local/
  docker-compose.postgres.yml           # NEW — postgres-eql, no PostgREST
  docker-compose.supabase.yml           # NEW — supabase/postgres (by digest) + PostgREST
  supabase-init.sql                     # NEW — authenticator LOGIN password
  docker-compose.yml                    # existing; keep or alias

packages/stack/
  integration/                          # NEW — excluded from `pnpm test`
    vitest.integration.config.ts
    global-setup.ts                     #   requireIntegrationEnv() — fails before docker work
    supabase/
      adapter.ts                        #   SupabaseAdapter implements IntegrationAdapter
      {integer,smallint,bigint,real-double,numeric,date,timestamp,text,boolean}.integration.test.ts
      wire.integration.test.ts          #   PORTED from __tests__/supabase-v3-pgrest-live.test.ts
    drizzle-v3/
      adapter.ts                        #   DrizzleAdapter implements IntegrationAdapter
      {integer,smallint,bigint,real-double,numeric,date,timestamp,text,boolean}.integration.test.ts
      relational.integration.test.ts    #   joins, exists/notExists, pagination, and/or/not, bigint
    matrix-sql.integration.test.ts      #   PORTED from __tests__/v3-matrix/matrix-live-pg.test.ts
  __tests__/v3-matrix/catalog.ts        # becomes a one-line re-export shim

.github/
  actions/integration-setup/action.yml  # NEW — checkout + pnpm + node + install
  workflows/integration-drizzle.yml     # NEW — db: [postgres]
  workflows/integration-supabase.yml    # NEW — db: [supabase]
```

---

### Task 1: Commit this plan

**Files:**
- Create: `docs/superpowers/plans/2026-07-10-eql-v3-integration-tests.md`

`docs/` does not ship in the `stash` tarball (only `skills/` does, per `CLAUDE.md:21`), so no changeset is required.

- [ ] **Step 1: Write the plan doc and commit**

---

### Task 2: `packages/test-kit` — the shared harness

Move the catalog into a private workspace package so both adapter suites (and, after PR3, both adapter packages) import one source of truth. Consumed as TypeScript source via a vitest alias so every package sees **one module instance** — stack's unit tests do `expect(builder(…)).toBeInstanceOf(spec.ColumnClass)`, which fails across module instances.

**Files:**
- Create: `packages/test-kit/{package.json,tsconfig.json,src/*.ts}`
- Create: `vitest.shared.ts`
- Modify: `packages/stack/__tests__/v3-matrix/catalog.ts` → one-line re-export shim
- Modify: `pnpm-workspace.yaml`, every `vitest.config.ts`

**Interfaces:**

```ts
export type Plain = string | number | bigint | boolean | Date

export type QueryOpKind =
  | 'eq' | 'ne' | 'in' | 'notIn'
  | 'gt' | 'gte' | 'lt' | 'lte' | 'between' | 'notBetween'
  | 'contains' | 'order' | 'isNull' | 'isNotNull'

export type QueryOp =
  | { kind: 'eq'|'ne'|'gt'|'gte'|'lt'|'lte'; column: string; value: Plain }
  | { kind: 'in'|'notIn'; column: string; values: Plain[]; asRawFilter?: boolean }
  | { kind: 'between'|'notBetween'; column: string; lo: Plain; hi: Plain }
  | { kind: 'contains'; column: string; needle: string }
  | { kind: 'order'; column: string; direction: 'asc'|'desc' }
  | { kind: 'isNull'|'isNotNull'; column: string }

export interface IntegrationAdapter {
  readonly name: 'drizzle' | 'supabase'
  readonly supportedOps: ReadonlySet<QueryOpKind>       // supabase omits 'order'
  readonly alwaysRejectedOps: ReadonlySet<QueryOpKind>  // supabase: {'order'}
  setup(): Promise<void>
  teardown(): Promise<void>
  createTable(t: TableSpec): Promise<void>
  insertSingle(t: TableSpec, row: PlainRow): Promise<void>   // MUST hit encryptModel
  insertBulk(t: TableSpec, rows: PlainRow[]): Promise<void>  // MUST hit bulkEncryptModels
  run(t: TableSpec, op: QueryOp): Promise<string[]>          // → matching rowKeys
  expectRejected(t: TableSpec, op: QueryOp): Promise<void>
}

export function runFamilySuite(family: FamilyName, make: () => IntegrationAdapter): void
```

Add one field to `DomainSpec`:

```ts
scope: { covered: true } | { covered: false; reason: string }
```

The nine ORE domains (eight numeric/date `_ord_ore` plus `text_ord_ore`) are `{ covered: false, reason: 'ORE is superuser-only; absent on managed Postgres — follow-up' }`. The driver skips them and `console.info`s the reason. Compile-enforcement survives, the exclusion is visible, and the follow-up flips flags rather than adding rows.

- [ ] **Step 1: Scaffold `packages/test-kit`** (private, no build, `exports: { ".": "./src/index.ts" }`), add to `pnpm-workspace.yaml`
- [ ] **Step 2: Move `catalog.ts`**, repoint its imports from `@/eql/v3`/`@/schema` to `@cipherstash/stack/eql/v3`/`@cipherstash/stack/schema`, add the `scope` field
- [ ] **Step 3: Leave the re-export shim** at `packages/stack/__tests__/v3-matrix/catalog.ts` so the ~10 unit tests importing it need no churn
- [ ] **Step 4: Add `vitest.shared.ts`** aliasing stack subpaths and `@cipherstash/test-kit` to source; spread into each package's vitest config
- [ ] **Step 5: Lift the oracle** (`plainValue`, `comparePlain`, `expectedKeysFor`, `sortedKeysFor`) out of `drizzle-v3/operators-live-pg.test.ts` into `oracle.ts`
- [ ] **Step 6: Write `ops.ts`** — the capability→operation table and `positiveOps`/`negativeOps`
- [ ] **Step 7: Write `rows.ts`** — `planTable()` and `planRows()` (see Task 4 notes on the single/bulk split)
- [ ] **Step 8: Ensure the kit is typechecked in CI** (add to `test:types`), then run `pnpm test` and commit

---

### Task 3: The harness — docker, CLI install, loud env gate

**Files:**
- Create: `local/docker-compose.postgres.yml`, `local/docker-compose.supabase.yml`, `local/supabase-init.sql`
- Create: `packages/stack/integration/{vitest.integration.config.ts,global-setup.ts}`
- Create: `.github/actions/integration-setup/action.yml`
- Modify: `turbo.json`, `packages/stack/{package.json,vitest.config.ts}`

**Install via the real CLI.** The harness runs `stash eql install --eql-version 3 --database-url $DATABASE_URL` after `turbo run build --filter stash`. This replaces the hand-rolled `installEqlV3IfNeeded` + `SUPABASE_PERMISSIONS_SQL_V3` apply, and means every integration run exercises the installer customers actually use. `isInstalled` is generation-aware, so repeat local runs are cheap.

**`supabase-init.sql`.** The `supabase/postgres` image already ships `anon`, `authenticated`, `service_role`, `authenticator`, and a non-superuser `postgres`. This file only guarantees the login PostgREST needs:

```sql
ALTER ROLE authenticator WITH LOGIN PASSWORD 'authpass' NOINHERIT;
GRANT anon, authenticated, service_role TO authenticator;
```

**Do not** reuse `local/postgrest-roles.sql` here: its `IF NOT EXISTS` create-branch skips the password when the role already exists, and PostgREST auth then fails.

**Loud failure.** `requireIntegrationEnv(requires)` throws, naming exactly what is missing and how to supply it. For CipherStash it accepts **either** the four `CS_*` vars **or** an existing `~/.cipherstash` profile — mirroring `examples/prisma/test/e2e/global-setup.ts:82-90` — then lets protect-ffi's AutoStrategy resolve. It runs in vitest `globalSetup` so it fails before any container work is wasted.

- [ ] **Step 1: Write the two compose files** (`supabase/postgres` pinned by digest) and `supabase-init.sql`; comment the never-a-pooler constraint
- [ ] **Step 2: Bring both stacks up locally** and confirm `eql_v3.version()` matches the pinned release after `stash eql install --eql-version 3`
- [ ] **Step 3: Confirm the CLI's grants suffice for `anon` without a superuser connection** — the step most likely to surprise us. If they do not, wire a `SUPABASE_ADMIN_URL` for the install only
- [ ] **Step 4: Write `env.ts`** (`requireIntegrationEnv`, `requireEncryptionClientV3`) and `install.ts`
- [ ] **Step 5: Add the integration vitest config + `global-setup.ts`**; add `exclude: ['integration/**']` to the base config; add the `test:integration` script and the `turbo.json` task (`dependsOn: ['^build']`, `cache: false`)
- [ ] **Step 6: Verify** `pnpm test` runs zero integration tests, and that unsetting `PGRST_URL` produces a red failure with an actionable message — **not** a green skip
- [ ] **Step 7: Commit**

---

### Task 4: Supabase v3 real-crypto integration suite

The headline gap. Nine per-family files, each three lines; all the work lives in `adapter.ts` and the shared driver.

**Files:**
- Create: `packages/stack/integration/supabase/adapter.ts` + nine `*.integration.test.ts`
- Create: `packages/stack/integration/supabase/wire.integration.test.ts` (ported)
- Create: `.github/workflows/integration-supabase.yml`
- Modify: `packages/stack/__tests__/live-coverage-guard.test.ts` (trim moved assertions)
- Delete: `packages/stack/__tests__/supabase-v3-pgrest-live.test.ts` (after porting)

**Adapter notes.** Build through the public `encryptedSupabaseV3(client, { schemas, databaseUrl })` so the shipped construction path — introspection, declared-schema merge, real `Encryption({ eqlVersion: 3 })` — is what runs. `supportedOps` = all except `order`; `alwaysRejectedOps = {'order'}` (PostgREST cannot emit `ORDER BY eql_v3.ord_term(col)`, and the adapter refuses by design). Synthesize what the builder lacks: `between` → `.gte(lo).lte(hi)`; `notBetween` → `.or('c.lt.lo,c.gt.hi')`; `notIn` → `.or('c.not.in.(…)')`.

**Single vs bulk.** `planRows` splits the value rows into disjoint halves: single = `{A, C}` via `.insert(obj)` (→ `encryptModel`), bulk = `{B, D}` via `.insert(array)` (→ `bulkEncryptModels`). The per-domain `eq`-over-every-row loop necessarily matches rows from both halves; on top of that, one explicit crossover assertion per family (a match-all predicate must return a superset of `{aSingle, aBulk}`) makes "the bulk path mangled a row" a red test rather than a coincidence.

**Rejection matrix, derived.**

```ts
const OPS_BY_CAPABILITY = {
  equality:       ['eq','ne','in','notIn'],
  orderAndRange:  ['gt','gte','lt','lte','between','notBetween','order'],
  freeTextSearch: ['contains'],
}
// isNull/isNotNull are structural, never capability-gated.
```

Flipping a capability flag must flip a positive test into a negative one. Verify this by perturbing `text_match` to `equality: true` and watching its `eq` test change from a passing rejection to a failing query.

**Why the wire suite survives.** `supabase-v3-pgrest-live.test.ts` is *not* superseded. It uniquely proves the `23514` rejection of a narrowed `encryptQuery`-shaped term (a shape the adapter cannot itself produce, so it must be hand-built), dense PostgREST parse edges, plaintext-passthrough containment on array/jsonb columns, and the grants as `anon`. The stub is the point: **no CipherStash credentials**, so it runs wherever the DB-only jobs run. Document the deliberate overlap at the top of the file, or someone will "clean up" one of the two.

**The two PR #535 fixes map here.** The raw `.filter(col,'in',[…])` element-wise encryption fix is covered by running every eq-capable domain through *both* `.in()` and the raw-filter path (`asRawFilter: true`) against the same oracle with real ciphertext. The PostgREST select-alias `Date` reconstruction fix is covered in the `date` and `timestamp` family files by asserting `select('row_key, ts:<col>')` yields a real `Date`; this needs a small `{ alias }` option on `SupabaseAdapter.run`, kept off the shared interface (Drizzle has no such concept).

**`live-coverage-guard.test.ts` must be trimmed in this same commit.** It asserts `LIVE_SUPABASE_PGREST_ENABLED` is true in CI; once these suites leave `tests.yml`, that job stops setting `PGRST_URL` and the guard goes red. Delete only the assertions whose suites moved; ~15 non-adapter live suites still use `LIVE_*`.

- [ ] **Step 1: Write `SupabaseAdapter`** against `encryptedSupabaseV3`
- [ ] **Step 2: Write one family file** (`integer`) and get it green against the supabase compose stack
- [ ] **Step 3: Verify the suite catches the #535 bugs** — revert only `packages/stack/src/supabase/`, confirm the raw-filter `in` and alias-`Date` tests go red, restore
- [ ] **Step 4: Verify the rejection matrix is derived** — perturb one capability flag, confirm the corresponding test flips, revert
- [ ] **Step 5: Fill in the remaining eight family files**
- [ ] **Step 6: Port `supabase-v3-pgrest-live.test.ts`** → `wire.integration.test.ts`, de-gated, with the overlap documented
- [ ] **Step 7: Trim `live-coverage-guard.test.ts`**; add `integration-supabase.yml`
- [ ] **Step 8: Run the full suite against `supabase/postgres`, then commit**

---

### Task 5: Port the Drizzle v3 suite onto the harness

**Files:**
- Create: `packages/stack/integration/drizzle-v3/adapter.ts` + nine `*.integration.test.ts`
- Create: `packages/stack/integration/drizzle-v3/relational.integration.test.ts`
- Create: `packages/stack/integration/matrix-sql.integration.test.ts` (ported)
- Create: `.github/workflows/integration-drizzle.yml`
- Delete: `packages/stack/__tests__/drizzle-v3/operators-live-pg.test.ts`, `__tests__/v3-matrix/matrix-live-pg.test.ts` (after porting)

The per-domain logic becomes `DrizzleAdapter` + `runFamilySuite`. The bespoke, non-family-shaped tests move to `relational.integration.test.ts`: plain-table joins, `exists`/`notExists` correlated subqueries, `limit`/`offset` pagination, `and`/`or`/`not` disjoint-predicate proofs, the statically-typed bigint round-trip, and the >4-value bulk in-list. Text-specific edge guards (short-needle rejection, astral `👍`, NFD normalization) are richer than the capability matrix and stay as bespoke assertions in the text family file.

`supportedOps` = all kinds; `alwaysRejectedOps` = ∅. Ordering uses `ORDER BY eql_v3.ord_term(col)`, safe because `_ord` is OPE.

`matrix-live-pg.test.ts` is **kept, not deleted for redundancy** — it tests the `eql_v3.*` SQL operators directly, independent of any ORM (`contained_by`, empty-string domain CHECK accept/reject, storage round-trip). It moves to `matrix-sql.integration.test.ts` and is de-gated.

This suite currently seeds only via `bulkEncryptModels`; the harness's single/bulk split closes that gap for free.

- [ ] **Step 1: Write `DrizzleAdapter`**
- [ ] **Step 2: Port one family file**, confirm parity with the assertions it replaces
- [ ] **Step 3: Fill in the remaining eight**
- [ ] **Step 4: Move the bespoke tests** into `relational.integration.test.ts`; confirm nothing is lost by diffing the `it(` titles against the original
- [ ] **Step 5: Port `matrix-live-pg.test.ts`** → `matrix-sql.integration.test.ts`, de-gated
- [ ] **Step 6: Delete the originals**; add `integration-drizzle.yml`
- [ ] **Step 7: Run both workflows' suites locally, then commit**

---

## CI

One workflow per adapter, not an adapter×db matrix: the cross-product is meaningless (each adapter is fixed to one DB variant), and `paths:` filters are per-workflow — a shared workflow would pull the ~2 GB `supabase/postgres` image on Drizzle-only PRs. Keep `strategy.matrix.db` as a one-element list so the shape is ready if that changes.

Both workflows: fork-PR gated via `if: github.event.pull_request.head.repo.full_name == github.repository` (a clean skip, as `prisma-next-e2e.yml` does); keep `require-cs-secrets` as a **fast pre-flight** before the docker pull; pass secrets via job-level `env:` rather than writing `.env` files (`dotenv/config` does not override an already-set `process.env`, so job env wins and ~5 `.env`-writing steps disappear).

## Verification

Observed, not assumed.

1. **Harness boots.** `docker compose -f local/docker-compose.supabase.yml up -d --wait`, `stash eql install --eql-version 3`, then `eql_v3.version()` matches the pinned release and `curl -s localhost:3000/ | jq '.paths|keys'` lists the test table.
2. **Loud failure works.** Run with `PGRST_URL` unset → fails with the actionable message; does **not** skip green.
3. **Profile fallback works.** Unset all four `CS_*` with `~/.cipherstash` present → suite runs. Move the profile aside → suite fails loudly.
4. **The suite catches the bugs it exists for.** Revert only `packages/stack/src/supabase/` and re-run: the raw-filter `in` tests and the alias-`Date` tests must go red. (This is how the current PR #535 fixes were validated — 4 of 6 live tests failed against unfixed source.)
5. **The rejection matrix is derived, not decorative.** Give `text_match` `equality: true` → its `eq` test must turn from a passing rejection into a failing query. Revert.
6. **Ordering works on the managed-Postgres variant.** `asc`/`desc` on an `_ord` (OPE) column returns true plaintext order against `supabase/postgres`.
7. **CI shape.** `pnpm test` at the repo root runs zero integration tests; a fork PR shows the integration jobs as *skipped*, not failed.

## Follow-ups queued after PR1

Both are consequences of PR1, and both are about the same thing: a skipped test reads exactly like a passing one.

**Remove the `LIVE_*` gates and the 16 unit-suite skips.** `__tests__/helpers/live-gate.ts` still turns `LIVE_CIPHERSTASH_ENABLED`, `LIVE_EQL_V3_PG_ENABLED`, `LIVE_PG_ENABLED` and `LIVE_LOCK_CONTEXT_ENABLED` into `describe.skip`. `live-coverage-guard.test.ts` exists *only* because a false gate is a silent whole-suite skip on a green job. Move those suites into the integration jobs — which throw rather than skip — then delete both files, and extend `no-skips-reporter.ts` to the unit config once it is clean.

**Port the remaining live suites onto the shared harness.** Still bypassing it: `drizzle-v3/operators-null-live-pg`, `drizzle-v3/operators-lock-context-live-pg`, `v3-matrix/matrix-live*`, `schema-v3-pg`, `supabase-v3-grants-pg`, `supabase-v3-introspect-pg`. Each gets the shared env gate and no skips. This is also where the **superuser-only ORE suite** lands — the one the catalog's `deferred` field points at, covering the nine `_ord_ore` domains that cannot hold data on managed Postgres.

## PR2 — type robustness (outline)

Import the canonical per-domain types from `@cipherstash/eql` and thread them through. Stop typing `OperandEncryptionClient.encrypt`/`bulkEncrypt` as returning `unknown` (`eql/v3/drizzle/operators.ts:51,55`); stop collapsing `Result<…>` to `{ data?: unknown }` (`:94-101`); stop returning `Promise<unknown[]>` from `encryptOperands` and from `encryptCollectedTerms`/`bulkEncryptGroup`/`encryptGroupPerTerm` (`supabase/query-builder-v3.ts:393,433,463`). Where a `JSON.stringify` is genuinely required at the SQL boundary, it should serialize a *typed* envelope, not an `unknown`. The PR1 suite is what makes this safe to attempt.

## PR3 — adapter package split (outline)

```
@cipherstash/stack            (core)
@cipherstash/stack-drizzle    deps: stack   ← stack/src/drizzle (v2) + src/eql/v3/drizzle
@cipherstash/stack-supabase   deps: stack   ← stack/src/supabase
@cipherstash/prisma-next      deps: stack   (existing precedent)

@cipherstash/drizzle@3.x      peer: @cipherstash/protect@12  — untouched, maintenance
```

stack does **not** re-export the new packages, so no build cycle arises — the shape `@cipherstash/prisma-next` already proves in production. `@cipherstash/protect` is succeeded by stack, so `@cipherstash/drizzle@3.x` and `packages/protect` enter maintenance and the two forked Drizzle implementations stop diverging by attrition. Once protect sunsets, `stack-drizzle` can reclaim the `@cipherstash/drizzle` name in a major — do not attempt that now.

Work: promote nine internal stack modules to public API; drop `./drizzle`, `./supabase`, `./eql/v3/drizzle` from `exports`/`typesVersions`/`tsup.config.ts` (stack is 0.19.0, so a minor bump carries the break under 0.x semver); update 15 doc/skill references; move the integration suites into the new packages; follow the `fta-v3.yml` complexity gate to the moved code or it silently loses its gate.

## PR4 — v3 JSON (outline)

Add a `'json'` `cast_as` kind and a `types.Json()` column to the core v3 schema, backed by `public.eql_v3_json` / `public.eql_v3_jsonb_entry` and the bundle's 56 ste_vec functions. Surface the query operations (`jsonb_path_exists`, selectors, containment) on both adapters. `eql/v3/drizzle/codec.ts:38` already decodes SteVec documents, so the read path is partly there. Add a `json` family file to the existing matrix. v3 only — v2 `searchableJson` is not a priority.

## Risks

- **Split blast radius (PR3).** Nine internal modules become public API, two published subpaths disappear, 15 doc references change. If any module is too internal to expose, relocate the shared piece to `packages/schema` or the test kit — a design call to make before coding, not during.
- **Two Drizzle implementations stay forked** until protect sunsets. Anyone fixing a bug in one should check the other; worth a comment atop both operator files.
- **`supabase/postgres` is ~2 GB.** Pin by digest, lean on the Blacksmith layer cache, rely on path-filtered triggering. If CI minutes bite, `postgres-eql` + `postgrest-roles.sql` reproduces the role surface at ~10% of the size — revisit then, not now.
- **CLI-based install adds a build step** (`turbo run build --filter stash`) to every integration job. Worth it: it is the only thing that tests the installer.
- **Source-aliasing stack's public surface in vitest** is the price of one shared catalog plus a working `instanceof`. Centralize it in `vitest.shared.ts` rather than copy-pasting.
- **Deliberate overlap** between the stub wire suite and the real-crypto matrix must be documented, or it will be "cleaned up".

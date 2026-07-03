# EQL v3 Supabase integration — design

**Status:** proposed
**Date:** 2026-07-03
**Stacks on:** `feat/eql-v3-types-module` (the `@cipherstash/stack/eql/v3` + `types.*`
refactor). All code here is authored against the final `eql/v3` surface.

## Core principle

**v3 on Supabase mirrors v2 exactly. The EQL implementation is unchanged; only the
column *types* differ** (v2's single composite `eql_v2_encrypted` → v3's per-domain
`eql_v3.*`). The query mechanism, the operator behaviour, the Supabase caveats, and
the install/permissions story are all **the same as v2**. This is not a new query
architecture — it is the v2 adapter taught about v3 types.

Everything below serves that principle. Where an earlier draft proposed a distinct
v3 query path (function pattern / generated index columns / RPC), that is dropped:
it tried to eliminate a Supabase operator-visibility caveat that **v2 already lives
with**, and it did not even help the one case (ORE range) it was invoked for.

## Context

`@cipherstash/stack/supabase` (`encryptedSupabase`) is **EQL v2 only**: it wraps a
supabase-js query builder, transparently encrypts mutations, `::jsonb`-casts
encrypted columns on select, encrypts filter terms, and decrypts results. It is
typed against the v2 schema and stores data in `eql_v2_encrypted (data jsonb)`.

EQL v3 keeps the identical runtime and index terms (hmac/bloom/ORE) but stores each
column in its **native `eql_v3.*` domain** (`text_eq`, `int4_ord`, `text_search`,
…), a `DOMAIN … AS jsonb` with a CHECK. The v3 authoring DSL
(`@cipherstash/stack/eql/v3`, `types.*`) and typed client
(`@cipherstash/stack/v3`, `EncryptionV3`) exist; **no Supabase support for v3 exists
yet** — neither the adapter nor the install path.

**Goal:** v3 on Supabase at parity with v2, using native `eql_v3.*` domains.
**Out of scope:** the plaintext→encrypted migration lifecycle (rollout / dual-write
/ backfill / cutover) — a later increment.

## Verified findings (inspection + live Supabase spikes)

### The v2 query mechanism — the baseline v3 copies
- v2 filters via **direct EQL operators**: `applyFilters` calls `q.eq/gt/gte/…(col,
  term)` (`query-builder.ts:777`), PostgREST emits `col <op> term`, resolved by the
  custom operator on `eql_v2_encrypted` (equality → `eql_v2.eq` = `hmac_256(a) =
  hmac_256(b)`; range → the ORE operator).
- **Verified on a real Supabase project:** with the schema exposed + grants applied,
  the custom operators **resolve over PostgREST as `anon`**:
  - equality `.eq()` → matches by hmac (`same-hm/diff-payload` hit, `diff-hm` miss).
    Corroborated by the shipped v2 suite (`supabase.test.ts` filters `.eq()` on an
    encrypted `age` column).
  - range `.gte()`/`.gt()` → the custom **ORE** operator resolves (it errored
    *inside* the ORE compare fn on synthetic ORE bytes — proof of resolution, not
    fallback; a real ZeroKMS ORE term compares correctly). **Caveat on the evidence:**
    the existing v2 suite has **no** range test (it only exercises `.eq()`), so this
    resolution result rests solely on the live spike — there is no CI-covered v2
    baseline for encrypted range on Supabase. See the test plan (C).
- **Caveats (shared by v2 and v3, accepted):**
  - **No operator families on Supabase** (they need superuser) → **no index
    acceleration and no `ORDER BY`** on the encrypted type. Range *filtering*
    (`WHERE col >= term`) works; sorting does not. (Forward path: **OPE index terms
    are in active development that *do* work on Supabase** — natively orderable,
    built-in comparison, btree + `ORDER BY`. Out of scope here; this increment
    targets ORE parity with v2.)
  - **Operator visibility requires exposing the schema.** For a bare `col <op>
    term` to reach the custom operator, the EQL schema must be on PostgREST's
    request-time search_path — i.e. added to the dashboard's **Exposed schemas**
    setting (Supabase [custom-schemas guide](https://supabase.com/docs/guides/api/using-custom-schemas)).
    If missing, operators do not error — they silently fall back to base-type
    comparison (wrong results). **This is a v2 caveat too** (v2's operators live in
    `eql_v2`); v3 inherits it unchanged. The CLI automates the grants (below) but
    **not** the Exposed-schemas step, which is a manual dashboard action for both
    versions.

### The v2 adapter coupling points (what the v3 dialect must fork)
1. **Type signature** — `.from(tableName, schema)` accepts only v2
   `EncryptedTable<EncryptedTableColumn>` (`src/supabase/index.ts:49`).
2. **Column gate** — `getColumnMap()` keeps columns via `instanceof EncryptedColumn`
   (v2 class, `query-builder.ts:1018`); v3 columns are `EncryptedV3Column` and would
   be silently dropped → every v3 filter skipped.
3. **Mutation encoding** — v2 wraps values with `encryptedToPgComposite` → the
   **object** `{ data: <payload> }` (JSON body → the `eql_v2_encrypted` composite).
4. **Query-term encoding** — v2 uses `returnType: 'composite-literal'` → `("json")`.
5. **Decrypt** — `decryptResults` calls `decryptModel`/`bulkDecryptModels`; it does
   **not** reconstruct `Date` from `cast_as`.

`helpers.ts` (`getEncryptedColumnNames`, `addJsonbCasts`, `mapFilterOpToQueryType`)
is already version-agnostic (`schema.build().columns` + string ops).

### The v3 domains (spike-verified against `eql_v3` in Postgres)
- `CREATE DOMAIN eql_v3.<name> AS jsonb` with a CHECK requiring `v:2` + the index
  keys for the domain (`text_eq`→`hm`; `int4_ord`→`ob`; `text_search`→`hm`+`ob`+`bf`).
- Custom operators exist for `(domain, domain)`, `(domain, jsonb)`, `(jsonb,
  domain)` for `=,<,<=,>,>=` — the v3 analogues of v2's operators.
- **Insert** a plain jsonb payload → works via implicit assignment cast (no
  composite wrap). **Select** `col::jsonb` is a no-op widening (domain *is* jsonb).
- **One v3-only wrinkle — the `text_search` domain CHECK.** Because `text_search` is
  multi-capability, its CHECK demands `hm`+`ob`+`bf` in **any** value coerced to it,
  including a query operand. An **equality** query term for a `text_search` column
  carries only `hm`, so `col = term` fires `23514 text_search_check`. This affects
  **only** the multi-capability `text_search` column queried by equality — every
  single-capability domain's term satisfies its own CHECK (e.g. an `int4_ord` range
  term carries `ob`, which is exactly what `int4_ord` requires). Fix in the adapter:
  for a `text_search` equality filter, build the operand from the **full** encrypted
  envelope (which carries `hm`+`ob`+`bf`, satisfies the CHECK, and still matches by
  `hm`) rather than the narrowed equality-only term. Proven on Supabase: a
  full-shaped term matched by hmac; a partial one raised `23514`.

### Install & bundle gaps
- The only checked-in v3 SQL is `packages/stack/__tests__/fixtures/eql-v3/
  cipherstash-encrypt-v3.sql` — a 28k-line monolith under `__tests__/fixtures/`, not
  `packages/cli/src/sql/` where shipped v2 bundles live. It contains exactly **2**
  `CREATE OPERATOR CLASS`/`FAMILY` statements (btree accel on the ORE composites) —
  plain SQL, but needing privileges Supabase lacks, so excluded from a Supabase
  build. Installing the opclass-stripped bundle on real Supabase **succeeds
  non-superuser** (verified); the full bundle fails on those two chunks.
- The CLI installer is v2-only (`installer/index.ts:362-370`) — no v3 path, no
  `--supabase` for v3.
- **Grants exist and are parameterized.** `SUPABASE_PERMISSIONS_SQL`
  (`installer/index.ts:22-28`) grants `USAGE`/`EXECUTE`/… to `anon, authenticated,
  service_role`, keyed by `EQL_SCHEMA_NAME`, applied as a separate install step and
  reused in generated migrations. Without it, encrypted queries fail `42501`
  (verified for both v2 and v3). v3 reuses this block keyed to `eql_v3`.
  > Provenance: the Exposed-schemas + grants recipe was documented at
  > `docs/reference/supabase-sdk.md` ("Exposing EQL schema", `ee56fb68`, 2025-05-30)
  > but that file was **deleted** in `def9f4bd`; it survives only in git history and
  > on the CipherStash docs site. Cite the Supabase guide, not the deleted file.

## Design

### A. SDK adapter — `encryptedSupabaseV3`

A dedicated typed entry mirroring `EncryptionV3` / `@cipherstash/stack/v3` (keeps the
"no v2 regression" mandate airtight and matches the established v3 pattern).

```ts
import { Encryption } from '@cipherstash/stack'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { encryptedSupabaseV3 } from '@cipherstash/stack/supabase'

const users = encryptedTable('users', {
  email:  types.TextSearch('email'),  // eql_v3.text_search
  amount: types.Int4Ord('amount'),    // eql_v3.int4_ord
})
const client = await Encryption({ schemas: [users] })
const es = encryptedSupabaseV3({ encryptionClient: client, supabaseClient })

await es.from('users', users).insert({ email: 'a@b.com', amount: 30 })
await es.from('users', users).select('id, email, amount').eq('email', 'a@b.com')
await es.from('users', users).select('id, amount').gte('amount', 10).lte('amount', 100)
```

The **public surface and call shape are identical to v2** — `.eq/.neq/.in/.like/
.ilike/.gt/.gte/.lt/.lte/.match/.or/.not/.filter`, `withLockContext`, `audit`. Only
the schema type and the internal encoding differ.

- `encryptedSupabaseV3({ encryptionClient, supabaseClient })` — accepts a plain
  `EncryptionClient` (built via `Encryption({ schemas: [v3tables] })`), exactly like
  v2. Strong typing comes from the `.from` generic, not the client.
- `.from<Table extends AnyV3Table>(tableName, table)` → a builder typed via
  `InferPlaintext<Table>` (rows) with filter methods constrained to
  `QueryableColumnsOf<Table>`.

**Make `EncryptedQueryBuilderImpl` version-aware via a small internal `dialect`**
selected by the factory (`encryptedSupabase` → v2, `encryptedSupabaseV3` → v3). v2
paths are byte-for-byte unchanged. The forks — all narrow, because the query
*mechanism* is shared:
- **Column recognition** — retain `EncryptedV3Column` too (dual `instanceof` or a
  duck-typed `getEqlType`/`build` check), not just the v2 class.
- **Property↔DB name** — resolve via the table's `buildColumnKeyMap()` where the
  builder assumes `property === dbName`, so camelCase/snake_case v3 schemas work.
- **Mutation encoding** — v3 sends the **raw encrypted payload object** (no `{data}`
  wrap); supabase-js serializes it into the jsonb domain column.
- **Query-term encoding** — v3 sends the **raw jsonb term** (not the `("json")`
  composite literal); the v3 operators compare it, the same way v2's composite
  operators compare the composite literal. Note Postgres may resolve `col <op> term`
  to the `(domain, domain)` form and **coerce the operand into the domain** (rather
  than the `(domain, jsonb)` form) — which is exactly why the `text_search` equality
  operand must be full-shaped (below): the coerced operand has to satisfy the domain
  CHECK. For every single-capability domain the coercion is harmless (the term
  already satisfies that domain's CHECK).
- **`text_search` equality operand** — build from the full envelope (see the
  `text_search` wrinkle above) so it satisfies the domain CHECK. This is the *only*
  place v3 filtering deviates in substance from v2.
- **Decrypt** — the v3 branch (only) ports `reconstructRow` (`encryption/v3.ts`) to
  rebuild `Date` from `cast_as: 'date'` via `buildColumnKeyMap()` (a v3-only method;
  v2 never calls it).
- **Select casts** — unchanged (`addJsonbCasts`, `::jsonb`), valid for both.

Same caveats as v2 carry over untouched: encrypted **`ORDER BY` is unsupported** on
Supabase (no operator families); range **filtering** works; correctness of the bare
operators depends on the schema being exposed (below).

### B. DB bundle + install (native domains) — same shape as v2

1. **v3 Supabase SQL bundle.** An unowned, vendored artifact like the v2 bundles.
   Preferred: regenerate from upstream `encrypt-query-language` with its Supabase
   build variant (opclass-excluded) and vendor as
   `packages/cli/src/sql/cipherstash-encrypt-v3-supabase.sql`, recording the upstream
   version. Fallback: strip the two `CREATE OPERATOR CLASS/FAMILY` chunks from the
   monolith and vendor that (temporary; note the sync risk). The full
   (opclass-bearing) v3 bundle also needs a `packages/cli/src/sql/` home for
   non-Supabase installs. The bundle forward-references its base types like the v2
   bundle, so the install path bootstraps in the same order.
2. **v3 install path.** Extend the installer to select the v3 bundle honoring
   `--supabase` (opclass-stripped variant) + non-superuser fallback, mirroring v2's
   `resolveBundledFilename`. Apply **`SUPABASE_PERMISSIONS_SQL` keyed to `eql_v3`**
   (generalize `EQL_SCHEMA_NAME` / the permissions helper to take the schema so v2
   and v3 share one source of truth). Make `installEqlV3IfNeeded` Supabase-aware.
3. **Exposed schemas.** Document (and, where the CLI generates a migration, note)
   the manual "add `eql_v3` to Exposed schemas" step — identical to the v2
   requirement — since it's what makes the operators resolve.
4. **Per-column DDL.** A v3 column is declared with its native domain, e.g.
   `ADD COLUMN email eql_v3.text_search;`, from `column.getEqlType()`. Document the
   `types.*` → `eql_v3.<name>` mapping.

### C. Tests, docs, release
- **Live integration suite** — mirror `packages/stack/__tests__/supabase.test.ts`
  for a v3 schema, same env-gating: insert+select round-trip; model round-trip
  **including a `Timestamptz`/`Date` column** (proves `reconstructRow`); bulk models;
  and encrypted **operator** filters — `text_search` equality (with the full-term
  operand) and `freeTextSearch`, `int4_ord` equality and **range** (`.gte/.lte`).
  Range needs real ORE terms, so the range assertions require live `CS_*` creds
  (same as the existing v3 PG suite); assert filtering, not `ORDER BY`.
  **The v3 range test is first-of-its-kind coverage:** the v2 suite never tested
  encrypted range on Supabase, so there is no v2 baseline to mirror for it. Add a
  matching **v2** range test (`.gte/.lte` on an encrypted numeric) in the same suite
  so the "parity with v2" claim is backed by CI rather than by the one-off spike.
- **Type-level tests** (`*.test-d.ts`) — v3 builder strongly typed; v2
  `encryptedSupabase` types unchanged.
- **Docs** — extend `skills/stash-supabase/SKILL.md`; **(re)create**
  `docs/reference/supabase-sdk.md` (deleted in `def9f4bd`; AGENTS.md's "Useful
  Links" is a dangling reference to fix) covering `encryptedSupabaseV3`, native
  domain DDL, the Exposed-schemas + grants setup, and the shared caveats (no
  `ORDER BY`; ORE range filter-only). Note the in-development OPE path for future
  native ordering.
- **Changeset** — minor for `@cipherstash/stack`.

## Units and boundaries
- **`encryptedSupabaseV3` factory** — thin; builds the shared builder in v3 dialect.
- **`EncryptedQueryBuilderImpl` + `dialect`** — the single, narrow v2/v3 fork
  (column recognition, encodings, `reconstructRow`, `text_search` operand). Filter
  collection, select building, operator application, and PostgREST execution are
  **shared and unchanged** — the query mechanism is v2's.
- **v3 Supabase bundle + grants** — install `eql_v3` domains (opclass-stripped) +
  `SUPABASE_PERMISSIONS_SQL` keyed to `eql_v3`.
- **installer v3 path** — selects the bundle + applies grants; mirrors v2.

## Risks
- **Operator visibility (shared with v2).** Bare operators resolve only when the EQL
  schema is exposed; if not, silent fallback → **wrong rows with no error** — the
  worst failure mode for an encryption layer, behind an uncodified manual dashboard
  step. Because it fails silently, documentation alone is not enough: **ship a
  post-install verification query** (insert a known term, filter for it, assert the
  hit) and, ideally, an install-time probe that warns when the schema is not exposed.
  This is a firm deliverable, not a "consider" — and it retroactively protects v2
  too (a cross-cutting improvement, not v3-specific).
- **ORE range needs live creds to test** — synthetic ORE terms can't validate
  ordering. The live range assertions are `CS_*`-gated.
- **v3 Supabase bundle is external/unowned** — provenance and re-sync must be named.
- **Base worktree uncommitted** — stacks on `feat/eql-v3-types-module`.

## Open questions
- **Branch/commit placement** — new branch off `feat/eql-v3-types-module` (once it
  commits) vs the current branch. Spec is written to the current tree; movable.
- **`text_search` equality operand** — confirm with a real `encryptQuery` that the
  full-envelope operand is the cleanest way to satisfy the CHECK (vs any SDK option
  to emit a non-narrowed term). Small; not blocking the design.

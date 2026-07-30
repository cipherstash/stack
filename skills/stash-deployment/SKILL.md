---
name: stash-deployment
description: Deploy a CipherStash encryption rollout to a live environment without losing data — the multi-deploy ladder (schema-add + dual-write → backfill → read cutover → stop dual-writes → drop plaintext), why each deploy boundary exists, what breaks if stages are merged, rollback per stage, and how to get CS_* credentials into a build and a runtime. Includes a Prisma Postgres / Prisma Compute section covering push-to-deploy, build-time credential requirements, destructive-migration policy, preview-branch databases, and running backfills against a hosted database. Use when shipping encryption to staging or production, planning the PR sequence for an encryption rollout, wiring deploy credentials, or deploying a CipherStash app to Prisma Compute.
---

# Stash Deployment

Encrypting a column that already holds live data is a **deployment problem**, not a
schema problem. The schema change is trivial; the danger is the window between
"the database can hold ciphertext" and "the application reads ciphertext". Getting
that window wrong loses data silently — rows written during the gap keep only
plaintext, or keep only ciphertext nobody can decrypt, and nothing errors until a
user reads the row.

This skill covers how to sequence that across deploys. For the API and the
lifecycle model see `stash-encryption`; for the commands see `stash-cli`; for
framework specifics see `stash-drizzle` / `stash-supabase` / `stash-prisma-next`.

Everything here describes **EQL v3**, the only authoring generation. The EQL v2
rollout commands were removed — `stash encrypt cutover` (the old v2 rename swap)
now exits with an error on every project. A column that started under v2
finishes the same way as v3: complete the backfill, switch reads to the
encrypted column by name, then `stash encrypt drop`. Legacy v2 payloads remain
readable; `stash-encryption` covers that.

> **Runner note.** `stash init` adds `stash` to the project as a dev dependency,
> so the bare `stash <command>` form used below runs through whichever package
> manager the project uses. Before init has run, prefix with your package
> manager's one-shot runner (`bunx`, `pnpm dlx`, `yarn dlx`, `npx`). The same
> substitution applies to the `prisma-next` and `@prisma/cli` invocations in the
> Prisma section.

## When to Use This Skill

- Planning the PR / deploy sequence for encrypting an existing column
- Shipping an encryption rollout to staging or production
- Running a backfill against a hosted (not local) database
- Getting `CS_*` credentials into a build pipeline and a deployed runtime
- Deploying a CipherStash app to **Prisma Postgres / Prisma Compute**
- Diagnosing a failed deploy, a failed migration, or rows that won't decrypt

## The rule

> **A column goes from plaintext to encrypted across at least four deploys, never one.**

Not a style preference. There is no atomic operation that replaces a populated
plaintext column with an encrypted one, because **ciphertext can only be produced
by the application**, client-side, holding your keys. No `UPDATE`, no migration,
no database-side function can encrypt an existing row. So the plaintext column must
stay authoritative — and stay populated — until every row has a ciphertext twin and
the deployed code is reading it.

Any plan that adds an encrypted column and drops the plaintext one in the same
deploy loses data. Any plan that backfills before dual-writes are live in
production loses the rows written during the backfill. The ladder below is the
minimum safe shape.

## The deployment ladder

```text
 DEPLOY 1     rollout           + encrypted twin (nullable) + dual-write
                                everywhere; reads unchanged

   ⛔ GATE 1  dual-writes live in the environment that owns the database

 out-of-band  BACKFILL          encrypt historical rows, against the prod DB
 migration    indexes           eql_v3.* extractor indexes + ANALYZE, shipped
                                through the integration's migration flow

 DEPLOY 2     read cutover      reads → encrypted column, decrypt at the
                                boundary; dual-writes stay

   ⛔ GATE 2  soak — real traffic reads decrypt correctly

 DEPLOY 3     stop dual-write   writes → encrypted column only; plaintext
                                column stays, now unwritten

   ⛔ GATE 3  Deploy 3 live everywhere; coverage re-checked

 DEPLOY 4     drop plaintext    drop the plaintext column (+ NOT NULL on
                                encrypted), guarded by an apply-time
                                coverage re-check
```

Four deploys, with the backfill and index build between the first two. Each gate
is a human decision, not a pipeline step.

### Deploy 0 — prepare the environment (optional, do it early)

Before any application change, make sure the target environment can encrypt at all:

- **EQL installed** in the target database. Direct install is `stash eql install`;
  **Drizzle** generates an install migration instead (apply it with
  `drizzle-kit migrate`), and **Prisma Next** installs it through the migration
  graph (`prisma-next migrate`).
- **`CS_*` credentials present** in the environment, minted with
  `stash env --name <app>-<env>`. On most platforms these are needed at **build**
  time as well as run time (see [Credentials](#credentials-in-a-deployed-environment)).
- **Bundling handled.** The default `@cipherstash/stack` entry wraps a native
  FFI module — exclude it from bundling (`serverExternalPackages`, esbuild
  `external`, …). On runtimes that cannot load native modules at all
  (Cloudflare Workers, Deno, Supabase Edge Functions), bundle
  `@cipherstash/stack/wasm-inline` instead — it inlines the WASM build, no
  externalization needed. See `stash-edge`.

Shipping this as its own deploy is cheap and de-risks Deploy 1: a credential or
bundling problem surfaces while nothing depends on encryption yet.

### Deploy 1 — rollout: encrypted twin + dual-write

One PR, one deploy. It changes what the app **writes**, never what it reads.

| Change | Detail |
|---|---|
| Migration | Add `<col>_encrypted` as a **nullable** encrypted column alongside the untouched plaintext `<col>`. Nullable is mandatory — existing rows have no ciphertext yet. |
| Code | Every persistence path that mutates the row writes **both** columns, in the same transaction, on every code branch. |
| Reads | Unchanged. Still plaintext. |

**"Dual-write" means every path.** Not the ORM model, not the main service — every
site. A CSV importer, an admin action, a background job, a webhook handler, a raw
SQL fixup script: one missed branch means rows created in production after this
deploy have no ciphertext, and the backfill (which ran earlier) will not catch them.
Grep for every writer of the plaintext column before merging.

After this deploy the system is in a safe steady state and can stay there
indefinitely. New rows are fully encrypted; old rows are not; reads work either way.

### ⛔ Gate 1 — dual-writes must be live *in the environment that owns the database*

Not on a laptop. Not in CI. In the deployed environment whose traffic writes to the
database you are about to backfill. Verify with `stash status` before continuing;
`stash impl` will refuse a cutover plan whose columns have no `dual_writing` event
in `cs_migrations`, and `stash encrypt backfill` prompts for the same confirmation
(`--confirm-dual-writes-deployed` in CI).

### Out-of-band — backfill

Not a deploy. A one-off job run against the production database, encrypting the
historical rows that predate Deploy 1.

```bash
stash encrypt backfill --table users --column email
```

Paginated by primary key, one transactional `UPDATE` per chunk plus a checkpoint,
SIGINT-safe, idempotent on re-run. Concurrent production writes are safe **because
dual-writes are live** — that is the entire reason for Gate 1.

Two hard requirements:

- **Encrypt under the same keyset the deployed app uses.** The credentials do
  not have to be identical — any client **bound** to that keyset works; a mere
  grant is not enough, because encrypt always lands under the client's bound
  keyset — but the ciphertext must land under the keyset the app resolves.
  Nothing fails at write time; what breaks at read time depends on grants:
  with no grant the app **cannot decrypt** those rows, and if the app *is*
  granted the stray keyset it decrypts them fine while its encrypted searches
  **silently miss them** (the routing asymmetry `stash-zerokms` documents).
  The trap: `CS_*` env
  vars beat the local `~/.cipherstash` profile, so a backfill that silently
  authenticates as your laptop profile can resolve a different keyset. Exporting
  the app's own `CS_*` vars for the run is the simplest way to guarantee a
  match. Keysets and grants: `stash-zerokms`; credential resolution order:
  `stash-auth`.
- **Verify coverage before moving on.** Count rows where the plaintext column is
  non-null and the encrypted column is null. It must be zero.

Then **build the `eql_v3.*` extractor indexes** for every capability you query and
`ANALYZE` — after backfill, before the read switch. One bulk build instead of per-row
index maintenance during the backfill, and the switched reads engage an index from
the first query. Ship the DDL through whatever migration flow owns the schema —
a Drizzle or Supabase migration, an index migration in the Prisma Next graph
(never out-of-band there — see `stash-prisma-next`), or your SQL migration tool.
Never ad-hoc against production. Recipes in `stash-indexing`.

### Deploy 2 — read cutover

Reads move to the encrypted column; writes still go to both.

| Change | Detail |
|---|---|
| Queries | Point them at the encrypted column **by name** (`<col>_encrypted`) and filter/sort through the encrypted operators. |
| Reads | Decrypt at the boundary before returning values to callers. Skipping this returns raw EQL payloads to end users. |
| Writes | **Still dual-write.** Do not remove it yet. |

There is no rename and no CLI step here — this deploy is application code only.
(There is no cutover command: `stash encrypt cutover` was the EQL v2 rename swap
and has been **removed** — running it exits with an error pointing at this
manual path.)

Keeping dual-writes through this deploy is what makes it reversible: if reads
misbehave, Deploy 2 reverts to plaintext reads and every row is still correct
in both columns.

### ⛔ Gate 2 — soak

Let real traffic read the encrypted column. Confirm results are correct — not just
non-empty: check ordering, range filters, and free-text matches against known rows.
Re-check coverage (still zero plaintext-only rows; new writes are covered by
dual-writes). Only then ship Deploy 3.

### Deploy 3 — stop writing the plaintext column

Remove the dual-write logic: writes now target only the encrypted column. The
plaintext column stays in place, unwritten. If the original column is `NOT NULL`,
this deploy's migration must relax that (`DROP NOT NULL`) — otherwise inserts
fail the moment dual-writes stop.

This is the deploy that ends easy reversibility: rows written after it have no
plaintext value, so reverting reads back to the plaintext column is no longer
safe. That is why Gate 2's soak comes first.

**Do not fold the drop into this deploy.** Most pipelines apply migrations before
the new code is live — a drop migration riding alongside the dual-write removal
executes while the previous deploy's still-dual-writing code is serving traffic,
and every insert and update fails against a column that no longer exists.

### ⛔ Gate 3 — nothing writes plaintext anymore

Deploy 3 must be live on **every** instance (rolling deploys included), and
coverage re-checked one last time: zero rows with plaintext and no ciphertext.
Only then is the drop safe.

### Deploy 4 — drop the plaintext column

Irreversible — every earlier stage can be walked back (see
[Rollback per stage](#rollback-per-stage)). This deploy is migration-only:
the application stopped touching the column in Deploy 3.

| Change | Detail |
|---|---|
| Migration | Drop the plaintext column, and (optionally) `SET NOT NULL` on the encrypted one. |

Generate the drop rather than hand-writing it where the tooling can:
`stash encrypt drop --table users --column email` emits a migration whose SQL takes
`ACCESS EXCLUSIVE` on the table, **re-counts uncovered rows at apply time**, and
raises instead of dropping if any remain. That re-check matters: the coverage you
verified at planning time is not the coverage at apply time.

If you author the drop by hand (some integrations require it — see the Prisma Next
notes below), reproduce that property: the drop and the coverage check must be in
**one transaction**, so a failed check rolls the drop back.

## Why the boundaries are non-negotiable

| Shortcut | What actually happens |
|---|---|
| Twin column + dual-write + backfill + read switch in one deploy | Rows written between migration-apply and code-live have no ciphertext. Reads return null/garbage for them. |
| Backfill before dual-writes are live in production | Every row written during and after the backfill window stays plaintext-only. Silent; found later by a user. |
| Backfill under credentials that resolve a different keyset (e.g. the laptop profile) | Ciphertext lands under the wrong keyset. No error at write time; in production the app either cannot decrypt those rows (no grant) or — if granted that keyset — decrypts them fine while encrypted search silently misses them. |
| Drop plaintext in the same deploy as the read switch | No rollback. If the read path is wrong, the source data is already gone. |
| Drop plaintext in the same deploy that removes dual-writes | Migrations usually apply before the new code is live: the still-deployed dual-writing code writes to a dropped column, and every insert/update fails until the rollout completes. |
| Drop without an apply-time coverage re-check | Rows written by a missed dual-write path are destroyed by the drop. |
| `NOT NULL` on the encrypted column before coverage is proven | Migration fails mid-deploy, or (worse) succeeds and the drop already ran. |

## Rollback per stage

| Stage | Rollback |
|---|---|
| Deploy 1 | Revert the code. Extra nullable column is inert; leave it. |
| Backfill | Nothing to undo — it only fills nulls. Re-runnable. |
| Deploy 2 | Revert the code; reads return to plaintext. Both columns still correct. |
| Deploy 3 | Revert the code; dual-writes resume. But rows written while it was live have no plaintext — reverting Deploy 2 after this point is unsafe. |
| Deploy 4 | **None.** The plaintext is gone. This is why Gates 2 and 3 exist. |

## Credentials in a deployed environment

Mint per-environment credentials from your device session:

```bash
stash env --name my-app-prod            # prints the four CS_* vars to stdout
stash env --name my-app-prod --json     # NDJSON, no prompts, for CI
```

```dotenv
CS_WORKSPACE_CRN=crn:<region>:<workspace-id>
CS_CLIENT_ID=<uuid>
CS_CLIENT_KEY=<hex>
CS_CLIENT_ACCESS_KEY=CSAK…
```

Rules that bite in practice:

- **The access key is shown exactly once.** Pipe it straight into the platform's
  secret store; it cannot be re-revealed. Stdout is pipe-clean (progress goes to
  stderr), so `stash env --name x | <secret-store-cli>` is safe.
- **Mint one credential per environment.** Preview and production are separate
  `--name` values. Each run mints a new credential; duplicate names are rejected.
- **Credentials are often needed at BUILD time, not just run time.** If the
  encryption client is constructed at module load — and it usually is, in a
  `db.ts`-style singleton — then any build step that imports that module
  authenticates during the build. Static-generation and page-data collection do
  exactly this. A build without `CS_*` fails with `Not authenticated`. Local builds
  mask it, because the `~/.cipherstash` device profile authenticates silently.
- **Keyset consistency governs decryptability and searchability.** Everything that
  writes ciphertext for an environment — the app, the backfill, one-off scripts —
  must resolve to the same keyset; the credentials themselves may differ, provided
  each client is **bound** to that keyset (a grant alone routes only decrypt).
  Mismatches are silent at write time. The model lives in `stash-zerokms`.
- **Never print or log the values.** They are secrets, and so is any one-time
  database connection URL used alongside them.

## Running one-off jobs against a hosted database

Backfills, coverage checks, and manual migrations need a plain Postgres connection
to the **exact** database the deployed app uses. Two things go wrong here:

1. **Targeting the wrong database.** Preview/branch environments usually have their
   own databases with confusingly similar names. Confirm the identity of the target
   before running anything — a job that succeeds against the wrong database looks
   like success and fixes nothing.
2. **Targeting the right database with the wrong keys.** See the keyset note above.

Run these as explicit, reviewed steps. Do not wire them into the deploy pipeline:
they are one-shot, they need production credentials, and they must not re-run on
every deploy.

## Prisma Postgres and Prisma Compute

> Observed on Prisma Compute (Public Beta) and Prisma Next Early Access, July 2026.
> Both move quickly — verify against the current CLI help before relying on a detail.

Prisma Next is **contract-first**: `contract.prisma` is emitted to `contract.json` /
`contract.d.ts`, and the database is advanced along a migration graph. CipherStash
integrates through `@cipherstash/prisma-next`, which contributes its own contract
space, so **EQL installs as part of your migration graph** — `prisma-next migrate`
(the top-level apply verb) installs the bundle alongside your schema. Never
`stash eql install`, which refuses on a Prisma Next project.

### The deploy pipeline runs `db init`

A Compute deploy (including every GitHub push-to-deploy build) runs
`prisma-next contract emit` followed by **`prisma-next db init`** against the target
branch database. Three consequences:

**1. Additive migrations deploy themselves.** The EQL bundle install and the
encrypted-twin columns of Deploy 1 apply during the build. No manual migrate step.

**2. Destructive migrations cannot ship through a deploy.** `db init` is
additive-only *by policy*. A merge carrying `dropColumn` or `setNotNull` fails the
build:

```text
PN-CLI-4020: Migration planning failed
Operation "Set NOT NULL on "transaction"."amountEncrypted"" requires class
"destructive", but policy allows only: additive
```

This happens **even when the PR contains a hand-authored migration covering exactly
that change** — `db init` reconciles live schema against the contract and does not
consult the authored edge. The failed build itself causes no outage: the previous
deployment keeps serving and the database is untouched.

The sequence that works for the drop (Deploy 4) — run it **only after the
Deploy 3 merge (dual-write removal) is live**, so nothing still writes the
plaintext column when it disappears:

```bash
# 1. Mint a one-time connection URL for the PRODUCTION database
npx @prisma/cli database list                       # identify the target — see below
npx @prisma/cli database connection create <db_id>

# 2. Apply the authored migration out-of-band, BEFORE merging the Deploy 4 PR
npx prisma-next db update --db "<one-time-url>"

# 3. Remove the connection, then merge. `db init` sees no drift and passes.
npx @prisma/cli database connection remove <connection_id>
```

Applying *before* the merge is strictly better than merging and recovering: the
build passes on the first try. The deploy ordering is what makes the window
safe — with dual-writes already removed in Deploy 3, nothing running touches
the column between the out-of-band apply and the merge going live.

**3. Preview branches get their own databases.** Each preview branch database is
created fresh, so `db init` reconciles it from empty and **never walks the
destructive migration history**. A destructive PR's preview deploy can pass while
its production deploy fails. Do not read a green preview as proof the production
deploy will work.

### Identifying the production database

`database list` shows one database per branch, and branch metadata is not a reliable
discriminator — entries can all report the same branch scope. Production is
identified by its **name** (the primary/production database), not by list order and
not by the entry named after your git branch. Confirm with
`npx @prisma/cli database show <database> --json` before minting a connection.

Getting this wrong is quiet: applying a migration to a preview database **succeeds**,
and the production deploy then fails with the identical error it failed with before.

### One merge deploys the whole merge

Merging to the default branch deploys everything in that merge. So the ladder above
maps to **separate PRs merged in sequence**, with the out-of-band steps run between
merges:

| Stage | PR | Manual step after merge |
|---|---|---|
| Deploy 1 | encrypted twins + dual-write | put `CS_*` into the production env, redeploy, then run the backfill |
| Indexes | `eql_v3.*` index migration, in the graph — never out-of-band | `ANALYZE`, verify with `EXPLAIN` |
| Deploy 2 | read cutover + decrypt at boundary | soak and verify |
| Deploy 3 | remove dual-writes (code; relax `NOT NULL` on plaintext if set) | verify writes are clean, re-check coverage |
| Deploy 4 | contract drop + authored migration | *(apply the migration before merging — after Deploy 3 is live)* |

Never combine two stages into one PR to save a review cycle. The gates are the
safety mechanism.

### `CS_*` and `NEXT_PUBLIC_*` are build-time inputs

Set both **before** the build, for **both** roles (preview and production):

- `NEXT_PUBLIC_*` values are inlined at build time.
- `CS_*` are needed at build time because `cipherstashFromStack` authenticates while
  constructing the client, and `db.ts` constructs it at module load.

### Next.js on Compute

- Exclude the native packages from bundling:
  `serverExternalPackages: ["@cipherstash/stack", "@cipherstash/protect-ffi", "@cipherstash/auth"]`.
- **Do not depend on middleware for authorization.** The bundled server has been
  observed not executing Next.js middleware on some deploys. Keep authorization
  checks in the page / server-action / route handler itself.
- Scale-to-zero: the first request after idle may cold-start or 404. Retry before
  diagnosing.

### Authoring the Deploy 4 migration on Prisma Next

`prisma-next migration plan` scaffolds `dropColumn` + `setNotNull` from the contract
diff, but the resulting migration has **no coverage guard** — and the usual remedy
(a `dataTransform` that fills the nulls in SQL) is impossible here, because
ciphertext cannot be produced in SQL and the plaintext source is dropped by the same
migration.

Until the extension pack ships a factory for this, add the guard by hand: a
`dataTransform` whose `check` selects rows still missing ciphertext acts as a
pre/post condition around a no-op `run`, so a single uncovered row rolls back the
whole transaction — the drop included. Order the operations so each `setNotNull` is
preceded by its gate. Re-run the migration file after editing so its `migration.json`
is re-emitted and the hashes match.

### Logs

`app logs` is runtime output; `build logs <build-id>` is CI output. Different
identifiers — the id in a check run's console URL is **not** the build id; the build
id is printed in the check output itself.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Not authenticated` during a **build** | `CS_*` missing from the build environment. Local builds mask it via the device profile. |
| Native module fails to load (edge runtime, bundled serverless) | The default entry needs native `require`. Bundle `@cipherstash/stack/wasm-inline` instead — see `stash-edge`. |
| Writes fail with `column "…" does not exist` after the drop | The drop was applied while dual-writing code was still deployed. Deploy the dual-write removal (Deploy 3) before applying the drop. |
| Rows read back as `null` / garbage after cutover | Uncovered rows: a write path that never dual-wrote, or a backfill that ran before dual-writes were live. Re-run the backfill with `--force`. |
| Decrypt fails only in production | Keyset mismatch — ciphertext written under a different keyset than the app resolves, with no grant covering it (see `stash-zerokms`). |
| Decrypt works but encrypted search returns zero rows | Reader bound to a different keyset than the writer while granted the writer's (see `stash-zerokms`), or an index/predicate issue (`stash-indexing`, `stash-postgres`). |
| Raw EQL payloads reaching end users | Read path not wired through decryption. |
| Deploy fails with a destructive-operation policy error | Additive-only deploy policy. Apply the authored migration out-of-band, ideally before merging. |
| Migration applied but the deploy still fails identically | It was applied to the wrong (preview) database. |
| `NOT NULL` migration fails at apply time | Coverage is not actually complete. Good — that is the guard working. |

## Related skills

- **`stash-encryption`** — the encryption API and the canonical rollout/cutover model
- **`stash-cli`** — `stash status` / `plan` / `impl` / `encrypt *` / `env` command surface
- **`stash-indexing`** — the `eql_v3.*` extractor indexes to build between backfill and cutover
- **`stash-zerokms`** — the keyset/grant model that governs who can decrypt what
- **`stash-auth`** — auth strategies, the `CS_*` variables, and credential resolution order
- **`stash-edge`** — edge/serverless runtimes and the `@cipherstash/stack/wasm-inline` entry
- **`stash-prisma-next`** / **`stash-drizzle`** / **`stash-supabase`** — integration specifics

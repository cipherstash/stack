# Stryker mutation testing as a blocking CI gate for EQL v3

Date: 2026-07-02
Status: Proposed (awaiting review)
Branch: feat/eql-v3-text-search-schema

## Goal

Add StrykerJS mutation testing scoped to **EQL v3 only**
(`packages/stack/src/schema/v3/`) and wire it into CI as a **blocking** check.
The gate mirrors the existing `fta-v3.yml` complexity gate: paths-filtered to v3,
directory-scoped, and blocking (no `continue-on-error`).

Mutation testing verifies that the v3 test suite actually *detects* changes in
behaviour — it mutates the source and fails if the tests still pass ("surviving
mutants"). This complements the FTA complexity gate (static) with a
test-effectiveness gate (dynamic).

## Context / prior art

- **rundown** (`~/psrc/rundown`) runs Stryker 9.6.1 across a pnpm monorepo with a
  **Jest** runner, per-package configs, incremental runs backed by the public
  Stryker Dashboard, a native `break: 70` aggregate threshold, and a custom
  `assert-mutation-score.mjs` per-file gate. Its PR run is advisory; only the
  push-to-`main`/weekly "producer" run is blocking.
- **stack** differs in ways that simplify the design considerably (below).

## Key facts driving the design

1. **stack uses Vitest 3.2.4, not Jest.** rundown's Jest-runner config is not
   reusable. We use `@stryker-mutator/vitest-runner`.
2. **v3 scope is a single file:** `packages/stack/src/schema/v3/index.ts`
   (~992 lines). Because the mutate scope is one file, the project-wide aggregate
   mutation score *is* that file's score. rundown needed a custom per-file gate
   script (`assert-mutation-score.mjs`) only because a single collapsing file can
   hide behind a green aggregate across many files. **We do not need that script.**
3. **Live/DB tests self-skip without env.** `schema-v3-pg.test.ts` (guarded by
   `DATABASE_URL` + `CS_*`) and `schema-v3-client.test.ts` (guarded by `CS_*`)
   skip their `describe` blocks when the env vars are absent. So a CI run with no
   Postgres service and no `.env` still runs cleanly — the live blocks skip; the
   pure `schema-v3.test.ts` (~21 KB) and `typed-client-v3.test.ts` provide the
   coverage. The gate stays as lean as the FTA job (no DB, no credentials).
4. **No build step needed.** Vitest transpiles TS on the fly and the tests import
   from `@/schema/v3` (source, via the `@/` alias), so Stryker instruments source
   directly — no `pnpm build` required.
5. **Supply-chain rule.** Tooling must be a pinned devDependency installed via
   `--frozen-lockfile` (no `pnpm dlx` / `npx`), matching how `fta-cli@3.0.0` is
   handled.

## Scope decisions

- **Mutate scope: `schema/v3` only** (`src/schema/v3/**/*.ts`). Matches the FTA
  gate exactly. `src/encryption/v3.ts` is also v3 but is outside the current FTA
  scope and is **excluded here** to keep the gate consistent and lean.
- **Test execution: lean, no DB.** Stryker runs only the v3 runtime test files;
  the live pg/client blocks self-skip. No Postgres service is provisioned.

## Components

### 1. Dependencies

Add to `packages/stack/package.json` devDependencies (pinned, matching versions,
9.x line):

- `@stryker-mutator/core`
- `@stryker-mutator/vitest-runner`

Update `pnpm-lock.yaml` accordingly (installed via `--frozen-lockfile` in CI).

### 2. `packages/stack/vitest.stryker.config.ts`

A dedicated Vitest config for mutation runs that:

- imports/extends the base `vitest.config.ts` (keeps the `@/` alias and the
  `wasm-inline` stub aliases — required for the pure tests to load),
- sets `test.include` to only the v3 runtime tests
  (`__tests__/*v3*.test.ts`) so Stryker does not run the whole repo suite,
- disables the `typecheck` block (mutation testing exercises runtime behaviour,
  not type tests; the `*.test-d.ts` files are excluded).

Rationale: without scoping, Stryker's initial dry run would execute every test in
the package, wasting time and coupling the v3 gate to unrelated tests.

### 3. `packages/stack/stryker.config.mjs`

```js
export default {
  packageManager: 'pnpm',
  testRunner: 'vitest',
  plugins: ['@stryker-mutator/vitest-runner'],
  vitest: { configFile: 'vitest.stryker.config.ts' },
  mutate: ['src/schema/v3/**/*.ts'],
  coverageAnalysis: 'perTest',
  reporters: ['clear-text', 'progress', 'html', 'json'],
  htmlReporter: { fileName: 'reports/mutation/index.html' },
  jsonReporter: { fileName: 'reports/mutation/mutation-report.json' },
  thresholds: { high: <TBD>, low: <TBD>, break: <BASELINE> },
  concurrency: /* env-tunable, default 2 */,
  timeoutMS: /* generous default, e.g. 60000 */,
}
```

- `break` is the **blocking mechanism**: Stryker exits non-zero when the score
  drops below it.
- **No dashboard reporter and no incremental mode** initially (YAGNI for a single
  file; avoids Stryker Dashboard API-key/project setup). Reporters kept local
  (html + json for artifacts/debugging, clear-text + progress for logs).
- The explicit `plugins` list is required under pnpm's isolated `node_modules`
  layout — Stryker's default `@stryker-mutator/*` auto-discovery fails there
  (learned from rundown).

### 4. Script

Add to `packages/stack/package.json` scripts:

```json
"test:mutation": "stryker run"
```

### 5. `.github/workflows/stryker-v3.yml`

A near-clone of `fta-v3.yml`:

- `on: push (main) / pull_request (**)` with `paths:`:
  - `packages/stack/src/schema/v3/**`
  - `packages/stack/package.json`
  - `packages/stack/stryker.config.mjs`
  - `packages/stack/vitest.stryker.config.ts`
  - `.github/workflows/stryker-v3.yml`
- `permissions: contents: read`
- one job on `blacksmith-4vcpu-ubuntu-2404`, `timeout-minutes: 30`
- steps: checkout → `pnpm/action-setup@v6.0.8` → `setup-node@v6` (node 22,
  `cache: pnpm`) → install `node-gyp` → `pnpm install --frozen-lockfile` →
  `pnpm --filter @cipherstash/stack run test:mutation`
- **No `continue-on-error`** on the Stryker step → the check is blocking.

## Threshold calibration (how "blocking" is made safe)

We cannot know the current v3 mutation score until Stryker runs once.
Implementation therefore includes a **baseline step**:

1. Install deps and run `pnpm --filter @cipherstash/stack run test:mutation`
   locally.
2. Record the reported mutation score for `schema/v3`.
3. Set `thresholds.break` just **below** the measured score (a small buffer, the
   way FTA sets `--score-cap 72` against a current 71.08). This ensures the
   current state passes while any regression that lowers the score fails the gate.
4. Set `high`/`low` to reasonable display bands (do not affect pass/fail).

If the measured baseline is very low (tests are weak), surface that to the user
before committing a `break` value — a near-zero gate provides little protection
and we may want to improve v3 tests first. This is a decision point during
implementation, not a silent choice.

## Testing / verification

- Run the Stryker gate locally and confirm it exits 0 at the chosen `break`.
- Confirm the run needs **no** Postgres/credentials (live blocks skip).
- Sanity-check the gate blocks: temporarily lower `break` above the score (or
  delete an assertion) and confirm a non-zero exit.
- Confirm the workflow triggers only on v3-relevant paths.

## Out of scope (YAGNI)

- Stryker Dashboard reporter and incremental baseline.
- Per-file gate script (`assert-mutation-score.mjs`) — unnecessary for a single
  mutate file.
- Advisory PR comment job.
- Postgres-backed mutation runs / mutating `src/encryption/v3.ts`.

These can be added later if the single-file gate proves insufficient.

## Open questions / assumptions made in the user's absence

- **Test execution model** was answered as *lean, no DB* by recommendation (the
  clarifying question timed out). Revisit if full DB-backed accuracy is wanted.
- **Exact `break` value** is deferred to the baseline measurement step.
- Stryker `9.x` exact patch version to be pinned at implementation time.

# EQL monorepo absorption — implementation plan

**Goal:** Build, version and publish the EQL subsystem — the `@cipherstash/eql` npm package, the `eql-bindings` crate, the SQL install bundle, the API docs, the `postgres-eql` Docker image and the dbdev extension — from this repository instead of `cipherstash/encrypt-query-language`, and eliminate the EQL version skew between the Rust that emits payloads and the SQL that stores them.

**Architecture:** A verbatim-prefix `git subtree` import at `packages/eql/`, so every repo-root-relative path inside EQL keeps resolving. The npm package therefore lands at `packages/eql/packages/eql` and needs its own pnpm-workspace glob — the `packages/protect-ffi/platforms/*` precedent. Publishing moves surface by surface, each inert behind a guard until its own cutover, as `scripts/lint-no-ffi-changeset.mjs` does for the FFI packages today.

**Tech Stack:** pnpm 10.33.2 workspaces + catalogs, Turborepo 2.10.4, Changesets 2.31, release-plz + crates.io OIDC, Rust/Cargo (a second nested workspace), SQLx + cargo-nextest, mise (a second nested `mise.toml`), Doxygen + Python 3.13, Docker/GHCR, Vitest 3.2.7, Biome 2.5.3.

---

## Global constraints

Inherited from the protect-ffi absorption, all still binding:

- **Root `pnpm test` must never invoke cargo.** `turbo test --filter './packages/*'` reaches every package; a cargo process on that path is a Rust toolchain on every contributor's machine. EQL's `codegen:parity` drift gate and the whole SQLx suite are cargo, so they need the same `test:cargo` split protect-ffi has, enforced the same way.
- **Publish workflows must never restore the GitHub Actions cache** (`scripts/lint-no-workflow-caching.mjs`). EQL's own release workflows already respect this — EQL is where that rule came from — but the reusable `_build-sql.yml` / `_build-docs.yml` need re-checking against this repo's target list once they move.
- **npm and crates.io trusted publishing both validate against the entry-point workflow filename**, and both require the manifest's repository field to match the publishing repository exactly. Seven EQL manifests plus `release-plz.toml` name `cipherstash/encrypt-query-language` today.
- **Do not write `pnpm run <script> -- --flag`.** pnpm forwards the `--` verbatim.
- **Biome gates on errors, not warnings.**
- **CI installs with `--frozen-lockfile`.**

New to this absorption:

- **A nested `mise.toml` is not found from the repo root.** Already recorded for protect-ffi. EQL's entire build is 887 lines of mise tasks plus 47 task scripts, so every CI step that touches EQL needs `working-directory: packages/eql`.
- **The SQLx suite needs Docker, PostgreSQL 14–17 on port 7432, and CipherStash credentials.** It is credentialed live coverage, in the same class as `integration-protect-ffi.yml`, and must be fork-PR-skipped the same way.

---

## Verified findings

Everything in this section was measured against the two working trees on 2026-08-13. Anything not measured is listed under "Not verified" at the end.

### The import is cheap — the 1.27 GiB is not history

`~/src/encrypt-query-language/.git` is 1.27 GiB, which reads as a blocker and is not one. That figure is 114 local branches, `.worktrees/`, and unreachable objects. A single-branch clone of `main` is:

| | commits | tracked files | packed |
|---|---|---|---|
| `encrypt-query-language` @ `main` | 1844 | 975 | **13.34 MiB** |
| `stack` @ `main` (today) | 2944 | 1218 | 32.26 MiB |

(File counts throughout this plan are **tracked** files. `find` reports 49 files under EQL's `tasks/`, for instance, but two are gitignored `.DS_Store`; 47 is what a subtree import moves.)

So a full-history subtree import takes this repo to roughly 46 MiB — the same order as the protect-ffi import. **History is not a constraint; do not squash.** The generated `crates/eql-bindings/sql/cipherstash-encrypt.sql` (2.6 MB, rewritten every release) and `tests/sqlx/snapshots/text_expanded.rs` (2.5 MB) are the largest blobs and are what makes the *local* clone look enormous; they delta-compress well inside a single-branch pack.

### The version skew is real but currently benign — which is exactly why now is the time

The protect-ffi plan flagged a three-way skew and called unifying it "the strongest argument for the import". Measuring it changes the risk assessment, not the conclusion.

`packages/protect-ffi/crates/protect-ffi` pins `eql-bindings = "=3.0.2"` from crates.io. The EQL tree carries 3.0.4 plus unreleased work. Diffing the vendored registry sources against the tree:

| Path | 3.0.2 → 3.0.4 → tree |
|---|---|
| `src/` | **byte-identical** |
| `bindings/` (generated TS) | **byte-identical** |
| `schema/` (generated JSON Schema) | **byte-identical** |
| `sql/cipherstash-encrypt.sql` | 2 642 603 → 2 649 582 → 2 649 631 bytes |

The Rust wire types have not moved since 3.0.2. What 3.0.3 and 3.0.4 changed was SQL behaviour — the empty-bloom fuzzy-match guard, `eql_v3.grouped_value`, and four docs-manifest extraction bugs — carried on the lockstep version number. The crate's own `CHANGELOG.md` is misleading here: its newest heading is `[0.4.2]` with a large `[Unreleased]` section describing the query-twin work, because the 3.0.x renumbering is applied to `Cargo.toml` by `scripts/sync-lockstep-versions.mjs` and the changelog headings were never cut to match. That section describes work already shipped, not work pending.

**Consequence for the plan:** flipping protect-ffi's `eql-bindings` dependency from `=3.0.2` to a path dep is a **no-op for the compiled Rust**, today. That is the best possible moment to install the mechanism — it lands with zero behaviour change, and from then on the skew is unrepresentable. Wait, and the first divergent release makes it a behaviour change that has to be reasoned about under credentialed test. **Do this early, not late** (Phase 3).

protect-ffi's exposure to the crate is small and stable: 11 references across two files (`crates/protect-ffi/src/eql_v3.rs`, `src/lib.rs`), importing `from_v2::{from_v2_query_typed, from_v2_typed, is_v3_payload, TargetDomain}`, `v3::domain_type::PUBLIC_TYPNAME_PREFIX`, `v3::json::SteVecEntry`, `v3::terms::Selector`, and `v3::{DomainPayload, QueryPayload}`.

### The two Cargo workspaces resolve cleanly on the dependency that matters

`cipherstash-client` is pinned `=0.42.0` in both `packages/protect-ffi/crates/protect-ffi` and `encrypt-query-language/tests/sqlx`, and both lockfiles carry the same checksum (`6c8714a2997ab5a8cc2c871f01dcae9ff7c6b342ed51c5c0d7c8edd4d954c9d1`). That is the heaviest shared dependency and it agrees, so neither the path-dep flip nor a later single-workspace unification is blocked by version resolution.

`eql-bindings` declares no `[lints] workspace = true`, so it carries no workspace-inheritance requirement when consumed by path from a different workspace. Its only dev-dependency is a sibling path dep (`eql-domains`), which is not built for a non-dev consumer.

### A verbatim prefix is forced by `sync-generated.mjs`, and pays for itself elsewhere

`packages/eql/scripts/sync-generated.mjs` computes `repoRoot = resolve(packageRoot, '../..')` and reads `crates/eql-bindings/bindings/v3` and `crates/eql-bindings/schema/v3` from it — this is how the crate's generated TypeScript and JSON Schemas become the npm package's `src/generated/`. Flattening the npm package up one directory breaks that resolution.

The same argument holds far more broadly: `mise.toml` (887 lines), the 47 scripts under `tasks/`, `Doxyfile`, `tests/docker-compose.yml`, `src/deps-ordered-*.txt` and every workflow path filter are all repo-root-relative. A verbatim prefix means those keep working with a `working-directory` change and nothing else.

**Decision: import to `packages/eql/` with no path rewriting.** The npm package lands at `packages/eql/packages/eql`.

Flattening would also collide `src/`: EQL has SQL at `src/v3/` and TypeScript at `packages/eql/src/`. Merged, that is 269 SQL files sharing a directory with `index.ts`.

### Two task scripts discover the EQL root via git, and a `working-directory` change is not enough for them

The verbatim-prefix claim above has exactly two exceptions in the tree, and both fail silently rather than loudly:

```
tasks/test/doc-anchors.sh:34     EQL_ROOT="${EQL_ROOT:-$(git rev-parse --show-toplevel)}"
tasks/test/known-failures.sh:23  EQL_ROOT="${EQL_ROOT:-$(git rev-parse --show-toplevel)}"
```

After the import, `--show-toplevel` returns the Stack root, not `packages/eql`. `known-failures.sh` then looks for `tests/sqlx/src/known_failure.rs` at the wrong root and exits 2 — noisy, fine. `doc-anchors.sh` is worse: it `cd`s to the computed root and scans documentation from there, so it would happily validate anchors across the wrong tree and report success.

**Both already honour an `EQL_ROOT` environment override**, so the fix is one line in `packages/eql/mise.toml`'s `[env]` block, not a script edit. mise's `[env]` overrides an inherited value — the same property this repo already relies on to stop a stale `PGPORT` misrouting the protect-ffi integration suite. Add both scripts to the verification checklist; a passing `doc-anchors.sh` proves nothing on its own.

### Nested `.gitattributes` and `.gitignore` need no rewriting

EQL's `.gitattributes` marks the generated scalar SQL and macro-expansion snapshots `linguist-generated`, and sets `CHANGELOG.md merge=union`. Patterns in a subdirectory's `.gitattributes` resolve relative to that directory, so at `packages/eql/.gitattributes` every pattern keeps its meaning — and `merge=union` correctly stops applying to the eleven other `CHANGELOG.md` files in this repo. Same for `.gitignore`. This repo has no root `.gitattributes` today, so there is nothing to merge.

### Four things arrive broken or duplicated

1. **`catalog:` references will not resolve.** `packages/eql/package.json` uses the *default* catalog (`"typescript": "catalog:"`). This repo defines only named catalogs (`catalogs.repo`) and no default catalog, so those four references fail at install. They also move versions: EQL is on `typescript ^5.8.3`, `vitest ^3.2.4`, `tsup ^8.5.0`; this repo pins `5.9.3`, `3.2.7`, `8.5.1`. `@types/node` is not in `catalogs.repo` at all.
2. **`.gitmodules` is dead.** It declares `languages/go/goeql`, a path with zero tracked files in the tree. Delete it in the cleanup commit.
3. **`scripts/lint-no-workflow-caching.mjs` exists in both repos.** This repo's copy is the descendant. The imported one is a duplicate with a different target list.
4. **The EQL subtree root's `package.json` is `@cipherstash/eql-workspace`** (private) and carries workspace-level scripts — `changeset`, `changeset:version`, `version`, `release` — that duplicate or conflict with this repo's root. The `version` script is the exception and is load-bearing: it is `changeset version && node scripts/sync-lockstep-versions.mjs`, the hook that writes the computed npm version into `Cargo.toml`. That hook has to move to this repo's root, not stay here.

### The subtree-root manifest has nothing load-bearing left once the necessary moves are made

This read as a balanced open decision. Measuring what `@cipherstash/eql-workspace` actually carries settles it. Its ten scripts sort into four groups and only one survives the move:

| Scripts | Fate |
|---|---|
| `changeset`, `changeset:version`, `release` | Delete — they conflict with this repo's root |
| `version` | **Moves to this repo's root.** Changesets runs only the root `version` script |
| `lint:workflow-cache`, `test:scripts` | Delete — this repo's root already defines both under the same names (`package.json:33`, `package.json:39`) |
| `build`, `test`, `types:generate`, `types:check` | Thin delegations to the nested package, and CI does not use them: `test-eql.yml:345` runs `mise run types:check`, not the npm alias |

The subtree also does not need a `node_modules` at all. `mise.toml:21` and `mise.toml:329-331` say so in their own comments — the generated-output gates invoke bare `node` because `sync-generated.mjs` uses only node builtins — and there are **zero** `pnpm` or `npx` invocations across the 47 scripts under `tasks/`. `sync-lockstep-versions.mjs` likewise imports only `node:child_process`, `node:fs`, `node:path`, `node:url` and `node:process`, so it relocates with no dependency baggage.

**The argument for keeping the manifest — that it matches `packages/protect-ffi/package.json` — does not hold.** That file *is* the published `@cipherstash/protect-ffi` package: name, version, `exports`, `files`, neon config. It is not a private workspace root wrapping a nested package. This repo has no precedent for the shape EQL brings.

**Decision: delete it.** See the turbo finding below — it is the same decision, not a second one.

One trap in the move. This repo's `scripts/vitest.config.mjs` includes `scripts/__tests__/**/*.test.mjs`; EQL's includes `scripts/**/*.test.mjs`, with tests sitting flat beside their scripts. Land `sync-lockstep-versions.test.mjs` at `scripts/sync-lockstep-versions.test.mjs` and it executes nowhere — the test covering this plan's one load-bearing hook, failing in precisely the way the rest of this plan is written to prevent. It goes in `scripts/__tests__/`.

### Turbo's filter does not reach two levels down — and the consequence is a silent test, not a broken build

Root `build` and `test` are `turbo <task> --filter './packages/*'`. That glob is one level, so it **selects** `packages/eql` (the private subtree root) and not `packages/eql/packages/eql`.

The build is nonetheless covered: `build` declares `dependsOn: ["^build"]`, and turbo traverses workspace dependencies regardless of which packages the filter selected. `packages/stack`, `packages/cli` and `packages/stack-prisma` would depend on `@cipherstash/eql`, so it gets built as their dependency. An earlier revision of this plan claimed `pnpm build` would leave it unbuilt; that was wrong.

The **test** is not covered. `turbo test --filter './packages/*'` never selects the nested package, and nothing depends on its `test` task, so `@cipherstash/eql`'s own Vitest suite — `src/index.test.ts`, `src/sql.test.ts` — would run nowhere. That is precisely the defect the protect-ffi round kept finding: a check that arrives as a file, appears wired up, and executes on no event.

Keeping the private `@cipherstash/eql-workspace` manifest would paper over this rather than fix it: its `test` script (`pnpm --filter @cipherstash/eql test`) *is* selected by the one-level glob and would delegate — but as a raw pnpm call outside turbo's graph, so it runs uncached, unordered against `^build`, invisible to `turbo run` filtering, and it gives the nested package two different execution paths depending on entry point. Deleting the manifest (finding above) forces the filter to be fixed properly.

**The fix is the broader glob** — `turbo test --filter './packages/**'` — rather than a second explicit `--filter` that can go stale as the tree grows. Verified safe: the six `packages/protect-ffi/platforms/*` manifests declare **no `scripts` block at all**, so the broader glob selects them and turbo finds no matching task. Keep the mutation test regardless: delete the nested package's `dist`, and separately break one of its unit tests, and confirm root `pnpm build` and root `pnpm test` each notice.

### The imported credentialed jobs fail two of this repo's CI guards on arrival

`scripts/__tests__/ffi-binding-step-order.test.mjs` scans every root workflow, collects every job carrying a `CS_*` credential, and asserts each one (a) builds the protect-ffi binding and (b) runs `require-cs-secrets` first. Both exemption lists — `BINDING_EXEMPT_JOBS` and `PREFLIGHT_EXEMPT_JOBS` — are **deliberately empty Maps**, each keyed `'<workflow> / <job>'` with a mandatory reason, and each self-checked so a stale entry fails the guard.

EQL's credentialed jobs (`test-eql.yml` lines 133–136 and 601–604) reach CipherStash through the `cipherstash-client` **crate**, never through `index.node` or `dist/wasm`. So on arrival they fail guard (a) for a reason that is legitimate and fail guard (b) for a reason that is not:

- Add each to `BINDING_EXEMPT_JOBS` with the reason "encrypts via the `cipherstash-client` crate; never loads the Node binding". Do not make them build the binding to satisfy the scan — that buys a four-minute compile for nothing.
- Add `require-cs-secrets` **before** the credentialed work rather than taking a `PREFLIGHT_EXEMPT_JOBS` entry. A job holding `CS_*` is a job a rotated secret can break, and the pre-flight is how it says so in seconds instead of in a timeout.

There is also a convention mismatch. EQL reads all four values from `secrets`; this repo reads `CS_WORKSPACE_CRN` and `CS_CLIENT_ID` from `vars` and only the key material from `secrets` (`integration-supabase.yml`, `integration-prisma-next.yml`, `prisma-next-e2e.yml`). Port to this repo's convention or `require-cs-secrets` will report the CRN missing.

### The credentials change WORKSPACE, not just variable plumbing — and two test constants are keyed to the workspace

The finding above treats the credentials as a wiring problem. They are also an *identity* problem, which the first credentialed run found and this plan had not anticipated: `vars.CS_WORKSPACE_CRN` here names a different CipherStash workspace than the one EQL was developed against. Two pinned SteVec selectors are MACs of (column context, JSONPath) **under the workspace keyset**, so they re-pin on the move even though no Rust, no SQL and no fixture logic changed:

- `tests/sqlx/src/fixtures/v3_doc_integer.rs::SELECTOR` — `fce8be75…` → `606a4a44…`, reported identically by two independent runs.
- `tests/sqlx/src/fixtures/v3_ste_vec.rs::SEL_HELLO_OP` — `b325a0c7…` → `6f1db3bd…`, identified from the new guard's report.

The identification is over-determined rather than rule-matched, which is the standard a silent mis-pin deserves. The guard printed all six `op`-carrying leaves, and at `16 * len + 20` hex chars every one reconciles against the fixture's known documents: `$.empty` 20, `$.accented` 84/180/196 — three lengths rather than four, because the `café`/`cafe` collision pair the fixture exists to carry shares one — `$.nested.deep` 148 for `"constant"`, `$.number` and `$.large` a fixed-width 132, and `$.hello` alone spanning 132/148 for `world-1..9` vs `world-10`.

This is a known, accepted property rather than a defect: the module comment says supporting multiple workspaces "would require runtime selector resolution, which the static `ScalarType::column_expr()` seam cannot do — out of scope here." The consequence to record is that **these pins are now coupled to this repo's CI workspace**, so rotating `CS_WORKSPACE_CRN` re-pins them again, and a contributor running the suite against their own workspace will see the drift message and must not commit their local value.

Three things this cost, all worth fixing rather than absorbing:

1. **Only one of the two constants had a drift guard.** `v3_doc_integer` failed with one copy-pasteable "pinned X, live Y" message. `SEL_HELLO_OP` has no such guard, so its drift surfaces as wrong ANSWERS — `LB3` counting 0 distinct ops, ORDER BY arms returning insertion order — with the live value nowhere in the output. `v3_jsonb_sel_hello_op_matches_fixture` closes that asymmetry. It deliberately does **not** infer the replacement: it prints every op-carrying selector with a row count and `op`-length profile and states the discriminator, because guessing wrong re-pins to the wrong leaf silently — the exact bug already recorded in `SEL_HELLO_OP`'s own history, where it named `$.number` while claiming `$.hello` and survived because equality-only suites cannot separate the two.
2. **The shards ran fail-fast**, so shard 1 reported 11 failures and skipped 643 of its 710 tests. One environmental fault therefore answered one question per CI round trip. `tasks/test/sqlx-partition.sh` now passes `--no-fail-fast` (nextest's own suggestion in that output); the cost is bounded because the shards run ~5s tests in parallel.
3. **`tests/sqlx/src/selectors.rs` holds five more workspace-keyed constants (`ROOT`, `HELLO`, `N`, `ARRAY_ELEMENTS`, `ARRAY_ROOT`) with zero consumers** — `rg 'Selectors::'` finds no use outside their own definition — and no guard. They are stale against this workspace and nothing says so. Delete them or guard them before anything starts using them; a dead constant that is silently wrong is worse than a missing one. Not done here: it is unrelated to the failure and belongs in its own change.

The other selector-shaped constants in the tree are **synthetic and unaffected** — `crates/eql-bindings/tests/*` and `tests/sqlx/tests/payload_schema_tests.rs` pair theirs with hand-made ciphertext literals and touch no keyset, and the `00000…01` / `deadbeef…` / `ffffffff…` literals in `v3_jsonb_tests.rs` are forged by construction.

### `workspace:^` silently moved every consumer from EQL's last RELEASE to its unreleased HEAD — and HEAD is not 3.0.4

The plan argued the `workspace:^` range on version grounds ("EQL is 3.x; `^3.0.4` spans every 3.x release, so a 3.1.2 does not drag `stash`…"). That reasoning is about *published* versions and misses what a workspace link actually does: it resolves to the working tree, so the range never applies. Before the absorption `@cipherstash/eql` was a registry tarball; after it, every consumer builds from source. Those are not the same artefact, and here they differ:

| | `installSqlSha256` |
|---|---|
| published `@cipherstash/eql@3.0.4` (npm tarball) | `63104a81…` |
| in-tree `packages/eql`, also calling itself **3.0.4** | `a92cc041…` |

The entire diff is one rename — `eql_v3.ste_vec_contains` → `eql_v3.jsonb_document_contains`, 14 lines, arriving with `63af028e chore(release): regenerate bundled installer SQL for jsonb_document_contains rename`. Upstream renamed it, regenerated the bundle, and **never released it**: npm's newest is 3.0.4, `packages/eql/packages/eql/package.json` still says `3.0.4`, the CHANGELOG's newest entry is 3.0.4, and there is no changeset for the rename. So `sql/release-manifest.json` currently asserts `"eqlVersion": "3.0.4"` over SQL that is not 3.0.4's.

`packages/stack-prisma`'s lockstep test is the only thing in the repo that noticed — it requires the installed release's SQL to be baked by some published migration, and `a92cc041…` is baked by none. That is the guard working, not a false positive. The reach is wider than one test:

- **`stash eql install` would install the renamed function under the name "3.0.4".** `packages/cli/src/installer/index.ts` calls `readInstallSql()` directly, with no digest check, so a customer database would end up carrying `jsonb_document_contains` while `eql_v3` reports a version whose published SQL defines `ste_vec_contains`. Two databases both truthfully reporting 3.0.4 would disagree on the function set.
- **A SQL function rename is breaking for direct callers** — the wrappers are public precisely so platforms without operator support (Supabase/PostgREST) can invoke them by name.
- **`examples/prisma/migrations/cipherstash/…/ops.json` bakes the old SQL**, as do the three `PUBLISHED_MIGRATIONS`; those artefacts sit byte-for-byte in consumers' repos and database ledgers, so they are frozen history, not files to edit.

**This was a release decision and was deliberately left open** rather than patched to green. Making the test pass required either bumping the in-tree EQL version and shipping a new baseline migration that bakes the new SQL (a new customer-facing artefact, and the rename's severity — patch vs minor vs major — is upstream's call), or reverting the rename until a deliberate release. Inventing either would forge exactly the kind of record the surrounding guards exist to protect.

**Resolved, in this PR, in two steps.** The severity call was made first — `3.0.5`, a patch, matching 3.0.1's precedent of shipping an operator change at that level (`9b1c44d9` proposed 4.0.0; `23079d7b` re-cut it as 3.0.5). Then `stack-prisma` grew the migration that bakes it: a new `20260814T0000_upgrade_eql_v3_3_0_5` upgrade edge for existing databases, plus a **re-emit of the baseline** so fresh databases land on 3.0.5 from the single all-additive genesis edge.

That re-emit is the part worth recording, because the append-only rule says not to. No upgrade edge can ever be walked by `db init`: every one of them is a self-edge, `checkIntegrity` requires a self-edge to carry a `data`-class op, and `db init` runs `allowedOperationClasses: ['additive']`. A fresh database therefore has to collect every head-ref invariant from the genesis edge, so a new required invariant either lands on the baseline or arrives on a second `from: null` edge duplicating the full ~2.6 MB bundle — permanently, once per EQL release. Re-emitting was chosen while `@cipherstash/stack-prisma@1.0.0` was 14 days old with ~253 monthly downloads, i.e. while the blast radius was small and knowable, and the changeset carries the delete-and-re-plan instruction. **Once this package has real adoption the second genesis edge is the correct shape** and the size cost is the price of not orphaning consumers; the trade should be re-argued on adoption numbers at the next bump, not defaulted to.

The narrower lesson for the absorption: **absorbing a repo swaps "last published release" for "current HEAD" across every consumer**, and nothing in the dependency graph announces that. Only a digest pin caught it here. Any other package this repo absorbs by workspace link deserves the same check — diff the built artefact against the published tarball — before the link is treated as neutral.

### Three imported release workflows violate the no-caching rule — by omission, not by setting

The global constraint is that publish workflows never restore the Actions cache. `release-plz.yml` complies explicitly:

```yaml
- uses: jdx/mise-action@v3
  with:
    cache: false   # with a comment naming the rule and the OIDC risk
```

`_build-sql.yml`, `_build-docs.yml` and `release-postgres-eql-image.yml` **omit the `cache:` key entirely**, and `jdx/mise-action` defaults it to `true`. The effect is a violation; the spelling is an absence. Anyone grepping for `cache: true` finds nothing and concludes the finding was bogus — so the fix is to *add* `cache: false`, and to add `release-plz.yml` and the image publisher to `scripts/lint-no-workflow-caching.mjs`'s target list so the omission cannot recur silently. Adding a workflow to `TARGETS` also requires its remote actions in `AUDITED_ACTIONS`; the protect-ffi round needed three entries it had not anticipated.

### The release surface is five artifacts at one lockstep version

EQL ships everything at a single version V, computed by Changesets from `packages/eql/package.json` and propagated by `sync-lockstep-versions.mjs`:

| Surface | Mechanism | Trusted publishing |
|---|---|---|
| `@cipherstash/eql` (npm) | Changesets, `release.yml` | npm OIDC, bound to `release.yml` |
| `eql-bindings` (crates.io) | release-plz, `release-plz.yml` | crates.io OIDC, bound to `release-plz.yml` |
| SQL install/uninstall bundle | `_build-sql.yml`, attached to the `eql-<V>` GitHub release | — |
| API docs (HTML/XML/Markdown) | `_build-docs.yml` + `rebuild-docs.yml` webhook to Vercel | `DOCS_WEBHOOK_URL` secret |
| `ghcr.io/cipherstash/postgres-eql` | `release-postgres-eql-image.yml` | `GITHUB_TOKEN` |

plus **dbdev**, which is documented as manual and lagging.

Two release-identity details matter. `release-plz.toml` deliberately tags the crate `eql-bindings-v<semver>` so that a crate release does *not* trigger the SQL build, Docker image or docs rebuild — the `eql-` prefixed tags do. And `release.yml`'s `classify` job supports prereleases from any non-`main` branch off a literal `chore(release):` commit subject, with a `eql-typescript-v<version>` tag as the idempotency short-circuit. Both behaviours have to survive the move or the release line changes shape.

---

## Corrections to the protect-ffi plan's EQL section

That plan's "Out of scope: importing EQL" listed four findings. Three hold. One needs restating:

- **"A live version skew" — true, but it is a SQL skew, not a Rust one.** `eql-bindings` 3.0.2 and 3.0.4 are byte-identical Rust. The payloads protect-ffi emits today are *not* generated from a different catalog commit than the SQL being installed; the two versions simply differ in SQL. The argument for the import survives intact — the skew is unguarded and will bite on the first divergent release — but the framing "the Rust emitting EQL payloads is generated from a different catalog commit" overstates the present state, and a plan that opens by claiming a live defect will spend its first phase chasing one that is not there.
- **"Pin EQL with `workspace:^`, not `workspace:*`"** — holds, and is load-bearing. EQL is 3.x; `^3.0.4` spans every 3.x release, so a 3.1.2 does not drag `stash` and `stack-prisma` — and through the fixed group all six Stack packages — into an EQL release.
- **"crates.io trusted publishing needs repointing"** — holds.
- **"Changesets cannot put a crate in a `fixed` group"** — holds, and the hook already exists upstream as `scripts/sync-lockstep-versions.mjs`. It arrives with the import rather than needing to be written.

---

## Phase 1 — import

- [ ] Branch from `main`. Add the remote and import at the verbatim prefix:

  ```bash
  git remote add eql ~/src/encrypt-query-language
  git fetch eql main
  git subtree add --prefix=packages/eql eql main
  ```

  Expect 1844 commits and 975 files. Verify the pack grows by ~13 MiB, not ~1.3 GiB — if it grows by more, the fetch pulled refs other than `main`.
- [ ] **Verify the import is faithful before changing anything.** 975 tracked files in, 975 out; `crates/`, `src/v3/`, `tests/`, `tasks/`, `docs/`, `packages/eql/` byte-identical to upstream `main`. The protect-ffi round proved the value of this: every defect it found was in what *ran*, not what arrived.
- [ ] Cleanup commit, mirroring `1e922ec0`:
  - Delete `packages/eql/.gitmodules` (dead `languages/go/goeql`).
  - Delete `packages/eql/pnpm-lock.yaml`, `packages/eql/pnpm-workspace.yaml`, `packages/eql/.npmrc` — the root ones govern.
  - Delete `packages/eql/scripts/lint-no-workflow-caching.mjs` and its test; this repo's copy is the descendant.
  - Delete `packages/eql/CODE_OF_CONDUCT.md`, `packages/eql/LICENSE` (duplicates).
  - Delete `packages/eql/biome.json` (schema 1.8.3; the root config is 2.5.2).
  - Delete `packages/eql/.changeset/config.json` — the root changeset config governs. **Keep any pending changeset markdown**; `rename-ste-vec-contains.md` is unreleased work and must move to the root `.changeset/`.
  - Move `packages/eql/CLAUDE.md` → `packages/eql/AGENTS.md`, matching this repo's convention.
- [ ] ~~Run `pnpm run code:fix` here.~~ **Moved to Phase 2** — found by executing this phase on 2026-08-13. The reflow cannot run before the `biome.json` ignore entries land, and those are a Phase 2 item. Two reasons, the second of which is not cosmetic:
  1. Biome is not installed until `pnpm install` runs, and installing at this point enrols the private `@cipherstash/eql-workspace` manifest that Phase 2 deletes.
  2. **The imported tree carries 211 generated `.ts` files that Biome would rewrite** — 104 under `crates/eql-bindings/bindings`, 92 schemas beside them, and 199 synced into the nested package's `src/generated`. Each carries a `ts-rs` "Do not edit this file manually" header and is drift-gated by `mise run types:check`, which regenerates and `git diff`s. Reformatting them produces a shape the generator never emits, so the gate fails and stays failing until the formatting is reverted. Ordering the reflow after the ignores is what stops this.

## Phase 2 — wire the workspace

- [x] Delete `packages/eql/package.json` (the private `@cipherstash/eql-workspace` root). `packages/*` already matches `packages/eql`, so leaving the file in place silently enrols a second workspace root; with the file gone pnpm skips the directory, and the mise layer needs no `node_modules` to work. See the finding above for the script-by-script accounting.
- [x] `pnpm-workspace.yaml`: add `packages/eql/packages/*`, so `@cipherstash/eql` is the only member the subtree contributes.
- [x] Move the lockstep hook to the root, **in three parts — the script alone does nothing**:
  1. `packages/eql/scripts/sync-lockstep-versions.mjs` moves to `scripts/sync-lockstep-versions.mjs`, and its test moves to **`scripts/__tests__/sync-lockstep-versions.test.mjs`** — not flat beside the script, where EQL keeps it. This repo's `scripts/vitest.config.mjs` includes `scripts/__tests__/**/*.test.mjs` only, so the flat path runs nowhere. The script imports node builtins exclusively, so nothing else moves with it. That empties `packages/eql/scripts/` — the caching lint and its test are deleted as duplicates in Phase 1 — so delete its now-orphaned `vitest.config.mjs` and the directory with it. (This is the subtree *root's* `scripts/`. The nested package's `packages/eql/packages/eql/scripts/` — `sync-generated.mjs`, `verify-release-assets.mjs`, `npm-publish.mjs` — is untouched, and the mise tasks that call it keep resolving under `working-directory: packages/eql`.)
  2. Root `package.json` gains `"version": "changeset version && node scripts/sync-lockstep-versions.mjs"`.
  3. `release.yml`'s `changesets/action` step gains `version: pnpm run version`. It currently passes only `publish:` and `commitMode:` (`.github/workflows/release.yml:278-281`), so the action runs its built-in `changeset version` and **never invokes the root script**. Without this line the hook is present, plausible, and dead: `Cargo.toml` and the SQL assets keep the old version while npm bumps, and the first sign is a released crate whose version disagrees with the bundle it ships. EQL's own `release.yml:158` already passes it — the port is one line against a pattern proven upstream.

  **Add all three in the commit that first writes a `Cargo.toml` version, with a test asserting the workflow passes `version:`** — the protect-ffi plan's warning about pass-through seams is exactly this failure, and it fails open.
- [x] Reconcile `packages/eql/packages/eql/package.json`: replace the four default-`catalog:` references with `catalog:repo`, adding `@types/node` to `catalogs.repo` if it should be catalogued. Accept the moves to `typescript 5.9.3` / `vitest 3.2.7` / `tsup 8.5.1` and run the package's own suite.
- [x] Remove `'@cipherstash/eql'` from `minimumReleaseAgeExclude` — it becomes dead config once the package is first-party. This stays true despite `packages/protect-ffi/integration-tests` keeping a registry pin (open decision 3): that directory installs with `npm ci`, and `minimumReleaseAge` is a pnpm setting that never applied to it.
- [x] Repoint `packages/stack`, `packages/cli` and `packages/stack-prisma` from `"@cipherstash/eql": "3.0.4"` to `"workspace:^"`. Also `packages/protect-ffi/integration-tests/package.json`, which pins `3.0.2` — but that directory is not a pnpm workspace member and installs with `npm ci`, so it cannot take a `workspace:` specifier. Leave it pinned and note it; it is already a deferred follow-up from the protect-ffi round.
- [x] Set `EQL_ROOT` in `packages/eql/mise.toml`'s `[env]` so `doc-anchors.sh` and `known-failures.sh` stop resolving the Stack root. One line; see the finding above.
- [x] Fix the turbo **test** selection so it reaches the nested package: root `test` becomes `turbo test --filter './packages/**'`. Prefer the glob over a second explicit `--filter`, which goes stale; it is safe because the `platforms/*` packages define no scripts. `build` is already covered by `^build` traversal. **Mutation-check both:** break one of the nested package's unit tests and confirm root `pnpm test` fails; delete its `dist` and confirm root `pnpm build` recreates it.
- [x] Add `packages/eql` paths to the root `biome.json` ignore list where the imported tree carries generated output — **before** running `code:fix`, not after. Counted on the imported tree: `packages/eql/crates/eql-bindings/bindings` (104 tracked files), `packages/eql/crates/eql-bindings/schema` (92), `packages/eql/packages/eql/src/generated` (199), plus the untracked build outputs `packages/eql/release`, `packages/eql/target`, `packages/eql/docs/api`. The first three are `ts-rs`/schemars output carrying "Do not edit this file manually" and drift-gated by `mise run types:check`; Biome reformatting them breaks that gate until reverted. Note the generated TypeScript lives under the *nested* package and under `crates/` — `packages/eql/src/generated` does not exist, and an ignore list naming only the nested path misses 196 of the 211 files.
- [x] **Then** run `pnpm run code:fix` and commit the Biome 1.8.3 → 2.5.2 reflow **as its own commit**, so it never confounds a semantic diff. Verify by comparing token multisets rather than by eye, and confirm `mise run types:check` still passes afterwards — that gate is the thing this ordering protects.
- [x] Extend `scripts/lint-typecheck-scope.mjs` to discover the nested package. Its `WORKSPACE_ROOTS = ['packages', 'examples']` walk is one `readdirSync` deep, so it finds `packages/eql` and silently misses `packages/eql/packages/eql` — a package outside the scan reads exactly like a package that passed. Either teach discovery the workspace globs or name the nested directory explicitly. Note there is nothing to "add it to" on the tsconfig side: the root `tsconfig.json` is a bare `compilerOptions` base with no `include`, no `references` and no project graph.
- [x] Changesets: add `@cipherstash/eql` as its own release line. It is **not** in the Stack fixed group and **not** in the FFI group — that is what `workspace:^` buys. Nothing to add: membership in `.changeset/config.json`'s `fixed` array is opt-in, so a workspace package named in neither group already versions independently. `publishConfig.access: "public"` does survive the root `"access": "restricted"` — confirmed against the installed Changesets 2.31.0 rather than the docs (`changesets-cli.esm.js:1031`, `access: publishConfig?.access || access`, reaching `publishFlags = ["--access", opts.access]` at `:842`).
- [ ] **Discovered while checking the line above, and it belongs to the FFI cutover, not this one:** `@cipherstash/protect-ffi` is publishable and carries **no** `publishConfig`, so that same resolution hands it `--access restricted`. Its six `platforms/*` siblings are safe only by accident — `release.yml:149` publishes them with an explicit `npm publish --access public --provenance` *before* `changeset publish` runs, so changesets finds them already published and skips them. The wrapper has no such shortcut. Whichever way npm resolves `--access restricted` on an already-public package, the outcome is bad at the worst moment: a 402 leaves the six platform packages published at V and the wrapper missing, and a paid org instead succeeds and silently makes a public package private. Fix in the FFI round by giving all seven manifests `publishConfig.access: "public"` and pinning the invariant with a test over every non-private workspace package — deliberately not done here, because that test cannot go green without the manifest change, and the manifest change needs a parked `.changeset/<name>.md.deferred`.
- [x] `pnpm install --frozen-lockfile` clean; `pnpm run code:check` error-free.

## Phase 3 — kill the skew

Do this before CI. It is the reason for the import, and it is verified-neutral today.

- [x] Change `packages/protect-ffi/crates/protect-ffi/Cargo.toml`: `eql-bindings = { version = "=3.0.2" }` → `eql-bindings = { path = "../../../eql/crates/eql-bindings" }`.
- [x] **Cargo accepts a path dep into a package that is a member of another workspace, and the build completes.** First probed for resolution only: a scratch crate path-depending on `encrypt-query-language/crates/eql-bindings` resolved cleanly (`cargo metadata` locked 36 packages and emitted the full graph). No workspace-membership rejection. That probe died on `No space left on device` before producing a binary; **re-run on 2026-08-13 with disk available, against the real target** — `packages/protect-ffi/crates/protect-ffi/Cargo.toml:25` temporarily pointed at the EQL tree, `cargo build -p protect-ffi` finishing the `dev` profile in 3m 10s from a cleared target with no errors and a 41 MB `libprotect_ffi.dylib`. `Cargo.lock` moved the entry to 3.0.4 **with no `source` line**, which is the path-dep signature; the scaffolding was reverted and the tree left clean. Byte-identity was re-confirmed the same day by `diff -rq`, so that 3.0.2 → 3.0.4 move is a version number changing over identical Rust.
- [x] **The uncredentialed half of the verification, run against the flipped manifest.** `cargo build -p protect-ffi` on the host: clean in 4m 51s, cargo resolving `eql-bindings v3.0.4` from `packages/eql/crates/eql-bindings` and rewriting the `Cargo.lock` entry with no `source` line. `pnpm --filter @cipherstash/protect-ffi test:cargo`: **310 tests passed, 0 failed**, `cargo fmt --check` clean. And `cargo build -p protect-ffi --target wasm32-unknown-unknown`, clean in 1m 18s — not in the original list, and worth adding: wasm32 is the target a cross-workspace path dep could plausibly break, since the EQL workspace never builds for it and a merged workspace was rejected partly on that ground. It does not break; the crate carries no `[lints] workspace = true` and nothing target-specific.
- [ ] **The credentialed half. Not run — no Docker and no `CS_*` credentials.** `packages/protect-ffi/integration-tests` against the path dep is what turns "no-op" from an argument about byte-identity into an observed result, and it is the only thing here that exercises an EQL payload end to end through Postgres. Run `mise run setup && mise run test:integration:all` from `packages/protect-ffi` on a credentialed machine, or dispatch `integration-protect-ffi.yml`. Do not tick this from the strength of the two boxes above: they prove the flip compiles and that the unit tests agree, not that a payload emitted by the path-dep build is read by the installed SQL.
- [x] Add a guard that fails if any manifest in the tree names `eql-bindings` by registry version rather than path, and extend it to `@cipherstash/eql`. A registry pin reintroduces the skew silently. The one surviving pin — `packages/protect-ffi/integration-tests`, which cannot take a `workspace:` specifier (open decision 3) — takes an **explicit named exemption carrying a mandatory reason**, in the shape of `BINDING_EXEMPT_JOBS`. An exemption that must be written down and justified stays visible; a scan that merely happens not to reach the directory reads exactly like a scan that found nothing.

  Landed as `scripts/lint-no-eql-registry-pins.mjs`, wired as `lint:eql-pins` and run from `tests.yml`'s `lint` job. **Three things the instruction did not anticipate, each found by executing it.**

  1. **Staleness has to mean "excuses nothing", not "names nothing".** The obvious spelling — an exemption is stale when no manifest declares what it names — passes on the day `integration-tests` joins the workspace, because that manifest still declares `@cipherstash/eql`; it just no longer needs excusing. The exemption would survive its own reason and stand as a permanent permission for a pin nothing needs, inherited by whatever lands at that path next. Measured against the *registry-pinned* declarations instead, that follow-up PR cannot go green until the entry is deleted. Mutation-checked both ways: flipping the pin to `workspace:^` exits 2 under the tightened rule and exited **0** under the looser one.
  2. **The exit-2 branches cannot fire against the tree the tests run in** — that is what they are for — so the code/message mapping is exported as `report()` and driven with synthetic results. Asserting only that `lint()` *detects* a stale exemption proves the condition is computed, not that anything happens next, and "detected, then exit 0" is this branch's recurring failure shape.
  3. **A broken scan is reported ahead of any offender it found.** A scan that lost its subject cannot be trusted to have found every offender either, so `missingExpected` and stale exemptions are checked first. The alternative sends the reader to fix a manifest, and the fix makes the linter exit 0 with its coverage still gone.

  Four mutations against the real tree, each hitting only its own guard: restoring the `=3.0.2` pin → exit 1; registry-pinning `@cipherstash/eql` in `packages/stack` → exit 1; blinding the walk by adding `packages` to `SKIP_DIRS` → exit **2**, not 0; and the exemption case above. The scan also reads the `[dependencies.eql-bindings]` table form, `resolutions` and both `overrides` spellings — an override is the quietest route back to a registry, since every `workspace:^` in the tree still reads correct while what installs has moved.
- [ ] **Do not unify the two Cargo workspaces in this round.** One root `Cargo.toml` with members `packages/protect-ffi/crates/protect-ffi`, `packages/eql/crates/*` and `packages/eql/tests/sqlx` would give one lockfile and one `target/`. Three things argue against doing it here: EQL's workspace root sets `default-members = ["tests/sqlx"]` and `[workspace.lints.rust] dead_code = "deny"` / `unused_imports = "deny"`, both of which become repo-wide policy on merge; protect-ffi builds for `wasm32-unknown-unknown`, which a merged workspace would attempt for the EQL crates unless every invocation is `-p`-scoped; and the usual argument *for* unifying is already neutralised, because the two lockfiles do not disagree — `cipherstash-client` is `=0.42.0` in both with matching checksums. So unification buys one `target/` directory and some build hygiene, not correctness; the path dep above is what buys the guarantee. Revisit when a Rust change first needs to span both trees in one PR, or when two `target/` directories cost more than the lint-policy negotiation would.

## Phase 4 — CI

The protect-ffi lesson applies verbatim: **a check that arrives as a file and then executes nowhere reads exactly like a check that passes.** EQL's ten workflows arrive under `packages/eql/.github/`, a directory GitHub never reads.

- [x] Port `test-eql.yml` to the root workflow directory, rewriting every path filter to the `packages/eql/**` prefix and every mise step to `working-directory: packages/eql`. Keep the event-shaped matrix (PR → PG17 × 4 shards; merge queue → PG 14–17 × 2 shards) and the `changes` job's must-always-succeed contract. **Two refinements found by doing it.** `working-directory` belongs on `defaults.run`, one line rather than ~30 forgettable copies — but that does *not* reach a `uses:` step, so the 13 mise-action steps need `working_directory:` separately (mise reads config from cwd and its parents; without it the action installs nothing and the config stays untrusted) and the artifact `path:` on upload/download needs the prefix too. And the `paths:` rewrite is the one silent item in the list: unprefixed, `src/**` selects `packages/stack/src/**` and never EQL's, so the heavy jobs skip on real EQL changes, report `skipped`, and `ci-required` treats skipped as pass.
- [x] Satisfy this repo's credentialed-job guards for the two `CS_*`-bearing jobs — `BINDING_EXEMPT_JOBS` entries with the crate-not-binding reason, a `require-cs-secrets` step before the credentialed work, and the `vars`/`secrets` split this repo uses. See the finding above; `scripts/__tests__/ffi-binding-step-order.test.mjs` fails the build until all three are done.
- [x] Fork-PR-skip the credentialed jobs, matching the other `integration-*.yml` workflows. Already true upstream — but **two of this repo's guards had to be extended rather than exempted**, which the plan did not anticipate. `workflow-dispatch-job-conditions.test.mjs` compared whole conditions and required exactly one spelling; EQL's two jobs `&&` the guard with a relevance gate, so the single-spelling rule now applies to the *clause*, compared verbatim, with another conjunct permitted beside it. Its synthetic contexts gained `merge_group` and a permissive `needs` (without which the compound conditions read as skipped on every event), and the verdict table is now derived from the workflow's declared triggers — `test-eql.yml` has no `push:`, and asserting about a run that cannot happen is not a check. Its evaluator also had to model `always()` for the `ci-required` aggregator: total on every event, therefore modellable; `success()` and argument-taking calls still throw.
- [x] Port `bench-eql.yml` and `macro-expand-eql.yml`. `bench` needed three things beyond paths: it holds `CS_*`, so it takes the `vars`/`secrets` split and a `require-cs-secrets` pre-flight (worth more on a scheduled 60-minute job than on a PR — nobody watches a nightly start); and its three actions were on floating major tags, now SHA-pinned to the same commits `test-eql.yml` uses. It also joins `EXPECTED_ASYMMETRIES` in the paths-filter parity guard: `push` only, no second list to drift from.
- [ ] **Moved to Phase 5** — `lint-release.yml` and the two reusable workflows, plus the `cache: false` additions and the `lint-no-workflow-caching.mjs` `TARGETS`/`AUDITED_ACTIONS` work. All of it is about the release machinery: EQL's `lint-release.yml` points actionlint at four release workflows that do not exist at the root yet, and `_build-sql.yml` / `_build-docs.yml` are `workflow_call`-only, reached from EQL's `release.yml` alone. Porting them here would land a gate aimed at absent files. The one genuinely Phase-4 piece is its `shellcheck` + `prepare-bindings-assets.test.sh` half, which covers the asset builder the root `version` script already calls — carry that into the root `lint-release.yml` rather than leaving it with the rest.
- [x] Split cargo off the default test path exactly as protect-ffi did. **Half of this was already true and the other half had nowhere to attach.** EQL has no npm-script layer over its cargo work — the checks are mise tasks invoked straight from workflows — so `@cipherstash/eql`'s `test` is `vitest run` and there is no `test:cargo` to be reachable from. The property therefore lands one level up, in `scripts/__tests__/eql-suite-ci.test.mjs`: every mise task that invokes cargo must be reached by a root workflow, directly or through `depends`. 19 tasks qualify (15 if you read only the task block — the rest hide behind `run = "bash tasks/test/*.sh"`, which is the class most worth checking, so the scan follows that hop and its floor is set to fail if it stops). Five are unreached and each is named with its reason: a watcher, two `:regen` write-halves whose read-halves run in CI, an unsharded local variant, and a unit-test task `test:crates` subsumes.
- [x] Add the EQL Cargo workspace to Dependabot. **The existing lockfile check would not have caught this**: `supply-chain.e2e.test.ts` asserts coverage per *ecosystem*, and `cargo` was already covered by the protect-ffi entry, so `packages/eql/Cargo.lock` read as monitored while nothing proposed an update for it. Dependabot's cargo `directory:` is one workspace root, not a glob. The `ignore` list carries the same four CipherStash crates, and here the argument is sharper than analogy: `tests/sqlx/Cargo.toml` pins `cipherstash-client = "=0.42.0"`, the same exact pin at the same version as protect-ffi, so a PR moving one workspace and not the other reintroduces exactly the skew this absorption removes.
- [x] `.github/actionlint.yaml` must declare the Blacksmith runner labels the imported workflows use — one label, `blacksmith-16vcpu-ubuntu-2204`, used by every job in the suite. Verified by running actionlint over the ported files: identical shellcheck findings before and after, and nothing structural.
- [ ] **Moved to Phase 5 — an ordering defect, found by executing this phase.** Four of the ten workflows *are* the release machinery, and Phase 5 ports them; deleting the directory here would mean reconstructing a publish pipeline from git history at the one moment nobody wants to be doing that. What lands now instead is the shrinking allowlist in `eql-suite-ci.test.mjs`: every file still in the deposit, named with the reason it has not been ported. It is an equality, so it fails in both directions — a file that comes back fails, and so does an entry left behind after its file is gone, which is what forces the last removal to be `rm -r` plus a straight `existsSync(...) === false`.
- [x] **Write the test that asserts a root workflow still runs the SQLx suite** — `scripts/__tests__/eql-suite-ci.test.mjs`, in the shape of `packages/protect-ffi/src/integrationSuiteCi.test.ts` and reusing its `executablePart` trick, so a `paths:` entry or a comment naming a task cannot satisfy it. Mutation-checked six ways across this phase: unprefixing a paths-filter entry, deleting the partition step, demoting it to a comment, pointing rust-cache back at the monorepo root, dropping the e2e pre-flight, and respelling the fork clause with its disjuncts swapped — each fails the intended guard and only that one.

## Phase 5 — release cutover

Five surfaces, each flipped independently, each inert until its own cutover.

- [ ] **Carried over from Phase 4, deliberately.** Port `lint-release.yml` and the two reusable workflows (`_build-sql.yml`, `_build-docs.yml`) alongside the release workflows they gate and are called from — a lint aimed at four absent files is worse than no lint. Add `cache: false` to the three `jdx/mise-action` steps that omit it (`_build-sql.yml`, `_build-docs.yml`, `release-postgres-eql-image.yml`), and add those two plus `release-plz.yml` to `scripts/lint-no-workflow-caching.mjs`'s `TARGETS`, with their remote actions in `AUDITED_ACTIONS` — or the gate fails on the addition itself.
- [ ] **Then delete `packages/eql/.github/` entirely**, and convert the shrinking allowlist in `scripts/__tests__/eql-suite-ci.test.mjs` to a straight `existsSync(...) === false`, alongside the existing protect-ffi assertion in `lintWiring.test.ts`. The allowlist is an equality, so it will already be failing by the time the last file goes — that is what makes this step forced rather than remembered.
- [x] ~~Add `scripts/lint-no-eql-changeset.mjs` in the shape of the FFI guard~~ — **superseded, and do not restore the parked changeset.** The guard landed instead as `FROZEN_PUBLISHERS` in `scripts/release-gate.mjs`, which is strictly stronger: it exits non-zero on any frozen package whose committed version is missing from npm *and* on any runtime `workspace:` range only that package could satisfy, a pair of conditions no changeset-side guard can see — which is why the hand-applied 3.0.5 bump needed this guard rather than that one. (Run `node scripts/release-gate.mjs` for what it blocks at any given moment; that answer comes from the registry and is not recorded here.) It runs at PR time via `tests.yml` and at release time via `release.yml`. `.changeset/rename-ste-vec-contains.md.deferred` was deleted deliberately in `9b1c44d9` — the 3.0.5 bump was entered by hand in the CHANGELOG, so re-parking that `major` changeset would make the cutover bump the package a second time (3.0.5 → 4.0.0) for a rename already released. **Phase-5 action: delete the `@cipherstash/eql` entry from `FROZEN_PUBLISHERS`, nothing more.**
- [ ] Repoint all EQL manifests at `cipherstash/stack`: `packages/eql/packages/eql/package.json` — `repository.url`, `repository.directory` → `packages/eql/packages/eql`, **and `bugs.url`** (line 13, still `encrypt-query-language/issues`, which would send users to an archived repo) — plus `crates/eql-bindings/Cargo.toml` (`repository`, `homepage`) and `release-plz.toml`'s prose. npm and crates.io both reject a publish whose repository field does not match; `bugs.url` is not enforced, which is why it is the one that survives a cutover unnoticed.
- [ ] Port `release.yml`'s EQL half into this repo's `release.yml` — the existing gate-then-publish structure already models "one version authority plus N idempotent publishers", which is the shape it was derived from. Preserve the `classify` prerelease path and the `eql-typescript-v<version>` idempotency short-circuit.
- [ ] Port `release-plz.yml` unchanged in filename — crates.io trusted publishing binds to it.
- [ ] Port `release-postgres-eql-image.yml` and `rebuild-docs.yml`.
- [ ] **Repoint trusted publishing**, only after a versioned dry run: npm for `@cipherstash/eql` (workflow `release.yml`, explicitly selecting `npm publish` under Allowed actions), and crates.io for `eql-bindings` (workflow `release-plz.yml`).
- [ ] Move the `DOCS_WEBHOOK_URL` secret and the GHCR package ownership.
- [ ] Activate the parked changesets, merge the Version Packages PR, and verify at one version V: the npm tarball, the crate, the `eql-<V>` release with both SQL assets, the docs rebuild, and the image tags.
- [ ] Update the dbdev runbook for the new paths. It stays manual.

## Phase 6 — flip

- [ ] Archive `cipherstash/encrypt-query-language`.
- [ ] Update `AGENTS.md` — Repository Layout, the skills map, the "Working on protect-ffi" section (which now has an EQL sibling), and `SECURITY.md`'s package list.
- [ ] Check the skills. `skills/stash-indexing` documents the `@cipherstash/eql` pin and `eql install` behaviour; `skills/stash-postgres` documents the EQL operator/domain surface. Both ship in the `stash` tarball.

---

## Verification checklist

- [ ] Single-branch import grows the pack by ~13 MiB; 975 files in, 975 out
- [ ] Every repo-root-relative path inside `packages/eql` still resolves — `sync-generated.mjs`, the mise tasks, `Doxyfile`, `docker-compose.yml`, `deps-ordered-*.txt`
- [x] **EQL's own SQL build runs here and produces the same bytes.** `mise run build` at `packages/eql`: 268 files in declared order, the trailing-newline and line-count-identity gates pass, 59 573 lines accounted for, 2 649 625 bytes out. Compared against both committed copies (`crates/eql-bindings/sql/` and the npm package's `sql/`), the fresh build differs in **exactly three lines** — `DEV` where the committed files say `3.0.4`. That is `release:prepare_bindings_assets --version V` stamping the identity, which `scripts/sync-lockstep-versions.mjs` invokes at `changeset version`. So the committed SQL is not stale, and the lag between releases is the design rather than a defect
- [x] **No EQL CI step was dropped in the port.** Every `mise run <task>` invocation in upstream's ten workflows (36 distinct tasks, read from `eql/main`) is invoked by a root workflow, with five exceptions — `docs:generate`, `docs:generate:json`, `docs:generate:markdown`, `docs:package` and `release:prepare_bindings_assets` — and all five appear **only** in the four release workflows Phase 5 ports. Compared by diffing task invocations across the two workflow sets rather than by reading the ported files, which is the comparison a faithful-looking port cannot pass by accident
- [x] **The turbo cache restores a COMPLETE `@cipherstash/eql`.** This is the `@cipherstash/protect-ffi#build` failure class — a cache hit that restores nothing while reporting success — and it is not hypothetical here, because `dist/sql/` (the 2.6 MB installer, the uninstaller, `release-manifest.json`) and `dist/schema/` are copied by tsup's `onSuccess` hook, not emitted by tsup. Verified by `diff -rq` between a cache-restored `dist/` and one built under `--force`: identical. No `outputs` override is needed, because the package's build output is `dist/**`, which is what the repo-wide `build` task already declares
- [x] **`stack-prisma` was the only consumer that needed the build.** With `@cipherstash/eql`'s `dist/` deleted and every other package left built, all six remaining bare `pnpm --filter … run …` steps in the workflows still pass (`test:types` for stack, test-kit, stack-drizzle and stack-supabase; `wizard` typecheck; protect-ffi's wasm typecheck). Confirmed `dist/` stayed absent for the whole run — a step that rebuilt it would have made every later PASS meaningless. **`workflow-turbo-build-deps.test.mjs` cannot see five of those six**: it matches bare invocations of scripts `turbo.json` declares as tasks, and `test:types` / `test:typecheck:wasm` are not tasks. They are checked here by hand and nothing keeps them checked
- [x] `tasks/test/doc-anchors.sh` and `tasks/test/known-failures.sh` resolve `packages/eql`, not the Stack root — checked by *running* them under mise (both pass; the known-failure marker resolves `cipherstash/encrypt-query-language#387` as OPEN). **The negative check is scope, not exit status.** `known-failures.sh` fails loudly without `EQL_ROOT` (exit 2, missing registry), but `doc-anchors.sh` exits **0** either way: unset, it scans the Stack root and checks 170 links instead of EQL's 117. That is a superset, so it is not even wrong — it silently widens an EQL gate into a monorepo-wide one, which is why the count, not the status, is the evidence
- [ ] `packages/eql/.gitattributes` still marks the generated scalar SQL `linguist-generated`, and `merge=union` applies to no `CHANGELOG.md` outside `packages/eql`
- [x] `pnpm install --frozen-lockfile` clean with `@cipherstash/eql` linked as a workspace package
- [x] `pnpm build` builds `@cipherstash/eql`; deleting its `dist` and rebuilding recovers it (mutation-checked)
- [x] Root `pnpm test` runs `@cipherstash/eql`'s own suite — mutation-checked by breaking one of its unit tests
- [x] `packages/eql/package.json` is gone and `pnpm list --depth -1` shows no `@cipherstash/eql-workspace` member
- [x] `sync-lockstep-versions.test.mjs` sits under `scripts/__tests__/` and root `pnpm test:scripts` actually runs it — mutation-checked by breaking an assertion
- [x] `scripts/lint-typecheck-scope.mjs` reports on `packages/eql/packages/eql`, verified by giving it a deliberately unscoped tsconfig and watching it fail. **The mutation needs two edits, not one**: the nested package's `build` is `tsup` and it has no `typecheck` script, so the linter skips it by design whatever its tsconfig says (a tsconfig no gate runs is an editor setting). Deleting `include` *and* adding `"typecheck": "tsc --noEmit"` produces the expected offender line; restoring `include` alone clears it. So the `WORKSPACE_ROOTS` entry is coverage for the day this package wires a gate, not a check that is live today
- [x] `packages/stack`, `packages/cli`, `packages/stack-prisma` resolve `@cipherstash/eql` from the workspace, at `workspace:^`
- [x] Root `pnpm test` invokes cargo **zero** times under a `PATH` trap — a shim that logs its argv and exits 0, so the run continues and reveals *every* call site rather than only the first. Run under `TURBO_FORCE=true`, without which a cached task is skipped and the trap proves nothing: 14 tasks executed, `@cipherstash/eql:test` among them (2 files, 5 tests), zero cargo lines. (`@cipherstash/stack#test` fails in this worktree on a missing `protect-ffi-darwin-arm64/index.node` — a gitignored build output nothing here has built, unrelated to EQL.)
- [x] `codegen:parity`, the crate tests and the SQLx suite are all reachable from a root workflow — asserted by discovery over the mise task graph, not by a list, in `scripts/__tests__/eql-suite-ci.test.mjs`. (`test:cargo` does not apply: EQL has no npm-script layer over cargo, so there is no such entry point to be reachable from.)
- [x] `cargo build -p protect-ffi` succeeds against the path-dep `eql-bindings` — host (4m 51s) and `wasm32-unknown-unknown` (1m 18s), plus `test:cargo` at 310 passed / 0 failed and `cargo fmt --check` clean
- [ ] The credentialed protect-ffi integration suite passes unchanged against the path dep. **Split out of the line above deliberately**: they were one box, and one box that is half-runnable is a box that gets ticked. Needs Docker and `CS_*`
- [x] No manifest names `eql-bindings` or `@cipherstash/eql` by registry version, except `packages/protect-ffi/integration-tests` under a named exemption with a written reason — `scripts/lint-no-eql-registry-pins.mjs`, run from `tests.yml`'s `lint` job, mutation-checked four ways
- [ ] `packages/eql/.github/` is deleted and a test fails if it returns — **Phase 5**, once the release workflows are ported. Until then `eql-suite-ci.test.mjs` holds the deposit as an equality against the list of files still waiting.
- [x] The SQLx matrix runs from a root workflow, fork-PR-skipped, credentialed, PG 14–17 in the merge queue
- [x] `scripts/__tests__/ffi-binding-step-order.test.mjs` passes with the EQL jobs present — exempted from the binding build with a reason, **not** exempted from `require-cs-secrets`
- [ ] No `jdx/mise-action` step in any release workflow omits `cache:`, and the caching lint's target list covers `release-plz.yml` and the image publisher
- [x] `actionlint` clean over every ported workflow — verified for `test-eql.yml`, `bench-eql.yml` and `macro-expand-eql.yml`. "Clean" means no structural, expression or runner-label findings; the shellcheck style/info diagnostics are upstream's and are byte-for-byte the same set before and after the port, which is the comparison that shows the port introduced nothing
- [ ] `release.yml` passes `version: pnpm run version` to `changesets/action`, and a dry run shows `Cargo.toml` and the SQL assets moving to the computed version — the hook is dead without it
- [ ] All EQL manifests read `cipherstash/stack`, including `repository.directory` and `bugs.url`
- [ ] `pnpm run code:check` error-free across the merged tree
- [ ] A Stack-only release does not publish EQL; an EQL 3.x patch does not force a Stack release
- [ ] One release produces npm + crate + SQL assets + docs + image at one version V

---

## Not verified

Stated so the next reader does not mistake inference for measurement.

1. ~~**A finished build against the path-dep `eql-bindings`.**~~ **Resolved 2026-08-13** — built clean in 3m 10s against a temporarily-pointed manifest, and again after the flip landed for real: host, `wasm32-unknown-unknown`, and `test:cargo` at 310 passed. See Phase 3. What remains unverified is the *credentialed* half: the `integration-tests` suite has not been run against the path dep, and that is what turns "no-op" from an argument about byte-identity into an observed result. It is the **only** unfinished item in Phase 3, and it cannot be closed by reasoning — it needs Docker and `CS_*`.
2. **Anything about CI runtime behaviour.** No Docker daemon and no credentials were used here. The SQLx suite's first run in this repo is unproven by construction, exactly as `integration-protect-ffi.yml`'s was.
3. **Whether `access: "restricted"` in the root changeset config is overridden by the package's `publishConfig.access: "public"`.** Asserted from changesets' documented precedence, not run.
4. **The Doxygen/Python docs pipeline.** `mise.toml` installs Python 3.13 for `tasks/docs/generate/*.py`. Not executed; the ported workflow is the first real test.
5. **crates.io's published version list for `eql-bindings`.** No network access during this pass. The local registry cache holds 3.0.2, 3.0.3 and 3.0.4.

## Resolved decisions

All three were measured against the two trees on 2026-08-13 and closed the same day. Kept here with their reasoning, because the reasoning is what a later reader needs in order to reopen one deliberately.

1. **The private `@cipherstash/eql-workspace` root manifest is deleted.** Once the `version` hook moves to this repo's root — which Changesets forces regardless — nothing load-bearing is left: three scripts conflict with the root, two are already defined there under the same names, and the remaining four are thin delegations CI does not call. The subtree needs no `node_modules` for its mise tasks to run. The precedent cited for keeping it was mistaken: `packages/protect-ffi/package.json` is a published package, not a private workspace root. See the finding above for the accounting.
2. **The two Cargo workspaces stay separate this round.** The path dep in Phase 3 is what buys the anti-skew guarantee; unification buys build hygiene, and it would make `dead_code = "deny"` and `default-members` repo-wide policy as a side effect of a move. The lockfiles already agree on the dependency that matters. See Phase 3 for the reopening signal.
3. **`packages/protect-ffi/integration-tests` is absorbed in a separate PR, immediately after.** Absorbing it moves `@cipherstash/auth`, `vitest` and `@cipherstash/eql` simultaneously, and only a run with Docker plus `CS_*` credentials can show that is neutral — bundling it makes the absorption PR unreviewable without a live credentialed result attached. The reason to do it soon is real and has strengthened: after Phase 2 this is the **last** registry pin of `@cipherstash/eql` in the tree, and it is the pin used by `tests/postgres.test.ts` and `tests/postgres-v3.test.ts`, the repo's only EQL v2 *and* v3 SQL coverage — precisely where a mismatch between the npm-pinned bundle and the in-tree SQL would surface as an expensive-to-diagnose failure. Until then it carries a named, reasoned exemption in the Phase 3 registry-pin guard.

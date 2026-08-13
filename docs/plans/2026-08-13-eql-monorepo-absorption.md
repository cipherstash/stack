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

### Turbo's filter does not reach two levels down — and the consequence is a silent test, not a broken build

Root `build` and `test` are `turbo <task> --filter './packages/*'`. That glob is one level, so it **selects** `packages/eql` (the private subtree root) and not `packages/eql/packages/eql`.

The build is nonetheless covered: `build` declares `dependsOn: ["^build"]`, and turbo traverses workspace dependencies regardless of which packages the filter selected. `packages/stack`, `packages/cli` and `packages/stack-prisma` would depend on `@cipherstash/eql`, so it gets built as their dependency. An earlier revision of this plan claimed `pnpm build` would leave it unbuilt; that was wrong.

The **test** is not covered. `turbo test --filter './packages/*'` never selects the nested package, and nothing depends on its `test` task, so `@cipherstash/eql`'s own Vitest suite — `src/index.test.ts`, `src/sql.test.ts` — would run nowhere. That is precisely the defect the protect-ffi round kept finding: a check that arrives as a file, appears wired up, and executes on no event.

This interacts with the open decision below. If the private `@cipherstash/eql-workspace` manifest stays a member, its `test` script (`pnpm --filter @cipherstash/eql test`) does get selected and would delegate — but as a raw pnpm call outside turbo's graph, so it is uncached, unordered against `^build`, and invisible to `turbo run` filtering. **Decide the manifest's fate first, then choose the filter change** — the two are one decision, not two. Either way, keep the mutation test: delete the nested package's `dist`, and separately break one of its unit tests, and confirm root `pnpm build` and root `pnpm test` each notice.

### The imported credentialed jobs fail two of this repo's CI guards on arrival

`scripts/__tests__/ffi-binding-step-order.test.mjs` scans every root workflow, collects every job carrying a `CS_*` credential, and asserts each one (a) builds the protect-ffi binding and (b) runs `require-cs-secrets` first. Both exemption lists — `BINDING_EXEMPT_JOBS` and `PREFLIGHT_EXEMPT_JOBS` — are **deliberately empty Maps**, each keyed `'<workflow> / <job>'` with a mandatory reason, and each self-checked so a stale entry fails the guard.

EQL's credentialed jobs (`test-eql.yml` lines 133–136 and 601–604) reach CipherStash through the `cipherstash-client` **crate**, never through `index.node` or `dist/wasm`. So on arrival they fail guard (a) for a reason that is legitimate and fail guard (b) for a reason that is not:

- Add each to `BINDING_EXEMPT_JOBS` with the reason "encrypts via the `cipherstash-client` crate; never loads the Node binding". Do not make them build the binding to satisfy the scan — that buys a four-minute compile for nothing.
- Add `require-cs-secrets` **before** the credentialed work rather than taking a `PREFLIGHT_EXEMPT_JOBS` entry. A job holding `CS_*` is a job a rotated secret can break, and the pre-flight is how it says so in seconds instead of in a timeout.

There is also a convention mismatch. EQL reads all four values from `secrets`; this repo reads `CS_WORKSPACE_CRN` and `CS_CLIENT_ID` from `vars` and only the key material from `secrets` (`integration-supabase.yml`, `integration-prisma-next.yml`, `prisma-next-e2e.yml`). Port to this repo's convention or `require-cs-secrets` will report the CRN missing.

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
- [ ] Run `pnpm run code:fix` and commit the Biome 1.8.3 → 2.5.2 reflow **as its own commit**, so it never confounds a semantic diff. Verify by comparing token multisets rather than by eye.

## Phase 2 — wire the workspace

- [ ] `pnpm-workspace.yaml`: add `packages/eql/packages/*`. Note that `packages/*` already matches `packages/eql` itself, whose `package.json` is the private `@cipherstash/eql-workspace` — decide deliberately whether that stays a member (it is a useful home for subtree-scoped scripts, as `packages/protect-ffi/package.json` is) or is deleted. If it stays, strip its `changeset`/`changeset:version`/`release` scripts and make sure its `test` reaches no cargo.
- [ ] Move the lockstep hook to the root, **in two parts — the script alone does nothing**:
  1. Root `package.json` gains `"version": "changeset version && node packages/eql/scripts/sync-lockstep-versions.mjs"`.
  2. `release.yml`'s `changesets/action` step gains `version: pnpm run version`. It currently passes only `publish:`, so the action runs its built-in `changeset version` and **never invokes the root script**. Without this line the hook is present, plausible, and dead: `Cargo.toml` and the SQL assets keep the old version while npm bumps, and the first sign is a released crate whose version disagrees with the bundle it ships.

  **Add both in the commit that first writes a `Cargo.toml` version, with a test asserting the workflow passes `version:`** — the protect-ffi plan's warning about pass-through seams is exactly this failure, and it fails open.
- [ ] Reconcile `packages/eql/packages/eql/package.json`: replace the four default-`catalog:` references with `catalog:repo`, adding `@types/node` to `catalogs.repo` if it should be catalogued. Accept the moves to `typescript 5.9.3` / `vitest 3.2.7` / `tsup 8.5.1` and run the package's own suite.
- [ ] Remove `'@cipherstash/eql'` from `minimumReleaseAgeExclude` — it becomes dead config once the package is first-party.
- [ ] Repoint `packages/stack`, `packages/cli` and `packages/stack-prisma` from `"@cipherstash/eql": "3.0.4"` to `"workspace:^"`. Also `packages/protect-ffi/integration-tests/package.json`, which pins `3.0.2` — but that directory is not a pnpm workspace member and installs with `npm ci`, so it cannot take a `workspace:` specifier. Leave it pinned and note it; it is already a deferred follow-up from the protect-ffi round.
- [ ] Set `EQL_ROOT` in `packages/eql/mise.toml`'s `[env]` so `doc-anchors.sh` and `known-failures.sh` stop resolving the Stack root. One line; see the finding above.
- [ ] Fix the turbo **test** selection so it reaches the nested package — `--filter './packages/*' --filter './packages/eql/packages/*'`, or a `./packages/**` glob — after deciding the subtree-root manifest's fate, since that decision changes which fix is right. `build` is already covered by `^build` traversal. **Mutation-check both:** break one of the nested package's unit tests and confirm root `pnpm test` fails; delete its `dist` and confirm root `pnpm build` recreates it.
- [ ] Add `packages/eql` paths to the root `biome.json` ignore list where the imported tree carries generated output: `packages/eql/packages/eql/src/generated`, `packages/eql/release`, `packages/eql/target`, `packages/eql/docs/api`. (The generated TypeScript lives under the *nested* package — `packages/eql/src/generated` does not exist.)
- [ ] Extend `scripts/lint-typecheck-scope.mjs` to discover the nested package. Its `WORKSPACE_ROOTS = ['packages', 'examples']` walk is one `readdirSync` deep, so it finds `packages/eql` and silently misses `packages/eql/packages/eql` — a package outside the scan reads exactly like a package that passed. Either teach discovery the workspace globs or name the nested directory explicitly. Note there is nothing to "add it to" on the tsconfig side: the root `tsconfig.json` is a bare `compilerOptions` base with no `include`, no `references` and no project graph.
- [ ] Changesets: add `@cipherstash/eql` as its own release line. It is **not** in the Stack fixed group and **not** in the FFI group — that is what `workspace:^` buys. Verify `publishConfig.access: "public"` on the package survives the root config's `"access": "restricted"`.
- [ ] `pnpm install --frozen-lockfile` clean; `pnpm run code:check` error-free.

## Phase 3 — kill the skew

Do this before CI. It is the reason for the import, and it is verified-neutral today.

- [ ] Change `packages/protect-ffi/crates/protect-ffi/Cargo.toml`: `eql-bindings = { version = "=3.0.2" }` → `eql-bindings = { path = "../../../eql/crates/eql-bindings" }`.
- [x] **Cargo accepts a path dep into a package that is a member of another workspace.** Probed: a scratch crate path-depending on `encrypt-query-language/crates/eql-bindings` resolved cleanly (`cargo metadata` locked 36 packages and emitted the full graph) and proceeded into compilation. No workspace-membership rejection. The probe did not reach a finished binary — the machine ran out of disk — so the resolution semantics are confirmed and a clean full build is not.
- [ ] Verify the flip is a no-op: `cargo build -p protect-ffi` before and after should produce identical behaviour, because the sources are byte-identical. Run `packages/protect-ffi`'s cargo suite and the credentialed `integration-tests` suite.
- [ ] Add a guard that fails if any manifest in the tree names `eql-bindings` by registry version rather than path. A registry pin reintroduces the skew silently.
- [ ] **Decide whether to unify the two Cargo workspaces now or later.** One root `Cargo.toml` with members `packages/protect-ffi/crates/protect-ffi`, `packages/eql/crates/*` and `packages/eql/tests/sqlx` gives one lockfile and one `target/`. Against doing it now: EQL's workspace root sets `default-members = ["tests/sqlx"]` and `[workspace.lints.rust] dead_code = "deny"` / `unused_imports = "deny"`, both of which become repo-wide decisions; and protect-ffi builds for `wasm32-unknown-unknown`, which a merged workspace would attempt for the EQL crates unless every invocation is `-p`-scoped. My recommendation is to defer it — the path dep above is what buys the guarantee, and unification is build hygiene that can be measured separately.

## Phase 4 — CI

The protect-ffi lesson applies verbatim: **a check that arrives as a file and then executes nowhere reads exactly like a check that passes.** EQL's ten workflows arrive under `packages/eql/.github/`, a directory GitHub never reads.

- [ ] Port `test-eql.yml` to the root workflow directory, rewriting every path filter to the `packages/eql/**` prefix and every mise step to `working-directory: packages/eql`. Keep the event-shaped matrix (PR → PG17 × 4 shards; merge queue → PG 14–17 × 2 shards) and the `changes` job's must-always-succeed contract.
- [ ] Satisfy this repo's credentialed-job guards for the two `CS_*`-bearing jobs — `BINDING_EXEMPT_JOBS` entries with the crate-not-binding reason, a `require-cs-secrets` step before the credentialed work, and the `vars`/`secrets` split this repo uses. See the finding above; `scripts/__tests__/ffi-binding-step-order.test.mjs` fails the build until all three are done.
- [ ] Fork-PR-skip the credentialed jobs, matching the other `integration-*.yml` workflows.
- [ ] Port `lint-release.yml`, `bench-eql.yml`, `macro-expand-eql.yml`, and the two reusable workflows. Add `cache: false` to the three `jdx/mise-action` steps that omit it (`_build-sql.yml`, `_build-docs.yml`, `release-postgres-eql-image.yml`), and add those two plus `release-plz.yml` to `scripts/lint-no-workflow-caching.mjs`'s `TARGETS` — with their remote actions in `AUDITED_ACTIONS`, or the gate fails on the addition itself.
- [ ] Split cargo off the default test path exactly as protect-ffi did: `codegen:parity`, the SQLx suite and the crate tests reachable from `test:cargo` and from CI, never from `test`. Extend `packages/protect-ffi/src/lintWiring.test.ts`'s model, or add its sibling for EQL, so that a check nothing invokes fails the build.
- [ ] Add the EQL Cargo workspace to Dependabot, and confirm every lockfile in the tree still maps to a monitored ecosystem.
- [ ] `.github/actionlint.yaml` must declare the Blacksmith runner labels the imported workflows use.
- [ ] Delete `packages/eql/.github/` entirely and add the assertion that it stays deleted, alongside the existing protect-ffi one.
- [ ] **Write the test that asserts a root workflow still runs the SQLx suite**, in the shape of `packages/protect-ffi/src/integrationSuiteCi.test.ts` — scanning the repo-root workflow directory, and rejecting a `paths:`-only mention.

## Phase 5 — release cutover

Five surfaces, each flipped independently, each inert until its own cutover.

- [ ] Add `scripts/lint-no-eql-changeset.mjs` in the shape of the FFI guard, so an `@cipherstash/eql` changeset parks as `.changeset/<name>.md.deferred` until npm publishing actually moves. Carry the pending `rename-ste-vec-contains.md` in parked form.
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
- [ ] `tasks/test/doc-anchors.sh` and `tasks/test/known-failures.sh` resolve `packages/eql`, not the Stack root — checked by *running* them, and by confirming `doc-anchors.sh` fails when `EQL_ROOT` is unset (it passes vacuously against the wrong tree)
- [ ] `packages/eql/.gitattributes` still marks the generated scalar SQL `linguist-generated`, and `merge=union` applies to no `CHANGELOG.md` outside `packages/eql`
- [ ] `pnpm install --frozen-lockfile` clean with `@cipherstash/eql` linked as a workspace package
- [ ] `pnpm build` builds `@cipherstash/eql`; deleting its `dist` and rebuilding recovers it (mutation-checked)
- [ ] Root `pnpm test` runs `@cipherstash/eql`'s own suite — mutation-checked by breaking one of its unit tests
- [ ] `scripts/lint-typecheck-scope.mjs` reports on `packages/eql/packages/eql`, verified by giving it a deliberately unscoped tsconfig and watching it fail
- [ ] `packages/stack`, `packages/cli`, `packages/stack-prisma` resolve `@cipherstash/eql` from the workspace, at `workspace:^`
- [ ] Root `pnpm test` invokes cargo **zero** times under a `PATH` trap
- [ ] `codegen:parity`, the crate tests and the SQLx suite are all reachable from `test:cargo` and from a root workflow
- [ ] `cargo build -p protect-ffi` succeeds against the path-dep `eql-bindings`, and the credentialed protect-ffi integration suite passes unchanged
- [ ] No manifest names `eql-bindings` by registry version
- [ ] `packages/eql/.github/` is deleted and a test fails if it returns
- [ ] The SQLx matrix runs from a root workflow, fork-PR-skipped, credentialed, PG 14–17 in the merge queue
- [ ] `scripts/__tests__/ffi-binding-step-order.test.mjs` passes with the EQL jobs present — exempted from the binding build with a reason, **not** exempted from `require-cs-secrets`
- [ ] No `jdx/mise-action` step in any release workflow omits `cache:`, and the caching lint's target list covers `release-plz.yml` and the image publisher
- [ ] `actionlint` clean over every ported workflow
- [ ] `release.yml` passes `version: pnpm run version` to `changesets/action`, and a dry run shows `Cargo.toml` and the SQL assets moving to the computed version — the hook is dead without it
- [ ] All EQL manifests read `cipherstash/stack`, including `repository.directory` and `bugs.url`
- [ ] `pnpm run code:check` error-free across the merged tree
- [ ] A Stack-only release does not publish EQL; an EQL 3.x patch does not force a Stack release
- [ ] One release produces npm + crate + SQL assets + docs + image at one version V

---

## Not verified

Stated so the next reader does not mistake inference for measurement.

1. **A finished build against the path-dep `eql-bindings`.** Resolution is confirmed (Phase 3); compilation is not — the probe died on `No space left on device` with 2.1 GiB free and a 47 GB `~/.cargo-shared-target`. Re-run it with disk available before relying on Phase 3.
2. **Anything about CI runtime behaviour.** No Docker daemon and no credentials were used here. The SQLx suite's first run in this repo is unproven by construction, exactly as `integration-protect-ffi.yml`'s was.
3. **Whether `access: "restricted"` in the root changeset config is overridden by the package's `publishConfig.access: "public"`.** Asserted from changesets' documented precedence, not run.
4. **The Doxygen/Python docs pipeline.** `mise.toml` installs Python 3.13 for `tasks/docs/generate/*.py`. Not executed; the ported workflow is the first real test.
5. **crates.io's published version list for `eql-bindings`.** No network access during this pass. The local registry cache holds 3.0.2, 3.0.3 and 3.0.4.

## Open decisions

1. **Does the private `@cipherstash/eql-workspace` root manifest stay a workspace member?** Keeping it gives subtree-scoped scripts a home, matching `packages/protect-ffi/package.json`; deleting it removes a confusing second root. Either way its `changeset`/`release` scripts must go.
2. **Unify the Cargo workspaces now or defer?** Recommended: defer. See Phase 3.
3. **Does `packages/protect-ffi/integration-tests` get absorbed into the pnpm workspace in the same PR?** It pins `@cipherstash/eql 3.0.2` and is the last place that pin survives. It was already deferred once because only a credentialed run can show the dependency change is neutral — the same argument still holds, but the reason to do it is now stronger.

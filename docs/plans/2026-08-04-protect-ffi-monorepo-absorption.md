# protect-ffi monorepo absorption — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, version and publish `@cipherstash/protect-ffi` and its six platform binary packages from this repository instead of `cipherstash/protectjs-ffi`, so a change spanning the Rust core and the JS SDK is one PR and one release.

**Architecture:** Source and publishing both move. The seven FFI packages get their own Changesets `fixed` group, separate from Stack's. The release pipeline is **one version authority (Changesets) plus N idempotent publishers ordered by dependency** — the model proven in `cipherstash/encrypt-query-language`. Native binaries are built by a target-explicit matrix, packed, and published *before* `changeset publish`, which then skips them as already-published.

**Tech Stack:** pnpm 10.33.2 workspaces + catalogs, Turborepo, Changesets 2.31, Neon (`@neon-rs/cli`, `@neon-rs/load`), Rust/Cargo (nested workspace), wasm-pack, Vitest 3.2.7, Biome 2.5.3, GitHub Actions with npm OIDC trusted publishing.

## Global Constraints

- **Node >= 22** (root `engines`); **pnpm 10.33.2**; CI installs with `--frozen-lockfile` — including `release.yml`, which currently does not (Task 5).
- **Publish jobs run on GitHub-hosted runners.** npm rejects provenance from self-hosted with E422. Build matrices may stay on Blacksmith.
- **Publish workflows must never restore the GitHub Actions cache.** Enforced by `scripts/lint-no-workflow-caching.mjs`. This is why upstream's `.github/actions/setup` composite action is **not** ported wholesale — it sets `cache: npm` on `setup-node` and `cache: true` on `mise-action`.
- **npm >= 11.5.1 is required for OIDC trusted publishing**, installed *after* any `mise-action` step.
- **Trusted publishing binds to `(repository, workflow filename)`.** The job performing a publish must live in the registered file. Reusable workflows are fine for building artifacts, not for publishing.
- **`repository.url` must exactly match the publishing GitHub repository** — verified against <https://docs.npmjs.com/trusted-publishers/>: *"your package's `repository.url` field in `package.json` must exactly match your GitHub repository."*
- **No `NPM_TOKEN` in the release workflow.** `changesets/action` writes a token `.npmrc` that shadows OIDC; every publish then fails with E404 (npm/cli#8976).
- **`pnpm pack` takes no positional directory argument.** Use `pnpm --dir <dir> pack` or `pnpm --filter <name> pack`. See Task 4.
- **Do not write `pnpm run <script> -- --flag`.** npm strips the `--`; pnpm forwards it verbatim.
- **Biome gates on errors, not warnings.**

---

## Status

**Phases 1 and 2 are complete** on branch `feat/protect-ffi-monorepo-absorption`, as 11 commits over a pure subtree import (`0b605912`…`b99cbd92`). Work continues on that branch, not on `import-protect-ffi` — the original import branch, which stops at `b99cbd92`. Every `gh` invocation below names the working branch.

| Commit | Delivers |
|---|---|
| `0b605912` | Pure `git subtree` import — 613 commits, 200 tracked files |
| `1e922ec0` | Deposit cleanup (lockfile, duplicate COC, nested Biome config) |
| `267ba11d` | Workspace linking: `platforms/*` glob, three `workspace:*` pins, six `optionalDependencies`, Dependabot + `minimumReleaseAgeExclude` removals |
| `a0236fa4` | FFI fixed group + `scripts/lint-no-ffi-changeset.mjs` publishing guard |
| `76696dab` | Manifest/toolchain reconciliation — cargo off the default test and build paths |
| `29af450d` | `packages/stack` consumes protect-ffi 0.31.0 |
| `9b7983ce` | Three WASM declaration files tracked; three-layer `.gitignore` chain |
| `d7128724` | `CS_CLIENT_KEY` hex guard in `require-cs-secrets` |
| `6c1f641a` | Non-ignored Stack changeset for the 0.31 adoption (`minor`) |
| `c0bfe6b5` | `AGENTS.md`, `SECURITY.md`, `skills/stash-auth` |
| `b99cbd92` | Lazy native load + `assertNativeBindingAvailable()` |

**Working-tree state is not part of this plan's guarantees.** An earlier revision claimed "working tree clean"; that was true when written and false shortly after. A prior rewrite of this document was lost by being left uncommitted across a branch switch — **commit plan edits in the session that makes them.**

**Remaining: phases 3, 4, 5.** Phase 3 is specified as executable tasks below. Phase 4 contains the only irreversible steps. Phase 5 is blocked until phase 4 publishes.

**Phase 3 Task 0 is committed (`70e1f7da`) and awaiting a CI run.** It is the
prerequisite for everything after it: PR #858's board is red without it, so no
later task can be verified against a green baseline.

### Phase 3 progress

| Commit | Delivers |
|---|---|
| `70e1f7da` | Task 0 — build the binding in the jobs that need it |
| `bc0cb132` | Task 8 (part) — `tests-rust.yml`, the Rust checks running again |
| `35397412` | Secrets pre-flight ordered before the binding build, with `scripts/__tests__/ffi-binding-step-order.test.mjs` to hold it |
| `15562406` | Two supply-chain gaps in `build-ffi-binding` |
| `ee35c801` | Gaps the previous round's guards did not cover; `test:typecheck:wasm` wired into the WASM job |
| `dfb8f4d3` | The `integration-tests/` suite runs from a root workflow again |
| `48fb5254` | `lintWiring` exemptions made mechanically checkable; dead `release`/`dryrun` scripts removed |
| `b5ab1ee5` | Dependabot monitors the in-tree Cargo workspace |

### The absorption was audited against upstream

`~/src/protectjs-ffi` at `ce820bb` (v0.31.0) versus `packages/protect-ffi`, file
by file. **The import itself is faithful** — 200 tracked files in, 200 out, the
full 613-commit history grafted, and `crates/`, `Cargo.*`, `docs/`,
`platforms/*`, `src/eql-v3-types/`, `integration-tests/` and `type-tests/`
byte-identical. Every content diff reduces to a deliberate commit above; the 16
integration-test diffs are Biome 2 reflow only, verified by comparing token
multisets rather than by eye.

The defects were all in what *ran*, not what arrived, and all three shared one
shape: **a check that came across as files and then executed nowhere, because
the thing that used to invoke it was the upstream workflow deposited under
`packages/protect-ffi/.github/`.** That directory is inert — GitHub does not read
workflows from a subdirectory — so every check it drove went quiet on the day of
the import while still appearing, to a reader, to be wired up. `test:typecheck:wasm`
had an exemption *claiming* a job ran it. The 19-file integration suite had no
claim at all. Prose in a guard is not a guard; the fixes above replace each claim
with an assertion against the root workflow directory.

Two documentation surfaces had drifted the same way and are fixed in `48fb5254`:
the README documented deleted scripts, `build` as producing `index.node`, and the
`--` separator anti-pattern `lintWiring` forbids.

---

## Corrections to earlier revisions

### The `ignore` guard is impossible

Changesets rejects it:

```
error The package "@cipherstash/stack" depends on the skipped package
      "@cipherstash/protect-ffi", but "@cipherstash/stack" is not being skipped.
      Please add "@cipherstash/stack" to the `ignore` option.
```

An ignored package's dependents must also be ignored, cascading through the Stack fixed group to a total release freeze — the alternative this plan rejected. Replaced by `scripts/lint-no-ffi-changeset.mjs`. All seven packages are already on npm at `0.31.0`, and `changeset publish` only publishes versions absent from the registry, so a release is *already* a no-op for them. Full analysis: `.work/2026-08-04-protect-ffi-changesets-ignore-analysis.md`.

### `optionalDependencies` were never tracked

`neon update` injected the six platform pins at prepack. Dropping it as originally planned would have published a wrapper with no platform dependencies. Fixed by committing them as `workspace:*`.

### The 0.31 delta is four breaking changes, not three

The fourth — filed as "lower-risk but worth knowing" — broke 61 tests: 0.31 forwards unrecognised top-level keys to Rust, and stack attached a correlation `id` to every bulk payload. A fifth surfaced on removing the `as never`: `encryptConfig` no longer needs `normalizeCastAs`.

### Release lines are coupled by pinning, not by fixed groups

Earlier text claimed the separate fixed group avoids "making every Rust patch republish the CLI, the core library, the wizard, and all three adapters". **That is false as pinned.** Measured with isolated `changeset status` runs:

| protect-ffi pinned as | FFI changeset | Stack group (6 packages) |
|---|---|---|
| `workspace:*` (current) | patch | **patch — all six** |
| `workspace:*` (current) | minor | **patch — all six** |
| `workspace:^` | patch | **untouched** |
| `workspace:^` | minor (0.31→0.32, outside `^0.31.0`) | **patch — all six** |

`updateInternalDependencies` is not the lever — it accepts only `patch` or `minor`, and an exact pin is always out of range after any bump. What the separate fixed group actually buys is avoiding a **version discontinuity**: joining Stack's group would take protect-ffi from `0.31.0` to `1.0.1`, since a fixed group adopts its highest member version.

The coupling is correct and should stay: an exact pin is how a wrapper/binary mismatch is made impossible, and caret is restrictive below 1.0 anyway. The forced bump is only a patch, so Stack's version line is never disturbed. **This matters for the EQL import** — see "Out of scope".

### pnpm argument forwarding

npm strips the `--` in `npm run x -- --release`; pnpm forwards it, landing it after the `> cargo.log` redirect where cargo rejects it as a positional. The release matrix passes `--target "${CARGO_BUILD_TARGET}.2.28"` this way, so the port depends on the separator-free spelling.

### `neon dist` needs `-o`

Bare `neon dist < cargo.log` writes `./index.node` — the `debug:` fallback in `load.cts`. Populating a platform package needs `neon dist -o platforms/<p>/index.node`.

### This package's `build` is not upstream's `build`

The matrix was ported verbatim from upstream, including `platform.includes('gnu') ? "zigbuild" : "build"`. Upstream's `build` was the cargo script. **Here `build` is `tsc` and nothing else** — phase 1 moved cargo to `build:native` precisely so the default path stays Rust-free. Ported as-is, four of the six platforms would have run a TypeScript compile, produced no binary, and failed one step later on a missing `cargo.log`.

The two cargo scripts also redirect to different files — `cargo-build` to `cargo.log`, `zig-build` to `zig.log` — and `neon dist` reads that file to locate the artifact. A single hardcoded `< cargo.log` is therefore wrong for the gnu half regardless of which script runs. Both the script and its log file are matrix fields (Task 4).

### A nested `mise.toml` is not found from the repo root

There is no root `mise.toml`; the pinned zig, cargo-zigbuild and wasm-pack all live in `packages/protect-ffi/mise.toml`. `jdx/mise-action` run at the repo root installs nothing, and mise additionally refuses an untrusted config at that path. Every mise step needs `working_directory: packages/protect-ffi`, as `.github/actions/build-ffi-binding` already does. wasm-pack **is** pinned there — it is reached by the same mechanism as the other two, not missing.

---

## Verified findings

### Option (3) holds for the scripts — but not for CI

With every `.js` and `.wasm` deleted from `dist/wasm` and only `protect_ffi.d.ts`, `protect_ffi_bg.wasm.d.ts` and `errors.d.ts` present (11.3KB): stack's `build` (tsup + dts), `test:types:dist`, `test:types` (59) and unit suite (1064) all pass. Confirmed with a `cargo` trap on `PATH` — zero invocations from root `pnpm test` or `turbo build`; `test:cargo` correctly exits 97.

**That measurement was true and the conclusion drawn from it was too broad.** "Ordinary CI needs no Rust" does not follow, because CI is credentialed and does exercise both the native and WASM paths. Seven jobs on PR #858 failed for three distinct reasons, all the same root cause — the three artifacts that used to arrive prebuilt in the npm tarball are now build outputs nobody produces:

| Failing jobs | Missing | Symptom |
|---|---|---|
| `Run Tests (Node 22)`, `(Node 24)` | `lib/` | 4 `TypeCheckError`s in `typed-client-v3.test-d.ts` — `tests.yml` calls `pnpm --filter … run test:types` directly, so turbo's `^build` never runs |
| Drizzle ×2, Supabase, prisma-next | `index.node` | `Cannot find module '.../protect-ffi-linux-x64-gnu/index.node'` |
| `Run WASM E2E Tests (Deno)` | `dist/wasm/*.js`, `*.wasm` | `Module not found ".../dist/wasm/protect_ffi_inline.js"` |

The unit suite's own `wasm-inline` tests are unaffected: 8 of 10 mock the module and the other two assert on the bundle graph, so none loads the real WASM. Fixed by Task 0.

Re-inclusion must start at the **root** `.gitignore` (git cannot re-include a file whose parent directory is excluded), and `inline-wasm.mjs` removes the `dist/wasm/.gitignore` wasm-pack writes, since the deepest file wins.

### `CS_CLIENT_KEY` is hex

Credentialed suites pass against the live service under 0.31, which decodes an explicit `clientKey` hex-only. `SecretKey::from_hex` is still lenient — 0.31 added its own `deserialize_hex_key` at the option boundary (`client_options.rs:84`). The repository secret remains unverifiable, hence the guard in `require-cs-secrets`.

### Binary-absent measurement

**11 of 65** test files need the binary, all credential-gated live suites (the "3 of 52" figure was stale). 54 files pass without it: 905 green, 159 skipped.

### The one real regression: `stash doctor`

With the binary removed, `require('@cipherstash/protect-ffi')` threw `MODULE_NOT_FOUND`; after the laziness change it returns 14 exports (15 via ESM) and the same error is raised on first use. `assertNativeBindingAvailable()` exists because there is no consumer-side fix: the loader is unreachable (`ERR_PACKAGE_PATH_NOT_EXPORTED`), touching an export never reaches the proxy, and calling a real wrapper means picking one whose validation does not reject first.

### Nested `mise.toml` must be trusted

`mise` refuses the config at its new path, and cargo goes through mise shims. `jdx/mise-action` handles it; a bare `cargo` call on a mise-equipped runner does not.

### Turbo outputs

protect-ffi's `build` emits `lib/**`, not `dist/**`. Without the `@cipherstash/protect-ffi#build` override, a Turbo cache **hit** restores nothing while reporting success.

---

## Release architecture

Derived from `cipherstash/encrypt-query-language`, verified against its workflows, scripts and published version streams (`@cipherstash/eql` and `eql-bindings` share an identical stream through `3.0.4`).

**One version authority. N idempotent publishers, ordered by dependency, each keyed on the committed version.**

1. **Changesets owns every version.** EQL's `release-plz.yml`: *"There is deliberately NO release-plz `release-pr` job — changesets opens the version PR, so a release-plz PR would fight it."* Every version this repo publishes is npm-side, so `changesets/action`'s default version command suffices; the `version:` hook that carries a computed version into a non-npm manifest belongs to the EQL absorption, which is where the first one appears (see "Out of scope").
2. **Every publisher is idempotent.** `changeset publish` logs `is not being published because version X is already published on npm` (`@changesets/cli@2.31.0` `changesets-cli.cjs.js:1114`).
3. **Publishers are ordered.** `changeset publish` packs from the workspace, so if it runs before the native artifacts exist it publishes six binary-less platform packages. Publishing the FFI tarballs first makes changesets skip them.

```
Version PR (changesets)  ──merge──►  push to main
                                          │
                   gate: which committed versions are unpublished?   (npm view)
                                          │
                        ┌─────────────────┴─────────────────┐
                        │ ffi unpublished?                  │
                        ▼                                   │
              build native matrix + wasm                    │
              (explicit CARGO_BUILD_TARGET per platform)    │
              pack 7 tarballs                               │
                        │                                   │
                        ▼                                   │
              publish 6 platform tarballs, THEN the wrapper │
              tag + GitHub release for all seven            │
                        │                                   │
                        └─────────────────┬─────────────────┘
                                          ▼
                              changeset publish
                    (JS packages; FFI already on npm → skipped)
```

### The gate is load-bearing, not a cost optimisation

An earlier revision claimed a wrong gate merely wastes 16 minutes. **False.** A false negative — reporting `ffi=false` when those versions are in fact unpublished — skips the artifact and publish jobs, and `changeset publish` then finds them unpublished and packs them **from the workspace, without `index.node`**. The gate must be correct, and its failure path is tested (Task 3, Step 1).

The related hazard is job-result semantics: if `ffi-artifacts` fails, `publish-ffi` is **skipped**, not failed. A condition of `needs.publish-ffi.result != 'failure'` therefore passes and lets changesets publish the broken packages. The condition must distinguish *skipped because unnecessary* from *skipped because a prerequisite failed* (Task 5).

### Changesets will not tag what it did not publish

`tagPublish(tool, successfulNpmPublishes, cwd)` receives `publishedPackages.filter(p => p.result === "published")` (`changesets-cli.cjs.js:~1187`). Packages skipped as already-published get **no git tag and no GitHub release**. Since the seven FFI packages are published before changesets runs, tagging them is this pipeline's responsibility (Task 5).

### Trusted-publishing constraint on file layout

Keep `release.yml` as the single npm entry point, so existing Stack packages need no npm-side change at cutover and only the seven FFI packages get repointed.

---

## Phase 3 — build the pipeline

Nine tasks. Task 0 is a prerequisite for the rest: until it lands the branch's CI
is red, so nothing after it can be verified against a green board.

### Task 0: Build the binding in the jobs that need it

The absorption made `lib/`, `index.node` and `dist/wasm/**` build outputs (see
"Option (3) holds for the scripts — but not for CI"). Seven jobs need one or
more of them and no job produces any.

A composite action rather than a reusable workflow with an artifact: the
integration jobs own their database service and credentials, so the build has to
happen *inside* them, and artifacts do not cross workflow files anyway. Caching
the 13MB `index.node` on a content hash of the Rust inputs beats caching cargo's
`target/`, which runs to gigabytes and is slower to save and restore than the
compile it saves.

**Files:**
- Create: `.github/actions/build-ffi-binding/action.yml`
- Modify: `packages/protect-ffi/mise.toml` (pin wasm-pack), `.github/workflows/tests.yml`, `.github/workflows/integration-{drizzle,supabase,prisma-next}.yml`, `.github/workflows/prisma-next-e2e.yml`, `.github/workflows/prisma-example-readme-e2e.yml`, `AGENTS.md`

- [x] **Step 1: Write the composite action**, with a `wasm` input (default
  `'false'`) and a verification step that runs on both the cache-hit and
  cache-miss paths. The verification is the point: a cache that restores nothing
  otherwise surfaces as dozens of unrelated encryption failures deep in a
  credentialed suite instead of one legible error.

- [x] **Step 2: Pin wasm-pack in `packages/protect-ffi/mise.toml`** at `0.13.1`,
  the version upstream's build and test workflows both used. Installed with
  `install_args: wasm-pack` so the step does not also build
  `cargo:cargo-zigbuild` from source, which only the release matrix needs.

- [x] **Step 3: Wire it into the seven jobs.** `wasm: 'true'` for exactly two —
  the Deno smoke test, and the Drizzle job, whose `CS_IT_SUITE` includes
  `integration/wasm/**`. The two prisma e2e workflows are path-filtered away
  from this PR but run on push to main, so they need it too.

- [x] **Step 4: Add protect-ffi to the integration path filters.** A crate
  change can now break these suites in a PR touching no TypeScript; without
  `packages/protect-ffi/crates/**` and `src/**` in `paths:`, it would skip them.

- [x] **Step 5: Correct `AGENTS.md`.** It promised contributors that cargo stays
  off every PR job. That is now true of the scripts only.

- [ ] **Step 6: Confirm green.** Push and check all seven previously-failing
  jobs. This is the only step that cannot be verified locally — the cache
  behaviour, the Linux `debug:`-fallback load, and the wasm-pack install are all
  first exercised on a runner.

---

### Task 1: Stop the protect-ffi crate being publishable

The crate has never been on crates.io (verified via its API) but carries no `publish` key, so it is publishable by default. EQL's convention — inherited when `eql-bindings` arrives — is exactly one publishable crate with every other member explicitly opted out.

**Files:**
- Modify: `packages/protect-ffi/crates/protect-ffi/Cargo.toml`
- Create: `scripts/__tests__/cargo-publish-opt-out.test.mjs`

**Interfaces:** Guard only; nothing consumes it.

- [ ] **Step 1: Write the failing test**

```js
// scripts/__tests__/cargo-publish-opt-out.test.mjs
import { readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')
const CRATES = join(REPO_ROOT, 'packages/protect-ffi/crates')

// Crates deliberately published to crates.io. Adding a name here is an audit
// decision: it means a future release-plz adoption will publish it.
const PUBLISHABLE = new Set([])

describe('cargo publish opt-out', () => {
  const members = readdirSync(CRATES, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)

  it('finds the workspace members it means to check', () => {
    expect(members).toContain('protect-ffi')
  })

  for (const name of members) {
    it(`${name} declares publish = false unless allowlisted`, () => {
      if (PUBLISHABLE.has(name)) return
      const manifest = readFileSync(join(CRATES, name, 'Cargo.toml'), 'utf8')
      expect(manifest).toMatch(/^publish = false$/m)
    })
  }
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run --config scripts/vitest.config.mjs cargo-publish-opt-out`
Expected: FAIL — `protect-ffi declares publish = false unless allowlisted`

- [ ] **Step 3: Add the opt-out**

In `packages/protect-ffi/crates/protect-ffi/Cargo.toml`, in `[package]`, after the `version` line:

```toml
# Never published to crates.io. This crate is a cdylib compiled into
# `index.node` and shipped inside the `@cipherstash/protect-ffi-<platform>` npm
# packages; it has no Rust-consumer identity. Without this key cargo treats it
# as publishable.
publish = false
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run --config scripts/vitest.config.mjs cargo-publish-opt-out`
Expected: PASS

- [ ] **Step 5: Verify cargo still builds**

Run: `pnpm --filter @cipherstash/protect-ffi build:native`
Expected: exit 0, `index.node` written

- [ ] **Step 6: Commit**

```bash
git add packages/protect-ffi/crates/protect-ffi/Cargo.toml \
        scripts/__tests__/cargo-publish-opt-out.test.mjs
git commit -m "chore(protect-ffi): mark the crate publish = false"
```

---

### Task 2: Repoint the FFI manifests at this repository

npm requires `repository.url` to exactly match the repository performing a trusted publish. All seven manifests still name `cipherstash/protectjs-ffi`, so OIDC publication from `cipherstash/stack` would fail. This must land **before** the cutover.

The six platform manifests also carry `repository.directory: platforms/<name>`, resolved from the **root of the repository named in `repository.url`**. That path exists in the old repo and not in this one, where they sit at `packages/protect-ffi/platforms/<name>`. Both fields are correct *today* — the packages still publish from the old repo, whose root really does hold `platforms/` — and both are wrong the moment publishing moves. The two fail differently: a stale `url` fails the publish outright, while a `directory` that does not resolve publishes fine and silently breaks the source link on the package page.

**Files:**
- Modify: `packages/protect-ffi/package.json`, `packages/protect-ffi/platforms/*/package.json` (six), `packages/protect-ffi/crates/protect-ffi/Cargo.toml`
- Create: `scripts/__tests__/ffi-repository-urls.test.mjs`

**Interfaces:** Guard only.

- [ ] **Step 1: Write the failing test**

```js
// scripts/__tests__/ffi-repository-urls.test.mjs
import { readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')
const FFI = join(REPO_ROOT, 'packages/protect-ffi')

// npm trusted publishing requires repository.url to match the repository the
// publish runs from EXACTLY. A stale URL does not warn — the publish fails.
const EXPECTED = 'https://github.com/cipherstash/stack'

const PLATFORMS = readdirSync(join(FFI, 'platforms'))

const manifests = [
  join(FFI, 'package.json'),
  ...PLATFORMS.map((p) => join(FFI, 'platforms', p, 'package.json')),
]

describe('FFI manifests name this repository', () => {
  it('checks the wrapper and all six platform packages', () => {
    expect(manifests).toHaveLength(7)
  })

  for (const path of manifests) {
    const pkg = JSON.parse(readFileSync(path, 'utf8'))
    it(`${pkg.name} points repository.url at cipherstash/stack`, () => {
      expect(pkg.repository.url).toBe(`git+${EXPECTED}.git`)
    })
  }

  it('the wrapper also updates bugs and homepage', () => {
    // Not required by npm, but a published package that links users to an
    // archived repository is its own kind of wrong.
    const pkg = JSON.parse(readFileSync(join(FFI, 'package.json'), 'utf8'))
    expect(pkg.bugs.url).toBe(`${EXPECTED}/issues`)
    expect(pkg.homepage).toBe(`${EXPECTED}#readme`)
  })

  for (const p of PLATFORMS) {
    it(`${p} names its own path from the repo root`, () => {
      // `directory` resolves from the root of the repository named above, so
      // `platforms/<p>` was right in the old repo and is wrong here. Step 3
      // rewrites the host and never touches this field — without these six
      // assertions the suite goes green on a source link that 404s, and Step 4
      // becomes a step nothing checks.
      const pkg = JSON.parse(
        readFileSync(join(FFI, 'platforms', p, 'package.json'), 'utf8'),
      )
      expect(pkg.repository.directory).toBe(
        `packages/protect-ffi/platforms/${p}`,
      )
    })
  }

  it('no manifest still references the old repository', () => {
    for (const path of manifests) {
      expect(readFileSync(path, 'utf8')).not.toMatch(/protectjs-ffi/)
    }
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run --config scripts/vitest.config.mjs ffi-repository-urls`
Expected: FAIL — 15 of 16: the seven `repository.url` assertions, the wrapper's `bugs`/`homepage`, the old-repository scan, and the six `repository.directory` paths. Only the manifest count passes.

- [ ] **Step 3: Rewrite the URLs**

```bash
cd packages/protect-ffi
perl -0pi -e 's{github\.com/cipherstash/protectjs-ffi}{github.com/cipherstash/stack}g' \
  package.json platforms/*/package.json
grep -rn "protectjs-ffi" package.json platforms/*/package.json || echo clean
```

- [ ] **Step 4: Fix each platform's `repository.directory`**

```bash
for d in platforms/*/ ; do
  p=$(basename "$d")
  node -e '
    const fs=require("node:fs"); const f=process.argv[1];
    const j=JSON.parse(fs.readFileSync(f,"utf8"));
    j.repository.directory = "packages/protect-ffi/platforms/" + process.argv[2];
    fs.writeFileSync(f, JSON.stringify(j,null,2)+"\n");
  ' "$d/package.json" "$p"
done
```

- [ ] **Step 5: Update the Cargo manifest**

In `packages/protect-ffi/crates/protect-ffi/Cargo.toml`, set any `repository` / `homepage` key to `https://github.com/cipherstash/stack`. The crate is `publish = false`, so this is documentation rather than a registry requirement — but a wrong URL in a shipped manifest is still wrong.

- [ ] **Step 6: Run the test to verify it passes**

Run: `npx vitest run --config scripts/vitest.config.mjs ffi-repository-urls`
Expected: PASS, 16 tests. Step 3 alone reaches only 10 of them — the six `directory` assertions are what makes skipping Step 4 visible.

- [ ] **Step 7: Verify the packed manifest carries the new URL**

```bash
pnpm --dir packages/protect-ffi pack --pack-destination /tmp/urlcheck
tar xzOf /tmp/urlcheck/*.tgz package/package.json | grep -A2 '"repository"'
```
Expected: `cipherstash/stack`

- [ ] **Step 8: Commit**

```bash
git add packages/protect-ffi/package.json packages/protect-ffi/platforms \
        packages/protect-ffi/crates/protect-ffi/Cargo.toml \
        scripts/__tests__/ffi-repository-urls.test.mjs
git commit -m "chore(protect-ffi): point the manifests at cipherstash/stack"
```

---

### Task 3: The release gate script

**Files:**
- Create: `scripts/release-gate.mjs`, `scripts/__tests__/release-gate.test.mjs`
- Modify: `package.json`

**Interfaces:**
- Produces `unpublished(manifests, lookup): string[]` — `manifests` is `[{name, version, private?}]`, `lookup(name)` returns published versions or `null` for a 404; `classify(names): { ffi: boolean, js: boolean }`; CLI writes `ffi=`, `js=`, `unpublished=` to `$GITHUB_OUTPUT`.

- [ ] **Step 1: Write the failing test**

```js
// scripts/__tests__/release-gate.test.mjs
import { describe, expect, it } from 'vitest'
import { classify, unpublished } from '../release-gate.mjs'

const FFI = '@cipherstash/protect-ffi'
const PLATFORM = '@cipherstash/protect-ffi-darwin-arm64'

describe('unpublished', () => {
  it('reports a package whose committed version is not on the registry', () => {
    expect(unpublished([{ name: FFI, version: '0.32.0' }], () => ['0.31.0']))
      .toEqual([FFI])
  })

  it('reports nothing when the committed version is already published', () => {
    expect(unpublished([{ name: FFI, version: '0.31.0' }], () => ['0.31.0']))
      .toEqual([])
  })

  it('treats a registry 404 as unpublished', () => {
    expect(unpublished([{ name: 'new-pkg', version: '1.0.0' }], () => null))
      .toEqual(['new-pkg'])
  })

  it('skips private packages', () => {
    expect(
      unpublished([{ name: 'bench', version: '1.0.0', private: true }], () => null),
    ).toEqual([])
  })

  it('propagates a lookup error instead of reporting "nothing to publish"', () => {
    // THE load-bearing case. A false negative here skips the artifact build,
    // and `changeset publish` then packs the platform packages WITHOUT
    // index.node and publishes them. A network or auth failure must fail the
    // gate, never read as "already published".
    const boom = () => { throw new Error('npm view failed: ETIMEDOUT') }
    expect(() => unpublished([{ name: FFI, version: '0.32.0' }], boom))
      .toThrow(/ETIMEDOUT/)
  })
})

describe('classify', () => {
  it('flags ffi when the wrapper is unpublished', () => {
    expect(classify([FFI])).toEqual({ ffi: true, js: false })
  })

  it('flags ffi when only a platform package is unpublished', () => {
    // A partially-failed publish can leave one platform package behind; that
    // still needs the matrix.
    expect(classify([PLATFORM])).toEqual({ ffi: true, js: false })
  })

  it('flags js for an ordinary Stack release', () => {
    expect(classify(['@cipherstash/stack', 'stash']))
      .toEqual({ ffi: false, js: true })
  })

  it('flags both when a release spans them', () => {
    expect(classify([FFI, '@cipherstash/stack']))
      .toEqual({ ffi: true, js: true })
  })

  it('flags neither when nothing is unpublished', () => {
    expect(classify([])).toEqual({ ffi: false, js: false })
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run --config scripts/vitest.config.mjs release-gate`
Expected: FAIL — `Failed to resolve import "../release-gate.mjs"`

- [ ] **Step 3: Write the script**

```js
// scripts/release-gate.mjs
/**
 * Decide what a push to `main` still has to publish.
 *
 * The gate is REGISTRY STATE, not changeset analysis. "No unconsumed
 * `.changeset/*.md`" is also true for an ordinary docs commit and for the very
 * next commit after a release, so gating on that would fire the 16-minute
 * native matrix routinely.
 *
 * This is LOAD-BEARING, not a cost control. A false negative skips the artifact
 * build, and `changeset publish` then packs the platform workspaces without
 * `index.node` and publishes them. Every failure mode here fails loudly.
 */
import { execFileSync } from 'node:child_process'
import { appendFileSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../..')

export const FFI_PREFIX = '@cipherstash/protect-ffi'

/** Names whose committed version is absent from the registry. */
export function unpublished(manifests, lookup) {
  const missing = []
  for (const { name, version, private: isPrivate } of manifests) {
    if (isPrivate) continue
    const published = lookup(name)
    if (published === null || !published.includes(version)) missing.push(name)
  }
  return missing
}

/** Which publisher branches the unpublished set requires. */
export function classify(names) {
  return {
    ffi: names.some((n) => n.startsWith(FFI_PREFIX)),
    js: names.some((n) => !n.startsWith(FFI_PREFIX)),
  }
}

/** Every workspace manifest, read from disk. */
export function workspaceManifests() {
  const entries = JSON.parse(
    execFileSync('pnpm', ['ls', '-r', '--depth', '-1', '--json'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    }),
  )
  return entries
    .filter((p) => p.path !== REPO_ROOT)
    .map((p) => JSON.parse(readFileSync(join(p.path, 'package.json'), 'utf8')))
    .map(({ name, version, private: isPrivate }) => ({
      name,
      version,
      private: Boolean(isPrivate),
    }))
}

/** Registry lookup. `null` on 404 so a first publish is not read as published. */
export function npmVersions(name) {
  try {
    return JSON.parse(
      execFileSync('npm', ['view', name, 'versions', '--json'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    )
  } catch (err) {
    const text = `${err.stdout ?? ''}${err.stderr ?? ''}`
    if (text.includes('E404')) return null
    throw new Error(`npm view ${name} failed: ${text.trim() || err.message}`)
  }
}

function main() {
  const manifests = workspaceManifests()
  const missing = unpublished(manifests, npmVersions)
  const { ffi, js } = classify(missing)

  console.log(
    missing.length
      ? `unpublished: ${missing.join(', ')}`
      : 'nothing to publish — every committed version is on the registry',
  )
  console.log(`ffi=${ffi} js=${js}`)

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `ffi=${ffi}\njs=${js}\nunpublished=${missing.join(' ')}\n`,
    )
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run --config scripts/vitest.config.mjs release-gate`
Expected: PASS, 10 tests

- [ ] **Step 5: Run the script against the live registry**

Run: `node scripts/release-gate.mjs`
Expected: `nothing to publish — every committed version is on the registry`, then `ffi=false js=false`.

- [ ] **Step 6: Add the npm script and commit**

In root `package.json` `scripts`, before `"release"`: `"release:gate": "node scripts/release-gate.mjs",`

```bash
git add scripts/release-gate.mjs scripts/__tests__/release-gate.test.mjs package.json
git commit -m "feat(release): gate publishing on registry state"
```

---

### Task 4: Reusable FFI artifact workflow

Ports upstream's `build.yml`. **The Rust target must be selected explicitly per platform** — upstream derives it from `neon list-platforms` and passes it as `CARGO_BUILD_TARGET`, and every cross-compilation detail hangs off it. Omitting it builds for the host: `macos-latest` now maps to `macos-15-arm64`, so both Darwin jobs would emit ARM64 and `darwin-x64` would ship an ARM binary.

Upstream's `.github/actions/setup` is **not** ported wholesale: it sets `cache: npm` on `setup-node` and `cache: true` on `mise-action`, which the no-caching policy forbids where artifacts get published.

Action pins match the rest of this repo (`actions/checkout@v6`, `actions/setup-node@v6.5.0`) rather than upstream's older ones. Not cosmetic for `setup-node`: **`package-manager-cache` does not exist before v5**, so on `@v4` the input the caching lint demands is silently ignored and actionlint rejects it outright — *input "package-manager-cache" is not defined in action "actions/setup-node@v4"*.

**Files:**
- Create: `.github/workflows/_build-ffi-artifacts.yml`
- Reference: `packages/protect-ffi/.github/workflows/build.yml`, `.../actions/setup/action.yml`

**Interfaces:** Produces artifact `ffi-tarballs` — seven `.tgz` files, downloaded **by name** in Tasks 5 and 7. Not exposed as a `workflow_call` output: a reusable workflow's `outputs.<id>.value` has to map to a job output (`${{ jobs.x.outputs.y }}`), a literal string is not that, and no caller reads one.

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/_build-ffi-artifacts.yml
name: Build FFI artifacts

# Reusable. Builds the six platform bindings and the WASM output, packs all
# seven npm tarballs, and uploads them. It does NOT publish: npm trusted
# publishing binds to the entry-point workflow FILENAME, so the publish step
# lives in `release.yml`.

on:
  workflow_call:
    inputs:
      ref:
        description: Commit to build from
        required: true
        type: string

permissions:
  contents: read

defaults:
  run:
    shell: bash

jobs:
  matrix:
    name: Compute platform matrix
    runs-on: ubuntu-latest
    timeout-minutes: 10
    outputs:
      matrix: ${{ steps.matrix.outputs.result }}
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ inputs.ref }}
          persist-credentials: false

      - uses: pnpm/action-setup@v6.0.9
        with:
          run_install: false
          cache: false

      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22
          # This workflow's output is published, so it is on the caching
          # lint's target list (Task 5, Step 5) — which requires the disable
          # to be explicit, not merely defaulted.
          package-manager-cache: false

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      # `neon list-platforms` maps each platform name to its Rust target
      # triple. This is the ONLY source of that mapping — `neon.platforms` in
      # package.json lists names, not triples — and getting it wrong silently
      # produces a binary for the runner's own architecture.
      #
      # Two matrix fields carry what upstream hardcoded, and both are wrong if
      # copied across verbatim:
      #
      #   script — upstream's non-gnu arm selects `build`, which upstream had
      #     as its cargo script. Here `build` is `tsc` and nothing else (phase
      #     1 moved cargo off the default path deliberately), so four of six
      #     platforms would compile TypeScript, emit no binary, and fail one
      #     step later on a missing log. The cargo script is `build:native`.
      #
      #   log — `cargo-build` redirects to cargo.log, `zig-build` to zig.log,
      #     and `neon dist` reads that file to locate the artifact. One
      #     hardcoded `< cargo.log` is wrong for whichever half it does not
      #     match.
      #
      # The body below is a single-quoted shell argument: no apostrophes, or
      # the quote closes and the rest is parsed by bash.
      - id: matrix
        run: |
          set -euo pipefail
          triples=$(pnpm --dir packages/protect-ffi exec neon list-platforms)
          echo "$triples"
          result=$(node -e '
            const map = JSON.parse(process.argv[1])
            const runner = (p) =>
              p.startsWith("win32") ? "windows-latest"
              : p.startsWith("darwin") ? "macos-latest"
              : "blacksmith-4vcpu-ubuntu-2404"
            // gnu targets cross-compile through cargo-zigbuild so the glibc
            // floor can be pinned; everything else builds with plain cargo.
            // See the step comment for why the script and log names differ.
            const gnu = (p) => p.includes("gnu")
            console.log(JSON.stringify(Object.entries(map).map(([platform, target]) => ({
              platform, target, os: runner(platform),
              script: gnu(platform) ? "zigbuild" : "build:native",
              log: gnu(platform) ? "zig.log" : "cargo.log",
            }))))
          ' "$triples")
          echo "result=$result" >> "$GITHUB_OUTPUT"

  binaries:
    name: ${{ matrix.cfg.platform }}
    needs: [matrix]
    strategy:
      fail-fast: false
      matrix:
        cfg: ${{ fromJSON(needs.matrix.outputs.matrix) }}
    runs-on: ${{ matrix.cfg.os }}
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ inputs.ref }}
          persist-credentials: false

      # Static OpenSSL; without it the Windows build fails to link.
      - name: Install OpenSSL (Windows)
        if: ${{ matrix.cfg.os == 'windows-latest' }}
        shell: powershell
        run: |
          vcpkg install openssl:x64-windows-static
          $vcpkgRoot = $env:VCPKG_INSTALLATION_ROOT
          $opensslDir = "$vcpkgRoot\installed\x64-windows-static"
          echo "OPENSSL_DIR=$opensslDir" >> $env:GITHUB_ENV
          echo "OPENSSL_LIB_DIR=$opensslDir\lib" >> $env:GITHUB_ENV
          echo "OPENSSL_INCLUDE_DIR=$opensslDir\include" >> $env:GITHUB_ENV
          echo "OPENSSL_STATIC=1" >> $env:GITHUB_ENV

      # aarch64 linker for the linux-arm64-gnu cross build.
      - name: Install cross-compile toolchain (Linux)
        if: ${{ contains(matrix.cfg.platform, 'linux') }}
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y gcc-13-aarch64-linux-gnu
          sudo ln -sf /usr/bin/aarch64-linux-gnu-gcc-13 /usr/bin/aarch64-linux-gnu-gcc

      - name: Install Rust with the platform's target
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.cfg.target }}

      - uses: pnpm/action-setup@v6.0.9
        with:
          run_install: false
          cache: false

      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22
          # This workflow's output is published, so it is on the caching
          # lint's target list (Task 5, Step 5) — which requires the disable
          # to be explicit, not merely defaulted.
          package-manager-cache: false

      # zig + cargo-zigbuild, pinned in packages/protect-ffi/mise.toml. Only
      # the zigbuild path uses them, so this is skipped for the four non-gnu
      # platforms rather than compiling cargo-zigbuild from source on two
      # macOS and one Windows runner that never call it.
      #
      # `working_directory` is load-bearing, not tidiness: the mise config is
      # nested, and mise refuses a config it has not trusted. Run from the
      # repo root this installs nothing, and the failure surfaces later as
      # "cargo-zigbuild: not found" — a toolchain problem rather than the
      # trust problem it is. Same reason `.github/actions/build-ffi-binding`
      # sets it.
      #
      # Cache disabled: this job's output is published.
      - name: Install zig + cargo-zigbuild (gnu targets only)
        if: ${{ contains(matrix.cfg.target, 'gnu') }}
        uses: jdx/mise-action@v3
        with:
          install: true
          install_args: zig cargo:cargo-zigbuild
          working_directory: packages/protect-ffi
          cache: false

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: Build binding
        working-directory: packages/protect-ffi
        env:
          CARGO_BUILD_TARGET: ${{ matrix.cfg.target }}
          NEON_BUILD_PLATFORM: ${{ matrix.cfg.platform }}
        # No `--` separator: pnpm forwards it verbatim and it lands after the
        # `> cargo.log` redirect, where cargo rejects the flag as a positional.
        run: |
          set -euo pipefail
          # `x86_64-unknown-linux-musl` -> `x86_64-linux-musl-gcc`. Parameter
          # expansion rather than upstream's `sed`, and assigned before export
          # rather than through it: actionlint runs shellcheck over `run:`
          # blocks, and the original spelling draws SC2001 and SC2155 — which
          # Task 6 turns into a gate failure.
          linker="${CARGO_BUILD_TARGET/unknown-/}-gcc"
          export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$linker"
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$linker"
          if [[ "$CARGO_BUILD_TARGET" =~ musl ]]; then
            wget -4 https://musl.cc/x86_64-linux-musl-native.tgz
            tar zxf x86_64-linux-musl-native.tgz
            sudo tar zxf x86_64-linux-musl-native.tgz -C /opt/
            export PATH="/opt/x86_64-linux-musl-native/bin/:${PATH}"
            export RUSTFLAGS="-C target-feature=-crt-static"
            pnpm run ${{ matrix.cfg.script }}
          elif [[ "$CARGO_BUILD_TARGET" =~ gnu ]]; then
            # cargo-zigbuild >= 0.23.0 no longer reads CARGO_BUILD_TARGET from
            # the environment, so the glibc-pinned target is passed as a flag.
            pnpm run ${{ matrix.cfg.script }} --target "${CARGO_BUILD_TARGET}.2.28"
          else
            pnpm run ${{ matrix.cfg.script }}
          fi

      - name: Place binding in its platform package
        working-directory: packages/protect-ffi
        # Bare `neon dist` writes ./index.node — the `debug:` fallback in
        # load.cts. Populating a platform package needs an explicit -o.
        run: |
          set -euo pipefail
          npx neon dist -o "platforms/${{ matrix.cfg.platform }}/index.node" \
            < "${{ matrix.cfg.log }}"
          test -s "platforms/${{ matrix.cfg.platform }}/index.node"

      # `pnpm pack` accepts NO positional directory — passing one is silently
      # ignored and it packs the package in the CWD (the wrapper). Verified:
      # `pnpm pack --pack-destination out ./platforms/darwin-arm64` produced
      # the wrapper tarball. `--dir` is what selects the package.
      - name: Pack platform package
        run: |
          set -euo pipefail
          mkdir -p ffi-dist
          pnpm --dir "packages/protect-ffi/platforms/${{ matrix.cfg.platform }}" \
            pack --pack-destination "${{ github.workspace }}/ffi-dist"
          ls ffi-dist

      - name: Verify the tarball is the platform package, not the wrapper
        run: |
          set -euo pipefail
          tgz=$(ls ffi-dist/*.tgz)
          name=$(tar xzOf "$tgz" package/package.json | node -p \
            'JSON.parse(require("node:fs").readFileSync(0,"utf8")).name')
          test "$name" = "@cipherstash/protect-ffi-${{ matrix.cfg.platform }}" \
            || { echo "::error::packed $name, expected the platform package"; exit 1; }
          tar tzf "$tgz" | grep -qx package/index.node \
            || { echo "::error::$tgz has no index.node"; exit 1; }

      - uses: actions/upload-artifact@v4
        with:
          name: ffi-platform-${{ matrix.cfg.platform }}
          path: ffi-dist/*.tgz
          if-no-files-found: error

  wrapper:
    name: WASM + wrapper tarball
    needs: [binaries]
    runs-on: blacksmith-4vcpu-ubuntu-2404
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ inputs.ref }}
          persist-credentials: false

      - uses: pnpm/action-setup@v6.0.9
        with:
          run_install: false
          cache: false

      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22
          # This workflow's output is published, so it is on the caching
          # lint's target list (Task 5, Step 5) — which requires the disable
          # to be explicit, not merely defaulted.
          package-manager-cache: false

      # wasm-pack, pinned in packages/protect-ffi/mise.toml — `build:wasm`
      # shells out to it and nothing else supplies it. Same two caveats as the
      # binaries job: `working_directory` because the nested config is
      # otherwise untrusted and this installs nothing, `install_args` to skip
      # cargo-zigbuild, which this job never calls and which is a from-source
      # cargo build. The argument is the full backend id — `wasm-pack` alone
      # is not a name in mise's registry and resolves to nothing.
      - name: Install wasm-pack
        uses: jdx/mise-action@v3
        with:
          install: true
          install_args: aqua:wasm-bindgen/wasm-pack
          working_directory: packages/protect-ffi
          cache: false

      # Explicit rather than relying on the runner image's preinstalled
      # rustup. wasm32 is never a side effect of anything else: `--all-targets`
      # in the Rust lint means target KINDS, not platforms.
      - name: Install Rust with the wasm32 target
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      # The wrapper's `files` include dist/wasm/**. Only three .d.ts are
      # tracked; the runtime .js/.wasm are generated here. Without this the
      # published ./wasm and ./wasm-inline entries resolve to nothing.
      - name: Build WASM
        working-directory: packages/protect-ffi
        run: pnpm run build:wasm

      - name: Pack wrapper
        run: |
          set -euo pipefail
          mkdir -p ffi-dist
          pnpm --dir packages/protect-ffi pack \
            --pack-destination "${{ github.workspace }}/ffi-dist"

      - name: Verify wrapper tarball contents
        run: |
          set -euo pipefail
          tgz=$(ls ffi-dist/cipherstash-protect-ffi-[0-9]*.tgz)
          for required in \
            package/lib/index.cjs \
            package/lib/index.mjs \
            package/dist/wasm/protect_ffi.js \
            package/dist/wasm/protect_ffi_inline.js \
            package/dist/wasm/protect_ffi_bg.wasm ; do
            tar tzf "$tgz" | grep -qx "$required" \
              || { echo "::error::$required missing from $tgz"; exit 1; }
          done
          # The six optionalDependencies must be concrete versions, not
          # `workspace:*` — pnpm rewrites them at pack time, and a failure here
          # means consumers install a wrapper with no binding.
          tar xzOf "$tgz" package/package.json | node -e '
            const j = JSON.parse(require("node:fs").readFileSync(0, "utf8"))
            const deps = Object.entries(j.optionalDependencies ?? {})
            if (deps.length !== 6) { console.error("expected 6 optionalDependencies, got " + deps.length); process.exit(1) }
            for (const [n, v] of deps) {
              // Concatenation, not a template literal: a dollar-brace inside
              // this single-quoted argument reads as a shell expansion to
              // shellcheck, which reports SC2016 — and actionlint runs
              // shellcheck over every run: block.
              if (!/^\d+\.\d+\.\d+/.test(v)) { console.error(n + " is " + v + ", not a concrete version"); process.exit(1) }
            }
            console.log("optionalDependencies OK")
          '

      - uses: actions/download-artifact@v4
        with:
          pattern: ffi-platform-*
          path: ffi-dist
          merge-multiple: true

      - name: Verify all seven tarballs are present and distinct
        run: |
          set -euo pipefail
          # A glob into an array, not `ls | wc -l` (SC2012), and `nullglob` so
          # an empty directory counts 0 rather than one literal `*.tgz`.
          shopt -s nullglob
          tarballs=(ffi-dist/*.tgz)
          count=${#tarballs[@]}
          test "$count" -eq 7 || {
            echo "::error::expected 7 tarballs, found $count"; ls ffi-dist; exit 1; }
          names=$(for t in "${tarballs[@]}" ; do
            tar xzOf "$t" package/package.json | node -p \
              'JSON.parse(require("node:fs").readFileSync(0,"utf8")).name'
          done | sort -u | wc -l)
          test "$names" -eq 7 || {
            echo "::error::expected 7 distinct package names, found $names"; exit 1; }

      - uses: actions/upload-artifact@v4
        with:
          name: ffi-tarballs
          path: ffi-dist/*.tgz
          if-no-files-found: error
```

- [ ] **Step 2: Teach actionlint the self-hosted runner label**

Thirteen jobs already run on `blacksmith-4vcpu-ubuntu-2404` and nothing has ever complained, because **actionlint has never run in this repo** — Task 6 is what introduces it. Its `runner-label` check knows only GitHub-hosted labels, so without this file every Blacksmith job is an error and the new gate is red on arrival:

```yaml
# .github/actionlint.yaml
# actionlint validates `runs-on:` against the GitHub-hosted label list.
# Blacksmith runners are self-hosted from its perspective, so they have to be
# declared here or every job using one is reported as an unknown label.
self-hosted-runner:
  labels:
    - blacksmith-4vcpu-ubuntu-2404
```

- [ ] **Step 3: Lint the workflow**

```bash
bash <(curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/v1.7.7/scripts/download-actionlint.bash) 1.7.7
./actionlint .github/workflows/_build-ffi-artifacts.yml
node scripts/lint-no-workflow-caching.mjs .github/workflows/_build-ffi-artifacts.yml
```
Expected: both clean — verified against the workflow above as written.

actionlint bundles shellcheck and applies it to every `run:` block, which is why the snippet departs from upstream in three places that look like style: parameter expansion instead of `sed` into `export` (SC2001, SC2155), a glob-into-array instead of `ls | wc -l` (SC2012), and string concatenation instead of a template literal inside a single-quoted `node -e` (SC2016 — shellcheck reads dollar-brace as a shell expansion). Reintroduce any of them and Task 6's gate is red.

- [ ] **Step 4: Verify the target mapping locally**

Run: `pnpm --dir packages/protect-ffi exec neon list-platforms`
Expected: JSON mapping all six platform names to Rust triples (`darwin-x64` → `x86_64-apple-darwin`, etc.). This is the mapping the matrix depends on.

- [ ] **Step 5: Verify the two build scripts and their log files**

```bash
node -p "JSON.stringify(require('./packages/protect-ffi/package.json').scripts, null, 1)" \
  | grep -E '"(build|build:native|zigbuild|cargo-build|zig-build)"'
```
Expected: `build` is `tsc` and nothing else — the matrix must select **`build:native`**, not `build`, for the non-gnu platforms. `build:native` → `cargo-build` → `> cargo.log`; `zigbuild` → `zig-build` → `> zig.log`. The `log` field in the matrix exists because those two differ and `neon dist` reads one of them.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/_build-ffi-artifacts.yml .github/actionlint.yaml
git commit -m "ci: add the reusable FFI artifact build workflow"
```

---

### Task 5: Ordered publishers in release.yml

**Files:**
- Modify: `.github/workflows/release.yml`, `scripts/lint-no-workflow-caching.mjs`

**Interfaces:** Consumes gate outputs `ffi` / `js` (Task 3) and artifact `ffi-tarballs` (Task 4).

- [ ] **Step 1: Fix the existing install**

`release.yml` runs bare `pnpm install`, violating the repository's own rule ("CI uses `pnpm install --frozen-lockfile`. Don't drop the flag."):

```yaml
      - name: Install dependencies
        run: pnpm install --frozen-lockfile
```

- [ ] **Step 2: Add the gate job**

```yaml
  gate:
    name: What needs publishing?
    runs-on: ubuntu-latest
    timeout-minutes: 10
    outputs:
      ffi: ${{ steps.gate.outputs.ffi }}
      js: ${{ steps.gate.outputs.js }}
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: pnpm/action-setup@v6.0.9
        with:
          run_install: false
          cache: false
      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22
          package-manager-cache: false
      - name: Install dependencies
        run: pnpm install --frozen-lockfile
      - id: gate
        run: node scripts/release-gate.mjs
```

- [ ] **Step 3: Add the artifact and publish jobs**

```yaml
  ffi-artifacts:
    name: Build FFI artifacts
    needs: [gate]
    if: needs.gate.outputs.ffi == 'true'
    uses: ./.github/workflows/_build-ffi-artifacts.yml
    with:
      ref: ${{ github.sha }}

  publish-ffi:
    name: Publish FFI packages
    needs: [gate, ffi-artifacts]
    if: needs.gate.outputs.ffi == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: write # git tags + GitHub release for the seven packages
      id-token: write # npm OIDC trusted publishing
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false

      - uses: actions/download-artifact@v4
        with:
          name: ffi-tarballs
          path: ffi-dist

      # No registry-url: setup-node with one writes a //registry/:_authToken
      # line that shadows OIDC and every publish fails with E404.
      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22
          package-manager-cache: false

      - name: Upgrade npm for OIDC trusted publishing
        run: npm install -g npm@^11.5.1

      # Publishes BEFORE `changeset publish`: changesets packs from the
      # workspace, where the platform packages have no index.node, so running
      # it first would publish six broken tarballs.
      #
      # PLATFORM PACKAGES FIRST, WRAPPER LAST. A plain `*.tgz` glob is
      # lexicographic and puts `cipherstash-protect-ffi-0.32.0.tgz` ahead of
      # `cipherstash-protect-ffi-darwin-arm64-0.32.0.tgz` ('0' < 'd'), which
      # would briefly expose a wrapper whose optionalDependencies do not exist.
      # Idempotent per tarball so a re-run completes a partial set.
      - name: Publish tarballs
        id: publish
        run: |
          set -euo pipefail
          meta () { tar xzOf "$1" package/package.json | node -p \
            "JSON.parse(require('node:fs').readFileSync(0,'utf8')).$2"; }

          wrapper=""
          platforms=()
          for tgz in ./ffi-dist/*.tgz ; do
            if [ "$(meta "$tgz" name)" = "@cipherstash/protect-ffi" ]; then
              wrapper="$tgz"
            else
              platforms+=("$tgz")
            fi
          done
          test -n "$wrapper" || { echo "::error::no wrapper tarball"; exit 1; }
          test "${#platforms[@]}" -eq 6 || {
            echo "::error::expected 6 platform tarballs, got ${#platforms[@]}"; exit 1; }

          published=()
          for tgz in "${platforms[@]}" "$wrapper" ; do
            name=$(meta "$tgz" name); version=$(meta "$tgz" version)
            if npm view "${name}@${version}" version >/dev/null 2>&1; then
              echo "${name}@${version} already published — skipping"
            else
              npm publish --access public --provenance "$tgz"
            fi
            published+=("${name}@${version}")
          done
          printf '%s\n' "${published[@]}" > published.txt
          echo "version=$(meta "$wrapper" version)" >> "$GITHUB_OUTPUT"

      # Changesets tags only what IT published (`tagPublish` receives
      # `publishedPackages.filter(p => p.result === "published")`), and it skips
      # these seven as already-published. Without this step the FFI release has
      # no git tag and no GitHub release.
      - name: Tag and release
        env:
          GH_TOKEN: ${{ github.token }}
          REPO: ${{ github.repository }}
          VERSION: ${{ steps.publish.outputs.version }}
        run: |
          set -euo pipefail
          # Existence is not the question — WHERE it points is. A re-run after
          # a partial failure must find its own tags and move on; a tag at a
          # different commit means this version was released from another tree,
          # and silently skipping would leave the published artifacts and the
          # tagged source disagreeing with nothing in the log to say so.
          while read -r tag ; do
            at=$(gh api "repos/${REPO}/git/ref/tags/${tag}" --jq .object.sha 2>/dev/null || true)
            if [ -n "$at" ]; then
              test "$at" = "$GITHUB_SHA" || {
                echo "::error::tag ${tag} points at ${at}, not ${GITHUB_SHA}"; exit 1; }
              echo "tag ${tag} already at this commit — skipping"
            else
              gh api -X POST "repos/${REPO}/git/refs" \
                -f ref="refs/tags/${tag}" -f sha="$GITHUB_SHA" >/dev/null
              echo "created ${tag}"
            fi
          done < published.txt

          # Attached to the wrapper's own tag, which the loop above just
          # created. A `protect-ffi-v<version>` release name would make `gh
          # release create` mint an EIGHTH tag for the same commit, and
          # `--verify-tag` is what refuses that: it aborts rather than creating
          # a tag that does not already exist. Naming matches what changesets
          # produces for the JS packages.
          rel="@cipherstash/protect-ffi@${VERSION}"
          if ! gh release view "$rel" --repo "$REPO" >/dev/null 2>&1; then
            gh release create "$rel" --repo "$REPO" --verify-tag \
              --title "protect-ffi v${VERSION}" \
              --notes "Native FFI bindings ${VERSION}. Published: $(tr '\n' ' ' < published.txt)"
          fi
          # Unconditional, and separate from creation: a release that exists
          # with a partial asset set is exactly what a failed re-run leaves
          # behind, so skipping on existence is not idempotence. `--clobber`
          # makes the complete case a no-op.
          gh release upload "$rel" ./ffi-dist/*.tgz --repo "$REPO" --clobber
```

- [ ] **Step 4: Order the changesets job correctly**

```yaml
  release:
    name: Release
    needs: [gate, publish-ffi]
    # `always()` because `publish-ffi` is SKIPPED for an ordinary JS release and
    # a skipped dependency would otherwise skip this job.
    #
    # The condition must distinguish "skipped because FFI was unnecessary" from
    # "skipped because its prerequisite failed". If `ffi-artifacts` fails,
    # `publish-ffi` is SKIPPED — not failed — so a bare `result != 'failure'`
    # check passes and `changeset publish` proceeds to pack and publish the
    # platform workspaces without their binaries.
    if: >-
      always() &&
      needs.gate.result == 'success' &&
      (
        needs.gate.outputs.ffi != 'true' ||
        needs.publish-ffi.result == 'success'
      )
    runs-on: ubuntu-latest
```

- [ ] **Step 5: Register the new workflow with the caching lint**

In `scripts/lint-no-workflow-caching.mjs`, `TARGETS`:

```js
      '.github/workflows/release.yml',
      '.github/workflows/_build-ffi-artifacts.yml',
      '.github/workflows/tests-supply-chain.yml',
```

**And in the test.** `scripts/__tests__/lint-no-workflow-caching.test.mjs` keeps its own copy of the list in `TARGET_WORKFLOWS`, and nothing asserts the two agree — the `actions/cache` sweep silently stops covering whatever the test's copy omits. Add the same entry there, and rename the stale `defaults to checking release.yml and tests-supply-chain.yml` case.

Adding the target is what makes the three `package-manager-cache: false` lines in Task 4 load-bearing rather than decorative.

- [ ] **Step 6: Verify**

```bash
node scripts/lint-no-workflow-caching.mjs
npx vitest run --config scripts/vitest.config.mjs lint-no-workflow-caching
./actionlint .github/workflows/release.yml
```
Expected: the lint names all three workflows, tests pass. Reverting one `package-manager-cache: false` in `_build-ffi-artifacts.yml` must turn the lint red — if it does not, the target never registered.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/release.yml scripts/lint-no-workflow-caching.mjs \
        scripts/__tests__/lint-no-workflow-caching.test.mjs
git commit -m "ci(release): publish FFI tarballs, tagged, before changeset publish"
```

---

### Task 6: Release-tooling lint gate

**Files:** Create `.github/workflows/lint-release.yml`

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/lint-release.yml
name: Lint release tooling

# A release workflow runs roughly once per release, so a syntax or shell error
# in it surfaces at the worst possible moment. This runs on every PR that
# touches it.

on:
  pull_request:
    paths:
      - .github/workflows/release.yml
      - .github/workflows/_build-ffi-artifacts.yml
      - .github/workflows/ffi-preflight.yml
      - .github/workflows/lint-release.yml
      - .github/actionlint.yaml
      - scripts/release-gate.mjs
      - scripts/lint-no-workflow-caching.mjs
      - package.json
  workflow_dispatch: {}

permissions:
  contents: read

defaults:
  run:
    shell: bash

jobs:
  lint:
    name: actionlint + release script tests
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false

      - name: Install actionlint
        run: |
          set -euo pipefail
          bash <(curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/v1.7.7/scripts/download-actionlint.bash) 1.7.7
          echo "$PWD" >> "$GITHUB_PATH"

      # Picks up `.github/actionlint.yaml` automatically — without it every
      # Blacksmith `runs-on:` is an unknown-label error (Task 4, Step 2).
      # actionlint also runs shellcheck over `run:` blocks, which is why the
      # ported build step avoids `sed`-into-`export` and `ls | wc -l`.
      - name: actionlint (release workflows)
        run: |
          set -euo pipefail
          actionlint \
            .github/workflows/release.yml \
            .github/workflows/_build-ffi-artifacts.yml \
            .github/workflows/ffi-preflight.yml \
            .github/workflows/lint-release.yml

      - uses: pnpm/action-setup@v6.0.9
        with:
          run_install: false
          cache: false

      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: Release script unit tests
        run: pnpm run test:scripts

      - name: No caching in publish workflows
        run: pnpm run lint:workflow-cache
```

- [ ] **Step 2: Lint it with itself**

Run: `./actionlint .github/workflows/lint-release.yml`
Expected: clean

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/lint-release.yml
git commit -m "ci: gate the release machinery on actionlint and script tests"
```

---

### Task 7: Pack-and-install pre-flight

`changeset publish` has no `--dry-run`, so this is the dry run. It must check **architecture**, not just size: a tarball carrying an ARM binary labelled `x64` installs cleanly and then fails to dlopen.

**Files:** Create `.github/workflows/ffi-preflight.yml`

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/ffi-preflight.yml
name: FFI release pre-flight

# Build the real artifacts, verify each binary's architecture, install the
# host-matching pair, and use them. Point it at the Version Packages PR branch
# so the tarballs tested carry the exact versions that will publish.
#
# Never publishes: it has no id-token permission, so it cannot.

on:
  workflow_dispatch:
    inputs:
      ref:
        description: Ref to build and test (e.g. changeset-release/main)
        required: true
        type: string

permissions:
  contents: read

defaults:
  run:
    shell: bash

jobs:
  artifacts:
    name: Build artifacts
    uses: ./.github/workflows/_build-ffi-artifacts.yml
    with:
      ref: ${{ inputs.ref }}

  smoke:
    name: Install and smoke-test
    needs: [artifacts]
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: ffi-tarballs
          path: ffi-dist

      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22

      # The five non-host platform tarballs cannot be installed here (npm
      # rejects a mismatched os/cpu with EBADPLATFORM), so verify them
      # statically — and check ARCHITECTURE, not just that a file exists.
      # macos-latest is arm64, so a darwin-x64 job that failed to set
      # CARGO_BUILD_TARGET would emit an ARM binary a size check passes.
      - name: Verify each binary's architecture
        run: |
          set -euo pipefail
          declare -A EXPECT=(
            [darwin-arm64]='Mach-O 64-bit.*arm64'
            [darwin-x64]='Mach-O 64-bit.*x86_64'
            [linux-arm64-gnu]='ELF 64-bit.*ARM aarch64'
            [linux-x64-gnu]='ELF 64-bit.*x86-64'
            [linux-x64-musl]='ELF 64-bit.*x86-64'
            [win32-x64-msvc]='PE32\+.*x86-64'
          )
          mkdir -p probe && cd probe
          for tgz in ../ffi-dist/*.tgz ; do
            name=$(tar xzOf "$tgz" package/package.json | node -p \
              "JSON.parse(require('node:fs').readFileSync(0,'utf8')).name")
            platform="${name#@cipherstash/protect-ffi-}"
            [ "$platform" = "$name" ] && continue   # the wrapper
            rm -rf x && mkdir x && tar xzf "$tgz" -C x
            desc=$(file -b x/package/index.node)
            echo "$platform: $desc"
            [[ "$desc" =~ ${EXPECT[$platform]} ]] || {
              echo "::error::$platform binary is '$desc', expected ${EXPECT[$platform]}"
              exit 1; }

            # `file` reads linux-x64-gnu and linux-x64-musl identically — both
            # are "ELF 64-bit ... x86-64" — so the check above passes if the
            # two are swapped, and the failure lands on an Alpine user at
            # runtime. The ABI is only visible in the dynamic section: the gnu
            # build links libc.so.6, the musl build links
            # libc.musl-x86_64.so.1 (RUSTFLAGS drops crt-static so it stays
            # dynamic).
            case "$platform" in
              linux-x64-gnu|linux-arm64-gnu)
                readelf -d x/package/index.node | grep -q 'NEEDED.*libc\.so\.6' || {
                  echo "::error::$platform does not link glibc"; exit 1; } ;;
              linux-x64-musl)
                readelf -d x/package/index.node | grep -q 'NEEDED.*libc\.so\.6' && {
                  echo "::error::linux-x64-musl links glibc — it is the gnu binary"; exit 1; }
                echo "linux-x64-musl: no glibc NEEDED entry" ;;
            esac
          done

      - name: Install wrapper + host platform package
        run: |
          set -euo pipefail
          mkdir -p /tmp/smoke && cd /tmp/smoke
          echo '{"name":"smoke","version":"1.0.0","type":"module","private":true}' > package.json
          wrapper=$(ls "$GITHUB_WORKSPACE"/ffi-dist/cipherstash-protect-ffi-[0-9]*.tgz)
          host=$(ls "$GITHUB_WORKSPACE"/ffi-dist/*linux-x64-gnu*.tgz)
          npm install --no-audit --no-fund "$wrapper" "$host"

      - name: Smoke-test the installed artifact
        run: |
          set -euo pipefail
          cd /tmp/smoke
          cat > smoke.mjs <<'EOF'
          import { createRequire } from 'node:module'
          const require = createRequire(import.meta.url)
          const cjs = require('@cipherstash/protect-ffi')
          // Forces the platform binary to resolve; throws MODULE_NOT_FOUND if
          // the tarball shipped without a usable binding.
          cjs.assertNativeBindingAvailable()
          if (typeof cjs.isEncrypted !== 'function') throw new Error('no isEncrypted')
          const wasm = await import('@cipherstash/protect-ffi/wasm')
          if (typeof wasm.newClient !== 'function') throw new Error('./wasm did not resolve')
          const inline = await import('@cipherstash/protect-ffi/wasm-inline')
          if (typeof inline.newClient !== 'function') throw new Error('./wasm-inline did not resolve')
          console.log('smoke OK')
          EOF
          node smoke.mjs
```

- [ ] **Step 2: actionlint**

Run: `./actionlint .github/workflows/ffi-preflight.yml`
Expected: clean

- [ ] **Step 3: Run it against the branch**

**`workflow_dispatch` only exists once the file is on the default branch.** GitHub resolves the dispatch trigger from `main`, not from the ref being tested, so `gh workflow run` before this merges fails with *"Workflow does not have 'workflow_dispatch' trigger"* — and the workflow is inert until dispatched, so merging it early costs nothing. Merge the Phase 3 branch, then:

```bash
gh workflow run ffi-preflight.yml --ref feat/protect-ffi-monorepo-absorption \
  -f ref=feat/protect-ffi-monorepo-absorption
gh run watch
```

(`--ref` selects the code that runs; `-f ref=` is this workflow's own input, the commit the artifacts are built from. They are the same branch here.)

Expected: green. First end-to-end proof of matrix, target selection, packing, architecture and install.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ffi-preflight.yml
git commit -m "ci: add the FFI pack-and-install pre-flight"
```

---

### Task 8: The Rust CI job, and retiring the deposited workflows

Since the import, the Rust checks run **nowhere**. Phase 1 moved `cargo test` and `cargo fmt --check` into `test:cargo` and clippy into `mise run lint:rust`, but no root workflow calls either. `src/lintWiring.test.ts` asserts against the deposited copy and says so: it is *"the specification the phase-3 pipeline port has to satisfy"*.

**Files:**
- Create: `.github/workflows/tests-rust.yml`
- Modify: `packages/protect-ffi/src/lintWiring.test.ts`
- Delete: `packages/protect-ffi/.github/` — **deferred, see Step 5**

**Steps 1–4 are done** (CIP-3717). Steps 5–8 wait on Task 4: this task was
pulled forward because the Rust checks running nowhere is a live regression,
not new pipeline work, but Task 4 still names the deposited
`packages/protect-ffi/.github/workflows/build.yml` and
`.../actions/setup/action.yml` as its reference material. Deleting them now
would remove the source for a task nobody has written yet.

- [x] **Step 1: Write the Rust workflow**

```yaml
# .github/workflows/tests-rust.yml
name: Tests (Rust)

# The Rust half of packages/protect-ffi. Path-filtered and separate from
# tests.yml because it is the only Rust in the repo. `src/lintWiring.test.ts`
# asserts the split from the manifest side; this is the other half.
#
# The filter is broader than `crates/**` — dependency, feature and toolchain
# changes all alter what cargo builds without touching a .rs file.

on:
  pull_request:
    paths:
      - 'packages/protect-ffi/crates/**'
      - 'packages/protect-ffi/Cargo.toml'
      - 'packages/protect-ffi/Cargo.lock'
      - 'packages/protect-ffi/mise.toml'
      - 'packages/protect-ffi/package.json'
      - '.github/workflows/tests-rust.yml'
  push:
    branches: [main]
  workflow_dispatch: {}

permissions:
  contents: read

defaults:
  run:
    shell: bash

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  rust:
    name: cargo test + clippy + rustfmt
    runs-on: blacksmith-4vcpu-ubuntu-2404
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false

      # mise supplies the pinned toolchain AND trusts
      # packages/protect-ffi/mise.toml. Without it, cargo through a mise shim
      # fails with "Config files ... are not trusted" — which reads as a
      # toolchain problem, not a trust one. Caching is allowed here: this
      # workflow publishes nothing.
      # `working_directory` is load-bearing: mise reads config from the current
      # directory and its PARENTS, so an action running at the repo root never
      # sees packages/protect-ffi/mise.toml. Without it this step installs
      # nothing and leaves the config untrusted, and the `mise run` below fails
      # with "Config files ... are not trusted".
      - uses: jdx/mise-action@v3
        with:
          install: true
          working_directory: packages/protect-ffi

      # `--all-targets` means all target KINDS, not all platform targets.
      # wasm32 needs its own invocation, and it is the build that ships to edge
      # runtimes with the least test coverage behind it.
      - name: Add wasm32 target
        run: rustup target add wasm32-unknown-unknown

      - uses: pnpm/action-setup@v6.0.9
        with:
          run_install: false

      - uses: actions/setup-node@v6.5.0
        with:
          node-version: 22

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: cargo test + rustfmt
        run: pnpm --filter @cipherstash/protect-ffi run test:cargo

      - name: clippy (host + wasm32)
        working-directory: packages/protect-ffi
        run: mise run lint:rust
```

- [x] **Step 2: Repoint the lintWiring assertion**

```ts
// The root workflow that actually runs the Rust checks. GitHub only reads
// workflows from the repository root, so this must never point back inside
// this package — that was true of the deposited upstream copy, which made the
// assertion below vacuous until the phase-3 port.
const testWorkflow = read('../../.github/workflows/tests-rust.yml')
```

- [x] **Step 3: Replace the CAVEAT comment**

```ts
  it('runs the lint entry point in CI, with the wasm32 target installed', () => {
    // Live again as of the phase-3 port: this reads the root workflow GitHub
    // actually executes. `lint:rust` is the aggregate entry point — an arm
    // reachable only by name is an arm nobody runs (#145) — and wasm32 must be
    // installed before clippy can lint it.
    expect(testWorkflow).toContain('mise run lint:rust')
    expect(testWorkflow).toContain('rustup target add wasm32-unknown-unknown')
  })
```

- [x] **Step 4: Run the test**

Run: `pnpm --filter @cipherstash/protect-ffi test`
Expected: PASS, 79 tests

- [ ] **Step 5: Delete the deposited upstream workflows** — *blocked on Task 4*

Only once Tasks 4, 7 and 8 have consumed all of the reference material. Task 4
still cites `build.yml` and `actions/setup/action.yml`, so this cannot run yet.

```bash
git rm -r packages/protect-ffi/.github
```

- [ ] **Step 6: Verify nothing else referenced them**

```bash
grep -rn "protect-ffi/.github" --include="*.ts" --include="*.mjs" --include="*.yml" --include="*.md" . | grep -v node_modules
```
Expected: no hits outside `docs/plans/` and `.work/`

- [ ] **Step 7: Run the repo linters**

```bash
node scripts/lint-no-dead-package-paths.mjs
./actionlint .github/workflows/tests-rust.yml
pnpm run test:scripts
```

- [ ] **Step 8: Commit**

```bash
git add .github/workflows/tests-rust.yml packages/protect-ffi/src/lintWiring.test.ts
git rm -r --cached packages/protect-ffi/.github 2>/dev/null || true
git commit -m "ci: run the Rust checks from a root path-filtered workflow"
```

---

## Phase 4 — flip

The only irreversible steps.

- [ ] Merge a cutover PR that deletes `scripts/lint-no-ffi-changeset.mjs`, its self-test, its fixtures, the `lint:ffi-changeset` script and the `tests.yml` step; **and** activates the deferred `@cipherstash/protect-ffi` **minor** changeset for the laziness change and `assertNativeBindingAvailable()` — it is already written and parked, so this half is a rename, not composition:

  ```bash
  for f in .changeset/*.md.deferred; do git mv "$f" "${f%.deferred}"; done
  ```

  Both halves in one PR — the guard exists to stop that changeset landing early. The `.md.deferred` extension is what makes parking safe: `@changesets/read` and the guard both select on `.endsWith('.md')`, so the file is inert to `changeset version`/`publish` until renamed. Check for more than one parked file — any protect-ffi change landing during the window parks its changeset the same way.
- [ ] Let the Version Packages job create the release PR. Verify it bumps all seven FFI packages to `0.32.0`, rewrites the wrapper's six `optionalDependencies`, and patch-bumps the six Stack packages (expected — see "Release lines are coupled by pinning").
- [ ] Run `ffi-preflight.yml` against that **versioned release-PR ref**.
- [ ] **Repoint npm trusted publishing for all seven packages**: `cipherstash/protectjs-ffi` → `cipherstash/stack`, workflow `release.yml`. For each publisher, **explicitly select `npm publish` under "Allowed actions"** — npm made that field required for configurations created after 2026-05-20, and these are new configurations. Confirm `repository.url` already reads `cipherstash/stack` (Task 2) or the publish is rejected. Only after the versioned pre-flight is green.
- [ ] Merge the Version Packages PR. The gate returns `ffi=true js=true`; artifacts build, six platform packages then the wrapper publish, tags and the GitHub release are created, and `changeset publish` skips the seven and publishes the JS packages.
- [ ] Verify npm provenance on all seven, the seven git tags, the `protect-ffi-v0.32.0` release, and the Stack tags from changesets. Smoke-test a fresh install.
- [ ] Archive `cipherstash/protectjs-ffi`.

## Phase 5 — wire `stash doctor`

- [ ] Add a `@cipherstash/stack/diagnostics` subpath (both `import` and `require`). It must import protect-ffi **without** importing `@cipherstash/auth`, be pure, and let the loader error propagate unwrapped.
- [ ] Rework `packages/cli/src/commands/doctor/index.ts` to probe it, keeping the separate `@cipherstash/auth` probe. This fixes a pre-existing bug: `dist/index.js` statically imports `@cipherstash/auth`, which is eager on two counts (top-level `require`, plus `module.exports = { ...native }` — a spread forces any loader), so today's stack probe silently duplicates the auth probe while rendering two green rows.
- [ ] Add the missing-binary e2e fixture.
- [ ] Add changesets for the new Stack subpath and the CLI diagnostic behaviour.

---

## Out of scope: importing EQL

`cipherstash/encrypt-query-language` will also be absorbed. **It needs its own plan** — an independent subsystem with its own release surface (npm + crates.io + a SQL bundle + docs + a Docker image). The release architecture above was derived from it. Four findings that plan must carry:

**A live version skew.** EQL ships npm and crate at one version by construction, but this repo spans two:

| Component | Pins EQL at |
|---|---|
| `packages/stack`, `packages/cli`, `packages/stack-prisma` | `@cipherstash/eql` **3.0.4** |
| `packages/protect-ffi/crates/protect-ffi` | `eql-bindings` **=3.0.2** |
| `packages/protect-ffi/integration-tests` | `@cipherstash/eql` **3.0.2** |

The Rust emitting EQL payloads is generated from a different catalog commit than the SQL being installed. A unified Cargo workspace turns that `=3.0.2` registry pin into a path dependency and makes the skew unrepresentable — **the strongest argument for the import, independent of releases.**

**Pin EQL with `workspace:^`, not `workspace:*`.** EQL is 3.x, so `^3.0.4` spans every 3.x release and a 3.1.2 would not force a Stack release. With an exact pin it would drag `stash` and `stack-prisma`, and through the fixed group all six Stack packages, into every EQL release. This is the direct answer to "can stack 1.1 release independently of EQL 3.1.2" — yes, but only with a caret range.

**crates.io trusted publishing needs repointing**, bound to a workflow filename in the same way, and with the same repository-field requirement.

**Changesets cannot put a crate in a `fixed` group** — a Cargo package is not an npm package. Lockstep comes from a `version:` hook on `changesets/action` writing the computed version into `Cargo.toml`, as EQL's `sync-lockstep-versions.mjs` does. **That hook is this plan's to add, not phase 3's.** An earlier revision put it in phase 3 as `"version": "changeset version"` — byte-identical to the action's default and to the existing `changeset:version` script, with a test asserting only that the seam existed. A pass-through seam introduced before anything passes through it cannot be wrong, so nothing tells you when it stops being right; add it in the commit that first writes a `Cargo.toml` version, where the test has something to assert.

---

## Verification checklist

**Done (phases 1–2)**

- [x] `CS_CLIENT_KEY` is hex — inferred from credentialed suites passing under 0.31's hex-only decoder
- [x] `pnpm install` clean with the seven new packages linked; `--frozen-lockfile` clean
- [x] `pnpm --filter @cipherstash/stack build` + `test:types:dist` pass against workspace 0.31.0
- [x] The 0.31 adoption has its own non-ignored Stack changeset (`minor`)
- [x] Root `pnpm test` completes without invoking cargo — 0 invocations under a `PATH` trap
- [x] `pnpm --filter @cipherstash/protect-ffi test` reaches neither `cargo test` nor `cargo fmt`; `test:cargo` does (exit 97 under the trap)
- [x] `pnpm turbo build --filter './packages/*'` invokes no cargo
- [x] `build:native` produces a loadable binding
- [x] protect-ffi suite passes on vitest 3.2.7 and Biome 2.5.3 — 79 tests
- [x] Option (3) holds — dts build resolves with only the three `.d.ts` present
- [x] `./wasm` and `./wasm-inline` both resolve from the packed tarball
- [x] Packed tarball matches published 0.31.0 — 12 files, 226 under `lib/`, `workspace:*` rewritten to concrete versions
- [x] `pnpm --filter @cipherstash/stack test` passes with the binary present — 1064 tests
- [x] Binary absent: 11 of 65 files fail, all credential-gated
- [x] `stash manifest --json` resolves every command in `skills/stash-cli/SKILL.md`
- [x] `pnpm run code:check` error-free across tracked source — 722 files
- [x] `e2e/tests/supply-chain.e2e.test.ts` passes — 18 tests

**Phase 3+**

- [ ] Every job that encrypts, decrypts or typechecks against protect-ffi builds the binding first
- [ ] The build action fails loudly when the artifact is absent, on both the cache-hit and cache-miss paths
- [ ] A Rust-only change triggers the three integration workflows
- [ ] All seven previously-failing jobs on PR #858 are green
- [ ] All seven FFI manifests read `cipherstash/stack`; no `protectjs-ffi` reference remains, and the six platform `repository.directory` values read `packages/protect-ffi/platforms/<name>` rather than the old repo's `platforms/<name>`
- [ ] `neon list-platforms` maps all six platforms to Rust triples, and the matrix consumes them
- [ ] Every platform job runs a **cargo** script — `build:native` or `zigbuild`, never `build` — and `neon dist` reads the log that script wrote
- [ ] Every mise step names `working_directory: packages/protect-ffi`; zig/cargo-zigbuild and wasm-pack are actually on PATH in the jobs that call them
- [ ] `actionlint` is clean over all four release workflows, with `.github/actionlint.yaml` declaring the Blacksmith label
- [ ] Each packed platform tarball contains `index.node` **of the correct architecture** (`file` check, not size), and the two `linux-x64` binaries are distinguished by **ABI** (`readelf -d`), which `file` cannot see
- [ ] Each platform job packs its own package, not the wrapper (name assertion)
- [ ] The wrapper tarball's six `optionalDependencies` are concrete versions
- [ ] A push to `main` with nothing unpublished does **not** start the native matrix
- [ ] A JS-only release publishes with the FFI jobs skipped
- [ ] **An `ffi-artifacts` failure blocks `changeset publish`** — the skipped-vs-failed distinction
- [ ] Platform packages publish before the wrapper
- [ ] Seven git tags after an FFI release and no eighth, with the GitHub release attached to the wrapper's `@cipherstash/protect-ffi@<version>` tag and carrying all seven tarballs
- [ ] Re-running the publish job on the same commit is a no-op that still completes a partial asset set (tag targets verified, `release upload --clobber`)
- [ ] Stack tags are still created by changesets on the same run
- [ ] `ffi-preflight.yml` runs against a release-PR ref without any publish step
- [ ] `release.yml` installs with `--frozen-lockfile`
- [x] `cargo test`, `cargo fmt --check` and clippy (host **and** wasm32) run in CI again — `tests-rust.yml` (`bc0cb132`)
- [ ] No dead upstream workflow files under `packages/protect-ffi/.github/`
- [x] `lintWiring.test.ts` asserts against a workflow GitHub actually executes
- [x] `test:typecheck:wasm` runs in CI, and its exemption is checked against the root workflow **directory** rather than a hardcoded filename
- [x] No package script dispatches a workflow this repo cannot run — trigger and declared inputs, not just the path
- [x] The `integration-tests/` suite runs from a root workflow, full suite including lock context, with a regression test that rejects a `paths:`-only mention
- [x] Every lockfile in the tree maps to a monitored Dependabot ecosystem, and every entry's `directory` holds the manifest its ecosystem reads
- [ ] **`integration-protect-ffi.yml`'s first run is green.** Unproven by construction — there is no Docker daemon and no CipherStash credentials on a dev machine, so nothing about the job's runtime behaviour was verified locally. Watch, in order of likelihood: `pg_isready` missing from the Blacksmith image (`start-db`'s loop retries forever, so the symptom is a 45-minute timeout, not an error); `npm ci` under CI's npm major, since the lock's `".."` entry names protect-ffi 0.29.0 while the manifest says 0.31.0; ZeroKMS/CTS host derivation from the CRN now that upstream's hardcoded `ap-southeast-2` pins are gone; `keyset.test.ts` mutating the shared workspace via `ensureKeyset`; and a long first run from a cold `cargo:cargo-zigbuild` source build plus a cold binding cache (PR cache writes are ref-scoped, so the cache only pays off once this is on `main`)
- [ ] Published `@cipherstash/stack` tarball's `dependencies` show a concrete protect-ffi version
- [ ] `stash doctor` exits non-zero with a hidden platform package (phase 5)

---

## Deferred follow-ups

Each of these was in reach and deliberately left, with the reason.

1. **pnpm-absorb `packages/protect-ffi/integration-tests`.** It is not a workspace
   member — `packages/*` globs one level and the only deeper entry is
   `platforms/*` — so it carries its own `package-lock.json` and installs with
   `npm ci`. Absorbing it means adding it to `pnpm-workspace.yaml`, reconciling
   `@cipherstash/auth ^0.39.0` / `vitest ^3.1.3` / `@cipherstash/eql 3.0.2` with
   the catalog, and dropping both the lockfile and the `npm ci` step. **Not done
   because it changes the suite's dependency versions, and only a credentialed
   run can show that change is neutral** — doing it blind would confound a
   wiring fix with a semantic one. Two things resolve with it: the second
   package manager in CI, and the five npm advisories osv-scanner reports in
   that lockfile today.

2. **`integration-tests/package-lock.json` gets no Dependabot PRs.** Covered at
   the ecosystem level, but the npm entry follows the pnpm workspace and this
   directory is not in it. Adding a second npm entry is ~10 lines; left because
   (1) deletes the file.

3. **CI and `tasks.toml` have forked.** `test:integration:all` still builds the
   binding (debug) and the WASM itself, while CI builds once via
   `build-ffi-binding` and calls vitest directly. Making that build step opt-out
   in `tasks.toml` would give both one definition.

4. **`.github/actionlint.yaml` does not exist,** so `actionlint` reports
   `blacksmith-4vcpu-ubuntu-2404` as an unknown runner label on every workflow in
   the repo. Task 4 already calls for this file; until it lands, actionlint output
   has to be read past a known-noisy diagnostic, which is how a real finding gets
   missed.

5. **The integration suite's own `npm test` (`tsc && vitest`)** typechecks
   `tests/` against `lib/*.d.cts`. Upstream CI never ran it and this round did not
   add it — a new check landing under a wiring change's name.

6. **`cooldown.semver-major-days: 14` is dead config** on all three Dependabot
   entries while every one of them ignores `version-update:semver-major`. Left in
   place for symmetry rather than removed.

## Open decisions

1. **Stack changeset bump level.** Currently `minor` in `.changeset/olive-pugs-invite.md`. A 1.0 package where a previously-working credential encoding stops working argues for `major`; against it, hex was always the documented encoding and the fixed group would take five other packages to 2.0.0.

2. **`packages/prisma-next/`, `packages/drizzle/`, `packages/protect/`, `packages/schema/`, `packages/stack-forge/`** are untracked build residue from earlier renames — zero tracked files each.

## Closed questions

- **Does option (3) hold?** Yes.
- **Is `CS_CLIENT_KEY` hex?** Yes; the CI secret is still guarded.
- **Can Stack release independently of an FFI/EQL release?** Stack-only: always. The reverse depends on the pin — see "Release lines are coupled by pinning".
- **Why no interim upstream release?** The only external dependent, `@cipherstash/protect@12.0.1`, pins `0.23.0`.
- **Does Windows stay in every release?** Yes — a fixed group publishes all seven atomically.
- **Does a Rust-only change need a changeset?** Yes; the fixed group propagates to the six platform packages.

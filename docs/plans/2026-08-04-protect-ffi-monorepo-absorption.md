# Absorbing `protectjs-ffi` into the monorepo — execution plan

Move `cipherstash/protectjs-ffi` into this repo as `packages/protect-ffi` (plus its
six `platforms/*` packages), so releases are built, versioned, and published from a
single repo instead of requiring coordinated PRs across two. **Decision taken: full
`workspace:*` synchronisation** — source and publishing both move.

Revised 2026-08-04 after review (**[rev]**, **[rev2]**, **[rev4]**). Revised again
the same day after the decision to **import first and make the laziness change
in-monorepo, with no interim upstream release** — those changes are marked **[rev3]**.

**[rev4]** closes the last execution gaps found in the final verification: the native
matrix now gates only on an FFI release (not every workspace release), phase 4 names
the Changesets version-PR lifecycle explicitly, the 0.31 adoption gets its own Stack
changeset, Rust formatting leaves the default test path, and the declarations-only
WASM inventory matches the actual published 0.31.0 tarball.

## Status

- **VERIFIED:** Neon works in a pnpm monorepo; the laziness change does not regress a
  consumer or bundling path; the eager-load diagnosis and its one-line fix. Tested
  empirically — see "Verified findings". The separate 0.31 adoption is intentionally
  user-visible and handled by its own changeset below.
- **[rev3] VERIFIED:** the import is *also* a `0.30.0` → `0.31.0` upgrade, and `0.31.0`
  is a breaking release. Three source changes in `packages/stack` are required to
  consume it. See "The import is also an upgrade" — this was missed by the first two
  drafts, which treated the drift as an anecdote.
- **DECIDED:** full sync. protect-ffi and its six platform packages get their **own**
  fixed group, separate from Stack's **[rev]**.
- **[rev3] DECIDED: no interim upstream release.** The laziness fix lands in this repo
  after the import, not in `protectjs-ffi` before it. This removes the last cross-repo
  release but introduces the ignore-window invariant below, which is what splits the
  `stash doctor` work away from the laziness fix.
- **[rev2] PROVISIONAL:** "ordinary CI needs no Rust". `dist/wasm/**` and `lib/**` are
  generated and untracked upstream, so a workspace consumer does not get them the way an
  npm consumer does. The proposed resolution is credible and the measurements favour it,
  but it is unproven until the phase-1 experiment runs. Do not quote the contributor-Rust
  conclusion as settled before then — see "Generated output is not source-controlled".
- **OPEN:** release-pipeline mechanics (publish gating, artifact restore) are specified
  below but unproven; phase 3 is where they get exercised. The workflow topology is
  decided, but its conditions and skipped-job behaviour still require an end-to-end
  workflow run before cutover.

## Verified findings

### Neon is not a blocker

The stated risk — "the Neon bindings may not support monorepos" — does not hold.
Tested in a scratch monorepo (root `package.json` + `pnpm-workspace.yaml` globbing
`packages/*` and `packages/protect-ffi/platforms/*`, an rsync of the FFI repo, and a
sibling consumer package).

| Checked | Result |
|---|---|
| `neon dist` / `neon update` / `neon show ci github` / `neon list-platforms` | All cwd-relative; work unchanged from a nested package |
| Nested Cargo workspace under `packages/protect-ffi/crates/` | Builds (342 crates, all from crates.io — no private registry) |
| `neon dist < cargo.log` | Writes `platforms/<p>/index.node` correctly |
| Sibling workspace package `require`s the binding | Resolves and dlopens the 41MB debug binding through pnpm symlinks |
| `workspace:*` on the six platform packages | Links fine; os/cpu constraints bypassed with a warning, not an error |
| changesets `fixed` group across all seven | Bumps in lockstep |
| `workspace:*` → concrete version rewrite at publish | Already proven in production by `@cipherstash/stack-drizzle` |

Two gotchas that will bite if missed:

1. **`neon update` must come out of `prepack`.** Changesets writes real versions into
   the platform `optionalDependencies`; `neon update` regenerates and overwrites them.
   The single most likely cause of a silently-wrong publish.
2. **`neon bump` is npm-lifecycle-coupled** and has an arg-parsing bug
   (`options[0]` where it means `options._unknown[0]`, yielding
   `npm version --force undefined`). Drop the `version` script rather than fix it.

### [rev3] The import is also an upgrade

This repo pins `@cipherstash/protect-ffi` at **`0.30.0`** in all three consumers.
Upstream `main` is **`0.31.0`**, a release whose changelog carries a `Breaking`
heading. Importing the source *is* adopting it. The first two drafts noted the version
gap only as "a decent illustration of the problem being solved" and never costed the
consumption.

Three concrete breakages, all verified against the tree:

**1. The `ProtectError` class is gone.** The export moved from a class to a guard:

```
v0.30.0  src/index.cts:23  export { ProtectError, type ProtectErrorCode } from './errors.js'
main     src/index.cts:16  export { isProtectErrorCode, type ProtectErrorCode } from './errors.js'
```

The *type* survives, so every type-only import in `packages/stack` is unaffected
(`src/types.ts`, `src/errors/index.ts`, `src/dynamodb/types.ts`, and the rest). Two
**value** sites break and must move to a `code`-property check:

- `packages/stack/src/encryption/helpers/error-code.ts:2,11` — `error instanceof FfiProtectError`
- `packages/stack/src/dynamodb/helpers.ts:2,48` — same pattern, with a plain-object fallback already beside it

**2. The wasm `newClient` credential move.** `packages/stack/src/wasm-inline.ts:1530`
passes `clientId` / `clientKey` at the top level:

```ts
const client = await wasmNewClient({
  strategy,
  encryptConfig: normalizeCastAs(encryptConfig),
  clientId: clientConfig.clientId,
  clientKey: clientConfig.clientKey,
  eqlVersion: 3,
} as never)
```

Under `0.31.0` they belong in `clientOpts`. The failure is **loud, not silent** —
`0.31.0` rejects unrecognised fields (``unknown field `clientId` ``) rather than
dropping them — but the silent-wrong-keyset mode the changelog warns about is exactly
what a direct FFI consumer with a top-level `keyset` would hit if only *some* fields
moved. Stack's WASM config currently forwards only `clientId` and `clientKey`, not a
keyset: move those **two** into `clientOpts`. Use the typed `authStrategy` spelling for
the resolved strategy rather than retaining the deprecated `strategy` alias.

The `as never` is why this type-checks today: `0.30.0`'s wasm declarations were
`(client, opts: any) => Promise<any>`. `0.31.0` types them properly, so **delete the
cast** and let the compiler enforce the shape. That also clears a
`no-type-erasing-assertions` plugin warning.

**3. `clientKey` must be hex.** `SecretKey::from_hex`'s base64 fallback is gone — and
base64 is the encoding `~/.cipherstash/secretkey.json` uses on disk. The Neon entry
forwards `CS_CLIENT_KEY` straight through as `clientKey`, so **any base64 value in a
developer `.env` or a CI secret starts failing at client construction** with `invalid
clientKey: expected a hex-encoded key`. This is an environment question, not a code
one: it cannot be settled by reading the tree, and it will present as every
credential-gated test failing at once. Check the CI secrets before the import lands,
not after.

Also in the release, lower-risk but worth knowing: a malformed `clientId` now fails
even without a `clientKey`; the Neon entry forwards unrecognised top-level keys to Rust
instead of dropping them; and a key whose value is `undefined` is rejected on wasm
where Neon still drops it.

### The eager-load diagnosis

Eager native loading traces to **one line** in `src/index.cts`:

```ts
import * as native from './load.cjs'   // → const native = __importStar(require("./load.cjs"))
```

`__importStar` enumerates the `@neon-rs/load` proxy, forcing the platform binary to
resolve at module-evaluation time. Changing it to `import native = require('./load.cjs')`
(emitting a plain `require`) makes the package importable **with no binary present at
all** — verified for both the CJS and ESM entries.

Measured build costs:

- Linux release build: **1m32s** cargo / **2m23s** job, *cold* (no cargo cache).
- Full release **16m27s**, Windows-dominated: **14m24s**, of which ~5.8 min is vcpkg
  static OpenSSL.
- Prebuilt platform fetch: 5.4MB in 1.7s.

**[rev] Correction:** the first draft said "only 3 of 52 stack test files need the
binary." The denominator is wrong — `packages/stack/__tests__` holds **65** `*.test.ts`
files (79 counting `integration/`). The numerator came from running the suite with the
binary absent and **must be re-measured** against the current tree before it is relied
on. The shape of the conclusion (a small, credential-gated minority) is unchanged, but
treat the number as unverified until re-run.

Constraint: `release.yml` may never use GitHub Actions caching — enforced by
`scripts/lint-no-workflow-caching.mjs`, whose default TARGETS are `release.yml` and
`tests-supply-chain.yml`. Artifact upload/download is *not* caching and stays legal.

### No consumer or bundling path regresses

- **Bundlers cannot observe the change.** esbuild A/B: without externalization, six
  identical resolution errors in both builds; with `--external:@cipherstash/protect-ffi`,
  output bundles are byte-identical (`diff` → IDENTICAL). `__importStar` is a
  runtime-only wrapper; the module graph is unchanged.
- **`@cipherstash/wizard`** depends only on `@cipherstash/auth` — not in scope.
- **`@cipherstash/nextjs`** has one runtime dep (`jose`) and one peer (`next`); its
  `serverExternalPackages` mentions are documentation. Not in scope.
- **`wasm-inline`** never imports the native root — only
  `@cipherstash/protect-ffi/wasm-inline` and `@cipherstash/auth/wasm-inline`. Its
  isolation guard (`wasm-inline-bundle-isolation.test.ts`) is a static scan of built
  import specifiers, so load timing is invisible to it.
- **CLI launcher** (`packages/cli/src/bin/stash.ts`) is already lazy-tolerant by
  explicit design — its outer handler comments *"in case a native addon loads lazily
  (at call time) rather than during module evaluation."*
- **`@cipherstash/migrate`** has no runtime dep on stack (peer + devDep). Its one
  import is `isEncryptedPayload` from the root entry — a pure-JS type guard that today
  drags in an ~8.7MB dlopen. Strict improvement.
- **`@cipherstash/stack-prisma`**: 14 of 15 stack imports go to `./eql/v3` (9),
  `./adapter-kit` (3), `./types` (2) — all three have **zero** cipherstash deps in
  their built chunk closure and never reach the loader. Only `src/stack/from-stack-v3.ts`
  pulls `Encryption` from `./v3`. Strict improvement.

Built chunk closure, for reference:

```
dist/index.js          12 chunks   @cipherstash/auth, @cipherstash/protect-ffi, …
dist/encryption/v3.js  14 chunks   @cipherstash/protect-ffi, …
dist/eql/v3/index.js    5 chunks   (none)
dist/adapter-kit.js     6 chunks   (none)
dist/types-public.js    3 chunks   (none)
```

### The one real regression: `stash doctor`

`packages/cli/src/commands/doctor/index.ts` probes with `await import(probe.pkg)` and
its comment states the mechanism it depends on: *"Importing each forces its
@neon-rs/load proxy to resolve the platform binary."* Measured with the binary removed:

| | eager (today) | lazy (after fix) |
|---|---|---|
| `require('@cipherstash/protect-ffi')` | throws `MODULE_NOT_FOUND` | succeeds, 12 exports |
| touching `m.newClient` | — | **succeeds, no throw** |
| calling `m.newClient({})` | — | throws `MODULE_NOT_FOUND`, same code + message |

Three things follow:

1. **Touching an export is not enough.** `index.cjs` exports its own wrapper
   functions, not the proxy's properties — the proxy is only reached from inside a
   wrapper body. A probe must *call through*. And `encryptBulk({})` throws a plain
   validation error before reaching native, so the forcing call must be chosen
   deliberately.
2. **There is no consumer-side fix.** `require('@cipherstash/protect-ffi/lib/load.cjs')`
   fails with `ERR_PACKAGE_PATH_NOT_EXPORTED` — the proxy is unreachable from outside
   the package. protect-ffi must export an explicit forcing function, named
   **`assertNativeBindingAvailable()`** **[rev]**: a stable diagnostic interface that
   does not expose the loader implementation.
3. **The failure is subtler than "doctor breaks."** `dist/index.js` also statically
   imports `@cipherstash/auth`, which is eager on two counts (`require` at module top,
   plus `module.exports = { ...native }` — a spread forces any loader). So
   `import('@cipherstash/stack')` still throws when *auth's* binary is missing. The
   stack probe silently degenerates into a duplicate of the auth probe on line 19,
   losing its protect-ffi coverage while still rendering two green rows.

The error's `code` and `message` are unchanged, so `isNativeBinaryMissing` still
classifies it (`native.test.ts` keeps passing) and `reportNativeBinaryMissing` still
produces the right guidance. Only the *moment* moves.

Test coverage for this is currently nil: `doctor.e2e.test.ts` exercises only the
healthy path, and `native.test.ts` is a pure unit test against synthetic errors.
Nothing in the repo removes a real binary. (`e2e/tests/package-managers.e2e.test.ts`
tests package-manager *detection* — runner prefixes in help text — not
missing-optional-dependency behaviour.)

### [rev2] How doctor reaches the forcing function

Adding `assertNativeBindingAvailable()` to protect-ffi does not by itself wire it to
doctor. **The CLI has no protect-ffi dependency** — `packages/cli/package.json` declares
only `@cipherstash/stack` (peer `>=1.0.0-rc.0`, dev `workspace:*`). Reaching protect-ffi
through a hoisted transitive dependency is invalid under pnpm's strict layout and must
not be relied on.

The clean seam is a new **`@cipherstash/stack/diagnostics`** subpath that:

- imports protect-ffi **without** importing `@cipherstash/auth` (so the two probes stay
  genuinely independent, which is exactly what today's implementation fails to do),
- calls `assertNativeBindingAvailable()` and lets the `MODULE_NOT_FOUND` propagate
  unchanged, so `isNativeBinaryMissing` keeps classifying it,
- ships both `import` and `require` conditions, per the repo's ESM/CJS rule,
- is pure — no client construction, no credentials, no network.

Doctor then probes `@cipherstash/stack/diagnostics` for the encryption engine and keeps
its existing separate `@cipherstash/auth` probe.

The alternative — declaring protect-ffi as a direct CLI dependency — leaks an
implementation dependency into the CLI and duplicates stack's ownership of it. Rejected.

**[rev3] This seam cannot ship until after the flip.** See the ignore-window invariant.

### [rev3] The ignore-window invariant

Dropping the interim upstream release creates one hazard, and it governs the phase
order.

From phase 1 until the flip, the seven packages sit in `.changeset/config.json`'s
`ignore` list, so their workspace version stays at `0.31.0`. But `workspace:*` is
rewritten to the **local** version at pack time — and `0.31.0` is already on npm,
published from upstream. So a `@cipherstash/stack` release during the window pins
`@cipherstash/protect-ffi@0.31.0`, and consumers get **upstream's tarball**, which does
not contain any workspace change made since the import.

> **Invariant: while the ignore list is in place, `packages/stack` must not consume a
> protect-ffi API that published `0.31.0` lacks.**

Consequences, and this is the whole reason the phases are ordered as they are:

- Changing protect-ffi *internals* is safe. The laziness fix alters when the binary
  resolves; stack consumes no new API, so a stack release in the window is unaffected.
- Adding `assertNativeBindingAvailable()` is safe **as an export**. Nothing breaks by
  publishing a function nobody calls.
- **`@cipherstash/stack/diagnostics` calling it is not safe.** That is stack consuming
  an API absent from published `0.31.0`; a stack release in the window ships an entry
  point that throws on import for every consumer.

So the doctor work — the diagnostics subpath, the probe rework, the e2e fixture — moves
*after* the flip, into its own phase. Everything else is unaffected.

The alternative is freezing `@cipherstash/stack` releases from the laziness fix through
to the flip. Rejected: this repo releases actively (`a3198ebc Version Packages (#750)`),
a freeze of unknown duration is a real operational cost, and the split costs nothing.

## [rev] Versioning: a separate fixed group

The first draft framed this as "join Stack's fixed group, or take `workspace:*` only."
That was a false choice. The correct seam is **two independent fixed groups**:

- **Unchanged:** `stash`, `@cipherstash/stack`, `stack-drizzle`, `stack-supabase`,
  `stack-prisma`, `wizard` — all currently at `1.0.0`.
- **New:** `@cipherstash/protect-ffi` + its six `protect-ffi-*` platform packages.

This keeps the wrapper/binary lockstep that actually matters (a platform binary must
never be published at a version its wrapper doesn't expect) without making every Rust
patch republish the CLI, the core library, the wizard, and all three adapters.

It also avoids a version discontinuity. Joining Stack's group would have taken
protect-ffi from `0.31.0` to **`1.0.1`** on the next patch release — fixed groups adopt
the highest member version and bump together.

`@cipherstash/migrate` and `@cipherstash/nextjs` are published but outside any fixed
group; selective membership is already the norm here.

**[rev] The external-dependents question is answered.** The first draft's claim that
"nothing outside this repo pins `@cipherstash/protect-ffi`" is false. npm reports two
dependents: `@cipherstash/stack` (ours) and `@cipherstash/protect@12.0.1` — our own
legacy predecessor — which pins `0.23.0` and therefore cannot float to a 1.x release.
The risk was low either way, but the separate fixed group removes the question.

## [rev] Release pipeline design

Today's release is a single `changesets/action` step whose `publish:` runs the root
`release` script (`.github/workflows/release.yml:60`), and that script is
`pnpm run build && changeset publish` (`package.json`) — it builds everything inline,
immediately before publishing. Five things must be specified before this can absorb a
native matrix.

**1. Publish gating.** The matrix must not run on every push to `main`.

**[rev2] The obvious gate is wrong.** "No unconsumed `.changeset/*.md`" is also true
for ordinary pushes — a docs commit, a refactor with no changeset, or the very next
commit after a release — so it would fire the matrix routinely. The changesets action
documentation makes the same point: a commit with no changesets can land after
publication, and custom publishing must independently detect what is already published.

**[rev4] One boolean is not enough.** The gate job computes three outputs without
calling the publishing form of `changesets/action`:

- `hasChangesets`: there is at least one unconsumed changeset;
- `shouldPublish`: at least one publishable workspace package has a local version not
  present on npm;
- `needsFfiArtifacts`: one of the **seven protect-ffi packages** has a local version
  not present on npm.

Derive the version outputs by enumerating non-private workspace manifests and querying
`npm view <name> versions`; handle a registry 404 as "unpublished". Do not infer either
output from `.changeset/` contents. `shouldPublish` controls whether the final publish
path runs. `needsFfiArtifacts` alone controls the native matrix and WASM job — an
ordinary Stack, CLI, Wizard, or adapter release must not pay the 16-minute FFI build.

The workflow topology is explicit:

1. A cheap gate job computes the three outputs.
2. A Version Packages job runs when `hasChangesets == true` and invokes
   `changesets/action` **without** `publish:` to create or update the release PR.
3. Native and WASM jobs run only when `hasChangesets == false && needsFfiArtifacts`.
4. A restore/verification job downloads the artifacts only on that branch.
5. The final GitHub-hosted release job runs when
   `hasChangesets == false && shouldPublish`; use `always()` plus explicit result checks
   so skipped FFI jobs do not skip an ordinary JS release.
6. That final job invokes the publishing form of `changesets/action`; it is the sole
   publishing invocation and preserves npm publication, git tags, and GitHub releases.

Add workflow tests for all four states: pending changeset; nothing unpublished; JS-only
release; FFI release. The last is the only state that may start the matrix.

**2. WASM is a first-class artifact, not an afterthought.** The main tarball's `files`
include `dist/wasm/**` — `protect_ffi.js`, `protect_ffi_bg.wasm`, `protect_ffi_inline.js`,
`errors.js`, and their `.d.ts`. Upstream's `build.yml` runs a **separate `wasm` job**
(`wasm-pack build --target bundler` + `scripts/inline-wasm.mjs`) and transfers its
output as an artifact before the `main` job packs. A native-only matrix would publish
a main tarball whose `./wasm` and `./wasm-inline` entries resolve to nothing. Port the
WASM job, its declaration typecheck (`tsconfig.wasm-errors.json`), and its artifact
transfer.

**3. Artifact restore before publish.** The six `platforms/<p>/index.node` files and
`dist/wasm/` must be materialised into the workspace *before* `changeset publish` runs.
Use `actions/download-artifact` into the correct paths in the publish job.

**4. The publish command must not rebuild.** `pnpm run release` currently runs a full
`turbo build`, which for protect-ffi means `cargo build --release` — on the publish
runner, producing only the host binary and overwriting the restored artifact. The
release script needs a variant that builds the JS packages and leaves native/WASM
outputs alone. See "Task separation" below.

**5. "Dry run" needs a definition.** `changeset publish` has no `--dry-run`. The real
pre-flight is: pack all seven tarballs (`npm pack`), run `npm publish --dry-run` per
tarball, then install the wrapper plus the **host-matching** platform tarball into a
scratch project and smoke-test — `require` the wrapper, call
`assertNativeBindingAvailable()`, and resolve both `./wasm` and `./wasm-inline` from the
packed artifact. Verify the other five platform tarballs statically or on matching
runners. That is the gate before the trusted-publisher cutover, not a workflow flag.

## [rev2] Generated output is not source-controlled

Upstream's `.gitignore` covers `dist`, `lib`, **and** `index.node`. Nothing under
either directory is tracked — `git ls-files dist` and `git ls-files lib` both return
zero. Of the 200 tracked files, `platforms/` contributes only 12: a `package.json` and
a README each. Today this is invisible because consumers install a *packed tarball*
that contains the generated output; after workspace linking they get the *source tree*,
which does not.

Two distinct consequences:

- **`lib/` is the package `main`** (`./lib/index.cjs`; the packed 0.31.0 package
  contains 226 files under `lib/`). A workspace consumer resolving
  `@cipherstash/protect-ffi` gets nothing until `tsc` has run. This is cheap to fix —
  `tsc` is already the first half of `prepack`.
- **`dist/wasm/**` is generated by `wasm-pack` + `scripts/inline-wasm.mjs`**, which
  needs Rust, the `wasm32-unknown-unknown` target, and wasm-pack. `packages/stack/src/wasm-inline.ts:101`
  value-imports `@cipherstash/protect-ffi/wasm-inline`, so its absence breaks stack's
  declaration build even though tsup keeps the runtime import external.

This is the finding that most threatens "ordinary CI needs no Rust", and it must be
settled empirically in phase 1 — after the npm package is replaced by the workspace
package. Until then, treat the contributor-Rust conclusion as **provisional**.

Measured inputs to that decision:

```
dist/wasm total                  ~8M
  protect_ffi_inline.js       4,610,881B   runtime only
  protect_ffi_bg.wasm         3,457,620B   runtime only
  protect_ffi_bg.js              38,289B   runtime only
  protect_ffi.d.ts                6,171B   needed for typecheck
  protect_ffi_bg.wasm.d.ts        3,298B   declaration companion
  errors.d.ts                    2,495B   needed: protect_ffi.d.ts re-exports it
```

And: stack's **unit** tests never load the real module. `packages/stack/vitest.config.ts`
aliases `@cipherstash/protect-ffi/wasm-inline` to
`__tests__/helpers/stub-protect-ffi-wasm-inline.ts`. Only
`packages/stack/integration/wasm/` needs real WASM at runtime.

Of the three options, the data favours the third:

1. **Build WASM in ordinary CI** — imposes the Rust + wasm-pack toolchain on every
   contributor and every PR job. Defeats the main benefit. Reject unless (3) fails.
2. **Commit the generated artifacts** — 7.4MB of regenerated binary output per release,
   permanently in git history. Reject.
3. **Commit declarations only; generate runtime output at release** — ~12KB across
   `protect_ffi.d.ts`, `protect_ffi_bg.wasm.d.ts`, and `errors.d.ts`; human-reviewable,
   rarely changing. Export maps resolve `types` and `default`
   independently, so typecheck and the dts build succeed without the `.js`/`.wasm`
   present. Unit tests already run stubbed. Integration WASM tests become a gated job
   that builds wasm first, alongside the existing credential-gated suites.

   The nested `.gitignore` currently ignores all of `dist`; add narrow negations for
   these three files (and their `dist/wasm/` parent) rather than force-adding them or
   exposing the runtime artifacts. Root Biome already excludes `**/dist`, so the
   generated declarations stay outside formatting and linting.

**Verify (3) before committing to it**: with the workspace package linked, delete
`dist/wasm/*.js` and `*.wasm` leaving all three `.d.ts`, then run
`pnpm --filter @cipherstash/stack build` and `typecheck`. If the dts build resolves,
(3) holds and ordinary CI stays Rust-free.

## [rev] Task separation — "PR CI needs no Rust" requires work

This does not follow automatically from the laziness fix. Once `packages/protect-ffi`
matches `packages/*`, three root entry points reach its scripts:

| Entry point | Reaches | Effect |
|---|---|---|
| `pnpm test` → `turbo test --filter './packages/*'` (`tests.yml`, "Run tests") | protect-ffi `test` → `test:rust` → `cargo test` | Cargo on every PR |
| `pnpm turbo build --filter './packages/*'` (`tests.yml`, Bun job "Build packages") | protect-ffi `build` → `cargo build --release` | Cargo in the Bun job |
| `pnpm run release` → `pnpm run build && changeset publish` | same `build` | Cargo during publish |

Path-filtering a standalone cargo workflow does nothing about any of these — Turbo
reaches the package's own scripts regardless.

**Fix it in protect-ffi's manifest, not the root scripts.** Its `test` today is
`test:typecheck && test:unit && test:lint && test:format && test:rust`, and
`test:format` itself expands to `test:format:ts && test:format:rust` where the latter
runs `cargo fmt --check`. Redefine the default test as the JS-only chain
`test:typecheck && test:unit && test:lint && test:format:ts`. Run `test:rust`,
`test:format:rust`, and clippy in the path-filtered Rust job. The verification is
literal: neither the default package test nor root `pnpm test` may execute a `cargo`
process.

**[rev2] `build` cannot become a no-op.** The first draft said "no-op or tsc-only" —
no-op is wrong, because `lib/` is generated and is the package's `main` (see "Generated
output" above). The default `build` must run **at least `tsc`**, or every workspace
consumer resolves an empty package. `build:native` carries the cargo invocation
(currently `build` → `cargo-build -- --release`); whether the default also needs a wasm
step depends on the option-(3) verification above.

Turbo already supports per-package task overrides if the graph needs pinning —
`stash#build`, `@cipherstash/wizard#build`, and `@cipherstash/bench#build` are existing
precedent in `turbo.json`.

**Naming caution:** do *not* reuse `build:js`. It already exists at root and means
`turbo build --filter './packages/nextjs'` — despite `AGENTS.md` describing it as
"only JS libraries". Either pick different names or fix that script deliberately, in
its own commit.

**[rev] Rust path filters must be broader than `crates/**`** — that misses dependency,
feature, and toolchain changes. Trigger cargo verification on at least: `crates/**`,
`Cargo.toml`, `Cargo.lock`, `rust-toolchain*`, `.cargo/**`, `mise.toml`, `build.rs` /
native build scripts, and the `neon` block in `packages/protect-ffi/package.json`.

## What changes

**Workspace**
- `pnpm-workspace.yaml`: add `packages/protect-ffi/platforms/*` (the `packages/*` glob
  already covers `packages/protect-ffi`).
- **[rev] All three exact pins** become `workspace:*` — leaving any on npm would build
  and test that adapter against the published FFI rather than the absorbed source:
  - `packages/stack/package.json:219`
  - `packages/stack-drizzle/package.json:65`
  - `packages/stack-supabase/package.json:72`
- `minimumReleaseAgeExclude`: the `@cipherstash/protect-ffi` / `-*` entries become dead
  once workspace-linked. Remove them, and the two lines of the explanatory comment above
  them that describe protect-ffi.
- **[rev]** `.github/dependabot.yml:56` ignores `@cipherstash/protect-ffi`, with a
  comment naming the same three consumers and their lockstep pin. Remove the entry and
  the comment. Audit the integration-workflow path logic for the same assumption —
  that FFI changes arrive as exact dependency-pin edits.

**[rev3] What the subtree deposits.** The import lands upstream's whole tracked tree
(200 files) under `packages/protect-ffi/`, including root-level files that now collide
conceptually with this repo's:

| Deposited | Disposition |
|---|---|
| `package-lock.json` | Delete — this is a pnpm workspace |
| `.github/workflows/{build,release,test}.yml`, `.github/actions/setup/`, `.github/.env` | Not read by GitHub from a subdirectory. Keep as reference through phase 3, then port and delete; do not leave dead workflow files behind |
| `biome.json` (1.9.4 config) | Reconcile against root Biome 2.5.3 — either delete and inherit, or keep a scoped override deliberately |
| `mise.toml` | Keep — it pins the Rust toolchain, and it belongs in the Rust path filter |
| `LICENSE.md`, `CODE_OF_CONDUCT.md` | Dedupe against root |
| `Cargo.toml` / `Cargo.lock` / `crates/` | Keep in place — the nested cargo workspace is verified working |
| `.gitignore` | Keep — nested, still covers `dist` / `lib` / `index.node` |
| `tsconfig*.json`, `vitest.config.ts` | Keep; reconcile versions per below |

Upstream also has uncommitted work: `.serena/`, `.work/`, and an untracked
`integration-tests/tests/json-array-docs-validation.test.ts`. A subtree carries tracked
history only — decide explicitly whether that test file comes across.

**protect-ffi package**
- Drop `neon update` from `prepack`; drop the `version` script (`neon bump`).
- Split `test` / `build` from `test:rust` / `build:native` (above).
- Split `test:format:ts` from `test:format:rust`; only the TypeScript formatter stays
  on the default test path.
- If declarations-only option (3) passes, narrow `.gitignore` so exactly the three
  WASM `.d.ts` files are tracked while runtime WASM output remains ignored.
- **[rev3]** Add `assertNativeBindingAvailable()` and the lazy
  `import native = require('./load.cjs')` — in phase 2, in this repo.
- Move the npm-only `overrides: { vite: "^8.0.5" }` to root `pnpm.overrides` or drop it
  — pnpm ignores `overrides` outside the workspace root. Note root already carries
  `vite` in `catalog:security` at `8.1.4` and a scoped `vite@>=7.0.0 <7.3.5` override.
- Reconcile toolchain to repo catalogs: Node 20 → 22, Biome 1.9.4 → 2.5.3,
  vitest ^4.1.0 → 3.2.7 (a *downgrade* for FFI — verify its suite still passes).

**[rev3] stack, to consume 0.31.0** — the three changes in "The import is also an
upgrade": the two `ProtectError` value sites, the wasm `newClient` shape (and its
`as never`), and a check that `CS_CLIENT_KEY` is hex everywhere it is set. Use
`isProtectErrorCode()` at the two error sites rather than asserting any string-valued
Node error code into the FFI union. Add a **separate, non-ignored Stack changeset** for
the 0.31 adoption; do not mix it with the ignored FFI changeset.

**CI / release**
- Implement the five-point pipeline above (gate, WASM job, artifact restore,
  no-rebuild publish command, pack-and-install pre-flight).
- Keep the Blacksmith-builds / GitHub-hosted-publish split from upstream's
  `release.yml` — npm rejects provenance from self-hosted runners with E422.
- Add the new release jobs to `lint-no-workflow-caching.mjs` TARGETS deliberately.
- npm trusted publishing repointed for all seven packages:
  `cipherstash/protectjs-ffi` → `cipherstash/stack`. Seven manual npmjs.com changes,
  hard cutover, no dry run.

**Repo meta** (per `AGENTS.md` step 7) — update the Repository Layout in `AGENTS.md`
and the package list in `SECURITY.md` in the same PR that adds the packages. Review
`skills/*/SKILL.md` for anything asserting protect-ffi is a separate repo or an
externally-versioned dependency.

## [rev3] Phased sequence

Reordered. The laziness fix now lands in this repo after the import, and the `stash
doctor` work is split off to after the flip — see the ignore-window invariant for why.
The trusted-publishing cutover is still the only irreversible step.

**Phase 1 — import.** Source moves, publishing does not.

- `git subtree` the history into `packages/protect-ffi` (**613 commits, 9.8MB `.git`,
  200 tracked files**) as a *pure* import commit; everything below follows as separate
  reviewable commits on top.
- Deposit cleanup per the table above.
- Workspace wiring: the `platforms/*` glob, the three `workspace:*` pins, the
  `minimumReleaseAgeExclude` and Dependabot removals.
- Changesets: create the seven-package fixed group **and add all seven to `ignore`**.
- Manifest reconciliation: `prepack`, the `version` script, the `test` / `build` split,
  `overrides`, toolchain catalogs.
- **Absorb the 0.30.0 → 0.31.0 breaking delta.** Check `CS_CLIENT_KEY` encoding in CI
  secrets *first* — if it is base64, every credentialed test fails at once and the
  cause will not be obvious from the failure.
- Add a separate, non-ignored changeset for `@cipherstash/stack` describing the 0.31
  dependency adoption, the hex-only client-key requirement, and the compatibility
  fixes. Decide its bump level explicitly: repository guidance documents hex, but the
  previous runtime accepted base64, so this is observable even if treated as a fix.
- **Run the option-(3) WASM verification.** This phase is where the contributor-Rust
  conclusion is settled.

> **[rev2] Publication guard — decided.** Once seven public packages are in the
> workspace, a protect-ffi changeset could trigger a publish before trusted publishing
> is repointed. `ignore` is the guard. (The first draft offered this *or* holding the
> workflow; that was a non-decision.) Note changesets' restriction: a single changeset
> may not mix ignored and non-ignored packages, so from here until the flip an FFI
> change needs its own changeset, separate from any stack-side change.

Upstream `main` was verified identical to the published `v0.31.0` tag at planning time,
so the ignore-window interface premise holds. It is **not** true that consumers see no
change: the next Stack release pins protect-ffi `0.31.0` instead of `0.30.0`, including
its hex-only key requirement and error-shape changes. The compatibility edits and
Stack changeset above make that adoption deliberate. Re-check `main...v0.31.0`
immediately before the subtree import; if upstream has advanced without a release,
import the tag or account for the additional delta separately.

**Phase 2 — the lazy change.** Entirely inside `packages/protect-ffi`:

- `import native = require('./load.cjs')` in `src/index.cts`; verify the `.mts` entry.
- Add `assertNativeBindingAvailable()` as a new export — **exported, not yet consumed**.
- A `@cipherstash/protect-ffi` **minor** changeset. It sits pending under `ignore` and
  becomes the first monorepo release in phase 4; no synthetic changeset is needed there.
- `stash doctor` is *not* touched in this phase. Its probe degrades silently (see "The
  one real regression") from the moment this ships — which is phase 4, and phase 5 is
  the fix. That gap is the price of dropping the interim release; it is one release
  wide and affects a diagnostic command, not the encryption path.

**Phase 3 — build the pipeline.** Implement the three-output gate, Version Packages
job, FFI-only native/WASM branch, artifact restore, and non-rebuilding publish command.
Expose the artifact build and pack/install pre-flight as a non-publishing reusable or
manually dispatched workflow that can check a versioned release-PR ref; the `main`
release path may call the same jobs, but only its final release job may publish.
Exercise all four workflow states (pending changeset, nothing unpublished, JS-only
release, FFI release) and the pack-and-install pre-flight. An ordinary JS-only release
must reach publication with the FFI jobs skipped.

**Phase 4 — flip.** This is a Changesets lifecycle, not one immediate publish command:

1. Merge a cutover PR that removes the seven `ignore` entries. Keep the phase-2 FFI
   changeset pending; do not run `changeset version` in an unrelated commit.
2. Let the Version Packages job create/update the release PR. Verify it bumps all seven
   FFI packages to `0.32.0`, rewrites the wrapper's six optional dependencies, and
   leaves the separate Stack release metadata correct.
3. Run the native/WASM matrix and pack/install pre-flight against that **versioned
   release PR**, so the tarballs tested have the exact versions that will publish.
4. Repoint npm trusted publishing for all seven packages only after the versioned
   pre-flight is green. Protect the Version Packages PR from merging before this manual
   cutover is complete.
5. Merge the Version Packages PR. The `main` push now has no pending changeset,
   `shouldPublish == true`, and `needsFfiArtifacts == true`; build, restore, and publish.
6. Smoke-test the installed artifacts, verify npm provenance, git tags, and the GitHub
   release, then archive `cipherstash/protectjs-ffi`.

> **[rev2] Removing `ignore` does not cause a publish.** `0.31.0` is already on npm;
> un-ignoring the packages does not make them unpublished. **[rev3]** What produces the
> release is the phase-2 changeset, which the dedicated fixed group propagates to all
> six platform packages — protect-ffi `0.32.0`, the first release built here.

> **[rev2] Install-testing all six platform tarballs on one host is not possible.**
> npm and pnpm reject an explicitly-requested package whose `os`/`cpu` does not match
> (`EBADPLATFORM`); the warn-only behaviour observed in the workspace harness applies to
> *linked* packages, not installed ones. The runtime smoke test installs **the wrapper
> plus the host-matching platform tarball**. Verify the other five statically (tarball
> contents, `package.json` `os`/`cpu`/`main`, `index.node` present and non-empty) or in
> a runner matrix.

**Phase 5 — wire `stash doctor`.** Only now is `assertNativeBindingAvailable()` on npm,
so stack may consume it:

- Add the `@cipherstash/stack/diagnostics` subpath (both `import` and `require`).
- Rework doctor to probe it, keeping the separate `@cipherstash/auth` probe — which
  fixes the pre-existing bug where the stack probe duplicated the auth probe.
- Add the missing-binary e2e fixture. Nothing in the repo removes a real binary today.
- Add explicit changesets for the new public Stack subpath and the CLI diagnostic
  behaviour; fixed-group propagation is not a substitute for accurate changelog text.
- Ships in an ordinary release.

## Verification checklist

- [ ] `CS_CLIENT_KEY` is hex-encoded in every CI secret and documented `.env` (**check
      before phase 1 lands**, not after)
- [ ] `pnpm install` clean at root with the seven new packages linked
- [ ] `pnpm --filter @cipherstash/stack build` and `typecheck` pass against workspace
      protect-ffi `0.31.0` — i.e. the `ProtectError` and wasm `newClient` changes are complete
- [ ] The 0.31 adoption has its own non-ignored Stack changeset and user-facing note
- [ ] `pnpm test` at root completes **without invoking cargo**
- [ ] `pnpm --filter @cipherstash/protect-ffi test` does not reach either `cargo test`
      or `cargo fmt`; both run in the Rust-specific job
- [ ] `pnpm turbo build --filter './packages/*'` completes **without invoking cargo**
- [ ] `pnpm --filter @cipherstash/protect-ffi build:native` produces `platforms/<p>/index.node`
- [ ] `pnpm --filter @cipherstash/protect-ffi test` passes on vitest 3.2.7 (downgrade) and Biome 2.5.3
- [ ] Option (3) holds: stack's dts build resolves with `dist/wasm/*.js` and `*.wasm`
      deleted while `protect_ffi.d.ts`, `protect_ffi_bg.wasm.d.ts`, and `errors.d.ts`
      remain tracked
- [ ] WASM job output resolves for both `./wasm` and `./wasm-inline` **from the packed tarball**
- [ ] `pnpm --filter @cipherstash/stack test` passes with the binary present
- [ ] Stack's suite passes with the binary **absent**, except the credential-gated files
      (re-measure the count — the old "3 of 52" figure is stale)
- [ ] `stash doctor` exits non-zero with a hidden platform package (new fixture, phase 5)
- [ ] `node packages/cli/dist/bin/stash.js manifest --json` still resolves every command
      named in `skills/stash-cli/SKILL.md`
- [ ] `pnpm run code:check` error-free
- [ ] `node scripts/lint-no-workflow-caching.mjs` passes against the new `release.yml`
- [ ] `e2e/tests/supply-chain.e2e.test.ts` passes
- [ ] No dead upstream workflow files left under `packages/protect-ffi/.github/`
- [ ] A push to `main` with pending changesets does **not** start the native matrix
- [ ] A push to `main` with **no** changesets and nothing unpublished does **not** start
      the native matrix (the case the first gate got wrong)
- [ ] A JS-only release publishes successfully **without** starting native or WASM jobs
- [ ] An FFI release is the only case that sets `needsFfiArtifacts == true`
- [ ] The native/WASM artifact and pre-flight workflow can run against a release-PR ref
      without invoking any publish step
- [ ] Git tags and the GitHub release are still created on a publish run
- [ ] All seven tarballs pack and `npm publish --dry-run` clean
- [ ] Wrapper + host-matching platform tarball install and smoke-test green in a scratch
      project (`assertNativeBindingAvailable()` succeeds; `./wasm` and `./wasm-inline`
      both resolve); other five platform tarballs verified statically
- [ ] Published `@cipherstash/stack` tarball's `dependencies` show a concrete
      protect-ffi version, not `workspace:*`
- [ ] Removing the FFI ignore entries creates a versioned release PR; its seven FFI
      packages are `0.32.0` and pass pre-flight before trusted publishing is repointed

## Closed questions

- **[rev3] Why no interim upstream release?** Decided: it buys a de-risking step whose
  value is largely consumed by the import itself, at the cost of one more cross-repo
  release dance — the exact thing this work exists to eliminate. The published
  `0.31.0` would reach almost nobody in the meantime: the only external dependent,
  `@cipherstash/protect@12.0.1`, pins `0.23.0`. The cost is the ignore-window
  invariant and the one-release doctor gap, both bounded and both handled above.
- **Does Windows stay in every release?** Yes. A fixed group publishes all seven
  packages atomically; moving Windows to a later schedule would mean releasing a group
  whose members do not all exist yet. Revisit only as part of a deliberately designed
  prebuilt-artifact system, not as a latency tweak.
- **Does a Rust-only change need a changeset?** Yes — `AGENTS.md` step 9 already
  answers it. Rust changes alter published behaviour, so they need a
  `@cipherstash/protect-ffi` changeset; the dedicated fixed group propagates the bump to
  the six platform packages.

## Open questions

1. **Does option (3) hold?** Whether committed `.d.ts` files alone satisfy stack's
   declaration build is the one unverified assumption the contributor-Rust conclusion
   rests on. Settled in phase 1 by the experiment described above.
2. **[rev3] Is `CS_CLIENT_KEY` hex in CI?** Unanswerable from the tree. If it is
   base64, phase 1 breaks every credentialed test simultaneously, and the error message
   deliberately says nothing beyond "expected a hex-encoded key".
3. **`packages/prisma-next/`, `packages/drizzle/`, `packages/protect/`,
   `packages/schema/`, `packages/stack-forge/`** are untracked build residue from
   earlier renames — zero tracked files each. Unrelated, but they make `packages/*`
   misleading to read, and this work adds a package directory containing six further
   nested packages to the same place.

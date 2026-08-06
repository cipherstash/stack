/**
 * Guards *when* the platform binary is resolved, which is invisible at runtime
 * on a machine that has one.
 *
 * The package used to resolve it at module evaluation: `import * as native from
 * './load.cjs'` compiles to `__importStar(require("./load.cjs"))`, and
 * `__importStar` enumerates the module's properties to copy them — which forces
 * `@neon-rs/load`'s proxy to load the binary. So merely importing the package
 * threw `MODULE_NOT_FOUND` with no binding installed, for callers that never
 * encrypt anything: `@cipherstash/migrate` imports a pure-JS type guard,
 * `@cipherstash/stack-prisma` reaches this package through one entry out of
 * fifteen.
 *
 * A regression here is silent for anyone with a binary installed — every
 * consumer who installs from npm, and every CI job that has run
 * `.github/actions/build-ffi-binding` — so the property is asserted against the
 * EMITTED JavaScript rather than behaviour. `lib/` exists by the time this
 * runs: `test:typecheck` emits it before `test:unit`.
 *
 * The same blind spot is why the last block goes the other way and asserts
 * behaviour: what `assertNativeBindingAvailable` does with a MISSING binary
 * cannot be read off the emit, so that block substitutes a failing loader
 * under the emitted entry instead of substituting an installation.
 *
 * Nothing in this file may REQUIRE a binary, though, and that is a separate
 * rule from the ones above. `packages/protect-ffi`'s `test` is the default task
 * root `pnpm test` reaches through `turbo test --filter './packages/*'`, and it
 * is deliberately Rust-free: `index.node` stopped being tarball content when
 * this package was absorbed, so on a fresh checkout there is no binary
 * anywhere and the six `platforms/*` links are empty. `lintWiring.test.ts`
 * guards that rule for the whole suite by re-running it with the artifact made
 * unresolvable.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import Module, { createRequire } from 'node:module'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Vitest resolves cwd to the directory holding vitest.config.ts.
const packageRoot = process.cwd()
const entryPath = join(packageRoot, 'lib/index.cjs')

// `lib/` is generated, so this file carries a prerequisite the package's `test`
// chain satisfies and a bare `test:unit` does not. Without this guard the whole
// suite fails as `ENOENT: no such file or directory, open '.../lib/index.cjs'`
// pointed at the readFileSync below — which names the missing file but not the
// command that produces it, and lands on whoever runs `test:unit` directly
// (every CI job that splits the chain, and anyone iterating on one test).
// A zero-byte entry counts as missing. An interrupted `tsc` leaves one, and it
// is the state where naming the build step — the entire point of this guard —
// otherwise fails to happen: `existsSync` is satisfied, and what the developer
// sees instead is five assertions reporting `expected '' to match /…/`, none of
// which says "run build". Not a vacuity fix: `reads the emitted entry, not the
// source` below already fails loudly on an empty read, which is why it is
// there. This is so the failure names its own cure.
//
// Deliberately only the empty case. A PARTIALLY written entry is not
// detectable by size and needs no separate handling — the content assertions
// below go red on any degraded emit; they cannot go quietly green.
if (!existsSync(entryPath) || statSync(entryPath).size === 0) {
  throw new Error(
    `${entryPath} is missing or empty. These tests assert on the EMITTED entry, and lib/ is a build output: run \`pnpm --filter @cipherstash/protect-ffi run build\` first, or \`pnpm --filter @cipherstash/protect-ffi test\`, whose test:typecheck step emits lib/ before test:unit runs.`,
  )
}

// Comments are stripped before matching. The doc comment on the import in
// `index.cts` quotes the exact `__importStar(require("./load.cjs"))` form it
// exists to warn against, and tsc carries comments through to the emit — so a
// naive search finds the warning and reports the bug it is warning about.
const emitted = readFileSync(entryPath, 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^[ \t]*\/\/.*$/gm, '')

// Everything below that runs code rather than reading it goes through the
// EMITTED entry. Vitest cannot parse `.cts` ("content contains invalid JS
// syntax"), and the built artifact is what a consumer resolves anyway.
//
// Seeded with the entry's own path rather than `import.meta.url`: this tsconfig
// emits CommonJS and tsc rejects `import.meta` outright with TS1470 (see the
// same note in `lintWiring.test.ts`). Seeding it there also means bare
// specifiers resolve the way the emitted entry resolves them — so
// `@neon-rs/load` below is the same instance `lib/load.cjs` proxies through,
// not a second copy from some other node_modules.
const requireFromEntry = createRequire(entryPath)

describe('native binding load timing', () => {
  it('reads the emitted entry, not the source', () => {
    // Asserting on the wrong file would make everything below vacuous rather
    // than failing — the source has no `require` call to find at all.
    expect(emitted).toContain('load.cjs')
  })

  it('requires ./load.cjs without __importStar', () => {
    // `import native = require('./load.cjs')` emits a bare `require`.
    // `import * as native from './load.cjs'` emits the enumerating wrapper.
    const loadRequire = /__importStar\(require\("\.\/load\.cjs"\)\)/
    expect(emitted).not.toMatch(loadRequire)
    expect(emitted).toMatch(/require\("\.\/load\.cjs"\)/)
  })

  it('does not enumerate the loader anywhere in the entry', () => {
    // Belt and braces: any spread or key-copy over the proxy has the same
    // effect as `__importStar`, whatever the import syntax.
    const spreadOfNative =
      /\.\.\.\s*native\b|Object\.(keys|assign|entries)\(\s*native\s*\)/
    expect(emitted).not.toMatch(spreadOfNative)
  })
})

/**
 * Every path a build of this package leaves an `index.node` at.
 *
 * This is the SPLIT the two branches below turn on, and it is deliberately a
 * filesystem fact rather than `process.env.CI`. `CI` is a claim about which
 * machine this is; the question is whether a cargo build has happened, which is
 * observable directly. `CI` also lies in both directions — it is set by `act`,
 * by pre-commit wrappers, and by anyone who exports it, none of which builds a
 * binding; and it says nothing about a developer who ran `build:native` and
 * whose positive case would then never be checked.
 */
function binariesUnder(dir: string): string[] {
  if (!existsSync(dir)) return []
  return readdirSync(dir).map((name) => join(dir, name, 'index.node'))
}

const BINDING_ARTIFACTS = [
  // `build:native` → the `postcargo-build` hook → a bare `neon dist`, which
  // writes it at the package ROOT. That is the `debug:` fallback registered in
  // `src/load.cts`, and it is what `.github/actions/build-ffi-binding`
  // produces — CI never populates a platform package.
  join(packageRoot, 'index.node'),
  // `neon dist -o platforms/<target>` — release packaging, and the shape an
  // `npm install` of `@cipherstash/protect-ffi-<target>` leaves behind. In
  // this workspace `node_modules/@cipherstash/protect-ffi-*` symlinks to
  // `platforms/*` so the two overlap; for a consumer only the first exists.
  ...binariesUnder(join(packageRoot, 'platforms')),
  ...binariesUnder(join(packageRoot, 'node_modules/@cipherstash')),
]

// Zero-byte counts as absent, matching the `lib/index.cjs` guard above: an
// interrupted `neon dist` leaves one, and treating it as present would send
// this into the branch that demands a successful load.
const builtArtifacts = BINDING_ARTIFACTS.filter(
  (path) => existsSync(path) && statSync(path).size > 0,
)

/**
 * The platform-package name in a loader failure, as `packages/cli` matches it
 * (`PLATFORM_PKG` in `packages/cli/src/native.ts`).
 *
 * Copied rather than imported — this package does not depend on the CLI, and
 * should not. The coupling is the point of the assertion: `index.cts`'s doc
 * comment promises the loader's error propagates UNWRAPPED so that "existing
 * classification of a missing binding keeps working unchanged", and the CLI is
 * the code doing that classification. Nothing checked the promise against a
 * real error until now: the CLI's own suite builds its inputs by hand
 * (`moduleError("Cannot find module '@cipherstash/protect-ffi-darwin-arm64'")`
 * in `packages/cli/src/__tests__/native.test.ts`), so it proves the matcher
 * matches a string, not that the string is what the loader raises.
 */
const PLATFORM_PACKAGE =
  /@cipherstash\/[a-z0-9-]+-(?:darwin|linux|win32)-[a-z0-9-]+/i

describe('assertNativeBindingAvailable', () => {
  const mod = requireFromEntry(entryPath)

  // Called ONCE, here, rather than inside a test: the loader memoises, so a
  // second call after a first success is not a second load, and the branches
  // below are two views of the same outcome rather than two attempts.
  const outcome: { error: unknown } = (() => {
    try {
      mod.assertNativeBindingAvailable()
      return { error: undefined }
    } catch (error) {
      return { error }
    }
  })()

  const errorDetail =
    outcome.error instanceof Error
      ? `${outcome.error.name} [${(outcome.error as NodeJS.ErrnoException).code}]: ${outcome.error.message}`
      : String(outcome.error)

  it('is exported from the package entry', () => {
    // `stash doctor` will consume this by name across a package boundary, so
    // its presence is the contract — see the doc comment on the function.
    expect(typeof mod.assertNativeBindingAvailable).toBe('function')
  })

  it('loads a built binding, and fails classifiably when none is built', () => {
    // This used to be a bare `expect(...).not.toThrow()` justified by "this
    // suite runs where a binary is installed". That premise died with the
    // absorption. `index.node` arrived prebuilt inside the npm tarball; as a
    // workspace package it is a cargo output, the six `platforms/*` links are
    // empty until someone builds one, and `packages/protect-ffi`'s `test` is
    // deliberately Rust-free. So on every fresh checkout the assertion failed
    // — and it failed under root `pnpm test`, which reaches this package via
    // `turbo test --filter './packages/*'`.
    //
    // Both branches assert. A `skipIf` here would be the trade this repo keeps
    // refusing: it goes quiet on every contributor machine, and quiet is
    // indistinguishable from passing. What replaces it is that the artifact-
    // free case has a contract of its OWN worth checking, and it is the one
    // `stash doctor` and `reportNativeBinaryMissing` depend on.
    if (builtArtifacts.length > 0) {
      expect(
        outcome.error,
        `A binding is built at ${builtArtifacts.join(', ')}, so the loader must resolve it. It threw instead:\n  ${errorDetail}\nEither the artifact is broken (wrong architecture, truncated write) or \`assertNativeBindingAvailable\` no longer calls a native export that loads cleanly — \`native.isEncrypted(null)\` is chosen because it is pure, synchronous, and validates nothing before reaching the addon.`,
      ).toBeUndefined()
      return
    }

    expect(
      outcome.error,
      `No index.node exists under packages/protect-ffi, so the loader cannot succeed and this call must throw. Looked at:\n${BINDING_ARTIFACTS.map((path) => `  ${path}`).join('\n')}\nA success here means the binding came from somewhere none of those paths covers, and the check above is then gated on a list that no longer describes reality.`,
    ).toBeInstanceOf(Error)

    const error = outcome.error as NodeJS.ErrnoException & {
      requireStack?: string[]
    }
    // The contract `index.cts` documents, verified against the real thing.
    expect(
      error.code,
      `The loader failure must reach callers unwrapped as MODULE_NOT_FOUND. \`packages/cli\`'s \`isNativeBinaryMissing\` tests \`code\` first and returns false for anything else, so a wrapped or re-thrown error turns \`stash doctor\`'s actionable "native binary missing" note back into a raw stack trace. Got: ${errorDetail}`,
    ).toBe('MODULE_NOT_FOUND')
    expect(
      `${error.message}\n${(error.requireStack ?? []).join('\n')}`,
      `The failure must name the platform package so \`packages/cli\` can tell a missing NATIVE binary from any other missing module. Got: ${errorDetail}`,
    ).toMatch(PLATFORM_PACKAGE)
  })

  it('has its success path exercised by the action that builds a binding', () => {
    // The other half of the split above, and what stops the artifact-free
    // branch from being a silent skip in disguise. The positive case only runs
    // where a binding exists, which is no contributor machine by default — so
    // the claim "it is checked where the artifact is guaranteed" has to be
    // mechanically checkable rather than a sentence in a comment.
    //
    // `.github/actions/build-ffi-binding` is that place: it ends in a `Verify
    // the binding loads` step calling this function through the emitted entry,
    // immediately after producing `index.node`, and
    // `scripts/__tests__/ffi-binding-step-order.test.mjs` requires every
    // credentialed job (`tests.yml / run-tests` among them) to run it.
    //
    // Cut to `runs:` before searching, the way `integrationSuiteCi.test.ts`
    // cuts to `jobs:`: the action's `description:` is prose, and a description
    // that mentions proving the binding loads is not a step that proves it.
    // Comments inside `runs:` go for the same reason.
    const action = readFileSync(
      join(packageRoot, '../../.github/actions/build-ffi-binding/action.yml'),
      'utf8',
    )
    const runsAt = action.search(/^runs:/m)
    expect(
      runsAt,
      'build-ffi-binding/action.yml has no `runs:` key, so it defines no steps and the search below would scan prose alone.',
    ).toBeGreaterThan(-1)

    expect(
      action.slice(runsAt).replace(/^[ \t]*#.*$/gm, ''),
      'No step in .github/actions/build-ffi-binding calls `assertNativeBindingAvailable`. That step is the only place the success path runs against a real binding: the test above takes its artifact-free branch on any checkout without one, which is every fresh checkout and every contributor who has not run `build:native`.',
    ).toContain('assertNativeBindingAvailable')
  })

  it('reaches the loader rather than short-circuiting', () => {
    // The whole point is that it forces resolution, and a body that returned
    // early would pass the load test above on any machine with a binding
    // while proving nothing. (Without one it is caught there — an empty body
    // does not throw, and the artifact-free branch requires a throw. Which is
    // the wrong way round: the machines that have a binding are the ones this
    // property is invisible on.) Asserting on
    // the emitted body — the technique the first describe block uses, and for
    // the same reason: on a machine with a binary installed, the difference
    // between forcing the load and not is invisible at runtime.
    //
    // This used to assert `mod.isEncrypted(null) === false`, which exercised
    // a DIFFERENT exported function that reaches the loader on its own. Empty
    // this one's body and that assertion still passed.
    const body =
      /function assertNativeBindingAvailable\(\)\s*\{\s*native\.\w+\(/
    expect(emitted).toMatch(body)
  })
})

/**
 * The negative half of the contract, which is the half the function exists for.
 *
 * Its doc comment promises that when the platform binary is missing the
 * loader's error propagates **unwrapped** — same `code`, same `message` — so
 * that anything already classifying a missing binding keeps working. Nothing
 * asserted that: the test above deferred it to a CLI missing-binary fixture
 * that does not exist, which left a promise about error handling verified by
 * prose alone.
 *
 * That test now checks the same contract on its artifact-free branch, which is
 * a complement rather than a duplicate — it only runs where nothing has been
 * built, so on the machines that DO have a binding (every CI job that ran
 * `.github/actions/build-ffi-binding`, every developer who ran `build:native`)
 * this block is the only place the missing-binary path executes at all.
 *
 * Reproduced by swapping the loader, not the environment: the REAL emitted
 * `lib/index.cjs` is re-required with a stand-in for `./load.cjs` whose
 * platform entry requires a package Node genuinely cannot resolve. So the code
 * under test is the shipped function and the error under test is Node's own
 * resolver error — neither half is simulated, which matters because a
 * hand-built `Error` with `code = 'MODULE_NOT_FOUND'` would satisfy every
 * assertion below while proving nothing about what the loader actually raises.
 *
 * **Not** a loader with no entry for the current platform, which is the obvious
 * way to write this and is the wrong shape. `@neon-rs/load`'s `proxy()` calls
 * `currentPlatform()` and checks the table EAGERLY, at `require` time, and
 * throws a plain `Error` with no `code` — so that fixture fails before
 * `assertNativeBindingAvailable` is ever reached, and asserts neither half of
 * the contract. A missing binary is the opposite: the platform key IS present,
 * and the lazy `load()` closure invokes it on first property access, where
 * `require('@cipherstash/protect-ffi-<platform>')` raises the real
 * `MODULE_NOT_FOUND`.
 */
describe('assertNativeBindingAvailable with the platform binary missing', () => {
  // Only the surface these tests touch. `requireFromEntry` returns `any`, and
  // naming the shape is what keeps that `any` from spreading through the file.
  type NeonLoad = {
    currentPlatform(): string
    proxy(options: {
      platforms: Record<string, () => unknown>
      debug?: () => unknown
    }): unknown
  }
  type Entry = { assertNativeBindingAvailable(): void }

  const neon: NeonLoad = requireFromEntry('@neon-rs/load')
  const loadPath = requireFromEntry.resolve('./load.cjs')

  /**
   * The specifier the stand-in loader asks for: the shipped naming scheme
   * (`@cipherstash/protect-ffi-<platform>`) with a platform token Neon can
   * never emit, so the message says `Cannot find module
   * '@cipherstash/protect-ffi-…'` exactly as a real missing binding does.
   *
   * A synthetic name, rather than the real platform package required from some
   * directory with no `node_modules` above it — which is the obvious way to
   * make an installed package unresolvable and does not work here. pnpm's bin
   * shims export `NODE_PATH` covering `node_modules/.pnpm/node_modules`, the
   * flat store holding every installed package, and Node appends `NODE_PATH`
   * to the lookup paths for EVERY bare specifier regardless of where the
   * requiring module sits. Under `pnpm run test:unit`
   * `require('@cipherstash/protect-ffi-darwin-arm64')` therefore succeeds from
   * the filesystem root, and the fixture would quietly load the very binary it
   * is meant to be missing. A name that exists nowhere cannot be rescued by a
   * lookup path, so this holds under pnpm, under a bare `vitest`, and in CI.
   */
  const MISSING_PLATFORM_PACKAGE = '@cipherstash/protect-ffi-no-such-platform'

  /**
   * The real emitted entry, re-required with `loaderExports` standing in for
   * `./load.cjs`.
   *
   * The swap is a `require.cache` entry rather than a `Module._resolveFilename`
   * patch, which is the reflex and does nothing on its own here. `Module._load`
   * keys a relative-resolve fast path on (parent directory, request), and on a
   * hit it returns the cached module without consulting `_resolveFilename` at
   * all — so with `./load.cjs` still cached, as it is once anything in this file
   * has touched the entry, a redirect installed on the resolver is simply never
   * asked. Verified on Node 22.23.1 by counting calls. The cache therefore has
   * to be cleared regardless, and once it is, priming it is the whole job:
   * patching the resolver too would buy an undocumented internal and a
   * checked-in fixture file for nothing.
   *
   * Both cache entries are put back on the way out. The tests above hold a
   * direct reference to the original exports and so are unaffected either way,
   * but a suite that leaves a deliberately broken module cached is a trap for
   * whatever gets added to this file next.
   */
  function requireEntryWithLoader(loaderExports: unknown): Entry {
    const { cache } = requireFromEntry
    const cachedEntry = cache[entryPath]
    const cachedLoader = cache[loadPath]

    const stub = new Module(loadPath)
    stub.filename = loadPath
    stub.exports = loaderExports
    // Node treats a cached module that is not `loaded` as mid-circular-require
    // and hands back its half-built exports instead of these.
    stub.loaded = true

    delete cache[entryPath]
    cache[loadPath] = stub
    try {
      return requireFromEntry(entryPath)
    } finally {
      delete cache[entryPath]
      if (cachedEntry !== undefined) cache[entryPath] = cachedEntry
      if (cachedLoader === undefined) delete cache[loadPath]
      else cache[loadPath] = cachedLoader
    }
  }

  type MissingBinaryOutcome = {
    /** What the platform loader's `require` raised, taken at the throw site. */
    raised: unknown
    /** What `assertNativeBindingAvailable` let out, if anything. */
    caught: unknown
    /** Separates "did not throw" from "threw something falsy". */
    threw: boolean
  }

  function callWithNoBinaryInstalled(): MissingBinaryOutcome {
    let raised: unknown

    const entry = requireEntryWithLoader(
      neon.proxy({
        // Keyed by the CURRENT platform deliberately — see the block comment:
        // a table without this key fails eagerly inside `proxy()` and never
        // reaches the function under test.
        platforms: {
          [neon.currentPlatform()]: () => {
            try {
              // Resolved from the same base the shipped loader resolves from,
              // `lib/`, so nothing about the lookup differs from production
              // except that this name has no package behind it.
              return requireFromEntry(MISSING_PLATFORM_PACKAGE)
            } catch (error) {
              // Captured here because it cannot be recovered afterwards:
              // `load()` leaves its memo null when the loader throws, so a
              // second property access re-runs the `require` and produces a
              // DIFFERENT Error object — which would make the identity check
              // below fail against a correct implementation.
              raised = error
              throw error
            }
          },
        },
        // The shipped loader declares a debug arm too — `() =>
        // require('../index.node')`, a local cargo build — and
        // `@neon-rs/load` swallows whatever it raises before falling through
        // to the platform entry. Reproduced so the fixture takes the same
        // route a real missing binding takes, and spelled as a throw rather
        // than that require because a contributor who has run `pnpm run debug`
        // does have `index.node` beside `lib/`, and the fixture has to reach
        // the platform arm on their machine as well as on a published install.
        debug: () => {
          throw new Error('no local debug build, as in a published install')
        },
      }),
    )

    try {
      entry.assertNativeBindingAvailable()
      return { raised, caught: undefined, threw: false }
    } catch (error) {
      return { raised, caught: error, threw: true }
    }
  }

  it('fails the way a real missing binding fails', () => {
    // Pins the fixture, not the function. The two tests below say "whatever the
    // loader raised came out intact", which is satisfied by any thrown object —
    // so without this one, a fixture that drifted into throwing a hand-built
    // error would keep the suite green while testing nothing about Node's
    // resolver or about the message a caller classifies on.
    const { raised } = callWithNoBinaryInstalled()

    expect(raised).toBeInstanceOf(Error)
    const error = raised as NodeJS.ErrnoException
    expect(error.code).toBe('MODULE_NOT_FOUND')
    expect(error.message).toContain(MISSING_PLATFORM_PACKAGE)

    // And that the shipped loader would fail in the same shape: a bare scoped
    // specifier for the current platform, so its message differs from the one
    // just asserted only in the package name. Checked rather than claimed —
    // a loader that switched to requiring a path would still produce
    // `MODULE_NOT_FOUND`, but no longer the text this fixture stands in for.
    const shippedLoader = readFileSync(
      join(process.cwd(), 'lib/load.cjs'),
      'utf8',
    )
    expect(shippedLoader).toMatch(
      new RegExp(
        `'${neon.currentPlatform()}':\\s*\\(\\)\\s*=>\\s*require\\('@[\\w.-]+/[\\w.-]+'\\)`,
      ),
    )
  })

  it('does not swallow the loader failure', () => {
    const { raised, threw } = callWithNoBinaryInstalled()

    // `raised` first, and separately. An empty body or an early return reaches
    // neither the loader nor the throw, and `threw === false` on its own reads
    // identically to a `try`/`catch` that discards the error. Both are
    // regressions, and they have different repairs.
    expect(raised).toBeInstanceOf(Error)
    expect(threw).toBe(true)
  })

  it('propagates the loader failure unwrapped', () => {
    const { raised, caught } = callWithNoBinaryInstalled()

    // Object identity, not a message comparison, because the failure mode is
    // a wrapper that looks right: `new Error(msg, { cause })` preserves the
    // message, and `Object.assign(new Error(msg), { code })` preserves the
    // code as well. Identity is the only assertion that separates "the
    // loader's error reached the caller" from "something indistinguishable
    // from it did" — and it is what the doc comment's `code` and `message`
    // promises reduce to, since they are that object's own.
    expect(raised).toBeInstanceOf(Error)
    expect(caught).toBe(raised)

    // Identity does not preclude editing the error on the way past, and `code`
    // is the property a caller branches on.
    expect((caught as NodeJS.ErrnoException).code).toBe('MODULE_NOT_FOUND')
  })
})

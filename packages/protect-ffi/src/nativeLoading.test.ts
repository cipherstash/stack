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
 * A regression here is silent for anyone with a binary installed, which is
 * everyone who would notice — so load timing is asserted against the EMITTED
 * JavaScript rather than behaviour. `lib/` exists by the time this runs:
 * `test:typecheck` emits it before `test:unit`.
 *
 * The same blind spot is why the last block goes the other way and asserts
 * behaviour: what `assertNativeBindingAvailable` does with a MISSING binary
 * cannot be read off the emit, so that block substitutes a failing loader
 * under the emitted entry instead of substituting an installation.
 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import Module, { createRequire } from 'node:module'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Vitest resolves cwd to the directory holding vitest.config.ts.
const entryPath = join(process.cwd(), 'lib/index.cjs')

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

describe('assertNativeBindingAvailable', () => {
  const mod = requireFromEntry(entryPath)

  it('is exported from the package entry', () => {
    // `stash doctor` will consume this by name across a package boundary, so
    // its presence is the contract — see the doc comment on the function.
    expect(typeof mod.assertNativeBindingAvailable).toBe('function')
  })

  it('succeeds when the binding is present', () => {
    // The positive half only — this suite runs where a binary is installed.
    // The negative half (a `MODULE_NOT_FOUND` propagating unwrapped) is the
    // last describe block in this file, which reproduces a missing binary by
    // swapping the loader under this same emitted entry rather than by
    // needing an installation without one.
    expect(() => mod.assertNativeBindingAvailable()).not.toThrow()
  })

  it('reaches the loader rather than short-circuiting', () => {
    // The whole point is that it forces resolution, and a body that returned
    // early would pass both tests above while proving nothing. Asserting on
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
 * asserted that. The test above deferred it to a CLI missing-binary fixture
 * that does not exist, which left a promise about error handling verified by
 * prose alone.
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

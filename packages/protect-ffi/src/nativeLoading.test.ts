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
 * everyone who would notice — so the property is asserted against the EMITTED
 * JavaScript rather than behaviour. `lib/` exists by the time this runs:
 * `test:typecheck` emits it before `test:unit`.
 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
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
  // Loaded from the EMITTED entry, not the source. Vitest cannot parse `.cts`
  // ("content contains invalid JS syntax"), and the built artifact is what a
  // consumer resolves anyway.
  //
  // `createRequire` is seeded with the entry's own path rather than
  // `import.meta.url`: this tsconfig emits CommonJS and tsc rejects
  // `import.meta` outright with TS1470 (see the same note in
  // `lintWiring.test.ts`).
  const mod = createRequire(entryPath)(entryPath)

  it('is exported from the package entry', () => {
    // `stash doctor` will consume this by name across a package boundary, so
    // its presence is the contract — see the doc comment on the function.
    expect(typeof mod.assertNativeBindingAvailable).toBe('function')
  })

  it('succeeds when the binding is present', () => {
    // This suite runs where a binary is installed, so the negative case (a
    // `MODULE_NOT_FOUND` propagating unwrapped) belongs to the CLI's
    // missing-binary fixture rather than here.
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

import { existsSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * The edge entry's whole reason to exist is what it does NOT import (#708).
 *
 * `@cipherstash/stack-supabase/wasm-inline` is edge-capable only if its module
 * graph reaches neither the native engine nor the Postgres driver. Both are
 * import-time properties, not runtime ones: a static import of the native
 * entry evaluates the engine's whole graph — `@cipherstash/auth` included,
 * which resolves its platform binding right there — whether or not any
 * encryption runs, and a dynamic `import('pg')` is still a specifier a bundler
 * resolves at build time. Neither failure is visible from any test that merely
 * *calls* the API on Node, where both resolve fine.
 *
 * So this asserts on the emitted file. It is a build-output gate, and it skips
 * when `dist/` is absent so `pnpm test` stays green without a prior build —
 * the same shape as the adapter-kit edge-safety gate added in #799.
 */

const HERE = dirname(fileURLToPath(import.meta.url))
const DIST = resolve(HERE, '../dist')
const WASM_ENTRY = resolve(DIST, 'wasm-inline.js')
const NATIVE_ENTRY = resolve(DIST, 'index.js')

/** `@cipherstash/stack`'s own emitted root — the engine the native entry binds. */
const STACK_PACKAGE = resolve(HERE, '../../stack')
const STACK_ROOT_ENTRY = resolve(STACK_PACKAGE, 'dist/index.js')

/**
 * Strip comments before scanning.
 *
 * The source comments in this package discuss the very specifiers being
 * asserted against, so a raw substring scan would match prose and fail on a
 * perfectly good bundle. Only real code should be able to fail this test.
 */
function code(file: string): string {
  return readFileSync(file, 'utf-8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^\s*\/\/.*$/gm, ' ')
}

/** Every module specifier the file imports, static or dynamic. */
function specifiers(file: string): string[] {
  const body = code(file)
  const found = new Set<string>()
  for (const match of body.matchAll(/\bfrom\s*["']([^"']+)["']/g)) {
    found.add(match[1])
  }
  for (const match of body.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) {
    found.add(match[1])
  }
  return [...found].sort()
}

/**
 * Every bare specifier reachable from `entry` through its own relative chunks.
 *
 * tsup code-splits, so an entry's own file names only the chunks it happens to
 * start in; the packages it depends on are spread across them. Reading one file
 * answers "what does this module import", which is not the question — the
 * question is what the module GRAPH pulls in, because that is what evaluates.
 */
function reachableBareSpecifiers(entry: string): string[] {
  const seen = new Set<string>()
  const bare = new Set<string>()
  const walk = (file: string): void => {
    if (seen.has(file)) return
    seen.add(file)
    for (const specifier of specifiers(file)) {
      if (specifier.startsWith('.')) walk(resolve(dirname(file), specifier))
      else bare.add(specifier)
    }
  }
  walk(entry)
  return [...bare].sort()
}

const built = existsSync(WASM_ENTRY) && existsSync(NATIVE_ENTRY)
const describeBuilt = built ? describe : describe.skip

describeBuilt('the wasm-inline entry, as emitted', () => {
  it('imports neither the native engine nor anything that loads it', () => {
    const imported = specifiers(WASM_ENTRY)
    // The package root is what statically pulls `@cipherstash/protect-ffi`
    // AND `@cipherstash/auth` (both Node-API). Its native-free subpaths are
    // fine, so this must match the root exactly, not by prefix.
    expect(imported).not.toContain('@cipherstash/stack')
    expect(imported).not.toContain('@cipherstash/protect-ffi')
    expect(imported).not.toContain('@cipherstash/auth')
  })

  it('imports no Postgres driver, not even dynamically', () => {
    const imported = specifiers(WASM_ENTRY)
    expect(imported).not.toContain('pg')
    expect(imported).not.toContain('pg-cloudflare')
    expect(imported).not.toContain('postgres')
  })

  it('gets its engine from the wasm entry', () => {
    expect(specifiers(WASM_ENTRY)).toContain('@cipherstash/stack/wasm-inline')
  })

  /**
   * The positive control. Without it, a scan that silently matched nothing —
   * a renamed output file, a changed emit format — would pass every assertion
   * above while proving nothing at all.
   */
  it('can tell the two entries apart: the native one DOES import the root', () => {
    const nativeImports = specifiers(NATIVE_ENTRY)
    expect(nativeImports).toContain('@cipherstash/stack')
    expect(nativeImports.length).toBeGreaterThan(0)
    // And the native entry keeps the driver reachable, which is what makes
    // introspection its exclusive capability.
    expect(specifiers(NATIVE_ENTRY)).toContain('pg')
  })
})

/**
 * What makes the native entry Node-only, asserted rather than asserted-about.
 *
 * The three `not.toContain` lines above are guarded by a comment claiming the
 * package root "is what statically pulls `@cipherstash/protect-ffi` AND
 * `@cipherstash/auth` (both Node-API)". Nothing checked it. If
 * `@cipherstash/stack` ever stopped importing one of them, those assertions
 * would keep passing while proving nothing about it — the classic vacuous
 * negative, and this file's own positive control (which checks only
 * `@cipherstash/stack` and `pg`) did not reach far enough to catch it.
 *
 * It is also the executable grounding for the runtime claims in this package's
 * TSDoc and in `docs/reference/supabase-sdk.md`, which
 * `scripts/__tests__/supabase-runtime-claims.test.mjs` polices as prose. Two
 * things had been written down wrong there and both are settled here:
 *
 * - **Which package loads a binary at import.** Not `@cipherstash/protect-ffi`:
 *   `packages/protect-ffi/src/index.cts` writes `import native =
 *   require('./load.cjs')` specifically so `__importStar` cannot enumerate the
 *   `@neon-rs/load` proxy into resolving the platform binary, and
 *   `packages/protect-ffi/src/nativeLoading.test.ts` guards that. It is
 *   `@cipherstash/auth`, whose Node entry evaluates its loader at module scope.
 * - **That none of it depends on introspection.** These are import-time
 *   properties of the module graph. Declaring `schemas` skips introspection
 *   entirely and moves none of them.
 */
const stackBuilt = existsSync(STACK_ROOT_ENTRY)
const describeStackBuilt = stackBuilt ? describe : describe.skip

describeStackBuilt('the engine the native entry binds', () => {
  it('reaches both Node-API packages, which is what the wasm assertions deny', () => {
    const reachable = reachableBareSpecifiers(STACK_ROOT_ENTRY)
    expect(
      reachable,
      `${STACK_ROOT_ENTRY} no longer reaches @cipherstash/auth. The "imports neither the native engine nor anything that loads it" assertions above are then vacuous for that package, and the import-time-load claims in src/index.ts and docs/reference/supabase-sdk.md need rewriting.`,
    ).toContain('@cipherstash/auth')
    expect(reachable).toContain('@cipherstash/protect-ffi')
  })

  /**
   * The two Node-API packages load their binaries at opposite times, and the
   * prose in this package used to name the wrong one. The difference is one
   * structural property, readable in both loaders and asserted in both
   * directions here — a one-sided check would pass on a tree where they had
   * BOTH gone lazy, which is the case that makes the prose wrong.
   *
   * `@cipherstash/auth`: the platform `require` is reached from an expression
   * that runs at module scope, so `import '@cipherstash/auth'` dlopens.
   * `@cipherstash/protect-ffi`: every platform `require` is wrapped in an arrow
   * and handed to `@neon-rs/load`'s proxy, which resolves nothing until a
   * property is read.
   */
  const DEFERRED_REQUIRE = /=>\s*(?:\r?\n\s*)?require\(/

  it('gets its import-time native load from @cipherstash/auth, which defers nothing', () => {
    // Resolved the way Node resolves it from inside `@cipherstash/stack`, so
    // this reads the `node` condition's entry — the one an edge bundler would
    // NOT pick (both packages also publish a non-`node` WASM condition, which
    // is why "it loads a Node-API binary" is not unconditionally true at the
    // resolution layer either).
    const authEntry = createRequire(
      resolve(STACK_PACKAGE, 'package.json'),
    ).resolve('@cipherstash/auth')

    // One hop is enough: the entry requires its platform loader, and the
    // loader is where the call lives.
    const chain = [authEntry]
    for (const match of code(authEntry).matchAll(
      /\brequire\(\s*["'](\.[^"']+)["']\s*\)/g,
    )) {
      chain.push(resolve(dirname(authEntry), match[1]))
    }
    const bodies = chain
      .filter((file) => existsSync(file))
      .map((file) => code(file))

    // Name-independent on purpose: `module.exports = <anything>()` is the
    // property — exports that ARE the result of a call. A rename must not fail
    // this; a change of loading strategy must, because that is exactly when
    // the prose needs revisiting.
    expect(
      bodies.filter((body) =>
        /^\s*module\.exports\s*=\s*\w+\(\s*\)\s*;?\s*$/m.test(body),
      ),
      `No module in @cipherstash/auth's Node entry chain (${chain.join(', ')}) invokes its binding loader at module scope. If auth has gone lazy, nothing in this graph dlopens at import, and the runtime prose in src/index.ts, src/create.ts and docs/reference/supabase-sdk.md describes a failure mode that no longer exists.`,
    ).not.toHaveLength(0)

    expect(
      bodies.filter((body) => DEFERRED_REQUIRE.test(body)),
      "A module in @cipherstash/auth's Node entry chain now defers a require behind an arrow, which is protect-ffi's lazy shape. Re-check which package this package's TSDoc should be naming.",
    ).toHaveLength(0)
  })

  it('does not get it from protect-ffi, whose loader defers every platform require', () => {
    const ffi = resolve(HERE, '../../protect-ffi/src')

    // The source, not the emit: `lib/` is another package's build output and
    // may not exist when this suite runs.
    expect(
      readFileSync(resolve(ffi, 'load.cts'), 'utf-8'),
      'packages/protect-ffi/src/load.cts no longer wraps its platform requires in arrows. If protect-ffi now resolves a binary at module scope it becomes a second import-time load, and the correction this file grounds is only half right.',
    ).toMatch(DEFERRED_REQUIRE)

    expect(
      readFileSync(resolve(ffi, 'index.cts'), 'utf-8'),
      'packages/protect-ffi/src/index.cts no longer uses `import native = require(...)`. That form is the other half of why importing protect-ffi resolves no platform binary — `import * as` would emit `__importStar`, which enumerates the proxy and forces the load.',
    ).toMatch(/import\s+native\s*=\s*require\(/)

    // The guard that owns this property in full. Duplicating its assertions
    // here would be a second, weaker copy of it.
    expect(
      existsSync(resolve(ffi, 'nativeLoading.test.ts')),
      'packages/protect-ffi/src/nativeLoading.test.ts is gone. It is what holds protect-ffi to deferred loading; without it the two checks above are the only thing left, and they read source rather than emit.',
    ).toBe(true)
  })
})

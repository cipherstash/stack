import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * The edge entry's whole reason to exist is what it does NOT import (#708).
 *
 * `@cipherstash/stack-supabase/wasm-inline` is edge-capable only if its module
 * graph reaches neither the native engine nor the Postgres driver. Both are
 * import-time properties, not runtime ones: a static import of the native
 * entry loads `@cipherstash/protect-ffi` whether or not any encryption runs,
 * and a dynamic `import('pg')` is still a specifier a bundler resolves at
 * build time. Neither failure is visible from any test that merely *calls* the
 * API on Node, where both resolve fine.
 *
 * So this asserts on the emitted file. It is a build-output gate, and it skips
 * when `dist/` is absent so `pnpm test` stays green without a prior build —
 * the same shape as the adapter-kit edge-safety gate added in #799.
 */

const DIST = resolve(dirname(fileURLToPath(import.meta.url)), '../dist')
const WASM_ENTRY = resolve(DIST, 'wasm-inline.js')
const NATIVE_ENTRY = resolve(DIST, 'index.js')

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

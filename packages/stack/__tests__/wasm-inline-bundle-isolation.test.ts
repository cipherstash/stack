import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// `@cipherstash/stack/wasm-inline` exists for exactly one reason: runtimes
// where the native `@cipherstash/protect-ffi` NAPI binding is unavailable
// (Deno, Bun, Cloudflare Workers, Supabase Edge). A single value-import that
// transitively reaches the NATIVE package puts a bare
// `@cipherstash/protect-ffi` specifier into the bundle and breaks it there:
//
//   - Workers / Edge resolve the non-`node` condition to `dist/wasm/…`, which
//     exports no `ProtectError` → missing-named-export at build/link time, and
//     top-level-imports a raw `.wasm` asset (the loading mode this entry avoids).
//   - Deno's `node` condition resolves it to the NAPI loader — the native
//     dependency this entry avoids. `e2e/wasm/deno.json` maps only the
//     `/wasm-inline` subpaths, so it is unresolvable there at all.
//
// This is not hypothetical: importing `@/encryption/helpers/error-code` (a
// value-import of the native `ProtectError` class, for an `instanceof` narrow)
// did exactly this during #741 and was caught only in review. Unit tests can't
// see it — they mock the `/wasm-inline` subpath and run under Node, where the
// native root resolves fine — so the assertion has to be on the built artifact.
//
// Mirrors `packages/prisma-next/test/bundling-isolation.test.ts`.

const packageRoot = path.resolve(fileURLToPath(import.meta.url), '../..')
const distDir = path.join(packageRoot, 'dist')
const srcDir = path.join(packageRoot, 'src')

function newestMtime(dir: string): number {
  let newest = 0
  const stack = [dir]
  while (stack.length > 0) {
    const current = stack.pop()
    if (!current) continue
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) stack.push(full)
      else newest = Math.max(newest, statSync(full).mtimeMs)
    }
  }
  return newest
}

function distIsFresh(): boolean {
  if (!existsSync(distDir)) return false
  const tsupConfigMtime = statSync(
    path.join(packageRoot, 'tsup.config.ts'),
  ).mtimeMs
  const distMtime = newestMtime(distDir)
  return distMtime >= newestMtime(srcDir) && distMtime >= tsupConfigMtime
}

// Same freshness gate as `cjs-require.test.ts`: assert against the CURRENT
// source, never a stale artifact that would pass for the wrong reason.
if (!distIsFresh()) {
  execFileSync('pnpm', ['run', 'build'], {
    cwd: packageRoot,
    stdio: 'inherit',
  })
}

const bundle = readFileSync(path.join(distDir, 'wasm-inline.js'), 'utf-8')

/** Every module specifier the built bundle imports from. */
function importedSpecifiers(source: string): string[] {
  const found = new Set<string>()
  for (const m of source.matchAll(/\bfrom\s*["']([^"']+)["']/g)) {
    if (m[1]) found.add(m[1])
  }
  for (const m of source.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) {
    if (m[1]) found.add(m[1])
  }
  return [...found]
}

describe('dist/wasm-inline.js stays free of the native FFI', () => {
  it('imports the /wasm-inline subpath, never the native protect-ffi root', () => {
    const specifiers = importedSpecifiers(bundle)
    const protectFfi = specifiers.filter((s) =>
      s.startsWith('@cipherstash/protect-ffi'),
    )

    expect(
      protectFfi,
      'the WASM entry must reach protect-ffi only through /wasm-inline',
    ).toEqual(['@cipherstash/protect-ffi/wasm-inline'])
  })

  it('reaches @cipherstash/auth only through its /wasm-inline subpath too', () => {
    // Same failure mode, same reasoning — the auth package also ships a native
    // entry, and the WASM one is what this bundle is built against.
    const auth = importedSpecifiers(bundle).filter((s) =>
      s.startsWith('@cipherstash/auth'),
    )
    for (const specifier of auth) {
      expect(specifier, 'auth import must be the wasm-inline subpath').toMatch(
        /\/wasm-inline$/,
      )
    }
  })

  it('names every external it does import, so additions are a conscious change', () => {
    // A snapshot-style allowlist: anything new here is either intentional (add
    // it) or the kind of transitive native leak this file exists to catch.
    const externals = importedSpecifiers(bundle)
      .filter((s) => !s.startsWith('.') && !s.startsWith('/'))
      .sort()

    expect(externals).toEqual([
      '@cipherstash/auth/wasm-inline',
      '@cipherstash/protect-ffi/wasm-inline',
    ])
  })
})

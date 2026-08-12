import { execFileSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

// `@cipherstash/stack/diagnostics` exists so `stash doctor` can prove the
// protect-ffi native binding is installed. Three properties make it work, and
// each one is invisible to a normal unit test:
//
//   1. It must not reach `@cipherstash/auth`. The root entry does — it
//      re-exports the auth strategies — and that package's binding is EAGER
//      (`module.exports = { ...native }`). A probe that lands on auth reports
//      auth's binary under the encryption engine's label, which is the bug
//      this entry was added to fix. Bundling is where that regresses: the main
//      tsup config emits ESM with `splitting: true`, so a shared chunk is one
//      import away. Hence an assertion on the ARTIFACT, not on the source.
//
//   2. Importing it must NOT force the load, and calling it must. That is the
//      whole contract `doctor` classifies on, and it is a property of the
//      emitted code — esbuild's CJS interop enumerates the required module to
//      build its re-exports, and enumerating the wrong object is exactly what
//      made the load eager before `b99cbd92`.
//
//   3. The loader's error must arrive unwrapped, so `MODULE_NOT_FOUND` and the
//      platform package name survive for the CLI to key on.
//
// Mirrors `wasm-inline-bundle-isolation.test.ts`, which guards the same class
// of accident on the other native-free entry.

const packageRoot = path.resolve(__dirname, '..')
const distDir = path.join(packageRoot, 'dist')
const srcDir = path.join(packageRoot, 'src')

function newestMtime(dir: string): number {
  let newest = 0
  const stack: string[] = [dir]
  while (stack.length > 0) {
    const current = stack.pop() as string
    const stat = statSync(current)
    if (stat.isDirectory()) {
      for (const entry of readdirSync(current)) {
        stack.push(path.join(current, entry))
      }
    } else if (stat.mtimeMs > newest) {
      newest = stat.mtimeMs
    }
  }
  return newest
}

// Same freshness gate as `cjs-require.test.ts`: assert against the CURRENT
// source, never a stale artifact that would pass for the wrong reason.
function distIsFresh(): boolean {
  if (!existsSync(distDir)) return false
  const tsupConfigMtime = statSync(
    path.join(packageRoot, 'tsup.config.ts'),
  ).mtimeMs
  const distMtime = newestMtime(distDir)
  return distMtime >= newestMtime(srcDir) && distMtime >= tsupConfigMtime
}

if (!distIsFresh()) {
  execFileSync('pnpm', ['run', 'build'], {
    cwd: packageRoot,
    stdio: 'inherit',
  })
}

const ESM_BUNDLE = path.join(distDir, 'diagnostics.js')
const CJS_BUNDLE = path.join(distDir, 'diagnostics.cjs')

/** Every bare specifier the bundle imports or requires. */
function specifiersOf(bundlePath: string): string[] {
  const source = readFileSync(bundlePath, 'utf8')
  const found = new Set<string>()
  for (const [, spec] of source.matchAll(
    /(?:\brequire\(\s*|\bfrom\s*|\bimport\s*\(\s*)['"]([^'"]+)['"]/g,
  )) {
    if (spec) found.add(spec)
  }
  return [...found]
}

/**
 * A CJS preload that makes every shape of the protect-ffi binding
 * unresolvable — the platform packages and the local debug `index.node`, which
 * is what `src/load.cts` reaches for. Patching the resolver rather than moving
 * files keeps the checkout untouched and works whether or not the developer
 * has run `build:native`.
 *
 * Adapted from `packages/protect-ffi/src/lintWiring.test.ts`, which runs its
 * own suite under the same hook. `fs` is patched too: a loader that stats the
 * artifact before requiring it would otherwise see a file that `require` then
 * refuses to load.
 */
function hideBindingPreload(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'stack-diagnostics-'))
  const file = path.join(dir, 'hide-binding.cjs')
  writeFileSync(
    file,
    `
const fs = require('node:fs')
const Module = require('node:module')

const BINDING =
  /(?:^|[\\\\/])index\\.node$|@cipherstash[\\\\/]protect-ffi-(?:darwin|linux|win32)-/

const load = Module._load
Module._load = function (request, parent, isMain) {
  if (BINDING.test(request)) {
    const error = new Error("Cannot find module '" + request + "'")
    error.code = 'MODULE_NOT_FOUND'
    throw error
  }
  return load.call(this, request, parent, isMain)
}

const existsSync = fs.existsSync
fs.existsSync = (p) => (BINDING.test(String(p)) ? false : existsSync(p))

const statSync = fs.statSync
fs.statSync = (p, ...rest) => {
  if (!BINDING.test(String(p))) return statSync(p, ...rest)
  const error = new Error('ENOENT: no such file or directory, stat ' + p)
  error.code = 'ENOENT'
  throw error
}

Module.syncBuiltinESMExports()
`,
  )
  return file
}

/**
 * Runs `script` in a child process resolved from this package, optionally with
 * the binding hidden. A child rather than an in-process require: the point is
 * to go through Node's own resolution of `@cipherstash/stack/diagnostics`
 * against the published `exports` map, which Vitest's aliases would bypass.
 */
function runNode(
  script: string,
  { esm = false, hideBinding = false } = {},
): string {
  const args = esm ? ['--input-type=module', '-e', script] : ['-e', script]
  return execFileSync(process.execPath, args, {
    cwd: packageRoot,
    encoding: 'utf8',
    stdio: 'pipe',
    env: hideBinding
      ? {
          ...process.env,
          NODE_OPTIONS: [
            process.env.NODE_OPTIONS,
            `--require "${hideBindingPreload()}"`,
          ]
            .filter(Boolean)
            .join(' '),
        }
      : process.env,
  })
}

describe('@cipherstash/stack/diagnostics', () => {
  it('reaches protect-ffi and nothing else', () => {
    for (const bundle of [ESM_BUNDLE, CJS_BUNDLE]) {
      const specifiers = specifiersOf(bundle)
      expect(specifiers, path.basename(bundle)).toContain(
        '@cipherstash/protect-ffi',
      )
      // Not `.not.toContain('@cipherstash/auth')` — the failure mode is a
      // SHARED CHUNK that imports auth, whose own specifier is a relative
      // `./chunk-XXXX.js`. Anything beyond the one bare specifier is the
      // symptom, whatever its name.
      expect(specifiers, path.basename(bundle)).toEqual([
        '@cipherstash/protect-ffi',
      ])
    }
  })

  it('is importable from both module systems', () => {
    expect(
      runNode(
        `const d = require('@cipherstash/stack/diagnostics')
         if (typeof d.assertNativeBindingAvailable !== 'function') throw new Error('missing export')
         process.stdout.write('ok')`,
      ),
    ).toBe('ok')

    expect(
      runNode(
        `const d = await import('@cipherstash/stack/diagnostics')
         if (typeof d.assertNativeBindingAvailable !== 'function') throw new Error('missing export')
         process.stdout.write('ok')`,
        { esm: true },
      ),
    ).toBe('ok')
  })

  // The reason the entry exists. If importing it were enough, `doctor` would
  // not need this module at all — and if importing it FORCED the load, this
  // package would have re-broken the laziness that `b99cbd92` bought.
  it.each([
    ['require', false],
    ['import', true],
  ])('with no binding installed, %s succeeds and only the call throws', (_label, esm) => {
    const script = esm
      ? `const d = await import('@cipherstash/stack/diagnostics')
         let raised = 'none'
         try { d.assertNativeBindingAvailable() } catch (e) { raised = e.code + ' ' + e.message.split('\\n')[0] }
         process.stdout.write('imported ' + raised)`
      : `const d = require('@cipherstash/stack/diagnostics')
         let raised = 'none'
         try { d.assertNativeBindingAvailable() } catch (e) { raised = e.code + ' ' + e.message.split('\\n')[0] }
         process.stdout.write('imported ' + raised)`

    const output = runNode(script, { esm, hideBinding: true })

    // "imported" at all means the import did not throw — the property under
    // test. A child that died during import produces no stdout and fails the
    // execFileSync above.
    expect(output).toMatch(/^imported /)
    // Unwrapped: same `code` and the platform package by name, which is what
    // `packages/cli/src/native.ts` classifies on.
    expect(output).toContain('MODULE_NOT_FOUND')
    expect(output).toMatch(
      /Cannot find module '@cipherstash\/protect-ffi-(darwin|linux|win32)-/,
    )
  })
})

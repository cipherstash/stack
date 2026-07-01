import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

// Regression test for CJS consumers. `uuid` is pure ESM, so externalizing it
// in the CJS build causes downstream apps to crash at runtime with
// `ERR_REQUIRE_ESM: Must use import to load ES Module: .../uuid/dist-node/index.js`.
// This file proves the published CJS bundles (a) don't contain an
// unresolved `require("uuid")` and (b) can be loaded from a real Node CJS
// process. See packages/stack/tsup.config.ts (noExternal: ['uuid']).

const packageRoot = path.resolve(__dirname, '..')
const distDir = path.join(packageRoot, 'dist')
const srcDir = path.join(packageRoot, 'src')

// All `.cjs` files in dist/ that aren't tsup's internal shared chunks
// (chunk-XXXXXX.cjs). Discovered after build so the test automatically
// covers any new entry point added to tsup.config.ts.
function findCjsEntries(): string[] {
  const entries: string[] = []
  const stack: string[] = [distDir]
  while (stack.length > 0) {
    const current = stack.pop() as string
    for (const name of readdirSync(current)) {
      const full = path.join(current, name)
      const stat = statSync(full)
      if (stat.isDirectory()) {
        stack.push(full)
      } else if (
        name.endsWith('.cjs') &&
        !name.endsWith('.cjs.map') &&
        !/^chunk-[A-Z0-9]+\.cjs$/.test(name)
      ) {
        entries.push(path.relative(packageRoot, full))
      }
    }
  }
  return entries.sort()
}

// ESM-only packages we depend on. If any of these ever ends up as a runtime
// `require("...")` in the CJS bundle, downstream apps crash with
// ERR_REQUIRE_ESM. Add new ESM-only deps here as we adopt them.
const ESM_ONLY_DEPENDENCIES = ['uuid']

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

const cjsEntries = findCjsEntries()

describe('CJS consumers can require the built bundles', () => {
  it('discovers at least the public entry points', () => {
    expect(cjsEntries).toContain('dist/index.cjs')
    expect(cjsEntries).toContain('dist/encryption/index.cjs')
    expect(cjsEntries).toContain('dist/schema/v3/index.cjs')
  })

  it('exposes v3 schema builders from the CJS bundle', () => {
    const v3Bundle = path.join(distDir, 'schema', 'v3', 'index.cjs')
    const script = [
      `const v3 = require(${JSON.stringify(v3Bundle)})`,
      `const required = ['encryptedTextSearchColumn', 'encryptedInt4Column', 'encryptedBoolColumn', 'encryptedTimestamptzColumn']`,
      `const missing = required.filter((k) => typeof v3[k] !== 'function')`,
      `if (missing.length > 0) { throw new Error('missing v3 CJS exports: ' + missing.join(', ')) }`,
    ].join('\n')

    expect(() =>
      execFileSync(process.execPath, ['-e', script], {
        cwd: packageRoot,
        stdio: 'pipe',
      }),
    ).not.toThrow()
  })

  it.each(
    cjsEntries,
  )('dist bundle does not externalize an ESM-only module: %s', (entry) => {
    const bundlePath = path.join(packageRoot, entry)
    const source = readFileSync(bundlePath, 'utf8')

    // Match `require("foo")` or `require('foo')` where `foo` is a bare
    // specifier (not a relative path or `node:` builtin) — those are the
    // cases that hit Node's CJS module resolver at runtime.
    const requireRegex = /\brequire\(\s*['"]([^'".\\/][^'"]*)['"]\s*\)/g
    const externalized = new Set<string>()
    for (const match of source.matchAll(requireRegex)) {
      externalized.add(match[1])
    }

    for (const dep of ESM_ONLY_DEPENDENCIES) {
      expect(
        externalized.has(dep),
        `${entry} externalizes "${dep}" via require(), which is ESM-only and will crash CJS consumers with ERR_REQUIRE_ESM. Add it to noExternal in packages/stack/tsup.config.ts.`,
      ).toBe(false)
    }
  })

  it.each(
    cjsEntries,
  )('CJS bundle loads in a real Node CJS process: %s', (entry) => {
    const bundlePath = path.join(packageRoot, entry)
    // Spawn a fresh Node process so this is a true CJS load — vitest's
    // own module graph and any test-time aliasing don't apply.
    // `--no-experimental-require-module` forces the legacy CJS-cannot-
    // require-ESM behavior, reproducing the exact ERR_REQUIRE_ESM that
    // downstream apps hit in production runtimes that don't enable
    // require(esm) (Node <22.12, Bun, Deno-as-Node, locked-down CI).
    try {
      execFileSync(
        process.execPath,
        [
          '--no-experimental-require-module',
          '-e',
          `require(${JSON.stringify(bundlePath)})`,
        ],
        {
          cwd: packageRoot,
          stdio: 'pipe',
          encoding: 'utf8',
        },
      )
    } catch (err) {
      const e = err as NodeJS.ErrnoException & {
        stderr?: string
        stdout?: string
      }
      throw new Error(
        `require("${entry}") failed in a Node CJS process:\n` +
          `${e.stderr ?? ''}\n${e.stdout ?? ''}`,
      )
    }
  })
})

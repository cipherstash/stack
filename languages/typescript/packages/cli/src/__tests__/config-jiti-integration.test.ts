import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * Integration test for `loadStashConfig` against the *real* jiti runtime.
 *
 * The companion file `config.test.ts` mocks the `jiti` module entirely,
 * which is fast but can't catch wrapper/unwrap regressions in how the
 * default export is returned. This file deliberately does NOT mock jiti —
 * it writes a real `stash.config.ts` into a temp dir and asserts that
 * `loadStashConfig` returns the inner config rather than the module
 * namespace. Regression net for #374: in jiti 2.x the constructor's
 * `interopDefault: true` does not apply to `.import()`, so the per-call
 * `{ default: true }` option is required.
 */

describe('loadStashConfig — real jiti', () => {
  let tmpDir: string
  let originalCwd: () => string
  let originalEnv: string | undefined

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-config-real-jiti-'))
    originalCwd = process.cwd
    originalEnv = process.env.STASH_TEST_DATABASE_URL
  })

  afterEach(() => {
    process.cwd = originalCwd
    if (originalEnv === undefined) {
      // biome-ignore lint/performance/noDelete: process.env.X = undefined coerces to the string "undefined" in Node, not an unset.
      delete process.env.STASH_TEST_DATABASE_URL
    } else {
      process.env.STASH_TEST_DATABASE_URL = originalEnv
    }

    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('unwraps `export default {...}` to the inner config (#374 regression)', async () => {
    // Test-namespaced env var, not `DATABASE_URL`, to avoid clobbering a
    // value a developer may have set in their shell or `.env`. The bug is
    // about jiti's default-export wrapping, not env-var resolution — the
    // `process.env.X` reference inside the config is just an arbitrary
    // expression demonstrating that the file body actually evaluated.
    process.env.STASH_TEST_DATABASE_URL =
      'postgresql://postgres:postgres@127.0.0.1:54322/postgres'
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      `export default {
         databaseUrl: process.env.STASH_TEST_DATABASE_URL,
         client: './src/encryption/index.ts',
       }`,
    )
    process.cwd = () => tmpDir

    const { loadStashConfig } = await import('@/config/index.ts')
    const config = await loadStashConfig()

    expect(config).toEqual({
      databaseUrl: 'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
      client: './src/encryption/index.ts',
    })
  })

  it('reports a useful error when databaseUrl is genuinely missing', async () => {
    // biome-ignore lint/performance/noDelete: see afterEach above; need an actual unset.
    delete process.env.STASH_TEST_DATABASE_URL
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      `export default {
         databaseUrl: process.env.STASH_TEST_DATABASE_URL,
       }`,
    )
    process.cwd = () => tmpDir

    const errSpy = vi
      .spyOn(console, 'error')
      .mockImplementation(() => undefined)
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    const { loadStashConfig } = await import('@/config/index.ts')
    await expect(loadStashConfig()).rejects.toThrow('process.exit')

    const allCalls = errSpy.mock.calls.flat().join('\n')
    expect(allCalls).toContain('Invalid stash.config.ts')
    expect(allCalls).toContain('databaseUrl')
  })
})

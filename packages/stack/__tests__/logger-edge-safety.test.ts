/**
 * `@cipherstash/stack/adapter-kit` re-exports this package's `logger`
 * (`src/adapter-kit.ts:60`), and three first-party adapters value-import
 * adapter-kit: `packages/stack-supabase/src/column-map.ts:1`,
 * `packages/stack-drizzle/src/column.ts:1`,
 * `packages/stack-prisma/src/exports/column-types.ts:19`. A realm with no
 * `process` binding turns an unguarded module-scope `process.env` read in the
 * logger into a `ReferenceError` at import time on exactly the runtimes those
 * builds exist to serve.
 *
 * This asserts the fix rather than a proxy for it: delete the `typeof process`
 * guard from `src/utils/logger/index.ts`, rebuild, and this test fails.
 *
 * It reads `dist/`, so it SKIPS when the package has not been built — run
 * `pnpm --filter @cipherstash/stack build` first for it to mean anything.
 * (`turbo.json` wires `test` to `build`, so the turbo path cannot skip it; a
 * bare `pnpm --filter … test` on a clean checkout still can.) The
 * portable-entry plan will point the same harness at the WASM entry.
 */
import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

const execFileAsync = promisify(execFile)
const testsDir = fileURLToPath(new URL('.', import.meta.url))
const harness = resolve(testsDir, 'helpers/process-free-realm.mjs')
const emittedEntry = resolve(testsDir, '../dist/adapter-kit.js')

describe.skipIf(!existsSync(emittedEntry))(
  'the emitted adapter-kit seam imports without a process global',
  () => {
    it('evaluates dist/adapter-kit.js in a process-free realm', async () => {
      // Rejects on a non-zero exit, so the harness's own failure line
      // (`ReferenceError: process is not defined`) surfaces as the assertion
      // failure.
      const { stdout } = await execFileAsync(process.execPath, [
        '--experimental-vm-modules',
        harness,
        emittedEntry,
      ])

      expect(stdout.trim()).toMatch(/^OK \d+ exports$/)
    }, 30_000)
  },
)

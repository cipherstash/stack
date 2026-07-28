/**
 * `@cipherstash/stack/wasm-inline` must IMPORT cleanly in a realm with no
 * `process` — a Cloudflare Worker without `nodejs_compat`, a browser, a Deno
 * isolate. That is the entire reason the entry exists, and it is the one
 * property none of the other checks can see:
 *
 * - `wasm-inline-bundle-isolation.test.ts` reads import SPECIFIERS, so a
 *   missing global is invisible to it.
 * - The Deno e2e (`e2e/wasm/`) runs under Deno, which PROVIDES `process`.
 * - The unit suites run under Node, likewise.
 *
 * The gap is not hypothetical. #798 stage 4 was written, passed 1073 unit
 * tests, the type tests and the bundle-isolation test, and was reverted only
 * after a manual check found the entry threw `ReferenceError: process is not
 * defined` on import: it had begun importing `@/utils/logger`, whose
 * `initStackLogger()` read `process.env` at module scope. Every automated gate
 * was green while the entry was unusable in the runtimes it targets.
 *
 * This closes that gap, using the same harness `logger-edge-safety.test.ts`
 * points at `dist/adapter-kit.js` — its docblock anticipated this ("the
 * portable-entry plan will point the same harness at the WASM entry"). It is a
 * precondition for retrying stage 4, not a consequence of it: the shared
 * operation layer pulls a wider transitive graph into this entry, and
 * ANYTHING that graph reaches ships to the edge.
 *
 * This asserts the property rather than a proxy for it: add an unguarded
 * module-scope `process.env` read anywhere reachable from `src/wasm-inline.ts`,
 * rebuild, and this fails with the ReferenceError above (verified by doing
 * exactly that).
 *
 * It reads `dist/`, so it SKIPS when the package has not been built — run
 * `pnpm --filter @cipherstash/stack build` first for it to mean anything.
 * (`turbo.json` wires `test` to `build`, so the turbo path cannot skip it; a
 * bare `pnpm --filter … test` on a clean checkout still can.)
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
const emittedEntry = resolve(testsDir, '../dist/wasm-inline.js')

/**
 * The externals this entry legitimately expects the host to resolve — Deno and
 * Workers supply both through an import map, and `e2e/wasm/deno.json` maps
 * exactly these. The harness STUBS them rather than loading them: the question
 * here is whether the graph evaluates without `process`, and pulling in the
 * real WASM binding would add a megabyte of unrelated behaviour and its own
 * global requirements for no extra signal.
 *
 * Keep this list identical to the allowlist in
 * `wasm-inline-bundle-isolation.test.ts`. Anything else in the bundle is
 * rejected by the harness, so a new external fails here too — deliberately,
 * since a new bare specifier on this entry is exactly the native-leak class
 * that test exists to catch.
 */
const ALLOWED_EXTERNALS = [
  '@cipherstash/protect-ffi/wasm-inline',
  '@cipherstash/auth/wasm-inline',
]

describe.skipIf(!existsSync(emittedEntry))(
  'the emitted WASM entry imports without a process global',
  () => {
    it('evaluates dist/wasm-inline.js in a process-free realm', async () => {
      // Rejects on a non-zero exit, so the harness's own failure line
      // (`ReferenceError: process is not defined`) surfaces as the assertion
      // failure rather than an opaque exit code.
      const { stdout } = await execFileAsync(process.execPath, [
        '--experimental-vm-modules',
        harness,
        emittedEntry,
        ...ALLOWED_EXTERNALS,
      ])

      expect(stdout.trim()).toMatch(/^OK \d+ exports$/)
    }, 30_000)
  },
)

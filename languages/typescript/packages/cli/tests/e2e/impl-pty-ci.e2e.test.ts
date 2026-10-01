import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { render } from '../helpers/pty.js'

/**
 * E2E: the real-hang reproducer. Under a genuine PTY (`process.stdin.isTTY`
 * is true) with `CI` set to a non-`'true'` spelling, the pre-fix inline
 * `CI !== 'true'` gate treated the run as interactive and blocked on the
 * plan-summary confirm forever — a hang, not an error.
 *
 * The unit suites mock `@clack/prompts` and assert the gate's boolean; only a
 * real PTY proves the process terminates. `pty.ts` `render()` defaults
 * `env.CI` to `'true'`, which is exactly why that regression never surfaced
 * here before — overriding to `1` / `TRUE` is the precise reproducer.
 * `impl-non-tty.e2e.test.ts` uses `runPiped`, which gives `isTTY === false`
 * by construction and cannot reach this path.
 */
describe('stash impl — PTY + CI (real-hang reproducer)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-impl-pty-ci-e2e-'))
    fs.mkdirSync(path.join(tmpDir, '.cipherstash'))
    fs.writeFileSync(
      path.join(tmpDir, '.cipherstash', 'context.json'),
      JSON.stringify({
        integration: 'postgresql',
        packageManager: 'npm',
        schemas: [],
      }),
    )
    // A plan on disk is what makes the pre-fix code reach the plan-summary
    // confirm (the prompt that hung); without one it exits earlier.
    fs.writeFileSync(path.join(tmpDir, '.cipherstash', 'plan.md'), '# Plan')
  })

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  for (const ciValue of ['1', 'TRUE']) {
    it(`exits instead of hanging under a PTY with CI=${ciValue}`, async () => {
      const r = render(['impl'], { cwd: tmpDir, env: { CI: ciValue } })
      // A regression re-opens the hang; the kill is the backstop so the suite
      // fails on timeout instead of blocking. The fix exits in ~100ms.
      const timer = setTimeout(() => r.kill('SIGKILL'), 10_000)
      const { exitCode } = await r.exit
      clearTimeout(timer)

      expect(exitCode).toBe(0)
      expect(r.output).not.toContain('Proceed with implementation')
    })
  }
})

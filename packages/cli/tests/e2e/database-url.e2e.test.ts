import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

/**
 * E2E coverage for the layered DATABASE_URL resolver. Each case spawns the
 * built `dist/bin/stash.js` and exercises a single resolution path —
 * `--database-url` flag, env, and the CI-guard fail-fast.
 *
 * The pty harness always provides a TTY, so the non-TTY path is covered by
 * the unit suite's `Object.defineProperty(process.stdin, 'isTTY', false)`
 * test in `src/__tests__/database-url.test.ts`.
 */
describe('db test-connection — DATABASE_URL resolver', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-db-url-e2e-'))
    // A scaffold-shaped config that defers to env. The resolver populates
    // env in-process before loadStashConfig runs.
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      `export default {
         databaseUrl: process.env.DATABASE_URL,
       }`,
    )
  })

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('uses --database-url flag and surfaces the source label', async () => {
    // Bogus host:port — connection will fail after the resolver succeeds.
    // The test asserts on the log line + non-zero exit, NOT on the specific
    // connection error (avoids flake if the port happens to be in use).
    const r = render(
      [
        'db',
        'test-connection',
        '--database-url',
        'postgresql://x:x@127.0.0.1:1/x',
      ],
      { cwd: tmpDir, env: { CI: 'false', DATABASE_URL: '' } },
    )

    await r.waitFor(messages.db.urlResolvedFromFlag, 10_000)
    const { exitCode } = await r.exit
    expect(exitCode).not.toBe(0)
    expect(r.output).toContain(messages.db.urlResolvedFromFlag)
  })

  it('CI=true with no DATABASE_URL and no flag exits 1 with the CI message', async () => {
    const r = render(['db', 'test-connection'], {
      cwd: tmpDir,
      env: { CI: 'true', DATABASE_URL: '' },
    })

    const { exitCode } = await r.exit
    expect(exitCode).toBe(1)
    expect(r.output).toContain(messages.db.urlMissingCi)
  })
})

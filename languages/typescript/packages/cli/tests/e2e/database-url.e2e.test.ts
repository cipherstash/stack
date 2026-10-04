import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// Absolute path to the built CLI's `dist/index.js`. The test config imports
// from this path because the tmp dir doesn't have a node_modules with
// `stash` symlinked. Real users get a clean
// `import { resolveDatabaseUrl } from 'stash'`.
const CLI_DIST_INDEX = path.resolve(__dirname, '../../dist/index.js')

describe('db test-connection — DATABASE_URL resolver', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-db-url-e2e-'))
    // Config calls resolveDatabaseUrl() at evaluation time. The CLI's
    // loadStashConfig wraps the jiti-import in withResolverContext so the
    // function picks up `--database-url` / `--supabase` flags.
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      `import { resolveDatabaseUrl } from '${CLI_DIST_INDEX}'
       export default {
         databaseUrl: await resolveDatabaseUrl(),
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
    // The test asserts on the log line + non-zero exit, NOT on the
    // specific connection error (avoids flake if the port is in use).
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
    // Belt-and-braces: the URL itself must never appear except where the
    // user typed it (here, on argv — but the spawned process's logs
    // shouldn't echo it back).
    expect(r.output).not.toContain('postgresql://x:x@127.0.0.1:1/x')
    // Connection failed → the failure hint should point users at the
    // sources they can actually fix (flag / env / dotenv file). The tmp
    // dir has no dotenv files so the hint defaults to `.env`. The OLD
    // misleading "Check your databaseUrl in stash.config.ts" message
    // must NOT appear — the URL doesn't live in that file anymore.
    expect(r.output).toContain(messages.db.urlConnectionFailedHint('.env'))
    expect(r.output).not.toContain('stash.config.ts or .env file')
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

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { run } from '../helpers/run.js'

/**
 * E2E coverage for the config-scaffold DX fixes (#578, #579). These run the
 * built CLI in a throwaway temp project OUTSIDE the monorepo, so `stash` /
 * `@cipherstash/stack` genuinely don't resolve from `node_modules` — the exact
 * condition that produced the raw `Cannot find module 'stash'` crash.
 */
describe('config-scaffold DX (missing config / missing deps)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-config-e2e-'))
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'bare', version: '1.0.0' }),
    )
  })

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('a read command with no config points at `init` / `eql install` (#578)', async () => {
    // `eql status` loads the encryption client, so it genuinely needs a config.
    const r = await run(['eql', 'status'], { cwd: tmpDir })
    expect(r.output).toContain('Could not find stash.config.ts')
    expect(r.output).toContain('stash init')
    expect(r.output).toContain('stash eql install')
  })

  it('`eql install` does not require a config — it resolves the URL directly (#579)', async () => {
    // With no config and no database URL, install must NOT scaffold a config and
    // then crash on `Cannot find module 'stash'`. It resolves the URL first and
    // fails cleanly asking for one; no stash.config.ts is written.
    const r = await run(['eql', 'install'], { cwd: tmpDir })

    expect(r.output).toContain('Cannot resolve DATABASE_URL')
    expect(r.output).toContain('--database-url')
    expect(r.output).not.toContain('Cannot find module')
    expect(r.output).not.toContain('MODULE_NOT_FOUND')
    expect(fs.existsSync(path.join(tmpDir, 'stash.config.ts'))).toBe(false)
    expect(r.exitCode).toBe(1)
  })

  // The `loadStashConfig` catch that translates a missing-module error into
  // guidance (the path for a project that HAS a config but lacks the CLI
  // packages) is covered by unit tests in src/__tests__/config.test.ts with a
  // mocked jiti rejection. It can't be reproduced end-to-end here: inside the
  // monorepo jiti resolves `stash` via the workspace self-reference even from a
  // temp dir, so the import never fails — which is exactly why the original bug
  // escaped the test suite.
})

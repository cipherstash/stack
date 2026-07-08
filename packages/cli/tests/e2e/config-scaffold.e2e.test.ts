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
    const r = await run(['eql', 'status'], { cwd: tmpDir })
    expect(r.output).toContain('Could not find stash.config.ts')
    expect(r.output).toContain('stash init')
    expect(r.output).toContain('stash eql install')
  })

  it('`eql install` with a config but missing deps guides instead of crashing (#579)', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      "import { defineConfig, resolveDatabaseUrl } from 'stash'\n" +
        'export default defineConfig({ databaseUrl: await resolveDatabaseUrl() })\n',
    )

    const r = await run(['eql', 'install'], { cwd: tmpDir })
    // Actionable guidance, not a raw module-resolution stack trace.
    expect(r.output).toContain('not installed')
    expect(r.output).toContain('stash init')
    expect(r.output).not.toContain('MODULE_NOT_FOUND')
    expect(r.output).not.toContain('Cannot find module')
    expect(r.exitCode).toBe(1)
  })

  // The `loadStashConfig` catch that translates a missing-module error into
  // guidance (the read-command path for #579) is covered by unit tests in
  // src/__tests__/config.test.ts with a mocked jiti rejection. It can't be
  // reproduced end-to-end here: inside the monorepo jiti resolves `stash` via
  // the workspace self-reference even from a temp dir, so the import never
  // fails — which is exactly why the original bug escaped the test suite.
})

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
    // Clear DATABASE_URL explicitly so a value in the parent env can't leak in
    // and resolve past the guidance we're asserting on.
    const r = await run(['eql', 'install'], {
      cwd: tmpDir,
      env: { DATABASE_URL: '' },
    })

    expect(r.output).toContain('Cannot resolve DATABASE_URL')
    expect(r.output).toContain('--database-url')
    expect(r.output).not.toContain('Cannot find module')
    expect(r.output).not.toContain('MODULE_NOT_FOUND')
    expect(fs.existsSync(path.join(tmpDir, 'stash.config.ts'))).toBe(false)
    expect(r.exitCode).toBe(1)
  })

  it('`eql install --database-url` is one-shot — it never scaffolds project files', async () => {
    // An explicit --database-url means "install EQL against this DB now"; it
    // must not drop a stash.config.ts or an encryption client into the project.
    // The bogus URL fails fast at connect (past the config stage), which is all
    // we need to observe the no-scaffold behaviour.
    const r = await run(
      [
        'eql',
        'install',
        '--database-url',
        'postgres://u:p@127.0.0.1:1/db?connect_timeout=2',
      ],
      { cwd: tmpDir },
    )

    expect(fs.existsSync(path.join(tmpDir, 'stash.config.ts'))).toBe(false)
    expect(
      fs.existsSync(path.join(tmpDir, 'src', 'encryption', 'index.ts')),
    ).toBe(false)
    expect(r.output).not.toContain('Created stash.config.ts')
    expect(r.output).not.toContain('Cannot find module')
  })

  it('`eql install --database-url` leaves an existing config untouched — no client scaffolded', async () => {
    // One-shot install with an EXISTING stash.config.ts pointing at a
    // not-yet-created client. The config branch must be bypassed entirely: no
    // client file is written, and the `stash` import in the config never runs
    // (so no `Cannot find module` in this bare project). The bogus URL fails
    // fast at connect, past the config/scaffold stage.
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      "import { defineConfig, resolveDatabaseUrl } from 'stash'\n" +
        "export default defineConfig({ databaseUrl: await resolveDatabaseUrl(), client: './src/encryption/index.ts' })\n",
    )

    const r = await run(
      [
        'eql',
        'install',
        '--database-url',
        'postgres://u:p@127.0.0.1:1/db?connect_timeout=2',
      ],
      { cwd: tmpDir },
    )

    expect(
      fs.existsSync(path.join(tmpDir, 'src', 'encryption', 'index.ts')),
    ).toBe(false)
    expect(r.output).not.toContain('Created stash.config.ts')
    expect(r.output).not.toContain('Cannot find module')
  })

  it('non-interactive `eql install` (URL from env) writes no config or client (#2, #4)', async () => {
    // No --database-url flag but DATABASE_URL in the env: offer mode, but a
    // non-TTY run can't prompt. It must NOT silently scaffold a config (which
    // imports `stash`) or a client (which imports `@cipherstash/stack`) into a
    // bare project. offerStashConfig returns null and the client scaffold is
    // skipped; the bogus URL then fails fast at connect.
    const r = await run(['eql', 'install'], {
      cwd: tmpDir,
      env: { DATABASE_URL: 'postgres://u:p@127.0.0.1:1/db?connect_timeout=2' },
    })

    expect(fs.existsSync(path.join(tmpDir, 'stash.config.ts'))).toBe(false)
    expect(
      fs.existsSync(path.join(tmpDir, 'src', 'encryption', 'index.ts')),
    ).toBe(false)
    expect(r.output).not.toContain('Created stash.config.ts')
    expect(r.output).not.toContain('Cannot find module')
  })

  it('`eql install --dry-run` writes no files, even with an existing config', async () => {
    // Dry run must not mutate the project. With an existing config pointing at a
    // not-yet-created client, the client scaffold used to run before the dry-run
    // guard — so assert the client file is NOT written.
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      "import { defineConfig, resolveDatabaseUrl } from 'stash'\n" +
        "export default defineConfig({ databaseUrl: await resolveDatabaseUrl(), client: './src/encryption/index.ts' })\n",
    )

    const r = await run(
      [
        'eql',
        'install',
        '--dry-run',
        '--database-url',
        'postgres://u:p@127.0.0.1:1/db?connect_timeout=2',
      ],
      { cwd: tmpDir },
    )

    expect(r.output).toContain('Dry run')
    expect(
      fs.existsSync(path.join(tmpDir, 'src', 'encryption', 'index.ts')),
    ).toBe(false)
    expect(r.exitCode).toBe(0)
  })

  // The `loadStashConfig` catch that translates a missing-module error into
  // guidance (the path for a project that HAS a config but lacks the CLI
  // packages) is covered by unit tests in src/__tests__/config.test.ts with a
  // mocked jiti rejection. It can't be reproduced end-to-end here: inside the
  // monorepo jiti resolves `stash` via the workspace self-reference even from a
  // temp dir, so the import never fails — which is exactly why the original bug
  // escaped the test suite.
})

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { HANDOFF_CHOICES } from '../../src/commands/impl/steps/how-to-proceed.js'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * E2E coverage for the BUGS.md reproducer: `bunx stash impl < /dev/null`
 * used to hang forever on the agent-target picker (clack `select` reads
 * from `/dev/tty`). The fix short-circuits with a hint when there's no
 * TTY and no `--target`, and accepts `--target <name>` as the
 * non-interactive escape hatch.
 *
 * These tests spawn the built CLI through `runPiped` (not the PTY
 * `render`) so the child actually sees `process.stdout.isTTY === false`,
 * which is the precondition that triggered the original hang.
 */
describe('stash impl — non-TTY safety (BUGS.md reproducer)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-impl-non-tty-e2e-'))
    fs.mkdirSync(path.join(tmpDir, '.cipherstash'))
    fs.writeFileSync(
      path.join(tmpDir, '.cipherstash', 'context.json'),
      JSON.stringify({
        integration: 'postgresql',
        packageManager: 'npm',
        schemas: [],
      }),
    )
    // A plan file is required to reach the agent-target picker — without
    // one, impl exits earlier on the "no plan + non-TTY" guard. The
    // BUGS.md repro had a plan on disk, which is how the bug surfaced.
    fs.writeFileSync(path.join(tmpDir, '.cipherstash', 'plan.md'), '# Plan')
  })

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('exits 0 with a hint instead of hanging on the agent-target picker', async () => {
    // 5s is well over the time the fix needs (≈100ms in practice) and
    // well under what would happen on a regression (the original bug
    // hung indefinitely).
    const r = await runPiped(['impl'], { cwd: tmpDir, timeoutMs: 5_000 })

    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('No agent selected')
    expect(r.stdout).toContain('--target')
    // Derive the target list from the same source the command renders it
    // from, so adding a handoff target can't silently drift the test.
    expect(r.stdout).toContain(HANDOFF_CHOICES.join('|'))
  })

  it('rejects an unknown --target with a clear error and exits 1', async () => {
    const r = await runPiped(['impl', '--target', 'bogus'], {
      cwd: tmpDir,
      timeoutMs: 5_000,
    })

    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const combined = r.stdout + r.stderr
    expect(combined).toContain('Unknown --target')
    expect(combined).toContain('bogus')
    expect(combined).toContain('claude-code')
    expect(combined).toContain('wizard')
  })

  it('--help documents the --target flag under Impl Flags', async () => {
    const r = await runPiped(['--help'], { timeoutMs: 5_000 })

    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('Impl Flags:')
    expect(r.stdout).toContain('--target')
    expect(r.stdout).toContain('claude-code | codex | agents-md | wizard')
  })
})

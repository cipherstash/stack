import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * #738: `stash plan` printed `Plan drafted at .cipherstash/plan.md` and exited
 * 0 unconditionally. The plan file is written by the handed-off agent, not by
 * the CLI, so a failed or deferred handoff produced a false success — and sent
 * `stash impl` (and any automation reading the outro) after a file that never
 * existed. The command now verifies the file on disk after the handoff and
 * reports the outcome that actually occurred.
 *
 * A fake `claude` binary prepended to PATH drives the "agent launched" paths
 * without the real agent — no DB, no network. (The e2e suite runs on POSIX
 * only, so a /bin/sh script is fine.)
 */
describe('stash plan — outcome reflects the plan file on disk', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'plan-outcome-e2e-'))
    mkdirSync(join(dir, '.cipherstash'), { recursive: true })
    writeFileSync(
      join(dir, '.cipherstash', 'context.json'),
      JSON.stringify({
        integration: 'postgresql',
        packageManager: 'npm',
        schemas: [],
      }),
    )
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  /**
   * Write an executable fake `claude` into a bin dir under the fixture and
   * return a PATH that resolves it first. `spawnAgent` inherits the CLI's
   * cwd, so the script's relative paths land inside the fixture project.
   */
  function fakeClaudePath(script: string): string {
    const bin = join(dir, 'fake-bin')
    mkdirSync(bin, { recursive: true })
    const file = join(bin, 'claude')
    writeFileSync(file, `#!/bin/sh\n${script}\n`)
    chmodSync(file, 0o755)
    return `${bin}${delimiter}${process.env.PATH ?? ''}`
  }

  it('exits 1 when the launched agent writes no plan (no false success)', async () => {
    const r = await runPiped(['plan', '--target', 'claude-code'], {
      cwd: dir,
      env: { PATH: fakeClaudePath('exit 0') },
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.plan.notWritten)
    expect(out).not.toContain(messages.plan.drafted)
  })

  it('reports "Plan drafted" and exits 0 when the agent wrote the plan', async () => {
    const r = await runPiped(['plan', '--target', 'claude-code'], {
      cwd: dir,
      env: {
        PATH: fakeClaudePath('echo "# Plan" > .cipherstash/plan.md'),
      },
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(0)
    const out = r.stdout + r.stderr
    expect(out).toContain(`${messages.plan.drafted} \`.cipherstash/plan.md\``)
  })

  it('reports a pre-existing plan as unchanged, not drafted', async () => {
    writeFileSync(join(dir, '.cipherstash', 'plan.md'), '# old plan\n')
    const r = await runPiped(['plan', '--target', 'claude-code'], {
      cwd: dir,
      env: { PATH: fakeClaudePath('exit 0') },
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    // A usable plan exists on disk, so this is not a failure — but the run
    // must not claim it drafted anything.
    expect(r.exitCode).toBe(0)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.plan.unchanged)
    expect(out).not.toContain(messages.plan.drafted)
  })

  it('reports "drafted" when the agent revises a pre-existing plan', async () => {
    writeFileSync(join(dir, '.cipherstash', 'plan.md'), '# old plan\n')
    const r = await runPiped(['plan', '--target', 'claude-code'], {
      cwd: dir,
      // The agent appends — a real revision that changes size (and mtime), so
      // the change-detection limb reports "drafted", not "unchanged".
      env: { PATH: fakeClaudePath('echo "# revised" >> .cipherstash/plan.md') },
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(0)
    const out = r.stdout + r.stderr
    expect(out).toContain(`${messages.plan.drafted} \`.cipherstash/plan.md\``)
    expect(out).not.toContain(messages.plan.unchanged)
  })

  it('treats a plan.md directory as no plan, not a false "unchanged"', async () => {
    // `statSync` succeeds for a directory, but no agent can write a plan there.
    // Without the isFile() gate this would warn "already exists" and then, with
    // an agent that writes nothing, report a false "unchanged" exit 0.
    mkdirSync(join(dir, '.cipherstash', 'plan.md'))
    const r = await runPiped(['plan', '--target', 'claude-code'], {
      cwd: dir,
      env: { PATH: fakeClaudePath('exit 0') },
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.plan.notWritten)
    expect(out).not.toContain(messages.plan.unchanged)
    expect(out).not.toContain(messages.plan.drafted)
  })

  it('agents-md handoff says "No plan drafted yet" instead of claiming success', async () => {
    const r = await runPiped(['plan', '--target', 'agents-md'], {
      cwd: dir,
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    // The deferred handoff delivered its files-and-instructions contract, so
    // exit 0 — but the plan is written later, by the user's editor agent.
    expect(r.exitCode).toBe(0)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.plan.noPlanYet)
    expect(out).not.toContain(messages.plan.drafted)
  })

  it('claude-code target without claude on PATH defers honestly', async () => {
    const r = await runPiped(['plan', '--target', 'claude-code'], {
      cwd: dir,
      // A PATH with no `claude` anywhere: the handoff writes files and
      // prints install instructions instead of spawning.
      env: { PATH: '/usr/bin:/bin' },
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(0)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.plan.noPlanYet)
    expect(out).not.toContain(messages.plan.drafted)
  })

  it('exits 1 with a clear message when the plan path cannot be statted', async () => {
    // A self-referential symlink at plan.md makes `statSync` throw ELOOP, not
    // ENOENT — a non-ENOENT fs error that must surface as a controlled exit
    // (clear message + non-zero), never an opaque "Fatal error" crash.
    symlinkSync('plan.md', join(dir, '.cipherstash', 'plan.md'))
    const r = await runPiped(['plan', '--target', 'agents-md'], {
      cwd: dir,
      timeoutMs: 20000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const out = r.stdout + r.stderr
    expect(out).toContain('Could not read')
    expect(out).not.toContain(messages.plan.drafted)
  })
})

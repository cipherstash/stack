import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * `stash plan --complete-rollout` skips the production-deploy gate, so it needs
 * explicit consent. Non-interactively that means `--yes` — without it the
 * command must REFUSE with a non-zero exit, never silently cancel-with-0 (which
 * would let automation assume a plan was drafted when none was).
 *
 * These cases resolve entirely before any agent handoff, so they need no DB and
 * no network — just a minimal `.cipherstash/context.json` so the command gets
 * past its "run init first" guard.
 */
describe('stash plan --complete-rollout — non-interactive consent', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'plan-complete-rollout-e2e-'))
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

  it('refuses without --yes and exits 1 (does not silently succeed)', async () => {
    const r = await runPiped(['plan', '--complete-rollout'], {
      cwd: dir,
      timeoutMs: 12000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.plan.completeRolloutNeedsYes)
    expect(out).toContain('--yes')
  })

  it('--yes confirms the gate-skip without a prompt (does not exit 1 on consent)', async () => {
    const r = await runPiped(['plan', '--complete-rollout', '--yes'], {
      cwd: dir,
      timeoutMs: 12000,
    })
    expect(r.timedOut).toBe(false)
    // With --yes the gate-skip is confirmed; the command proceeds past the
    // refusal (it then stops at the no-agent-target hint, exit 0 — no plan is
    // drafted without a --target, which is the existing non-interactive
    // behaviour and not what this flag governs).
    expect(r.exitCode).toBe(0)
    const out = r.stdout + r.stderr
    expect(out).toContain(messages.plan.completeRolloutConfirmed)
    expect(out).not.toContain(messages.plan.completeRolloutNeedsYes)
  })
})

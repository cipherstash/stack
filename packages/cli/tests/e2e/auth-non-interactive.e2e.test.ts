import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * Non-interactive auth. These cases all resolve the region *before* any
 * network I/O (an invalid or missing region fails in `resolveRegion`), so
 * they're deterministic and never touch the auth server. The happy path
 * (valid region → device-code flow) is intentionally not exercised here —
 * it would hit the network and block on a human completing the browser step.
 *
 * The core regression these guard against: in a non-TTY context the region
 * picker used to be the only prompt with no escape hatch, so an agent
 * running `stash auth login` would hang. It must now exit cleanly instead.
 */

/** Find the first stdout line that parses as a JSON object, or undefined. */
function firstJsonLine(stdout: string): Record<string, unknown> | undefined {
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('{')) continue
    try {
      return JSON.parse(trimmed) as Record<string, unknown>
    } catch {
      // not JSON — keep scanning
    }
  }
  return undefined
}

describe('stash auth login — non-interactive region resolution', () => {
  it('exits 1 (no hang) in a non-TTY context with no region', async () => {
    const r = await runPiped(['auth', 'login'], { timeoutMs: 8000 })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    expect(r.stdout + r.stderr).toContain(
      messages.auth.regionMissingNonInteractive,
    )
  })

  it('--json with no region emits a JSON region_required error and exits 1', async () => {
    const r = await runPiped(['auth', 'login', '--json'], { timeoutMs: 8000 })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const payload = firstJsonLine(r.stdout)
    expect(payload).toMatchObject({
      status: 'error',
      code: 'region_required',
    })
  })

  it('--json with an unknown region emits a JSON region_invalid error and exits 1', async () => {
    const r = await runPiped(
      ['auth', 'login', '--region', 'moon-base-1', '--json'],
      { timeoutMs: 8000 },
    )
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const payload = firstJsonLine(r.stdout)
    expect(payload).toMatchObject({
      status: 'error',
      code: 'region_invalid',
    })
  })

  it('an unknown region (no --json) prints an actionable error and exits 1', async () => {
    const r = await runPiped(['auth', 'login', '--region', 'us-east-9'], {
      timeoutMs: 8000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    // Stable leader from messages.auth.regionInvalid + the offending value.
    expect(r.stdout + r.stderr).toContain('Unknown region')
    expect(r.stdout + r.stderr).toContain('us-east-9')
  })
})

describe('stash CLI help — non-interactive auth flags are documented', () => {
  it('top-level --help lists --region and --json', async () => {
    const r = await runPiped(['--help'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('--region')
    expect(r.stdout).toContain('--json')
    expect(r.stdout).toContain('STASH_REGION')
  })

  it('auth --help lists --region, --json and --no-open', async () => {
    const r = await runPiped(['auth', '--help'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('--region')
    expect(r.stdout).toContain('--json')
    expect(r.stdout).toContain('--no-open')
  })
})

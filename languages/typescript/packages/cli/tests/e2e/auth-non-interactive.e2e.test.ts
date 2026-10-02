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

  it('a valueless --region exits 1 with a "needs a value" message (not a hang)', async () => {
    // `--region` with nothing after it is booleanised by the arg parser; the
    // command must call it out rather than silently treating it as "no region".
    const r = await runPiped(['auth', 'login', '--region'], { timeoutMs: 8000 })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    expect(r.stdout + r.stderr).toContain(messages.auth.regionFlagNeedsValue)
  })

  it('--json with a valueless --region emits a JSON region_invalid error and exits 1', async () => {
    const r = await runPiped(['auth', 'login', '--region', '--json'], {
      timeoutMs: 8000,
    })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const payload = firstJsonLine(r.stdout)
    expect(payload).toMatchObject({ status: 'error', code: 'region_invalid' })
  })
})

describe('stash auth regions — list available regions', () => {
  it('prints the region labels and exits 0', async () => {
    const r = await runPiped(['auth', 'regions'])
    expect(r.exitCode).toBe(0)
    // A couple of known regions should appear in the human output.
    expect(r.stdout).toContain('us-east-1')
    expect(r.stdout).toContain('ap-southeast-2')
  })

  it('--json emits an array of { slug, label } objects', async () => {
    const r = await runPiped(['auth', 'regions', '--json'])
    expect(r.exitCode).toBe(0)
    const parsed = JSON.parse(r.stdout.trim()) as Array<{
      slug: string
      label: string
    }>
    expect(Array.isArray(parsed)).toBe(true)
    expect(parsed.length).toBeGreaterThan(0)
    for (const entry of parsed) {
      expect(typeof entry.slug).toBe('string')
      expect(typeof entry.label).toBe('string')
      expect(entry.slug).not.toMatch(/\.aws$/)
    }
    expect(parsed.map((e) => e.slug)).toContain('us-east-1')
  })

  it('is listed in `auth --help`', async () => {
    const r = await runPiped(['auth', '--help'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('regions')
  })
})

describe('stash CLI help — non-interactive auth flags are documented', () => {
  it('top-level --help points at per-command help for flags', async () => {
    // The banner no longer inlines every command's flags; it lists the commands
    // and directs users to `<command> --help` for the flag detail (which is
    // asserted per-command below).
    const r = await runPiped(['--help'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('auth login')
    expect(r.stdout).toContain('--help')
  })

  it('auth --help lists the auth subcommands', async () => {
    // `auth` is a command group: its `--help` lists the subcommands and points
    // at their per-command help, rather than dumping every subcommand's flags.
    const r = await runPiped(['auth', '--help'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('auth login')
    expect(r.stdout).toContain('auth regions')
    expect(r.stdout).toContain('--help')
  })

  it('auth login --help lists --region, --json and --no-open', async () => {
    const r = await runPiped(['auth', 'login', '--help'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('--region')
    expect(r.stdout).toContain('--json')
    expect(r.stdout).toContain('--no-open')
  })
})

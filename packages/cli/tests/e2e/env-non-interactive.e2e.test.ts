import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * Non-interactive `stash env`. Only the missing-name failure is exercised:
 * the command resolves the credential name BEFORE loading the device profile
 * or touching the network, so these cases are deterministic, credential-free,
 * and — critically — can never mint real keys on a developer machine that
 * happens to have a live `~/.cipherstash` session.
 *
 * The happy path (real CTS + ZeroKMS calls) is covered by unit tests with a
 * stubbed fetch; minting live credentials from CI is deliberately not done.
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

describe('stash env — non-interactive name resolution', () => {
  it('exits 1 (no hang, no mint) in a non-TTY context with no --name', async () => {
    const r = await runPiped(['env'], { timeoutMs: 8000 })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    expect(r.stdout + r.stderr).toContain(messages.env.missingName)
    // The actionable fix is named.
    expect(r.stdout + r.stderr).toContain('--name')
  })

  it('--json with no --name emits a JSON missing_name error and exits 1', async () => {
    const r = await runPiped(['env', '--json'], { timeoutMs: 8000 })
    expect(r.timedOut).toBe(false)
    expect(r.exitCode).toBe(1)
    const payload = firstJsonLine(r.stdout)
    expect(payload).toMatchObject({ status: 'error', code: 'missing_name' })
  })
})

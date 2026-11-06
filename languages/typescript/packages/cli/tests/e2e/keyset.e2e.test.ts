import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { run } from '../helpers/run.js'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * `stash keyset create` / `rewrap` end to end. The vendor backends need cloud
 * credentials, so the round trip uses the static key backend, which runs the
 * real native binding (`keysetCreate` / `keysetRewrap` in @cipherstash/auth)
 * with no network. The vendor clients are tested in their own crates.
 */

/** A fixed, test-only static key (bytes 0..31), and a second one. */
const TEST_ONLY_KEY_A = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
const TEST_ONLY_KEY_B = 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8='

const dir = mkdtempSync(join(tmpdir(), 'stash-keyset-e2e-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

function jsonLine(stdout: string): Record<string, unknown> {
  const line = stdout
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.startsWith('{'))
  if (!line) throw new Error(`no JSON line in stdout: ${stdout}`)
  return JSON.parse(line) as Record<string, unknown>
}

describe('stash keyset', () => {
  it('help says ZeroKMS users never need it', async () => {
    const r = await run(['keyset', 'create', '--help'], {
      env: { npm_config_user_agent: '' },
    })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('Usage: npx stash keyset create [options]')
    expect(r.output).toContain('ZeroKMS users never need this command')
    for (const flag of ['--backend', '--vendor-key', '--mode', '--key-env']) {
      expect(r.output).toContain(flag)
    }
  })

  it('lists both subcommands in the group help and the banner', async () => {
    const group = await run(['keyset', '--help'], {
      env: { npm_config_user_agent: '' },
    })
    expect(group.output).toContain('keyset create')
    expect(group.output).toContain('keyset rewrap')
    const banner = await run(['--help'])
    expect(banner.output).toContain('keyset create')
  })

  it('an unknown subcommand exits 1 with the ZeroKMS note', async () => {
    const r = await runPiped(['keyset', 'bogus'], { timeoutMs: 8000 })
    expect(r.exitCode).toBe(1)
    expect(r.stderr).toContain(messages.keyset.unknownSubcommand)
    expect(r.stderr).toContain('ZeroKMS users never need stash keyset')
  })

  it('missing flags fail with a JSON error before any vendor call', async () => {
    const r = await runPiped(
      ['keyset', 'create', '--backend', 'aws', '--json'],
      {
        timeoutMs: 8000,
      },
    )
    expect(r.exitCode).toBe(1)
    expect(jsonLine(r.stdout)).toMatchObject({
      status: 'error',
      code: 'missing_flag',
    })
  })

  it('creates a static keyset record and rewraps it to another key', async () => {
    const env = {
      CS_TEST_ONLY_KEY_A: TEST_ONLY_KEY_A,
      CS_TEST_ONLY_KEY_B: TEST_ONLY_KEY_B,
    }
    const out = join(dir, 'keyset.env')
    const created = await runPiped(
      [
        'keyset',
        'create',
        '--backend',
        'static',
        '--vendor-key',
        'key-a',
        '--mode',
        'derived',
        '--name',
        'users',
        '--key-env',
        'CS_TEST_ONLY_KEY_A',
        '--out',
        out,
      ],
      { env, timeoutMs: 15000 },
    )
    expect(created.stderr).not.toContain('Error')
    expect(created.exitCode).toBe(0)
    expect(statSync(out).mode & 0o777).toBe(0o600)
    const block = readFileSync(out, 'utf-8')
    const record = /^CS_KEYSET_RECORD_USERS=(stack-keyset:\S+)$/m.exec(
      block,
    )?.[1]
    expect(record).toBeDefined()
    // The key came from the environment, so none is written.
    expect(block).not.toContain('CS_STATIC_KEY=')
    expect(block).not.toContain(TEST_ONLY_KEY_A)

    const rewrapped = await runPiped(
      [
        'keyset',
        'rewrap',
        '--in',
        out,
        '--key-env',
        'CS_TEST_ONLY_KEY_A',
        '--vendor-key',
        'key-b',
        '--new-key-env',
        'CS_TEST_ONLY_KEY_B',
        '--json',
      ],
      { env, timeoutMs: 15000 },
    )
    expect(rewrapped.exitCode).toBe(0)
    const event = jsonLine(rewrapped.stdout)
    expect(event).toMatchObject({
      status: 'rewrapped',
      name: 'users',
      backend: 'static',
      mode: 'derived',
      vendorKey: 'key-b',
      envVar: 'CS_KEYSET_RECORD_USERS',
    })
    expect(event.record).not.toBe(record)

    // The old key no longer opens the rewrapped record.
    const wrong = await runPiped(
      [
        'keyset',
        'rewrap',
        String(event.record),
        '--key-env',
        'CS_TEST_ONLY_KEY_A',
        '--json',
      ],
      { env, timeoutMs: 15000 },
    )
    expect(wrong.exitCode).toBe(1)
    expect(jsonLine(wrong.stdout)).toMatchObject({
      status: 'error',
      code: 'vendor_error',
    })
  })
})

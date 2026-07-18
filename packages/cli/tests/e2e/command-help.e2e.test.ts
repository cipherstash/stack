import { describe, expect, it } from 'vitest'
import { run } from '../helpers/run.js'

/**
 * E2E coverage for per-command `--help`. The renderer itself is unit-tested in
 * `src/cli/__tests__/help.test.ts`; these tests close the gap between "the
 * renderer works in isolation" and "`stash <command> --help` actually routes
 * to it" — i.e. the `run()` dispatch in `bin/main.ts` and the `-h` short-flag
 * handling in `parseArgs`.
 */

describe('per-command --help', () => {
  it('renders a group listing for `eql --help`', async () => {
    const r = await run(['eql', '--help'], {
      env: { npm_config_user_agent: '' },
    })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('Usage: npx stash eql <command> [options]')
    expect(r.output).toContain('eql install')
    expect(r.output).toContain('eql migration')
    expect(r.output).toContain('eql upgrade')
    expect(r.output).toContain('eql status')
    // A group listing must NOT be the global banner.
    expect(r.output).not.toContain('CipherStash CLI v')
  })

  it('renders full command help for `eql migration --help`', async () => {
    const r = await run(['eql', 'migration', '--help'], {
      env: { npm_config_user_agent: '' },
    })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('Usage: npx stash eql migration [options]')
    expect(r.output).toContain('--drizzle')
    expect(r.output).toContain('--supabase')
  })

  it('renders full command help for `eql install --help`', async () => {
    const r = await run(['eql', 'install', '--help'], {
      env: { npm_config_user_agent: '' },
    })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('Usage: npx stash eql install [options]')
    expect(r.output).toContain('--eql-version <2|3>')
    expect(r.output).toContain('Also settable via DATABASE_URL.')
  })

  it('honours the `-h` short flag after a command', async () => {
    const r = await run(['eql', 'install', '-h'], {
      env: { npm_config_user_agent: '' },
    })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('Usage: npx stash eql install [options]')
  })

  it('falls back to the global banner for an unknown command path', async () => {
    // `wizard` forwards to its own parser, but an unknown top-level token with
    // --help should still surface the global help rather than crashing.
    const r = await run(['definitely-not-a-command', '--help'], {
      env: { npm_config_user_agent: '' },
    })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('CipherStash CLI v')
  })

  it('still renders the global banner for a bare `--help`', async () => {
    const r = await run(['--help'], { env: { npm_config_user_agent: '' } })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('CipherStash CLI v')
    expect(r.output).toContain('Usage: npx stash <command> [options]')
  })
})

import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { requireIntegrationEnv } from '@cipherstash/test-kit'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

/**
 * The credential gate is the only thing between a rotated secret and a run that
 * fails once per test with `[encryption]: Not authenticated`. It had no test.
 *
 * A partial environment — `CS_WORKSPACE_CRN` set, the client keys missing — used
 * to pass, because the check was `if (CS_WORKSPACE_CRN) return true`. Reported by
 * Copilot on #616, reproduced against a live suite, fixed here.
 *
 * `homedir()` reads `$HOME` on POSIX, so pointing `HOME` at a scratch directory
 * controls whether a `~/.cipherstash` profile appears to exist.
 */
const CS_VARS = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
] as const

let home: string
let saved: Record<string, string | undefined>

function setEnv(values: Partial<Record<(typeof CS_VARS)[number], string>>) {
  for (const name of CS_VARS) delete process.env[name]
  for (const [name, value] of Object.entries(values)) process.env[name] = value
}

function withProfile() {
  mkdirSync(join(home, '.cipherstash'), { recursive: true })
}

const ALL_FOUR = Object.fromEntries(
  CS_VARS.map((name) => [name, `value-of-${name}`]),
) as Record<(typeof CS_VARS)[number], string>

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'cs-env-'))
  saved = { HOME: process.env['HOME'] }
  for (const name of CS_VARS) saved[name] = process.env[name]
  process.env['HOME'] = home
})

afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name]
    else process.env[name] = value
  }
  rmSync(home, { recursive: true, force: true })
})

describe('requireIntegrationEnv — cipherstash credentials', () => {
  it('accepts all four variables, with no profile', () => {
    setEnv(ALL_FOUR)

    expect(() => requireIntegrationEnv(['cipherstash'])).not.toThrow()
  })

  it('accepts a profile with no variables', () => {
    setEnv({})
    withProfile()

    expect(() => requireIntegrationEnv(['cipherstash'])).not.toThrow()
  })

  it('rejects a partial environment even when a profile exists', () => {
    // The regression. `CS_WORKSPACE_CRN` alone used to satisfy the gate, and the
    // run then died inside `encrypt()` rather than here.
    setEnv({ CS_WORKSPACE_CRN: 'crn:ap-southeast-2.aws:ABC' })
    withProfile()

    expect(() => requireIntegrationEnv(['cipherstash'])).toThrow(
      /PARTIALLY configured/,
    )
  })

  it('names exactly the missing variables', () => {
    setEnv({ CS_WORKSPACE_CRN: 'crn', CS_CLIENT_ID: 'id' })

    expect(() => requireIntegrationEnv(['cipherstash'])).toThrow(
      /missing CS_CLIENT_KEY, CS_CLIENT_ACCESS_KEY/,
    )
  })

  it('rejects an empty environment with no profile, and offers both routes', () => {
    setEnv({})

    let message = ''
    try {
      requireIntegrationEnv(['cipherstash'])
    } catch (cause) {
      message = (cause as Error).message
    }

    expect(message).toContain('none are configured')
    expect(message).toContain('stash auth login')
    expect(message).not.toContain('PARTIALLY')
  })

  it('treats an empty-string variable as missing, not as set', () => {
    // A cleared GitHub secret expands to the empty string, not to unset.
    setEnv({ ...ALL_FOUR, CS_CLIENT_KEY: '' })

    expect(() => requireIntegrationEnv(['cipherstash'])).toThrow(
      /missing CS_CLIENT_KEY/,
    )
  })

  it('reports every unmet requirement at once, not one per run', () => {
    setEnv({})
    delete process.env['DATABASE_URL']
    delete process.env['PGRST_URL']

    let message = ''
    try {
      requireIntegrationEnv(['cipherstash', 'database', 'pgrest'])
    } catch (cause) {
      message = (cause as Error).message
    }

    expect(message).toContain('CipherStash credentials')
    expect(message).toContain('DATABASE_URL')
    expect(message).toContain('PGRST_URL')
  })
})

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { checkPrerequisites } from '../lib/prerequisites.js'

// Force the auth check to fail so we exercise the missing-list copy.
// `@cipherstash/auth` `0.41`: `detect()` returns `Result<AutoStrategy, AuthFailure>`
// and `getToken()` returns `Result<TokenResult, AuthFailure>` (no throwing).
// A `NOT_AUTHENTICATED` failure is what `hasCredentials` reads as "missing".
vi.mock('@cipherstash/auth', () => ({
  default: {
    AutoStrategy: {
      detect: () => ({
        data: {
          getToken: async () => ({
            failure: {
              type: 'NOT_AUTHENTICATED',
              error: new Error('not authed'),
            },
          }),
        },
      }),
    },
  },
}))

describe('checkPrerequisites missing-list copy', () => {
  let tmp: string
  let originalUA: string | undefined

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wiz-prereq-'))
    originalUA = process.env.npm_config_user_agent
    delete process.env.npm_config_user_agent
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
    if (originalUA === undefined) delete process.env.npm_config_user_agent
    else process.env.npm_config_user_agent = originalUA
  })

  it('uses bunx when bun.lock is present', async () => {
    writeFileSync(join(tmp, 'bun.lock'), '')
    const r = await checkPrerequisites(tmp)
    expect(r.ok).toBe(false)
    expect(r.missing.join('\n')).toContain('Run: bunx stash auth login')
    expect(r.missing.join('\n')).toContain('Run: bunx stash eql install')
    expect(r.missing.join('\n')).not.toMatch(/\bnpx\b/)
  })

  it('uses pnpm dlx when pnpm-lock.yaml is present', async () => {
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), '')
    const r = await checkPrerequisites(tmp)
    expect(r.missing.join('\n')).toContain('Run: pnpm dlx stash auth login')
  })

  it('falls back to npx when no package manager can be detected', async () => {
    const r = await checkPrerequisites(tmp)
    expect(r.missing.join('\n')).toContain('Run: npx stash auth login')
  })
})

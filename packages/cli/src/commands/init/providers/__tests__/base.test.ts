import { describe, expect, it } from 'vitest'
import { createBaseProvider } from '../base.js'

describe('createBaseProvider getNextSteps', () => {
  const provider = createBaseProvider()

  it('uses npx when package manager is npm', () => {
    const steps = provider.getNextSteps({}, 'npm')
    expect(steps[0]).toBe('Set up your database: npx stash db install')
    expect(steps[1]).toContain('npx stash wizard')
  })

  it('uses bunx when package manager is bun', () => {
    const steps = provider.getNextSteps({}, 'bun')
    expect(steps[0]).toBe('Set up your database: bunx stash db install')
    expect(steps[1]).toContain('bunx stash wizard')
    // Sanity: the old hardcoded `npx` should be gone.
    for (const s of steps) expect(s).not.toMatch(/\bnpx\b/)
  })

  it('uses pnpm dlx when package manager is pnpm', () => {
    const steps = provider.getNextSteps({}, 'pnpm')
    expect(steps[0]).toBe('Set up your database: pnpm dlx stash db install')
    expect(steps[1]).toContain('pnpm dlx stash wizard')
  })

  it('uses yarn dlx when package manager is yarn', () => {
    const steps = provider.getNextSteps({}, 'yarn')
    expect(steps[0]).toBe('Set up your database: yarn dlx stash db install')
  })

  it('still includes the manual-edit suffix when clientFilePath is set', () => {
    const steps = provider.getNextSteps(
      { clientFilePath: './src/encryption/index.ts' },
      'bun',
    )
    expect(steps[1]).toContain('edit ./src/encryption/index.ts directly')
  })
})

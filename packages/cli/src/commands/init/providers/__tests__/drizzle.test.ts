import { describe, expect, it } from 'vitest'
import { createDrizzleProvider } from '../drizzle.js'

describe('createDrizzleProvider getNextSteps', () => {
  const provider = createDrizzleProvider()

  it('uses npx when package manager is npm', () => {
    const steps = provider.getNextSteps({}, 'npm')
    expect(steps[0]).toBe(
      'Set up your database: npx stash eql install --drizzle',
    )
  })

  it('uses bunx when package manager is bun', () => {
    const steps = provider.getNextSteps({}, 'bun')
    expect(steps[0]).toBe(
      'Set up your database: bunx stash eql install --drizzle',
    )
    expect(steps[1]).toContain('bunx stash wizard')
    for (const s of steps) expect(s).not.toMatch(/\bnpx\b/)
  })

  it('uses pnpm dlx when package manager is pnpm', () => {
    const steps = provider.getNextSteps({}, 'pnpm')
    expect(steps[0]).toBe(
      'Set up your database: pnpm dlx stash eql install --drizzle',
    )
  })

  it('uses yarn dlx when package manager is yarn', () => {
    const steps = provider.getNextSteps({}, 'yarn')
    expect(steps[0]).toBe(
      'Set up your database: yarn dlx stash eql install --drizzle',
    )
  })
})

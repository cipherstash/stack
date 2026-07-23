import { describe, expect, it } from 'vitest'
import { createPrismaNextProvider } from '../prisma-next.js'

describe('createPrismaNextProvider getNextSteps', () => {
  const provider = createPrismaNextProvider()

  it('points at prisma-next migration plan + apply rather than stash eql install', () => {
    const steps = provider.getNextSteps({}, 'pnpm')
    // The whole story hinges on this: Prisma Next users never run
    // `stash eql install` — the framework handles the EQL bundle.
    for (const step of steps) {
      expect(step).not.toMatch(/stash eql install/)
    }
    const planApply = steps.find((s) => s.includes('migration plan'))
    expect(planApply).toBeDefined()
    expect(planApply).toContain('prisma-next migrate')
  })

  it('uses pnpm dlx for invocations when the package manager is pnpm', () => {
    const steps = provider.getNextSteps({}, 'pnpm')
    expect(steps.some((s) => s.includes('pnpm dlx prisma-next'))).toBe(true)
  })

  it('uses npx for invocations when the package manager is npm', () => {
    const steps = provider.getNextSteps({}, 'npm')
    expect(steps.some((s) => s.includes('npx prisma-next'))).toBe(true)
    for (const step of steps) {
      expect(step).not.toMatch(/\bbunx\b/)
    }
  })

  it('mentions cipherstashFromStack rather than a hand-written encryption client', () => {
    const steps = provider.getNextSteps({}, 'pnpm')
    expect(steps.some((s) => s.includes('cipherstashFromStack'))).toBe(true)
    for (const step of steps) {
      expect(step).not.toMatch(/encryption\/index\.ts/)
    }
  })
})

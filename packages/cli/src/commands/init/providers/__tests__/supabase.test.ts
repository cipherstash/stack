import { describe, expect, it } from 'vitest'
import { createSupabaseProvider } from '../supabase.js'

describe('createSupabaseProvider getNextSteps', () => {
  const provider = createSupabaseProvider()

  it('uses npx when package manager is npm', () => {
    const steps = provider.getNextSteps({}, 'npm')
    expect(steps[0]).toBe(
      'Install EQL: npx stash db install --supabase (prompts for migration vs direct)',
    )
  })

  it('uses bunx when package manager is bun', () => {
    const steps = provider.getNextSteps({}, 'bun')
    expect(steps[0]).toBe(
      'Install EQL: bunx stash db install --supabase (prompts for migration vs direct)',
    )
    expect(steps[2]).toContain('bunx stash wizard') // wizard step is third
    for (const s of steps) expect(s).not.toMatch(/\bnpx\b/)
  })

  it('uses pnpm dlx when package manager is pnpm', () => {
    const steps = provider.getNextSteps({}, 'pnpm')
    expect(steps[0]).toContain('pnpm dlx stash db install --supabase')
  })

  it('uses yarn dlx when package manager is yarn', () => {
    const steps = provider.getNextSteps({}, 'yarn')
    expect(steps[0]).toBe(
      'Install EQL: yarn dlx stash db install --supabase (prompts for migration vs direct)',
    )
    expect(steps[2]).toContain('yarn dlx stash wizard')
    // Sanity: the supabase CLI commands stay untouched.
    expect(steps.join('\n')).toContain('supabase db reset')
    expect(steps.join('\n')).toContain('supabase migration up')
  })

  it('leaves the supabase CLI commands alone (those are not npm packages)', () => {
    const steps = provider.getNextSteps({}, 'bun')
    expect(steps.join('\n')).toContain('supabase db reset')
    expect(steps.join('\n')).toContain('supabase migration up')
  })
})

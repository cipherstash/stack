import { describe, expect, it } from 'vitest'
import type { InitState } from '../../types.js'
import { createSupabaseProvider } from '../supabase.js'

describe('createSupabaseProvider getNextSteps', () => {
  const provider = createSupabaseProvider()

  it('uses npx when package manager is npm', () => {
    const steps = provider.getNextSteps({}, 'npm')
    expect(steps[0]).toBe(
      'Install EQL: npx stash eql migration --supabase (writes it into supabase/migrations/)',
    )
  })

  it('uses bunx when package manager is bun', () => {
    const steps = provider.getNextSteps({}, 'bun')
    expect(steps[0]).toBe(
      'Install EQL: bunx stash eql migration --supabase (writes it into supabase/migrations/)',
    )
    expect(steps[2]).toContain('bunx stash wizard') // wizard step is third
    for (const s of steps) expect(s).not.toMatch(/\bnpx\b/)
  })

  it('uses pnpm dlx when package manager is pnpm', () => {
    const steps = provider.getNextSteps({}, 'pnpm')
    expect(steps[0]).toContain('pnpm dlx stash eql migration --supabase')
  })

  it('uses yarn dlx when package manager is yarn', () => {
    const steps = provider.getNextSteps({}, 'yarn')
    expect(steps[0]).toBe(
      'Install EQL: yarn dlx stash eql migration --supabase (writes it into supabase/migrations/)',
    )
    expect(steps[2]).toContain('yarn dlx stash wizard')
    // Sanity: the supabase CLI commands stay untouched.
    expect(steps.join('\n')).toContain('supabase db reset')
    expect(steps.join('\n')).toContain('supabase db push')
  })

  it('leaves the supabase CLI commands alone (those are not npm packages)', () => {
    const steps = provider.getNextSteps({}, 'bun')
    expect(steps.join('\n')).toContain('supabase db reset')
    expect(steps.join('\n')).toContain('supabase db push')
  })

  it('never pairs a direct `eql install` with `supabase db reset` (#613)', () => {
    // That pairing was the defect: these steps told the user to install EQL
    // directly and then run the one command that drops it. Whatever the
    // wording, a direct install must not appear alongside a reset.
    for (const state of [{}, { eqlMigrationPending: true } as InitState]) {
      const joined = provider.getNextSteps(state, 'npm').join('\n')
      expect(joined).not.toContain('eql install')
    }
  })

  it('says only "apply it" once init has already generated the migration', () => {
    // init writes the migration itself on this path, so repeating the generate
    // step would have the user run a command that then refuses (one install
    // migration already exists).
    const steps = provider.getNextSteps(
      { eqlMigrationPending: true } as InitState,
      'npm',
    )

    expect(steps[0]).toBe(
      'Apply the generated EQL migration: supabase db reset (local) or supabase db push (remote/linked)',
    )
    expect(steps.join('\n')).not.toContain('eql migration --supabase')
  })

  it('never sends a remote apply to a bare `supabase migration up`', async () => {
    // That form targets the LOCAL database — the remote ones are `db push` and
    // `migration up --linked`. Telling a user it is the remote command means
    // their production database silently never gets EQL.
    for (const state of [{}, { eqlMigrationPending: true } as InitState]) {
      const joined = provider.getNextSteps(state, 'npm').join('\n')
      expect(joined).not.toMatch(/supabase migration up(?! --linked)/)
    }
  })
})

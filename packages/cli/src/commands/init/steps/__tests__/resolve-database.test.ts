import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

// The resolver is the step's only collaborator: it walks --database-url → env →
// `supabase status` → prompt → hard fail. Mock it so the step's one decision —
// whether to hint that this is a Supabase project — is observable without a
// database, a Supabase CLI, or a TTY.
vi.mock('../../../../config/database-url.js', () => ({
  resolveDatabaseUrl: vi.fn(async () => 'postgresql://localhost:5432/app'),
}))

import { resolveDatabaseUrl } from '../../../../config/database-url.js'
import { resolveDatabaseStep } from '../resolve-database.js'

const state = {} as unknown as InitState

/** The `{ supabase }` hint the step passed to the resolver. */
function supabaseHint(): boolean | undefined {
  return vi.mocked(resolveDatabaseUrl).mock.calls[0][0]?.supabase
}

describe('resolveDatabaseStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('hints Supabase for `--supabase`, so the resolver may try `supabase status`', async () => {
    const result = await resolveDatabaseStep.run(state, {
      name: 'supabase',
      selected: ['supabase'],
    } as unknown as InitProvider)

    expect(supabaseHint()).toBe(true)
    expect(result.databaseUrl).toBe('postgresql://localhost:5432/app')
  })

  it('still hints Supabase when `--supabase` is combined with another flag', async () => {
    // `stash init --drizzle --supabase` joins the flags into a single provider
    // name for referrer tracking. 'drizzle-supabase' is not 'supabase', so the
    // hint was dropped and a local Supabase project — whose URL is only
    // discoverable via `supabase status` — fell through to the interactive
    // prompt, or to a hard failure in a non-interactive run.
    await resolveDatabaseStep.run(state, {
      name: 'drizzle-supabase',
      selected: ['supabase', 'drizzle'],
    } as unknown as InitProvider)

    expect(supabaseHint()).toBe(true)
  })

  it('does not hint Supabase for a run that never asked for it', async () => {
    // The symmetric negative: hinting unconditionally would shell out to
    // `supabase status` on every plain Postgres project.
    await resolveDatabaseStep.run(state, {
      name: 'drizzle',
      selected: ['drizzle'],
    } as unknown as InitProvider)

    expect(supabaseHint()).toBe(false)
  })
})

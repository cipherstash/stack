import type { InitProvider, InitState } from '../types.js'
import { type PackageManager, runnerCommand } from '../utils.js'

export function createSupabaseProvider(): InitProvider {
  return {
    name: 'supabase',
    introMessage: 'Setting up CipherStash for your Supabase project...',
    getNextSteps(state: InitState, pm: PackageManager): string[] {
      const cli = runnerCommand(pm, 'stash')
      // Migration-first, always. A direct `eql install` does not survive
      // `supabase db reset` — the reset drops the database and replays
      // supabase/migrations/, so an install that isn't in there is gone.
      const steps = state.eqlMigrationPending
        ? [
            'Apply the generated EQL migration: supabase db reset (local) or supabase migration up (remote)',
          ]
        : [
            `Install EQL: ${cli} eql migration --supabase (writes it into supabase/migrations/)`,
            'Apply it: supabase db reset (local) or supabase migration up (remote)',
          ]

      const manualEdit = state.clientFilePath
        ? `edit ${state.clientFilePath} directly`
        : 'edit your encryption schema directly'
      steps.push(
        `Customize your schema: ${cli} wizard (AI-guided, automated) — or ${manualEdit}`,
      )

      steps.push(
        'Supabase guide: https://cipherstash.com/docs/stack/cipherstash/supabase',
        'Dashboard: https://dashboard.cipherstash.com/workspaces',
        'Need help? #supabase in Discord or support@cipherstash.com',
      )

      return steps
    },
  }
}
